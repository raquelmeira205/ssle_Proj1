# Shared helpers for the threat tests (test-ddos.sh, test-spam.sh, test-dns.sh, test-rootcause.sh).
# Sourced, not run. Every test:
#   - prints a threat card (what it is, why it matters here, how it is exploited, what is
#     monitored, what the action-response is), as asked in the project's "Discussion of results"
#   - runs the PoC and checks detection, response and recovery
#   - saves everything for the post-mortem under evidence/<threat>/ (run.log + raw excerpts)
#
# Run the tests on the Incus host (the Kali VM), from the repo root.

WAZUH_CONTAINER=${WAZUH_CONTAINER:-wazuh-container}
PROM_CONTAINER=${PROM_CONTAINER:-prometheus-container}
ALERTS_JSON=/var/ossec/logs/alerts/alerts.json

PASS=0; FAIL=0
ok()      { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()     { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
info()    { echo "  ....  $1"; }
section() { echo; echo "== $1"; }
now()     { date +%s.%N; }
elapsed() { python3 -c "print('%.1f' % ($2 - $1))"; }          # elapsed <from> <to>  (seconds)

# Mirror all output into evidence/<name>/run.log. Call once, at the top of the test.
start_evidence() {
  cd "$(dirname "$0")" || exit 1
  EVID="evidence/$1"; [ "${PLATFORM:-incus}" = k3s ] && EVID="evidence/k3s/$1"   # k3s runs never overwrite the Incus evidence
  mkdir -p "$EVID"
  exec > >(tee "$EVID/run.log") 2>&1
  echo "Run started $(date -Is) on $(hostname), platform ${PLATFORM:-incus}"
}

# Threat card. Args: name, description, relevance, exploitation, monitoring, response.
threat_card() {
  cat <<EOF

################################################################################
 THREAT: $1
################################################################################
 Description   : $2
 Why relevant  : $3
 Exploitation  : $4
 Monitoring    : $5
 Action-resp.  : $6
################################################################################
EOF
}

# Container IPv4 (exact name match).
ip_of() { incus list "^$1\$" -c4 --format csv 2>/dev/null | grep -oE '^[0-9.]+' | head -1; }

# ---------------------------------------------------------------- platform: incus | k3s
# PLATFORM=incus (default): one Incus container per service (deploy-incus.sh).
# PLATFORM=k3s: the services run as pods in the k3s cluster (Guide 2, k3s/). The helpers below
# hide the difference, so every test runs unchanged on both.
PLATFORM=${PLATFORM:-incus}
K3S_MASTER=${K3S_MASTER:-k3s-master}
K3S_NODE1=${K3S_NODE1:-k3s-node1}
declare -A SVC_PORT=([registry]=5050 [storage]=5002 [ingestion]=5001 [analytics]=5003)
declare -A NODE_PORT=([ingestion]=30001 [analytics]=30003)
is_k3s() { [ "$PLATFORM" = k3s ]; }
kctl() { incus exec "$K3S_MASTER" -- k3s kubectl -n ssle "$@"; }

# public_url <svc> [node]: the URL clients/attackers use. On k3s it is a NodePort; with
# externalTrafficPolicy Local, the node chosen decides which location answers (master = dc1).
public_url() {
  if is_k3s; then echo "http://$(ip_of "${2:-$K3S_MASTER}"):${NODE_PORT[$1]}"
  else echo "http://$(ip_of "$1"):${SVC_PORT[$1]}"; fi
}
# internal_url <svc>: URL of a cluster-internal service, valid where `near` runs
internal_url() {
  if is_k3s; then echo "http://$(kctl get svc "$1" -o jsonpath='{.spec.clusterIP}'):${SVC_PORT[$1]}"
  else echo "http://$(ip_of "$1"):${SVC_PORT[$1]}"; fi
}
# near <cmd...>: run a command where internal services are reachable (a k3s node, or here)
near() { if is_k3s; then incus exec "$K3S_MASTER" -- "$@"; else "$@"; fi; }
# agent_box <svc>: container whose Wazuh agent watches the svc's dc1 instance and runs its
# active responses (the service container itself, or the k3s node hosting the dc1 pod)
agent_box() { if is_k3s; then echo "$K3S_MASTER"; else echo "$1"; fi; }
# deploy_of <svc>: the dc1 Deployment of a service on k3s
deploy_of() { case $1 in ingestion|analytics|sensor) echo "$1-dc1" ;; *) echo "$1" ;; esac; }
svc_stop() {
  if is_k3s; then kctl scale deploy "$(deploy_of "$1")" --replicas=0 >/dev/null
  else incus stop "$1"; fi
}
svc_start() {
  if is_k3s; then kctl scale deploy "$(deploy_of "$1")" --replicas=1 >/dev/null
    kctl rollout status deploy "$(deploy_of "$1")" --timeout=120s >/dev/null
  else incus start "$1"; fi
}

# Make sure a throw-away client container exists, runs, and has python3 + bash.
ensure_client() {
  incus info "$1" >/dev/null 2>&1 || { info "creating client container $1"; incus launch images:debian/trixie "$1" >/dev/null; }
  incus start "$1" 2>/dev/null || true
  until incus exec "$1" -- getent hosts deb.debian.org >/dev/null 2>&1; do sleep 2; done
  incus exec "$1" -- sh -c 'command -v python3 >/dev/null || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null)'
}

# ---------------------------------------------------------------- Wazuh alerts
# alerts_mark: current size of alerts.json, so later reads only see THIS run's alerts.
alerts_mark() { incus exec "$WAZUH_CONTAINER" -- stat -c %s "$ALERTS_JSON" 2>/dev/null || echo 0; }

# alerts_since <mark> <rule id>: raw JSON alerts of that rule written after <mark>.
# Filters on rule.id (a plain grep also matches the 651/652 firewall alerts, which embed the
# original alert, rule id included).
alerts_since() {
  incus exec "$WAZUH_CONTAINER" -- sh -c "tail -c +$(( $1 + 1 )) $ALERTS_JSON" 2>/dev/null | python3 -c '
import sys, json
for line in sys.stdin:
    try:
        if json.loads(line).get("rule", {}).get("id") == sys.argv[1]:
            sys.stdout.write(line)
    except ValueError:
        pass
' "$2"
}

# wait_alert <mark> <rule id> <seconds> [grep filter]: poll until a matching alert appears.
wait_alert() {
  local i out
  for i in $(seq 1 "$3"); do
    out=$(alerts_since "$1" "$2" | grep -- "${4:-.}")
    [ -n "$out" ] && { echo "$out"; return 0; }
    sleep 1
  done
  return 1
}

# Human readable alert lines (stdin = JSON alerts). The agent name is the hierarchical ID
# (service-01.node.rack.dc.region.country), so it says WHERE the incident happened.
alert_summary() {
  python3 -c '
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line)
    except ValueError:
        continue
    r, ag, d = a.get("rule", {}), a.get("agent", {}), a.get("data", {})
    print("  %s  rule %s (level %s, fired %s times)" % (a.get("timestamp"), r.get("id"), r.get("level"), r.get("firedtimes", 1)))
    print("      source : srcip=%s" % d.get("srcip", "-"))
    print("      where  : agent=%s (%s)" % (ag.get("name"), ag.get("ip", "manager")))
    print("      what   : %s" % r.get("description"))
'
}

# Epoch of the first alert on stdin.
alert_first_epoch() {
  python3 -c '
import sys, json
from datetime import datetime
for line in sys.stdin:
    try:
        ts = json.loads(line)["timestamp"]
    except (ValueError, KeyError):
        continue
    print(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()); break
'
}

# ---------------------------------------------------------------- Prometheus
# On k3s the alerting Prometheus is the one inside the cluster (NodePort 30090).
prom_url() {
  if [ -n "${PROM_URL:-}" ]; then echo "$PROM_URL"
  elif is_k3s; then echo "http://$(ip_of "$K3S_MASTER"):30090"
  else echo "http://$(ip_of "$PROM_CONTAINER"):9090"; fi
}

# prom_query '<PromQL>': one line per series.
prom_query() {
  curl -s -G --max-time 5 "$(prom_url)/api/v1/query" --data-urlencode "query=$1" | python3 -c '
import sys, json
try:
    res = json.load(sys.stdin)["data"]["result"]
except Exception:
    print("    (Prometheus unreachable or bad query)"); sys.exit()
if not res:
    print("    (no data)")
for r in res:
    m = r["metric"]
    lab = ",".join("%s=%s" % (k, v) for k, v in sorted(m.items()) if k != "__name__")
    print("    {%s} %s" % (lab, r["value"][1]))
'
}

# prom_alerts: every pending/firing alert.
prom_alerts() {
  curl -s --max-time 5 "$(prom_url)/api/v1/alerts" | python3 -c '
import sys, json
try:
    alerts = json.load(sys.stdin)["data"]["alerts"]
except Exception:
    print("    (Prometheus unreachable)"); sys.exit()
if not alerts:
    print("    (no active alerts)")
for a in alerts:
    l = a["labels"]
    print("    %-32s %-8s job=%-16s root_cause=%-8s since %s" % (l["alertname"], a["state"], l.get("job", "-"), l.get("root_cause", "-"), a.get("activeAt", "")[:19]))
'
}

# prom_wait_firing <alertname> <seconds>
prom_wait_firing() {
  local i
  for i in $(seq 1 "$2"); do
    prom_alerts | grep -qE "^ +$1 +firing" && return 0
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------- firewall (firewall-drop AR)
# blocked <container> <ip>: is there an iptables DROP rule for that source that actually stops
# the traffic? Service containers: INPUT (firewall-drop). k3s nodes: only raw/PREROUTING
# (k3s-block) counts: firewall-drop also runs there, but its INPUT rule never sees NodePort
# traffic, which kube-proxy forwards to the pods.
blocked() {
  local chains='iptables -S INPUT'
  case $1 in "$K3S_MASTER"|"$K3S_NODE1") chains='iptables -t raw -S PREROUTING' ;; esac
  incus exec "$1" -- sh -c "$chains" 2>/dev/null | grep -- "-j DROP" | grep -q -- "-s $2/32"
}
# firewall <container>: both chains, for the evidence files
firewall() {
  incus exec "$1" -- sh -c 'echo "# filter INPUT"; iptables -L INPUT -n -v; echo; echo "# raw PREROUTING"; iptables -t raw -L PREROUTING -n -v' 2>&1
}

finish() {
  echo
  echo "========================================"
  echo "Result: $PASS passed, $FAIL failed"
  echo "Evidence saved in $EVID/"
  echo "========================================"
  [ "$FAIL" -eq 0 ]
}
