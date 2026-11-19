#!/usr/bin/env bash
# Threat 1 - Massive denial-of-service: HTTP flood against an SSLE service.
#
# Phases (each one saved under evidence/ddos/):
#   1. baseline        legitimate client alone
#   2. unmitigated     2 attackers + legitimate client, Wazuh agent on the target stopped
#   3. mitigated       same attack with Wazuh: rule 100210 -> firewall-drop (60 s) per attacker IP
#   4. recovery        after the block expires the attacker IPs are reachable again
# Then a post-mortem summary (legit success rate and latency per phase, detection time,
# time to block, false positives).
#
# Attackers and the legitimate client are separate Incus containers, so every source has its
# own IP and the test can prove the attackers are blocked while the legitimate client is not.
# They are created on first use (Debian + python3). The legitimate client sends ~1 req/s,
# below the rule's threshold (15 requests in 10 s from one IP).
#
# Run on the Incus host from the repo root:   ./test-ddos.sh  [--no-wait]
#   TARGET=analytics ENDPOINT='/stats?limit=1000'
#   PLATFORM=k3s   attack the k3s deployment instead: the target is the NodePort on k3s-master
#                  (dc1 pod), the agent and the k3s-block response are on that node
#   ATTACKERS="attacker1 attacker2"  LEGIT=legit-client  ATTACK_SECS=25  ATTACK_WORKERS=20
set -u
source "$(dirname "$0")/test-lib.sh"

TARGET=${TARGET:-analytics}
ENDPOINT=${ENDPOINT:-/stats?limit=1000}
ATTACKERS=${ATTACKERS:-"attacker1 attacker2"}
LEGIT=${LEGIT:-legit-client}
ATTACK_SECS=${ATTACK_SECS:-25}
ATTACK_WORKERS=${ATTACK_WORKERS:-20}
BLOCK_SECS=60                        # <timeout> of the firewall-drop response for rule 100210
SVC_JOB=${SVC_JOB:-ssle-$TARGET}     # Prometheus job of the target (same name on k3s)
BOX=$(agent_box "$TARGET")           # container whose Wazuh agent + firewall protect the target
if is_k3s; then RESP="k3s-block (iptables raw/PREROUTING on the node, before kube-proxy)"
else RESP="firewall-drop (iptables INPUT in the service container)"; fi

start_evidence ddos
threat_card "Massive denial-of-service (HTTP flood)" \
  "Many requests per second from one or more sources exhaust the service (CPU, worker threads, SQLite reads)." \
  "Analytics /stats reads up to 1000 rows from storage on every call; ingestion is the only entry point for sensor data. Saturating them stops the whole pipeline for every location." \
  "Attackers loop on an expensive, unauthenticated endpoint ($ENDPOINT) with many parallel connections; no credentials needed." \
  "Wazuh: JSON access log, rule 100200 per request, rule 100210 = 15 requests in 10 s from the same srcip. Prometheus: http_requests_total rate, p95 of http_request_duration_seconds, http_requests_in_progress (alerts SSLEHighRequestRate / SSLEHighP95Latency / SSLEHighConcurrentRequests)." \
  "$RESP on the agent that saw the flood: DROP of the source IP for ${BLOCK_SECS} s, then automatic unblock."

# ------------------------------------------------------------------ setup
section "0. Setup"
BASE=$(public_url "$TARGET")
[ -n "${BASE#http://}" ] && [ "${BASE#http://:}" = "$BASE" ] || { echo "Could not find the address of '$TARGET'"; exit 1; }
URL="$BASE$ENDPOINT"
info "platform $PLATFORM, target $TARGET = $URL, protected by the agent in $BOX"
declare -A IP=()
for c in $ATTACKERS $LEGIT; do
  ensure_client "$c"
  incus file push ddos-poc.py "$c/root/ddos-poc.py" >/dev/null
  IP[$c]=$(ip_of "$c")
  info "$c = ${IP[$c]}"
done
LEGIT_IP=${IP[$LEGIT]}
if incus exec "$BOX" -- systemctl is-active -q wazuh-agent; then ok "Wazuh agent active on $BOX"; else bad "Wazuh agent not active on $BOX"; fi
for c in $ATTACKERS $LEGIT; do
  for i in $(seq 1 70); do blocked "$BOX" "${IP[$c]}" || break; [ "$i" = 1 ] && info "${IP[$c]} still blocked from a previous run, waiting"; sleep 1; done
done

# poc <container> <label> <seconds> <workers> <delay> <outfile>
poc() { incus exec "$1" -- python3 /root/ddos-poc.py --url "$URL" --label "$2" --duration "$3" \
          --workers "$4" --delay "$5" --timeout 2 > "$6" 2>&1; }
res() { grep -oE "$2=[0-9]+" "$1" 2>/dev/null | tail -1 | cut -d= -f2; }   # res <file> ok|failed|p50|p95
pct() { python3 -c "o,f=${1:-0},${2:-0}; print('%.0f' % (100.0*o/(o+f)) if o+f else 0)"; }

# attack <phase>: run all attackers + the legit client together, snapshot Prometheus mid-attack
attack() {
  local a
  for a in $ATTACKERS; do poc "$a" "Attacker $a ($1)" "$ATTACK_SECS" "$ATTACK_WORKERS" 0 "$EVID/$1-$a.txt" & done
  sleep 3
  poc "$LEGIT" "Legitimate client during $1 attack" $((ATTACK_SECS - 5)) 1 1 "$EVID/$1-legit.txt" &
  sleep 10
  { echo "Prometheus during the $1 attack ($(date -Is))"
    echo "  request rate (req/s):";       prom_query "sum by (job) (rate(http_requests_total{job=\"$SVC_JOB\"}[15s]))"
    echo "  p95 latency (s):";            prom_query "histogram_quantile(0.95, sum by (le, job) (rate(http_request_duration_seconds_bucket{job=\"$SVC_JOB\"}[15s])))"
    echo "  requests in progress:";       prom_query "sum by (job) (http_requests_in_progress{job=\"$SVC_JOB\"})"
    echo "  where (service_info):";       prom_query "service_info{job=\"$SVC_JOB\"}"
    echo "  active alerts:";              prom_alerts
  } > "$EVID/$1-prometheus.txt"
  wait          # until every attacker and the legit client are done
}

# ------------------------------------------------------------------ 1. baseline
section "1. Baseline: legitimate client alone (15 s)"
poc "$LEGIT" "Baseline (legitimate client only)" 15 1 1 "$EVID/1-baseline-legit.txt"
cat "$EVID/1-baseline-legit.txt"
[ "$(res "$EVID/1-baseline-legit.txt" failed)" = 0 ] && ok "baseline: every request answered" || bad "baseline already has failures"

# ------------------------------------------------------------------ 2. unmitigated
section "2. Unmitigated attack: ${ATTACK_WORKERS} workers x $(echo $ATTACKERS | wc -w) attackers, Wazuh agent on $BOX stopped"
incus exec "$BOX" -- systemctl stop wazuh-agent
trap 'incus exec "$BOX" -- systemctl start wazuh-agent' EXIT
attack 2-unmitigated
wait
cat "$EVID/2-unmitigated-legit.txt" "$EVID/2-unmitigated-prometheus.txt"
grep -q "SSLEHighRequestRate" "$EVID/2-unmitigated-prometheus.txt" \
  && ok "Prometheus raised SSLEHighRequestRate during the attack" || bad "Prometheus did not raise SSLEHighRequestRate"
incus exec "$BOX" -- systemctl start wazuh-agent
info "Wazuh agent restarted, waiting 20 s for it to reconnect"
sleep 20

# ------------------------------------------------------------------ 3. mitigated
section "3. Mitigated attack: same attack with Wazuh detection + active response"
MARK=$(alerts_mark)
AR_LINES=$(incus exec "$BOX" -- sh -c 'wc -l < /var/ossec/logs/active-responses.log' 2>/dev/null || echo 0)
T0=$(now)
attack 3-mitigated &
ATTACK_PID=$!
declare -A BLOCKED_AT=()
for i in $(seq 1 $((ATTACK_SECS * 2))); do
  for a in $ATTACKERS; do
    [ -z "${BLOCKED_AT[$a]:-}" ] && blocked "$BOX" "${IP[$a]}" && BLOCKED_AT[$a]=$(now)
  done
  [ ${#BLOCKED_AT[@]} -eq $(echo $ATTACKERS | wc -w) ] && break
  sleep 0.5
done
firewall "$BOX" > "$EVID/3-iptables-during-block.txt"
wait "$ATTACK_PID"
wait
cat "$EVID/3-mitigated-legit.txt" "$EVID/3-mitigated-prometheus.txt"

section "3a. Detection (Wazuh rule 100210)"
alerts_since "$MARK" 100210 > "$EVID/3-wazuh-alerts-100210.json"
alert_summary < "$EVID/3-wazuh-alerts-100210.json" | awk '!seen[$0]++' | head -30
for a in $ATTACKERS; do
  grep -q "\"srcip\":\"${IP[$a]}\"" "$EVID/3-wazuh-alerts-100210.json" \
    && ok "rule 100210 fired for attacker $a (${IP[$a]})" || bad "no rule 100210 alert for attacker $a (${IP[$a]})"
done
grep -q "\"srcip\":\"$LEGIT_IP\"" "$EVID/3-wazuh-alerts-100210.json" \
  && bad "legitimate client $LEGIT_IP was flagged (false positive)" || ok "legitimate client $LEGIT_IP was not flagged"
FIRST=$(alert_first_epoch < "$EVID/3-wazuh-alerts-100210.json")
DETECT=$([ -n "$FIRST" ] && elapsed "$T0" "$FIRST" || echo "n/a")
info "time from attack start to first alert: ${DETECT} s"

# Pipeline check: if the target's agent ships no access-log events, nothing above can fire.
# (matched on the logged service name, which is the same on Incus and on k3s)
N=$(alerts_since "$MARK" 100200 | grep -c "\"service\":\"$TARGET-service\"")
if [ "$N" -gt 0 ]; then
  ok "$N access-log events from $TARGET's agent reached the manager"
else
  bad "no access-log events from $TARGET's agent reached the manager"
  info "manager view: $(incus exec "$WAZUH_CONTAINER" -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -iE "$TARGET|$BOX")"
  info "access log in the agent config:"; incus exec "$BOX" -- grep -n "access.log" /var/ossec/etc/ossec.conf | sed 's/^/        /'
  info "agent log:"; incus exec "$BOX" -- tail -n 8 /var/ossec/logs/ossec.log | sed 's/^/        /'
fi

# Internal calls are not an attack: the only addresses blocked anywhere (rule 651 "host blocked",
# any agent) must be the attackers'. Catches services (or k3s pods) blocking each other.
alerts_since "$MARK" 651 > "$EVID/3-wazuh-alerts-651.json"
OTHERS=$(python3 -c '
import sys, json
attackers = set(sys.argv[2:])
seen = set()
for line in open(sys.argv[1]):
    try: ip = json.loads(line).get("data", {}).get("srcip")
    except ValueError: continue
    if ip and ip not in attackers: seen.add(ip)
print(" ".join(sorted(seen)))
' "$EVID/3-wazuh-alerts-651.json" $(for a in $ATTACKERS; do echo "${IP[$a]}"; done))
[ -z "$OTHERS" ] && ok "only the attackers were blocked (no service or pod blocked another)"                  || bad "non-attacker addresses were blocked: $OTHERS (internal traffic treated as an attack?)"

section "3b. Response ($RESP, on $BOX)"
cat "$EVID/3-iptables-during-block.txt"
incus exec "$BOX" -- sh -c "tail -n +$((AR_LINES + 1)) /var/ossec/logs/active-responses.log" > "$EVID/3-active-responses.log" 2>/dev/null
for a in $ATTACKERS; do
  if [ -n "${BLOCKED_AT[$a]:-}" ]; then ok "attacker $a (${IP[$a]}) blocked $(elapsed "$T0" "${BLOCKED_AT[$a]}") s after the attack started"
  else bad "attacker $a (${IP[$a]}) was never blocked"; fi
  grep -q "\"command\":\"add\".*${IP[$a]}" "$EVID/3-active-responses.log" \
    && ok "active-responses.log on $BOX shows the add for ${IP[$a]}" || bad "no active-response add for ${IP[$a]} in $BOX's active-responses.log"
done
grep -qw "$LEGIT_IP" "$EVID/3-iptables-during-block.txt" \
  && bad "legitimate client $LEGIT_IP is in the firewall" || ok "legitimate client $LEGIT_IP is not blocked"

U_OK=$(res "$EVID/2-unmitigated-legit.txt" ok); U_F=$(res "$EVID/2-unmitigated-legit.txt" failed)
M_OK=$(res "$EVID/3-mitigated-legit.txt" ok);   M_F=$(res "$EVID/3-mitigated-legit.txt" failed)
U_PCT=$(pct "$U_OK" "$U_F"); M_PCT=$(pct "$M_OK" "$M_F")
# The flood shows up as failures (Incus: timeouts) or only as latency (k3s: the pod keeps
# answering, slowly), so mitigation counts if success went up OR p50 dropped to under half.
U_P50=$(res "$EVID/2-unmitigated-legit.txt" p50); M_P50=$(res "$EVID/3-mitigated-legit.txt" p50)
if [ "$M_PCT" -gt "$U_PCT" ]; then
  ok "legitimate success rate improved: ${U_PCT}% unmitigated -> ${M_PCT}% mitigated"
elif [ "$M_PCT" -ge "$U_PCT" ] && [ "${M_P50:-0}" -gt 0 ] && [ $(( ${M_P50:-0} * 2 )) -lt "${U_P50:-0}" ]; then
  ok "legitimate latency improved: p50 ${U_P50} ms unmitigated -> ${M_P50} ms mitigated (success ${U_PCT}% -> ${M_PCT}%)"
else
  bad "legitimate client did not improve (success ${U_PCT}% -> ${M_PCT}%, p50 ${U_P50:-?} -> ${M_P50:-?} ms)"
fi

# ------------------------------------------------------------------ 4. recovery
section "4. Recovery: block removed after ${BLOCK_SECS} s (skip with --no-wait)"
if [ "${1:-}" != "--no-wait" ]; then
  sleep $((BLOCK_SECS + 10))
  firewall "$BOX" > "$EVID/4-iptables-after-timeout.txt"
  for a in $ATTACKERS; do
    blocked "$BOX" "${IP[$a]}" && bad "${IP[$a]} still blocked after the timeout" || ok "${IP[$a]} unblocked after the timeout"
  done
  first=$(echo $ATTACKERS | cut -d' ' -f1)
  poc "$first" "Attacker after unblock" 3 1 1 "$EVID/4-recovery-$first.txt"
  [ "$(res "$EVID/4-recovery-$first.txt" ok)" -gt 0 ] 2>/dev/null && ok "$first can reach $TARGET again" || bad "$first still cannot reach $TARGET"
else
  info "skipped"
fi

# ------------------------------------------------------------------ post-mortem
section "Post-mortem summary"
{
  printf "  %-34s %10s %10s %10s\n" "legitimate client" "success" "p50 (ms)" "p95 (ms)"
  for p in 1-baseline 2-unmitigated 3-mitigated; do
    f="$EVID/$p-legit.txt"
    printf "  %-34s %9s%% %10s %10s\n" "$p" "$(pct "$(res "$f" ok)" "$(res "$f" failed)")" "$(res "$f" p50)" "$(res "$f" p95)"
  done
  echo "  detection (attack start -> first 100210 alert): ${DETECT} s"
  for a in $ATTACKERS; do
    echo "  time to block $a (${IP[$a]}): $([ -n "${BLOCKED_AT[$a]:-}" ] && elapsed "$T0" "${BLOCKED_AT[$a]}" || echo never) s"
  done
  echo "  false positives (legit client flagged/blocked): $(grep -qw "$LEGIT_IP" "$EVID/3-iptables-during-block.txt" && echo yes || echo no)"
  echo "  limitation: per-source threshold; a flood spread over many IPs below 15 req/10 s each is not detected by 100210"
} | tee "$EVID/summary.txt"

finish
