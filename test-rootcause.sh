#!/usr/bin/env bash
# Fault management (FCAPS): anomaly events + correlation for root-cause detection.
#
# Stops the storage container and checks that:
#   - the dependents produce symptoms (HTTP 502 in ingestion/analytics -> Wazuh rule 100201 per
#     agent, so each event carries the location of the service that saw it)
#   - Prometheus correlates them into ONE root-cause alert (SSLERootCauseStorageDown,
#     prometheus/ssle_rules.yml) and does NOT blame the network (SSLERootCauseStorageUnreachable)
#   - the registry removes the dead instance, and everything clears after storage restarts
# Saved under evidence/rootcause/.
#
# Run on the Incus host from the repo root:   ./test-rootcause.sh
#   STORAGE=storage ANALYTICS=analytics REGISTRY=registry
set -u
source "$(dirname "$0")/test-lib.sh"

STORAGE=${STORAGE:-storage}
ANALYTICS=${ANALYTICS:-analytics}
REGISTRY=${REGISTRY:-registry}

start_evidence rootcause
threat_card "Service failure -> root-cause detection (fault management)" \
  "A dependency (storage) fails; every service that uses it starts failing too, producing many unrelated-looking alarms." \
  "Storage is the single writer of all readings; when it fails ingestion and analytics both return errors and operators see alarms from several locations at once." \
  "Crash, resource exhaustion (e.g. after a DoS), or an attacker stopping the service." \
  "Prometheus: up, analytics_storage_errors_total, ingestion_readings_total{result=storage_error}, registry_instances. Wazuh: rule 100201 (HTTP 5xx) per agent with its hierarchical ID." \
  "Correlation rule SSLERootCauseStorageDown names storage as the cause; the registry stops handing out the dead instance; recovery is checked when storage comes back."

section "0. Baseline"
PROM=$(prom_url); info "Prometheus at $PROM"
AN_IP=$(ip_of "$ANALYTICS"); REG_IP=$(ip_of "$REGISTRY")
prom_query 'up{job=~"ssle-.+"}' | tee "$EVID/0-up.txt"
grep -qE '\} 0$' "$EVID/0-up.txt" && bad "some targets are already down" || ok "every SSLE target is up"
prom_alerts | tee "$EVID/0-alerts.txt"
grep -q "root-cause\|SSLERootCause" "$EVID/0-alerts.txt" && bad "a root-cause alert is already active" || ok "no root-cause alert before the failure"

section "1. Failure: stopping container $STORAGE"
MARK=$(alerts_mark)
T0=$(now)
incus stop "$STORAGE"
trap 'incus start "$STORAGE" 2>/dev/null' EXIT
# users keep asking analytics for stats while storage is down
( end=$(( $(date +%s) + 90 )); while [ "$(date +%s)" -lt "$end" ]; do
    curl -s -o /dev/null --max-time 6 "http://$AN_IP:5003/stats"; sleep 2; done ) &
LOAD=$!

if prom_wait_firing SSLERootCauseStorageDown 120; then ok "SSLERootCauseStorageDown firing $(elapsed "$T0" "$(now)") s after the failure"
else bad "SSLERootCauseStorageDown did not fire within 120 s"; fi
prom_alerts | tee "$EVID/1-alerts-during-failure.txt"
grep -qE "SSLERootCauseStorageUnreachable +firing" "$EVID/1-alerts-during-failure.txt" \
  && bad "network/discovery was wrongly blamed" || ok "network/discovery not blamed (correct diagnosis)"
grep -qE "SSLEInstanceDown +firing +job=ssle-storage" "$EVID/1-alerts-during-failure.txt" \
  && ok "SSLEInstanceDown points at ssle-storage" || info "SSLEInstanceDown for ssle-storage not firing yet"
{ echo "storage errors seen by dependents (1 min):"
  prom_query 'increase(analytics_storage_errors_total[1m])'
  prom_query 'increase(ingestion_readings_total{result="storage_error"}[1m])'
  echo "registry instances of storage:"; prom_query 'registry_instances{service="storage-service"}'
} | tee "$EVID/1-prometheus-symptoms.txt"

# The registry needs 2 failed health checks 10 s apart (up to ~30 s), which can be slower than
# Prometheus naming the root cause, so wait for it instead of checking once.
for i in $(seq 1 45); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$REG_IP:5050/services/storage-service")
  [ "$code" = 404 ] && break
  sleep 1
done
[ "$code" = 404 ] && ok "registry removed the dead storage instance (HTTP 404) $(elapsed "$T0" "$(now)") s after the failure" \
                  || bad "registry still returns storage-service after 45 s (HTTP $code)"

section "1a. SIEM view: HTTP 5xx events per service/location (Wazuh rule 100201)"
alerts_since "$MARK" 100201 > "$EVID/1-wazuh-alerts-100201.json"
if [ -s "$EVID/1-wazuh-alerts-100201.json" ]; then
  ok "Wazuh recorded $(wc -l < "$EVID/1-wazuh-alerts-100201.json") HTTP 5xx events"
  python3 -c '
import sys, json, collections
c = collections.Counter()
for l in open(sys.argv[1]):
    try: a = json.loads(l)
    except ValueError: continue
    c[(a["agent"]["name"], a.get("data", {}).get("path", "?"))] += 1
for (agent, path), n in c.most_common():
    print("    %4d x  %-60s %s" % (n, agent, path))
' "$EVID/1-wazuh-alerts-100201.json" | tee "$EVID/1-wazuh-5xx-by-location.txt"
else
  bad "no rule 100201 events from the dependents"
fi

section "2. Recovery: starting $STORAGE"
kill "$LOAD" 2>/dev/null; wait 2>/dev/null
incus start "$STORAGE"; T1=$(now)
for i in $(seq 1 120); do
  prom_query 'up{job="ssle-storage"}' | grep -qE '\} 1$' && ! prom_alerts | grep -qE "SSLERootCauseStorageDown +firing" && break
  sleep 1
done
prom_alerts | tee "$EVID/2-alerts-after-recovery.txt"
grep -qE "SSLERootCauseStorageDown +firing" "$EVID/2-alerts-after-recovery.txt" \
  && bad "root-cause alert still firing after recovery" || ok "root-cause alert cleared $(elapsed "$T1" "$(now)") s after storage restarted"
for i in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$REG_IP:5050/services/storage-service")" = 200 ] && break; sleep 1
done
[ "$i" -lt 30 ] && ok "storage-service registered again" || bad "storage-service did not re-register"

section "Post-mortem summary"
{
  echo "  failure injected        : container $STORAGE stopped at $(date -d @"${T0%.*}" +%T)"
  echo "  root cause identified   : $(grep -qE 'SSLERootCauseStorageDown +firing' "$EVID/1-alerts-during-failure.txt" && echo 'storage (SSLERootCauseStorageDown)' || echo 'NOT identified')"
  echo "  symptoms correlated     : $(grep -cE 'firing|pending' "$EVID/1-alerts-during-failure.txt") Prometheus alerts and $(wc -l < "$EVID/1-wazuh-alerts-100201.json") Wazuh 5xx events -> 1 root cause"
  echo "  limitations             : rules are written per dependency (storage, ingestion); a full dependency graph"
  echo "                            (or Alertmanager inhibition) would generalise it; the 1 min increase() window"
  echo "                            delays clearing after recovery."
} | tee "$EVID/summary.txt"

finish
