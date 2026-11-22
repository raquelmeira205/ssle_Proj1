#!/usr/bin/env bash
# Experiment for the report (TODO: Wazuh scalability). Not part of the platform.
# Writes synthetic SSLE access-log lines at increasing rates on a k3s node and measures, at the
# manager, how many become alerts (rule 100200, level 3) per second and the end-to-end latency
# (log line timestamp -> alert timestamp). Each line uses a different source address from
# 100.64.0.0/16 (not used in the lab), so no address repeats 15 times in 10 s and rule 100210 /
# active responses are never triggered.
# Run on the Incus host from the repo root:  report/experiments/wazuh-eps.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
OUT=evidence/k3s/wazuh-eps; mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
NODE=${NODE:-k3s-master}; WAZUH=${WAZUH:-wazuh-container}
RATES=${RATES:-"100 250 500 1000 2000"}; SECS=${SECS:-30}
DIR=/var/log/ssle/eps-test
ALERTS=/var/ossec/logs/alerts/alerts.json
WPY=/var/ossec/framework/python/bin/python3
echo "Run started $(date -Is): node $NODE, rates $RATES lines/s, $SECS s each"

GEN='
import json, sys, time
from datetime import datetime, timezone
path, rate, secs, tag = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
with open(path, "a", buffering=1) as f:
    t0 = time.time(); n = 0
    while time.time() - t0 < secs:
        target = int((time.time() - t0) * rate)
        while n < target:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "service": "eps-test", "id": tag, "srcip": "100.64.%d.%d" % (n // 250 % 250, n % 250 + 1),
                "method": "GET", "path": "/eps", "http_status": 200, "ms": 1.0, "bytes": 10,
                "ua": "eps"}) + "\n"); n += 1
        time.sleep(0.005)
print(n)
'
COUNT='
import json, sys
from datetime import datetime
path, start, tag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lat = []
with open(path, "rb") as f:
    f.seek(start)
    for line in f:
        if tag.encode() not in line: continue
        try:
            a = json.loads(line)
            if a.get("rule", {}).get("id") != "100200": continue
            t_log = datetime.fromisoformat(a["data"]["ts"]).timestamp()
            t_alert = datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
            lat.append(t_alert - t_log)
        except Exception:
            pass
lat.sort()
p = lambda q: lat[min(len(lat) - 1, int(q * len(lat)))] if lat else float("nan")
print(len(lat), round(p(0.5), 2), round(p(0.95), 2), round(lat[-1], 2) if lat else "nan")
'
agent_warn() { incus exec "$NODE" -- sh -c "grep -cE 'buffer at|buffer full|Events may be lost' /var/ossec/logs/ossec.log"; }

incus exec "$NODE" -- mkdir -p "$DIR"
incus exec "$NODE" -- sh -c ": > $DIR/access.log"
echo "waiting 15 s for the agent to pick up the new file"; sleep 15
W0=$(agent_warn)
printf "%-8s %-9s %-9s %-9s %-11s %-11s %-11s %-8s\n" rate written alerts lost% "alerts/s" "p50 lat s" "p95 lat s" warnings | tee "$OUT/summary.txt"
for r in $RATES; do
  tag="eps-$r-$(date +%s)"
  M=$(incus exec "$WAZUH" -- stat -c %s "$ALERTS")
  written=$(incus exec "$NODE" -- python3 -c "$GEN" "$DIR/access.log" "$r" "$SECS" "$tag")
  sleep 20   # let the pipeline drain
  read -r n p50 p95 pmax < <(incus exec "$WAZUH" -- "$WPY" -c "$COUNT" "$ALERTS" "$M" "$tag")
  W=$(agent_warn)
  printf "%-8s %-9s %-9s %-9s %-11s %-11s %-11s %-8s\n" "$r/s" "$written" "$n" \
    "$(python3 -c "print(round(100*(1-$n/$written),1))")" "$(python3 -c "print(round($n/$SECS))")" \
    "$p50" "$p95" "$((W - W0))" | tee -a "$OUT/summary.txt"
  W0=$W
done
echo "  lost% = lines written on the node that never became an alert; latency = log timestamp -> alert timestamp" | tee -a "$OUT/summary.txt"
incus exec "$NODE" -- sh -c "grep -E 'buffer at|buffer full|Events may be lost' /var/ossec/logs/ossec.log | tail -5" > "$OUT/agent-buffer-warnings.txt"
incus exec "$NODE" -- sh -c "sed -n '/<client_buffer>/,/<\/client_buffer>/p' /var/ossec/etc/ossec.conf" > "$OUT/agent-client-buffer.txt"
incus exec "$NODE" -- rm -rf "$DIR"
echo "removed $DIR"
