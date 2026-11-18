#!/usr/bin/env bash
# Scalability evaluation (saved under evidence/scale/).
#
#   1. Horizontal scaling across locations: a second ingestion and analytics instance is
#      deployed in ANOTHER data centre (dc2). The same closed-loop load is run against 1 instance
#      and then against both (round-robin); throughput, latency and the per-instance /
#      per-location split are compared. Storage stays a single SQLite writer, so the test
#      also shows where the bottleneck moves.
#   2. Location-aware discovery: the new instances register with their hierarchical ID, show up
#      in /tree, and a dc2 lookup returns the dc2 instance.
#   3. Registry growth: 0 -> 2000 fake instances over 2 countries x 3 regions x 4 dcs x 5 racks;
#      registration rate, filtered lookup latency, /tree cost, unfiltered vs filtered payload.
#   4. Monitoring bandwidth by location (bonus): bytes of a full scrape per instance, and a
#      federation of every raw series vs only the per-location aggregates (location:* rules).
#
# Wazuh agents on the services are stopped during the benchmark (it measures capacity, so the
# DoS rule must not block the load generators) and restarted at the end.
#
# Run on the Incus host from the repo root (needs ./apply-configs.sh prometheus first):
#   ./test-scale.sh [--keep]        --keep leaves the dc2 instances running afterwards
#   LOADGENS="attacker1 attacker2 legit-client" WORKERS=8 DURATION=20 SIZES=0,100,500,2000
set -u
source "$(dirname "$0")/test-lib.sh"

LOADGENS=${LOADGENS:-"attacker1 attacker2 legit-client"}
WORKERS=${WORKERS:-8}            # per load generator
DURATION=${DURATION:-20}
SIZES=${SIZES:-0,100,500,2000}
NEW_DC=${NEW_DC:-dc2}
SERVICES="registry storage ingestion analytics"

start_evidence scale
cat <<EOF

################################################################################
 SCALABILITY EVALUATION
################################################################################
 Questions : does adding instances in another location add capacity? does discovery stay
             location-aware? how do the registry and the monitoring scale with the number of
             instances and locations?
 Load      : $(echo $LOADGENS | wc -w) load generators x $WORKERS workers, ${DURATION} s per phase, closed loop
################################################################################
EOF

# ------------------------------------------------------------------ setup
section "0. Setup"
REG_IP=$(ip_of registry)
[ -n "$REG_IP" ] || { echo "registry container not found"; exit 1; }
for c in $LOADGENS; do ensure_client "$c"; incus file push scale-tool.py "$c/root/scale-tool.py" >/dev/null; done
for c in $SERVICES; do incus exec "$c" -- systemctl stop wazuh-agent 2>/dev/null; done
trap 'for c in $SERVICES; do incus exec "$c" -- systemctl start wazuh-agent 2>/dev/null; done' EXIT
info "Wazuh agents on $SERVICES stopped for the benchmark (restarted on exit)"

# deploy_extra <container> <service dir> <port> <instance>: same unit as deploy-incus.sh, other DC
deploy_extra() {
  local name=$1 svc=$2 port=$3 inst=$4
  incus info "$name" >/dev/null 2>&1 || { info "creating $name"; incus launch images:debian/trixie "$name" >/dev/null; }
  until incus exec "$name" -- getent hosts deb.debian.org >/dev/null 2>&1; do sleep 2; done
  incus exec "$name" --env DEBIAN_FRONTEND=noninteractive -- sh -c \
    'python3 -c "import flask, requests, prometheus_client" 2>/dev/null || (apt-get update -qq && apt-get install -y -qq python3-flask python3-requests python3-prometheus-client >/dev/null)'
  incus exec "$name" -- mkdir -p /opt/app /var/lib/app /var/log/ssle
  incus file push common.py "$name/opt/app/common.py" >/dev/null
  incus file push "$svc/app.py" "$name/opt/app/app.py" >/dev/null
  incus exec "$name" -- tee /etc/systemd/system/ssle.service >/dev/null <<EOF
[Unit]
Description=SSLE $name
After=network-online.target
[Service]
WorkingDirectory=/opt/app
ExecStart=/usr/bin/python3 /opt/app/app.py
Restart=always
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/app
Environment=REGISTRY_URL=http://registry.incus:5050
Environment=SERVICE_URL=http://$name.incus:$port
Environment=ACCESS_LOG=/var/log/ssle/access.log
Environment=COUNTRY=pt
Environment=REGION=centro
Environment=DC=$NEW_DC
Environment=RACK=rack1
Environment=NODE=$name
Environment=INSTANCE=$inst
[Install]
WantedBy=multi-user.target
EOF
  incus exec "$name" -- sh -c 'systemctl daemon-reload && systemctl enable -q ssle && systemctl restart ssle'
}

EXTRA="ingestion-$NEW_DC:ingestion:5001 analytics-$NEW_DC:analytics:5003"
for e in $EXTRA; do
  IFS=: read -r name svc port <<<"$e"
  deploy_extra "$name" "$svc" "$port" 02
done
for e in $EXTRA; do
  IFS=: read -r name svc port <<<"$e"
  ip=$(ip_of "$name"); up=""
  for i in $(seq 1 30); do curl -sf --max-time 2 "http://$ip:$port/health" >/dev/null && { up=1; break; }; sleep 1; done
  [ -n "$up" ] && ok "$name ($ip) is up in $NEW_DC" || bad "$name did not come up"
done
# let Prometheus scrape the new instances (file_sd, picked up without a reload)
printf '[{"targets": ["ingestion-%s.incus:5001", "analytics-%s.incus:5003"]}]\n' "$NEW_DC" "$NEW_DC" \
  | incus exec "$PROM_CONTAINER" -- sh -c 'cat > /etc/prometheus/scale-targets.json'
info "waiting 20 s for registration and the first scrapes"
sleep 20

# ------------------------------------------------------------------ 2. discovery
section "1. Location-aware discovery"
curl -s "http://$REG_IP:5050/tree" | python3 -m json.tool > "$EVID/1-registry-tree.json"
grep -q "\"$NEW_DC\"" "$EVID/1-registry-tree.json" && ok "/tree shows the new location $NEW_DC" || bad "$NEW_DC missing from /tree"
for svc in ingestion analytics; do
  got=$(curl -s "http://$REG_IP:5050/services/$svc-service?dc=$NEW_DC")
  echo "$got" > "$EVID/1-lookup-$svc-$NEW_DC.json"
  echo "$got" | grep -q "$svc-$NEW_DC" && ok "lookup $svc-service?dc=$NEW_DC -> $(echo "$got" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')" \
    || bad "lookup $svc-service?dc=$NEW_DC did not return the $NEW_DC instance"
done

# ------------------------------------------------------------------ 1. horizontal scaling
res() { grep -oE "$2=[0-9.]+" "$1" | cut -d= -f2; }      # all values of a key, one per line
sumcol() { python3 -c "import sys; print('%.1f' % sum(float(x) for x in sys.stdin.read().split() or [0]))"; }
maxcol() { python3 -c "import sys; print('%.0f' % max([float(x) for x in sys.stdin.read().split()] or [0]))"; }

# phase <svc> <label> <url list>: all load generators at once, Prometheus snapshot near the end
phase() {
  local svc=$1 label=$2 urls=$3 out="$EVID/2-$1-$2"
  local method=GET body=""
  [ "$svc" = ingestion ] && { method=POST; body='{"device_id":"scale-test","temperature":21.5}'; }
  : > "$out.txt"
  for g in $LOADGENS; do
    incus exec "$g" -- python3 /root/scale-tool.py load --urls "$urls" --method "$method" --body "$body" \
      --workers "$WORKERS" --duration "$DURATION" --label "$g -> $svc ($label)" >> "$out.txt" 2>&1 &
  done
  sleep $((DURATION - 4))
  { echo "requests/s per instance:"; prom_query "sum by (instance) (rate(http_requests_total{service=\"$svc-service\"}[15s]))"
    echo "requests/s per location (location:http_requests:rate1m):"; prom_query "location:http_requests:rate1m{service=\"$svc-service\"}"
    echo "storage writes/s:"; prom_query 'sum(rate(storage_readings_stored_total[15s]))'
    echo "storage p95 latency (s):"; prom_query 'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{service="storage-service"}[15s])))'
  } > "$out-prometheus.txt"
  wait
  RPS=$(res "$out.txt" rps | sumcol); P95=$(res "$out.txt" p95 | maxcol)
  ERR=$(res "$out.txt" failed | sumcol); OKS=$(res "$out.txt" ok | sumcol)
  grep "^  ok" "$out.txt"
  sed 's/^/  /' "$out-prometheus.txt"
  info "$svc, $label: ${RPS} req/s total, worst p95 ${P95} ms, ${ERR} failed of $(python3 -c "print(int($OKS+$ERR))")"
}

declare -A R
for svc in ingestion analytics; do
  ip1=$(ip_of "$svc"); ip2=$(ip_of "$svc-$NEW_DC")
  case $svc in ingestion) port=5001; path=/ingest ;; analytics) port=5003; path='/stats?limit=100' ;; esac
  section "2. Horizontal scaling: $svc"
  phase "$svc" 1-instance "http://$ip1:$port$path"
  R[$svc-1]=$RPS; R[$svc-1p95]=$P95
  phase "$svc" 2-instances "http://$ip1:$port$path,http://$ip2:$port$path"
  R[$svc-2]=$RPS; R[$svc-2p95]=$P95
  SPEEDUP=$(python3 -c "a,b=${R[$svc-1]},${R[$svc-2]}; print('%.2f' % (b/a) if a else 0)")
  R[$svc-x]=$SPEEDUP
  info "$svc speed-up with a second instance in $NEW_DC: x$SPEEDUP"
  grep -q "$NEW_DC" "$EVID/2-$svc-2-instances-prometheus.txt" \
    && ok "Prometheus sees $svc traffic per location ($NEW_DC included)" || bad "no per-location $svc traffic for $NEW_DC in Prometheus"
done

# ------------------------------------------------------------------ 3. registry growth
section "3. Registry growth (fake instances, sizes $SIZES)"
python3 scale-tool.py registry --registry "http://$REG_IP:5050" --sizes "$SIZES" | tee "$EVID/3-registry.txt"
LAST=$(grep '^RESULT' "$EVID/3-registry.txt" | tail -1)
ALL_B=$(echo "$LAST" | grep -oE 'all_bytes=[0-9]+' | cut -d= -f2)
DC_B=$(echo "$LAST" | grep -oE ' dc_bytes=[0-9]+' | cut -d= -f2)
LP95=$(echo "$LAST" | grep -oE 'lookup_p95_ms=[0-9.]+' | cut -d= -f2)
[ -n "$ALL_B" ] && [ "${DC_B:-0}" -lt "$ALL_B" ] \
  && ok "location filter: one dc = $DC_B bytes vs $ALL_B bytes unfiltered ($(python3 -c "print('%.1f' % (100.0*$DC_B/$ALL_B))")%)" \
  || bad "location filter did not reduce the payload"
info "filtered lookup p95 at the largest size: ${LP95} ms"

# ------------------------------------------------------------------ 4. monitoring bandwidth
section "4. Monitoring bandwidth by location"
PROM=$(prom_url)
{
  echo "bytes of one full scrape (/metrics):"
  for c in $SERVICES; do
    case $c in registry) p=5050 ;; storage) p=5002 ;; ingestion) p=5001 ;; analytics) p=5003 ;; esac
    printf "    %-10s %8s bytes\n" "$c" "$(curl -s -o /dev/null -w '%{size_download}' "http://$(ip_of "$c"):$p/metrics")"
  done
  RAW=$(curl -s -G -o /dev/null -w '%{size_download}' "$PROM/federate" --data-urlencode 'match[]={job=~"ssle-.+"}')
  RAWZ=$(curl -s -G --compressed -o /dev/null -w '%{size_download}' "$PROM/federate" --data-urlencode 'match[]={job=~"ssle-.+"}')
  AGG=$(curl -s -G -o /dev/null -w '%{size_download}' "$PROM/federate" --data-urlencode 'match[]={__name__=~"location:.+"}')
  AGGZ=$(curl -s -G --compressed -o /dev/null -w '%{size_download}' "$PROM/federate" --data-urlencode 'match[]={__name__=~"location:.+"}')
  echo "federation of every raw series : $RAW bytes ($RAWZ gzip)"
  echo "federation of location:* only  : $AGG bytes ($AGGZ gzip)"
  echo "per-location view (location:instances:count, location:http_requests:rate1m):"
  prom_query 'location:instances:count'
  prom_query 'location:http_requests:rate1m'
  echo "$RAW $AGG" > "$EVID/.bw"
} | tee "$EVID/4-monitoring-bandwidth.txt"
read -r RAW AGG < "$EVID/.bw"; rm -f "$EVID/.bw"
if [ "${AGG:-0}" -gt 0 ] && [ "$AGG" -lt "$RAW" ]; then
  ok "per-location federation is $(python3 -c "print('%.1f' % (100.0*$AGG/$RAW))")% of the raw federation"
else
  bad "no location:* aggregates (run ./apply-configs.sh prometheus to load the recording rules)"
fi

# ------------------------------------------------------------------ cleanup
section "5. Cleanup"
if [ "${1:-}" = "--keep" ]; then
  info "--keep: $NEW_DC instances left running"
else
  printf '[]\n' | incus exec "$PROM_CONTAINER" -- sh -c 'cat > /etc/prometheus/scale-targets.json'
  for e in $EXTRA; do incus delete --force "${e%%:*}" && info "deleted ${e%%:*}"; done
  info "the registry drops them after 2 failed health checks"
fi

section "Summary"
{
  printf "  %-11s %12s %12s %9s %14s %14s\n" "service" "1 inst req/s" "2 inst req/s" "speed-up" "1 inst p95 ms" "2 inst p95 ms"
  for svc in ingestion analytics; do
    printf "  %-11s %12s %12s %8sx %14s %14s\n" "$svc" "${R[$svc-1]}" "${R[$svc-2]}" "${R[$svc-x]}" "${R[$svc-1p95]}" "${R[$svc-2p95]}"
  done
  echo "  registry: $(grep '^RESULT' "$EVID/3-registry.txt" | tail -1 | sed 's/^RESULT //')"
  echo "  monitoring: raw federation $RAW bytes vs per-location aggregates $AGG bytes"
  echo "  reading the numbers:"
  echo "   - ingestion writes go to ONE SQLite storage: if the speed-up is well below 2, storage is the"
  echo "     bottleneck (compare 'storage writes/s' and storage p95 in evidence/scale/2-ingestion-*)"
  echo "   - analytics only reads, so it should scale better until storage reads saturate"
  echo "   - the registry is in memory: lookups stay fast, but /services without a filter grows"
  echo "     linearly and the health checker pings every instance one by one (O(N) per sweep)"
  echo "   - all instances run on one physical host, so 'dc2' is a logical location: absolute"
  echo "     numbers are lower bounds, the trends are what matters"
} | tee "$EVID/summary.txt"

finish
