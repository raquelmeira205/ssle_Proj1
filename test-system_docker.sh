#!/usr/bin/env bash
# Smoke test for the SSLE system (Docker Compose layout: ports published on localhost).
#
# Usage:  ./test-system_docker.sh [--failure]
#   HOST=<ip>   test another machine instead of localhost
#   DC=<dc>     datacenter used for the location-filter test (default: dc1)
#   --failure   also stop and restart the storage container (needs `docker compose`,
#               run it from the project folder). Takes about a minute.
set -u

HOST=${HOST:-localhost}
DC=${DC:-dc1}
REG=$HOST:5050; ING=$HOST:5001; STO=$HOST:5002; ANA=$HOST:5003; SEN=$HOST:8000
PASS=0; FAIL=0

ok()  { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
get() { curl -s --max-time 5 "$@"; }
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@"; }
count_of() { sed -n 's/.*"count": *\([0-9][0-9]*\).*/\1/p' | head -1; }

# ---------------------------------------------------------------- 0. is it up?
echo "== 0. Registry reachable"
if [ "$(http_code "$REG/health")" = "200" ]; then
  ok "registry answers on $REG"
else
  bad "registry does not answer on $REG (is 'docker compose up' running?)"
  echo; echo "Result: $PASS passed, $FAIL failed"; exit 1
fi

# ---------------------------------------------------------------- 1. services + locations
echo "== 1. Registry: services and locations"
SERVICES=$(get "$REG/services")
for s in storage-service ingestion-service analytics-service; do
  if grep -q "\"$s\"" <<<"$SERVICES"; then ok "$s is registered"; else bad "$s is NOT registered (wait ~15 s after startup)"; fi
done
if grep -Eq '"id": *"[^".]+(\.[^".]+){5}"' <<<"$SERVICES"; then
  ok "instances have hierarchical IDs (service.node.rack.dc.region.country)"
else
  bad "no hierarchical IDs found in /services"
fi

# ---------------------------------------------------------------- 2. tree
echo "== 2. Registry: location tree"
if grep -q '"level"' <<<"$(get "$REG/tree")"; then ok "/tree returns the location hierarchy"; else bad "/tree has no hierarchy"; fi

# ---------------------------------------------------------------- 3. filters
echo "== 3. Registry: location filter"
c=$(http_code "$REG/services/storage-service?dc=$DC")
if [ "$c" = "200" ]; then ok "?dc=$DC finds storage-service"; else bad "?dc=$DC returned HTTP $c (expected 200)"; fi
c=$(http_code "$REG/services/storage-service?dc=nope")
if [ "$c" = "404" ]; then ok "?dc=nope returns 404"; else bad "?dc=nope returned HTTP $c (expected 404)"; fi

# ---------------------------------------------------------------- 4. data flow
echo "== 4. Data flow: sensor -> ingestion -> storage -> analytics (waits 12 s)"
n1=$(get "$ANA/stats" | count_of)
sleep 12
n2=$(get "$ANA/stats" | count_of)
if [ -n "$n1" ] && [ -n "$n2" ] && [ "$n2" -gt "$n1" ]; then
  ok "analytics count grew from $n1 to $n2"
else
  bad "analytics count did not grow (before='$n1', after='$n2')"
fi

# ---------------------------------------------------------------- 5. validation
echo "== 5. Input validation"
c=$(http_code -X POST -H 'Content-Type: application/json' -d '{"x":1}' "$ING/ingest")
if [ "$c" = "400" ]; then ok "invalid reading rejected with 400"; else bad "invalid reading returned HTTP $c (expected 400)"; fi

# ---------------------------------------------------------------- 6. metrics
echo "== 6. Prometheus metrics"
m=$(get "$ING/metrics")
grep -q '^service_info{' <<<"$m"                                   && ok "ingestion exports service_info (location)"     || bad "ingestion: service_info missing"
grep -Eq '^http_requests_total\{.*endpoint="/ingest"' <<<"$m"      && ok "ingestion counts HTTP requests"                || bad "ingestion: http_requests_total missing"
grep -Eq '^ingestion_readings_total\{result="accepted"\} [1-9]' <<<"$m" && ok "ingestion accepted readings > 0"           || bad "ingestion: no accepted readings"
grep -Eq '^ingestion_readings_total\{result="invalid"\} [1-9]' <<<"$m"  && ok "ingestion counted the invalid reading"      || bad "ingestion: invalid counter did not move"
m=$(get "$STO/metrics")
grep -Eq '^storage_rows [1-9]' <<<"$m"                             && ok "storage_rows > 0"                              || bad "storage: storage_rows is 0 or missing"
grep -Eq '^storage_readings_stored_total [1-9]' <<<"$m"            && ok "storage_readings_stored_total > 0"             || bad "storage: nothing stored"
grep -Eq '^http_request_duration_seconds_bucket' <<<"$m"           && ok "storage exports a latency histogram"           || bad "storage: latency histogram missing"
m=$(get "$ANA/metrics")
grep -q '^analytics_storage_errors_total' <<<"$m"                  && ok "analytics exports its error counter"           || bad "analytics: error counter missing"
m=$(get "$REG/metrics")
grep -q '^registry_instances{' <<<"$m"                             && ok "registry exports instances per location"       || bad "registry: registry_instances missing"
m=$(get "$SEN/metrics")
grep -Eq '^sensor_readings_sent_total\{result="ok"\} [1-9]' <<<"$m" && ok "sensor sent readings (ok > 0)"                 || bad "sensor: no successful readings"

# ---------------------------------------------------------------- 7. failure test (optional)
if [ "${1:-}" = "--failure" ]; then
  echo "== 7. Failure test: stop and restart storage (about a minute)"
  cd "$(dirname "$0")" || exit 1

  wait_for() { local t=$1 i=0; shift; while [ "$i" -lt "$t" ]; do "$@" && return 0; sleep 2; i=$((i + 2)); done; return 1; }
  storage_listed() { get "$REG/services" | grep -q '"storage-service"'; }
  storage_gone()   { ! storage_listed; }

  if docker compose stop storage >/dev/null 2>&1; then
    if wait_for 60 storage_gone; then ok "registry removed storage-service after it stopped"; else bad "storage-service still listed after 60 s"; fi

    c=$(http_code "$ANA/stats")
    if [ "$c" = "502" ]; then ok "analytics answers 502 while storage is down"; else bad "analytics returned HTTP $c (expected 502)"; fi
    e=$(get "$ANA/metrics" | grep -E '^analytics_storage_errors_total' | awk '{print $2}')
    if [ -n "$e" ] && awk -v v="$e" 'BEGIN{exit !(v > 0)}'; then ok "analytics_storage_errors_total is $e"; else bad "analytics error counter did not move"; fi
    if get "$ING/metrics" | grep -Eq '^ingestion_readings_total\{result="storage_error"\} [1-9]'; then
      ok "ingestion counted storage_error readings"
    else
      bad "ingestion: storage_error counter did not move"
    fi
  else
    bad "could not run 'docker compose stop storage' (run the script from the project folder)"
  fi

  docker compose start storage >/dev/null 2>&1
  if wait_for 60 storage_listed; then ok "storage-service re-registered by itself"; else bad "storage-service did not come back within 60 s"; fi
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]