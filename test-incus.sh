#!/usr/bin/env bash
# Smoke test for the SSLE system running in Incus containers.
#
# Usage:
#   chmod +x test-incus.sh
#   ./test-incus.sh
#   ./test-incus.sh --failure
#
# Optional overrides:
#   REGISTRY_IP=10.255.255.208
#   INGESTION_IP=10.255.255.68
#   STORAGE_IP=10.255.255.49
#   ANALYTICS_IP=10.255.255.133
#   SENSOR_IP=10.255.255.26
#   REGISTRY_PORT=5050
#   INGESTION_PORT=5001
#   STORAGE_PORT=5002
#   ANALYTICS_PORT=5003
#   SENSOR_PORT=8000
#   DC=dc1
#
# The --failure test stops and restarts the Incus container named "storage".
# Run this only when interrupting the storage service is safe.

set -u

# ---------------------------------------------------------------------------
# Incus container addresses and service ports
# ---------------------------------------------------------------------------
REGISTRY_IP=${REGISTRY_IP:-10.255.255.208}
INGESTION_IP=${INGESTION_IP:-10.255.255.68}
STORAGE_IP=${STORAGE_IP:-10.255.255.49}
ANALYTICS_IP=${ANALYTICS_IP:-10.255.255.133}
SENSOR_IP=${SENSOR_IP:-10.255.255.26}

REGISTRY_PORT=${REGISTRY_PORT:-5050}
INGESTION_PORT=${INGESTION_PORT:-5001}
STORAGE_PORT=${STORAGE_PORT:-5002}
ANALYTICS_PORT=${ANALYTICS_PORT:-5003}
SENSOR_PORT=${SENSOR_PORT:-8000}

DC=${DC:-dc1}

REG="http://${REGISTRY_IP}:${REGISTRY_PORT}"
ING="http://${INGESTION_IP}:${INGESTION_PORT}"
STO="http://${STORAGE_IP}:${STORAGE_PORT}"
ANA="http://${ANALYTICS_IP}:${ANALYTICS_PORT}"
SEN="http://${SENSOR_IP}:${SENSOR_PORT}"

PASS=0
FAIL=0

ok() {
    echo "  PASS  $1"
    PASS=$((PASS + 1))
}

bad() {
    echo "  FAIL  $1"
    FAIL=$((FAIL + 1))
}

get() {
    curl -fsS --connect-timeout 3 --max-time 8 "$@"
}

http_code() {
    curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 3 --max-time 8 "$@"
}

count_of() {
    sed -n 's/.*"count": *\([0-9][0-9]*\).*/\1/p' | head -1
}

# ---------------------------------------------------------------------------
# 0. Check prerequisites
# ---------------------------------------------------------------------------
echo "== 0. Prerequisites"

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required."
    exit 1
fi

if [ "${1:-}" = "--failure" ] && ! command -v incus >/dev/null 2>&1; then
    echo "ERROR: incus is required for the --failure test."
    exit 1
fi

ok "curl is installed"

# ---------------------------------------------------------------------------
# 1. Registry health
# ---------------------------------------------------------------------------
echo
echo "== 1. Registry reachable"

if [ "$(http_code "$REG/health")" = "200" ]; then
    ok "registry answers at $REG"
else
    bad "registry does not answer at $REG"
    echo
    echo "Check the registry container, service port and network connectivity."
    echo "Result: $PASS passed, $FAIL failed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Registered services and hierarchical IDs
# ---------------------------------------------------------------------------
echo
echo "== 2. Registry: services and locations"

SERVICES=$(get "$REG/services" || true)

for s in storage-service ingestion-service analytics-service; do
    if grep -q "\"$s\"" <<<"$SERVICES"; then
        ok "$s is registered"
    else
        bad "$s is NOT registered"
    fi
done

if grep -Eq '"id": *"[^".]+(\.[^".]+){5}"' <<<"$SERVICES"; then
    ok "instances have hierarchical IDs (service.node.rack.dc.region.country)"
else
    bad "no hierarchical IDs found in /services"
fi

# ---------------------------------------------------------------------------
# 3. Location tree
# ---------------------------------------------------------------------------
echo
echo "== 3. Registry: location tree"

TREE=$(get "$REG/tree" || true)

if grep -q '"level"' <<<"$TREE"; then
    ok "/tree returns the location hierarchy"
else
    bad "/tree has no hierarchy"
fi

# ---------------------------------------------------------------------------
# 4. Location filters
# ---------------------------------------------------------------------------
echo
echo "== 4. Registry: location filter"

c=$(http_code "$REG/services/storage-service?dc=$DC")
if [ "$c" = "200" ]; then
    ok "?dc=$DC finds storage-service"
else
    bad "?dc=$DC returned HTTP $c (expected 200)"
fi

c=$(http_code "$REG/services/storage-service?dc=nope")
if [ "$c" = "404" ]; then
    ok "?dc=nope returns 404"
else
    bad "?dc=nope returned HTTP $c (expected 404)"
fi


# ----------------------------------------------------------------
# 5. Data flow: sensor -> ingestion -> storage -> analytics
# ----------------------------------------------------------------
# ----------------------------------------------------------------
# 5. Data flow: sensor -> ingestion -> storage
# ----------------------------------------------------------------
echo "== 5. Data flow: sensor -> ingestion -> storage (waits 20 s)"

# Read a Prometheus metric, including metrics with labels.
metric_value() {
    get "$1/metrics" |
        awk -v metric="$2" '$1 == metric {print $2; exit}'
}

# Compare numeric values as floating-point numbers.
increased() {
    awk -v before="$1" -v after="$2" \
        'BEGIN {
            if (before == "" || after == "") exit 1
            exit !(after + 0 > before + 0)
        }'
}

sensor_before=$(metric_value "$SEN" 'sensor_readings_sent_total{result="ok"}')
ingestion_before=$(metric_value "$ING" 'ingestion_readings_total{result="accepted"}')
storage_before=$(metric_value "$STO" 'storage_readings_stored_total')

sleep 20

sensor_after=$(metric_value "$SEN" 'sensor_readings_sent_total{result="ok"}')
ingestion_after=$(metric_value "$ING" 'ingestion_readings_total{result="accepted"}')
storage_after=$(metric_value "$STO" 'storage_readings_stored_total')

if increased "$sensor_before" "$sensor_after"; then
    ok "sensor sent readings ($sensor_before -> $sensor_after)"
else
    bad "sensor counter did not increase (before='$sensor_before', after='$sensor_after')"
fi

if increased "$ingestion_before" "$ingestion_after"; then
    ok "ingestion accepted readings ($ingestion_before -> $ingestion_after)"
else
    bad "ingestion counter did not increase (before='$ingestion_before', after='$ingestion_after')"
fi

if increased "$storage_before" "$storage_after"; then
    ok "storage stored readings ($storage_before -> $storage_after)"
else
    bad "storage counter did not increase (before='$storage_before', after='$storage_after')"
fi
# ---------------------------------------------------------------------------
# 6. Input validation
# ---------------------------------------------------------------------------
echo
echo "== 6. Input validation"

c=$(http_code -X POST \
    -H 'Content-Type: application/json' \
    -d '{"x":1}' \
    "$ING/ingest")

if [ "$c" = "400" ]; then
    ok "invalid reading rejected with HTTP 400"
else
    bad "invalid reading returned HTTP $c (expected 400)"
fi

# ---------------------------------------------------------------------------
# 7. Prometheus metrics
# ---------------------------------------------------------------------------
echo
echo "== 7. Prometheus metrics"

m=$(get "$ING/metrics" || true)

grep -q '^service_info{' <<<"$m" \
    && ok "ingestion exports service_info (location)" \
    || bad "ingestion: service_info missing"

grep -Eq '^http_requests_total\{.*endpoint="/ingest"' <<<"$m" \
    && ok "ingestion counts HTTP requests" \
    || bad "ingestion: http_requests_total missing"

grep -Eq '^ingestion_readings_total\{result="accepted"\} [1-9]' <<<"$m" \
    && ok "ingestion accepted readings > 0" \
    || bad "ingestion: no accepted readings"

grep -Eq '^ingestion_readings_total\{result="invalid"\} [1-9]' <<<"$m" \
    && ok "ingestion counted the invalid reading" \
    || bad "ingestion: invalid counter did not move"

m=$(get "$STO/metrics" || true)

grep -Eq '^storage_rows [1-9]' <<<"$m" \
    && ok "storage_rows > 0" \
    || bad "storage: storage_rows is 0 or missing"

grep -Eq '^storage_readings_stored_total [1-9]' <<<"$m" \
    && ok "storage_readings_stored_total > 0" \
    || bad "storage: nothing stored"

grep -Eq '^http_request_duration_seconds_bucket' <<<"$m" \
    && ok "storage exports a latency histogram" \
    || bad "storage: latency histogram missing"

m=$(get "$ANA/metrics" || true)

grep -q '^analytics_storage_errors_total' <<<"$m" \
    && ok "analytics exports its error counter" \
    || bad "analytics: error counter missing"

m=$(get "$REG/metrics" || true)

grep -q '^registry_instances{' <<<"$m" \
    && ok "registry exports instances per location" \
    || bad "registry: registry_instances missing"

m=$(get "$SEN/metrics" || true)

grep -Eq '^sensor_readings_sent_total\{result="ok"\} [1-9]' <<<"$m" \
    && ok "sensor sent readings (ok > 0)" \
    || bad "sensor: no successful readings"

# ---------------------------------------------------------------------------
# 8. Optional Incus failure test
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--failure" ]; then
    echo
    echo "== 8. Failure test: stop and restart Incus storage container"

    wait_for() {
        local timeout_seconds=$1
        local interval=2
        local elapsed=0
        shift

        while [ "$elapsed" -lt "$timeout_seconds" ]; do
            if "$@"; then
                return 0
            fi
            sleep "$interval"
            elapsed=$((elapsed + interval))
        done

        return 1
    }

    storage_listed() {
        get "$REG/services" 2>/dev/null | grep -q '"storage-service"'
    }

    storage_gone() {
        ! storage_listed
    }

    if ! incus info storage >/dev/null 2>&1; then
        bad "Incus container 'storage' was not found or is inaccessible"
    elif incus stop storage; then
        if wait_for 60 storage_gone; then
            ok "registry removed storage-service after storage stopped"
        else
            bad "storage-service still listed after 60 seconds"
        fi

        c=$(http_code "$ANA/stats")
        if [ "$c" = "502" ]; then
            ok "analytics answers HTTP 502 while storage is down"
        else
            bad "analytics returned HTTP $c (expected 502)"
        fi

        e=$(get "$ANA/metrics" 2>/dev/null \
            | grep -E '^analytics_storage_errors_total' \
            | awk '{print $2}')

        if [ -n "$e" ] && awk -v v="$e" 'BEGIN { exit !(v > 0) }'; then
            ok "analytics_storage_errors_total is $e"
        else
            bad "analytics error counter did not move"
        fi

        if get "$ING/metrics" 2>/dev/null \
            | grep -Eq '^ingestion_readings_total\{result="storage_error"\} [1-9]'; then
            ok "ingestion counted storage_error readings"
        else
            bad "ingestion: storage_error counter did not move"
        fi
    else
        bad "could not stop Incus container 'storage'"
    fi

    # Always attempt to restore storage after the failure test.
    if incus start storage >/dev/null 2>&1; then
        ok "Incus storage container start command succeeded"

        if wait_for 60 storage_listed; then
            ok "storage-service re-registered after restart"
        else
            bad "storage-service did not re-register within 60 seconds"
        fi
    else
        bad "could not start Incus container 'storage' -- check it manually"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "========================================"
echo "Result: $PASS passed, $FAIL failed"
echo "========================================"

[ "$FAIL" -eq 0 ]
