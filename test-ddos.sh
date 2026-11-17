#!/usr/bin/env bash
# Threat 1 - DDoS / HTTP flood: rule 100210 (15 hits in 10s from one srcip on
# rule 100200) and its firewall-drop active response (60s) on the hit container.
#
# Run from the Incus host (e.g. the Kali VM), NOT from inside a service
# container, so the flood's source IP is a real, blockable address.
#
#   TARGET=ingestion   PORT=5001   ENDPOINT=/ingest   (override if needed)
#   REQUESTS=25        requests fired in the burst (rule needs 15 in 10s)
#   ./test-ddos.sh --no-wait   skip the 60s unblock check at the end
set -u
TARGET=${TARGET:-ingestion}
PORT=${PORT:-5001}
ENDPOINT=${ENDPOINT:-/ingest}
REQUESTS=${REQUESTS:-25}
WAZUH_CONTAINER=${WAZUH_CONTAINER:-wazuh-container}
BODY='{"device_id":"flood-test","temperature":21.0}'

PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
hit() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 -X POST -H 'Content-Type: application/json' -d "$BODY" "$1"; }

IP=$(incus list "$TARGET" -c4 --format csv 2>/dev/null | cut -d' ' -f1)
[ -n "$IP" ] || { echo "Could not find the IP of container '$TARGET' (is it running?)"; exit 1; }
URL="http://$IP:$PORT$ENDPOINT"
echo "Target: $URL"

echo "== 0. Baseline reachability"
code=$(hit "$URL")
if [ "$code" = "200" ]; then ok "baseline request succeeds (HTTP $code)"; else bad "baseline request failed (HTTP $code)"; fi

echo "== 1. Flood: $REQUESTS requests as fast as possible"
start=$(date +%s)
for i in $(seq 1 "$REQUESTS"); do hit "$URL" >/dev/null & done
wait
elapsed=$(( $(date +%s) - start ))
echo "    sent $REQUESTS requests in about ${elapsed}s"
if [ "$elapsed" -le 10 ]; then ok "burst completed within the rule's 10s window"; else bad "burst took ${elapsed}s (rule window is 10s)"; fi

echo "== 2. Wait for Wazuh to raise rule 100210 (up to 15s)"
found=""
for i in $(seq 1 15); do
  incus exec "$WAZUH_CONTAINER" -- grep -q "Rule: 100210" /var/ossec/logs/alerts/alerts.log 2>/dev/null && { found=1; break; }
  sleep 1
done
if [ -n "$found" ]; then ok "rule 100210 (DDoS) fired"; else bad "rule 100210 did not fire within 15s"; fi

echo "== 3. Check the active response ran on $TARGET"
sleep 3   # execd + firewall-drop need a moment after the alert
if incus exec "$TARGET" -- grep -q "firewall-drop" /var/ossec/logs/active-responses.log 2>/dev/null; then
  ok "firewall-drop ran on $TARGET"
else
  bad "no firewall-drop entry in $TARGET's active-responses.log"
fi

echo "== 4. Confirm the flooding IP is now blocked (expect no response)"
code=$(hit "$URL")
if [ "$code" = "000" ]; then ok "request from the flooding IP got no response (blocked)"; else bad "request still answered with HTTP $code (expected blocked)"; fi

echo "== 5. Wait out the 60s block, then confirm access returns (skip with --no-wait)"
if [ "${1:-}" != "--no-wait" ]; then
  sleep 60
  code=$(hit "$URL")
  if [ "$code" = "200" ]; then ok "access restored after the block timed out"; else bad "still not answering after 60s (HTTP/code: $code)"; fi
else
  echo "    skipped"
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]