#!/usr/bin/env bash
# Threat 2 - Junk email:
#   A) spam content detection (rule 100220, SpamAssassin/GTUBE, no response)
#   B) mail volume flood from one source (rule 100222: 10 in 30s) + firewall-drop
#
# Run from the Incus host (e.g. the Kali VM), NOT from inside mail-container,
# so Postfix logs a real, blockable client IP for part B.
#
#   MAIL=mail-container   SMTP_PORT=25
#   COUNT=12               messages fired in the burst (rule needs 10 in 30s)
#   ./test-spam.sh --no-wait   skip the 60s unblock check at the end
set -u
MAIL=${MAIL:-mail-container}
SMTP_PORT=${SMTP_PORT:-25}
COUNT=${COUNT:-12}
WAZUH_CONTAINER=${WAZUH_CONTAINER:-wazuh-container}
GTUBE='XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'

PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

IP=$(incus list "$MAIL" -c4 --format csv 2>/dev/null | cut -d' ' -f1)
[ -n "$IP" ] || { echo "Could not find the IP of container '$MAIL' (is it running?)"; exit 1; }
echo "Mail server: $IP:$SMTP_PORT"

# One raw SMTP dialogue over TCP. $1 = envelope-from. No external tool needed.
send_one() {
  local from="$1"
  timeout 6 bash -c "
    exec 3<>/dev/tcp/$IP/$SMTP_PORT
    printf 'EHLO test.local\r\nMAIL FROM:<%s>\r\nRCPT TO:<root@mail-container>\r\nDATA\r\nSubject: test\r\n\r\n%s\r\n.\r\nQUIT\r\n' '$from' '$GTUBE' >&3
    cat <&3 >/dev/null
  " 2>/dev/null
}

echo "== 1. Baseline: can we reach port $SMTP_PORT?"
if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$SMTP_PORT" 2>/dev/null; then
  ok "SMTP port is open"
else
  bad "cannot connect to $IP:$SMTP_PORT"
  echo; echo "Result: $PASS passed, $FAIL failed"; exit 1
fi

echo "== 2. Send one GTUBE test message (spam content detection)"
send_one "test-single@evil.test"
sleep 3
if incus exec "$WAZUH_CONTAINER" -- grep -q "Rule: 100220" /var/ossec/logs/alerts/alerts.log 2>/dev/null; then
  ok "rule 100220 fired (SpamAssassin identified spam)"
else
  bad "rule 100220 did not fire"
fi

echo "== 3. Send $COUNT messages quickly (mail flood from one source)"
start=$(date +%s)
for i in $(seq 1 "$COUNT"); do send_one "flood$i@evil.test" & done
wait
elapsed=$(( $(date +%s) - start ))
echo "    sent $COUNT messages in about ${elapsed}s"
if [ "$elapsed" -le 30 ]; then ok "burst completed within the rule's 30s window"; else bad "burst took ${elapsed}s (rule window is 30s)"; fi

echo "== 4. Wait for rule 100222 (mail flood) to fire (up to 20s)"
found=""
for i in $(seq 1 20); do
  incus exec "$WAZUH_CONTAINER" -- grep -q "Rule: 100222" /var/ossec/logs/alerts/alerts.log 2>/dev/null && { found=1; break; }
  sleep 1
done
if [ -n "$found" ]; then ok "rule 100222 fired (mail flood)"; else bad "rule 100222 did not fire within 20s"; fi

echo "== 5. Check the active response ran on $MAIL"
sleep 3
if incus exec "$MAIL" -- grep -q "firewall-drop" /var/ossec/logs/active-responses.log 2>/dev/null; then
  ok "firewall-drop ran on $MAIL"
else
  bad "no firewall-drop entry in $MAIL's active-responses.log"
fi

echo "== 6. Confirm the flooding IP is now blocked (expect the connection to fail)"
if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$SMTP_PORT" 2>/dev/null; then
  bad "SMTP port still reachable (expected blocked)"
else
  ok "SMTP connection from the flooding IP is now blocked"
fi

echo "== 7. Wait out the 60s block, then confirm access returns (skip with --no-wait)"
if [ "${1:-}" != "--no-wait" ]; then
  sleep 60
  if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$SMTP_PORT" 2>/dev/null; then
    ok "access restored after the block timed out"
  else
    bad "still blocked after 60s"
  fi
else
  echo "    skipped"
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]