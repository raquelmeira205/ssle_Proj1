#!/usr/bin/env bash
# Threat 3 - Route/signal hijacking: DNS hijacking of the SSLE service names.
#
# DNS-server-container (dnsmasq) answers *.ssle.local from /etc/dnsmasq-zones/ssle.hosts.
# The PoC overwrites that zone so ingestion.ssle.local points to an attacker IP.
#
# Phases (saved under evidence/dns/):
#   1. control (only with --control)  Wazuh agent stopped: the hijack stays in place
#   2. protected                       FIM (syscheck realtime) -> rule 550 -> rule 100230 ->
#                                      restore-dns.sh puts the clean zone back
# A client queries the name every 0.25 s during the attack, so the post-mortem shows the
# exposure window (how long and how many answers pointed to the attacker).
#
# Run on the Incus host from the repo root:   ./test-dns.sh [--control]
#   DNS_CONTAINER=DNS-server-container DOMAIN=ingestion.ssle.local HIJACK_IP=10.255.255.42
set -u
source "$(dirname "$0")/test-lib.sh"

DNS_CONTAINER=${DNS_CONTAINER:-DNS-server-container}
DOMAIN=${DOMAIN:-ingestion.ssle.local}
HIJACK_IP=${HIJACK_IP:-10.255.255.42}
ZONE=/etc/dnsmasq-zones/ssle.hosts
CLEAN=/etc/dnsmasq.hosts.clean
WATCH_SECS=${WATCH_SECS:-15}

start_evidence dns
threat_card "Route / signal hijacking (DNS hijacking)" \
  "An attacker changes name resolution so clients connect to a host they control instead of the real service." \
  "Sensors and operators reach the services by name (*.ssle.local). A hijacked ingestion name sends every sensor reading to the attacker (data theft/poisoning) and silently stops the real pipeline." \
  "Write access to the DNS server's zone file (compromised admin account, bad automation, malicious insider) and a dnsmasq restart; all clients follow immediately." \
  "Wazuh syscheck (FIM, realtime) on /etc/dnsmasq-zones: rule 550 'checksum changed' -> rule 100230 (level 12). dnsmasq query log shows who received the bad answer." \
  "restore-dns.sh active response on the DNS agent: copies the golden zone ($CLEAN) back and restarts dnsmasq (no timeout, the fix is permanent)."

section "0. Setup and baseline"
DNS_IP=$(ip_of "$DNS_CONTAINER")
[ -n "$DNS_IP" ] || { echo "Could not find the IP of '$DNS_CONTAINER'"; exit 1; }
info "DNS server $DNS_CONTAINER = $DNS_IP, name under test: $DOMAIN, attacker IP: $HIJACK_IP"
command -v dig >/dev/null || { echo "dig not installed (apt install dnsutils)"; exit 1; }
incus exec "$DNS_CONTAINER" -- cmp -s "$CLEAN" "$ZONE" && ok "zone matches the golden copy" || bad "zone differs from the golden copy before the test"
incus exec "$DNS_CONTAINER" -- systemctl is-active -q wazuh-agent && ok "Wazuh agent active on $DNS_CONTAINER" || bad "Wazuh agent not active on $DNS_CONTAINER"
BASELINE=$(dig +short "@$DNS_IP" "$DOMAIN" | head -1)
[ -n "$BASELINE" ] && ok "baseline: $DOMAIN -> $BASELINE" || { bad "baseline resolution failed"; finish; exit 1; }

hijack() { incus exec "$DNS_CONTAINER" -- sh -c "sed -i 's/^[0-9.]*\([[:space:]]\+$DOMAIN\)\$/$HIJACK_IP\1/' $ZONE && systemctl restart dnsmasq"; }
# timeline <seconds> <file>: "epoch answer" every 0.25 s
timeline() {
  local end=$(( $(date +%s) + $1 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    echo "$(date +%s.%N) $(dig +short +time=1 +tries=1 "@$DNS_IP" "$DOMAIN" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)"
    sleep 0.25
  done > "$2"
}
# analyse <timeline file> <hijack epoch>: readable timeline + exposure numbers
analyse() {
  python3 - "$1" "$2" "$BASELINE" "$HIJACK_IP" <<'EOF'
import sys
from datetime import datetime
path, t_hijack, good, bad = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
rows = [l.split(" ", 1) for l in open(path) if l.strip()]
rows = [(float(t), (a.strip() or "no answer")) for t, a in rows]
last = None
for t, a in rows:                       # print only the changes, relative to the hijack
    if a != last:
        print("    %s (t%+.2fs)  %s" % (datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3], t - t_hijack, a))
        last = a
badt = [t for t, a in rows if a == bad]
print("    answers: %d total, %d pointed to the attacker, %d failed" % (len(rows), len(badt), sum(a == "no answer" for _, a in rows)))
print("EXPOSURE %.2f" % ((badt[-1] - badt[0] + 0.25) if badt else 0.0))
print("FINAL %s" % rows[-1][1])
EOF
}

if [ "${1:-}" = "--control" ]; then
  section "1. Control: same hijack with the Wazuh agent stopped (${WATCH_SECS} s)"
  incus exec "$DNS_CONTAINER" -- systemctl stop wazuh-agent
  timeline "$WATCH_SECS" "$EVID/1-control-timeline.raw" &
  sleep 2; T_H=$(now); hijack; wait
  analyse "$EVID/1-control-timeline.raw" "$T_H" | tee "$EVID/1-control-timeline.txt" | grep -v '^FINAL\|^EXPOSURE'
  [ "$(grep '^FINAL' "$EVID/1-control-timeline.txt" | cut -d' ' -f2)" = "$HIJACK_IP" ] \
    && ok "without Wazuh the hijack stays in place" || bad "control run did not stay hijacked"
  incus exec "$DNS_CONTAINER" -- sh -c "cp $CLEAN $ZONE && systemctl restart dnsmasq"
  incus exec "$DNS_CONTAINER" -- systemctl start wazuh-agent
  info "zone restored by hand, agent restarted, waiting 20 s for it to reconnect"
  sleep 20
fi

section "2. Protected: hijack with Wazuh FIM + restore-dns active response (${WATCH_SECS} s)"
MARK=$(alerts_mark)
DLOG=$(incus exec "$DNS_CONTAINER" -- sh -c 'wc -l < /var/log/dnsmasq.log' 2>/dev/null || echo 0)
timeline "$WATCH_SECS" "$EVID/2-protected-timeline.raw" &
sleep 2
T_H=$(now); info "hijack: $DOMAIN -> $HIJACK_IP"; hijack
wait
analyse "$EVID/2-protected-timeline.raw" "$T_H" | tee "$EVID/2-protected-timeline.txt" | grep -v '^FINAL\|^EXPOSURE'
EXPOSURE=$(grep '^EXPOSURE' "$EVID/2-protected-timeline.txt" | cut -d' ' -f2)
FINAL=$(grep '^FINAL' "$EVID/2-protected-timeline.txt" | cut -d' ' -f2-)

section "2a. Detection (rule 100230)"
if wait_alert "$MARK" 100230 20 > "$EVID/2-wazuh-alerts-100230.json"; then ok "rule 100230 (DNS hijacking) fired"
else bad "rule 100230 did not fire"; fi
alert_summary < "$EVID/2-wazuh-alerts-100230.json" | head -8
FIRST=$(alert_first_epoch < "$EVID/2-wazuh-alerts-100230.json")
DETECT=$([ -n "$FIRST" ] && elapsed "$T_H" "$FIRST" || echo n/a)

section "2b. Response (restore-dns.sh)"
incus exec "$DNS_CONTAINER" -- journalctl -t ssle-dns-ar --since "2 min ago" -o short-unix --no-pager > "$EVID/2-restore-journal.txt" 2>&1
cat "$EVID/2-restore-journal.txt"
RESTORED_AT=$(grep -m1 Restored "$EVID/2-restore-journal.txt" | cut -d' ' -f1)
[ -n "$RESTORED_AT" ] && ok "restore-dns ran $(elapsed "$T_H" "$RESTORED_AT") s after the hijack" || bad "no restore-dns entry in the journal"
incus exec "$DNS_CONTAINER" -- cmp -s "$CLEAN" "$ZONE" && ok "zone file equals the golden copy again" || bad "zone file still differs from the golden copy"
[ "$FINAL" = "$BASELINE" ] && ok "$DOMAIN resolves to $BASELINE again" || bad "$DOMAIN resolves to '$FINAL' (expected $BASELINE)"

section "2c. Who received the hijacked answer (dnsmasq query log)"
incus exec "$DNS_CONTAINER" -- sh -c "tail -n +$((DLOG + 1)) /var/log/dnsmasq.log" 2>/dev/null \
  | grep -E "query|reply|$DOMAIN" > "$EVID/2-dnsmasq-queries.log"
grep "is $HIJACK_IP" "$EVID/2-dnsmasq-queries.log" | head -5 || true
info "$(grep -c "is $HIJACK_IP" "$EVID/2-dnsmasq-queries.log") hijacked replies in the dnsmasq log"

section "Post-mortem summary"
{
  echo "  hijack -> first 100230 alert : ${DETECT} s"
  echo "  hijack -> zone restored      : $([ -n "$RESTORED_AT" ] && elapsed "$T_H" "$RESTORED_AT" || echo never) s"
  echo "  exposure window              : ${EXPOSURE} s with $DOMAIN -> $HIJACK_IP seen by the client"
  [ -f "$EVID/1-control-timeline.txt" ] && echo "  control (no Wazuh)           : still $(grep '^FINAL' "$EVID/1-control-timeline.txt" | cut -d' ' -f2) after ${WATCH_SECS} s"
  echo "  limitations : detects tampering of the zone FILE only (not cache poisoning, rogue DHCP/DNS or"
  echo "                on-path spoofing); clients may cache the bad answer for its TTL; an attacker with root"
  echo "                on the DNS host can also change the golden copy or stop the agent."
} | tee "$EVID/summary.txt"

finish
