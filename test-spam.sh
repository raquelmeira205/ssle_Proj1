#!/usr/bin/env bash
# Threat 2 - Junk email against the SSLE mail server (mail-container: Postfix + SpamAssassin).
#
# Phases (saved under evidence/spam/):
#   1. baseline      a legitimate message from legit-client is delivered
#   2. spam content  a GTUBE message: SpamAssassin flags it (rule 100220) and Postfix
#                    quarantines it on HOLD (mail/header_checks, rule 100223) - not delivered
#   3. open relay    a lab host tries to relay to an outside domain: must be refused
#   4. flood         many messages from one source: rule 100222 (10 in 30 s) -> firewall-drop
#                    of that IP for 60 s, while legit-client can still send
#   5. recovery      the flooding IP is unblocked after the timeout
#
# Needs the hardening in mail/ (apply-configs.sh) for phases 2 and 3.
# Run on the Incus host from the repo root:   ./test-spam.sh  [--no-wait]
#   MAIL=mail-container SMTP_PORT=25 ATTACKER=attacker1 LEGIT=legit-client COUNT=12
set -u
source "$(dirname "$0")/test-lib.sh"

MAIL=${MAIL:-mail-container}
SMTP_PORT=${SMTP_PORT:-25}
ATTACKER=${ATTACKER:-attacker1}
LEGIT=${LEGIT:-legit-client}
COUNT=${COUNT:-12}
RCPT=${RCPT:-root@mail-container}
BLOCK_SECS=60
GTUBE='XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'

start_evidence spam
threat_card "Junk email (spam content and bulk mail flood)" \
  "Unsolicited bulk mail: spam/phishing content, and high-volume sending from one source." \
  "The mail server is how operators get alerts and talk to users; spam is the main carrier of phishing/fraud, and a flood fills the queue, the disk and the spamd workers." \
  "Anyone who can reach port 25 can submit mail (no authentication for local recipients); before the hardening the whole lab /24 was trusted and could relay." \
  "Wazuh reads /var/log/mail.log: 100220 spamd 'identified spam', 100223 Postfix 'hold' (quarantine), 100221 accepted message per client IP, 100222 = 10 messages in 30 s from the same srcip." \
  "Spam content: quarantined in the Postfix hold queue (header_checks). Flood: firewall-drop of the sender IP for ${BLOCK_SECS} s. Relay: refused by Postfix (mynetworks = localhost only)."

section "0. Setup"
MAIL_IP=$(ip_of "$MAIL")
[ -n "$MAIL_IP" ] || { echo "Could not find the IP of '$MAIL'"; exit 1; }
info "mail server $MAIL = $MAIL_IP:$SMTP_PORT"
ensure_client "$ATTACKER"; ensure_client "$LEGIT"
ATT_IP=$(ip_of "$ATTACKER"); LEGIT_IP=$(ip_of "$LEGIT")
info "attacker $ATTACKER = $ATT_IP, legitimate sender $LEGIT = $LEGIT_IP"
for ip in "$ATT_IP" "$LEGIT_IP"; do
  for i in $(seq 1 70); do blocked "$MAIL" "$ip" || break; [ "$i" = 1 ] && info "$ip still blocked from a previous run, waiting"; sleep 1; done
done
incus exec "$MAIL" -- postconf -h mynetworks > "$EVID/0-postfix-mynetworks.txt"
incus exec "$MAIL" -- postconf -h header_checks > "$EVID/0-postfix-header_checks.txt" 2>&1
info "mynetworks = $(cat "$EVID/0-postfix-mynetworks.txt")"
info "header_checks = $(cat "$EVID/0-postfix-header_checks.txt")"

# smtp <container> <from> <to> <subject> <body>: one SMTP dialogue, prints the server's replies
smtp() {
  incus exec "$1" -- timeout 20 bash -c '
    exec 3<>/dev/tcp/'"$MAIL_IP/$SMTP_PORT"' || exit 1
    send() { printf "%s\r\n" "$1" >&3; sleep 0.3; }
    sleep 0.3
    send "EHLO client.test"; send "MAIL FROM:<$0>"; send "RCPT TO:<$1>"; send "DATA"
    printf "Date: %s\r\nMessage-ID: <%s@client.test>\r\nFrom: <%s>\r\nTo: <%s>\r\nSubject: %s\r\n\r\n%s\r\n.\r\n" \
      "$(date -R)" "$(date +%s%N)" "$0" "$1" "$2" "$3" >&3
    sleep 0.5; send "QUIT"
    timeout 3 cat <&3' "$2" "$3" "$4" "$5" 2>/dev/null   # Postfix may hang up first (relay test)
}
can_connect() { incus exec "$1" -- timeout 3 bash -c "exec 3<>/dev/tcp/$MAIL_IP/$SMTP_PORT" 2>/dev/null; }
mlog_mark()   { incus exec "$MAIL" -- sh -c 'wc -l < /var/log/mail.log'; }
mlog_since()  { incus exec "$MAIL" -- sh -c "tail -n +$(( $1 + 1 )) /var/log/mail.log"; }
# wait_mlog <mark> <pattern> <seconds>
wait_mlog() { local i; for i in $(seq 1 "$3"); do mlog_since "$1" | grep -q -- "$2" && return 0; sleep 1; done; return 1; }

# ------------------------------------------------------------------ 1. baseline
section "1. Baseline: legitimate message from $LEGIT"
M=$(mlog_mark)
smtp "$LEGIT" "alice@client.test" "$RCPT" "Weekly sensor report" \
  "Hello, the weekly temperature report for dc1 is ready on the analytics service." > "$EVID/1-legit-smtp.txt"
cat "$EVID/1-legit-smtp.txt"
grep -q "^250 2.0.0 Ok: queued" "$EVID/1-legit-smtp.txt" && ok "legitimate message accepted" || bad "legitimate message not accepted"
info "waiting for SpamAssassin + local delivery (up to 60 s)"
wait_mlog "$M" "delivered to mailbox" 60 && ok "legitimate message delivered to the mailbox" || bad "legitimate message not delivered"
mlog_since "$M" > "$EVID/1-mail.log"
grep -q "spamd: clean message" "$EVID/1-mail.log" && ok "SpamAssassin scored it as clean" || info "no 'clean message' line from spamd (check $EVID/1-mail.log)"

# ------------------------------------------------------------------ 2. spam content
section "2. Spam content: GTUBE message from $ATTACKER"
M=$(mlog_mark); MARK=$(alerts_mark)
smtp "$ATTACKER" "promo@evil.test" "$RCPT" "You won a prize" "$GTUBE" > "$EVID/2-spam-smtp.txt"
grep -q "^250 2.0.0 Ok: queued" "$EVID/2-spam-smtp.txt" && ok "spam accepted for scanning" || bad "spam not accepted by Postfix"
info "waiting for SpamAssassin (up to 60 s)"
wait_mlog "$M" "identified spam" 60 && ok "SpamAssassin identified the spam" || bad "SpamAssassin did not flag the message"
wait_mlog "$M" "hold: header X-Spam-Flag" 30 && ok "spam quarantined on HOLD (not delivered)" || bad "spam was not quarantined (is mail/header_checks applied?)"
mlog_since "$M" > "$EVID/2-mail.log"
grep -q "delivered to mailbox" "$EVID/2-mail.log" && bad "the spam reached the mailbox" || ok "nothing was delivered to the mailbox"
incus exec "$MAIL" -- postqueue -p > "$EVID/2-hold-queue.txt" 2>&1
grep -q '!' "$EVID/2-hold-queue.txt" && info "hold queue (! = on hold): $(grep -c '!' "$EVID/2-hold-queue.txt") message(s)"
for r in 100220 100223; do
  if wait_alert "$MARK" "$r" 20 > "$EVID/2-wazuh-alerts-$r.json"; then ok "Wazuh rule $r fired"; alert_summary < "$EVID/2-wazuh-alerts-$r.json" | head -4
  else bad "Wazuh rule $r did not fire"; fi
done

# ------------------------------------------------------------------ 3. open relay
section "3. Open relay: $ATTACKER tries to send to an outside domain"
smtp "$ATTACKER" "promo@evil.test" "victim@example.org" "relay test" "relay test" > "$EVID/3-relay-smtp.txt"
cat "$EVID/3-relay-smtp.txt"
grep -qi "Relay access denied" "$EVID/3-relay-smtp.txt" && ok "relay refused (Relay access denied)" || bad "relay was not refused (mynetworks still trusts the lab?)"

# ------------------------------------------------------------------ 4. flood
section "4. Flood: $COUNT messages in parallel from $ATTACKER"
M=$(mlog_mark); MARK=$(alerts_mark)
AR_LINES=$(incus exec "$MAIL" -- sh -c 'wc -l < /var/ossec/logs/active-responses.log' 2>/dev/null || echo 0)
T0=$(now)
for i in $(seq 1 "$COUNT"); do
  smtp "$ATTACKER" "flood$i@evil.test" "$RCPT" "Cheap offer $i" "Buy now $i" > "$EVID/4-flood-smtp-$i.txt" 2>&1 &
done
BLOCKED_AT=""
for i in $(seq 1 60); do blocked "$MAIL" "$ATT_IP" && { BLOCKED_AT=$(now); break; }; sleep 0.5; done
incus exec "$MAIL" -- iptables -L INPUT -n -v > "$EVID/4-iptables-during-block.txt" 2>&1
wait
SENT=$(grep -l "^250 2.0.0 Ok: queued" "$EVID"/4-flood-smtp-*.txt 2>/dev/null | wc -l)
# "client=" is logged when Postfix starts a message (after MAIL FROM): these are what rule 100222
# counts. A session cut by the firewall before the final "250 queued" never delivers anything.
STARTED=$(mlog_since "$M" | grep -c "client=.*\[$ATT_IP\]")
# How many finish is a race between the 12 parallel sessions and the block (threshold: 10 in 30 s)
if [ "$SENT" -lt "$STARTED" ]; then
  info "flood: $STARTED of $COUNT sessions reached Postfix, $SENT completed (the rest were cut by the block mid-transfer)"
else
  info "flood: $STARTED of $COUNT sessions reached Postfix, all $SENT completed before the block (threshold is 10 messages)"
fi
cat "$EVID"/4-flood-smtp-*.txt > "$EVID/4-flood-smtp.txt"; rm -f "$EVID"/4-flood-smtp-*.txt

if wait_alert "$MARK" 100222 20 "\"srcip\":\"$ATT_IP\"" > /dev/null; then ok "rule 100222 (mail flood) fired for $ATT_IP"
else bad "rule 100222 did not fire for $ATT_IP"; fi
alerts_since "$MARK" 100222 > "$EVID/4-wazuh-alerts-100222.json"
alert_summary < "$EVID/4-wazuh-alerts-100222.json" | head -5
FIRST=$(alert_first_epoch < "$EVID/4-wazuh-alerts-100222.json")
DETECT=$([ -n "$FIRST" ] && elapsed "$T0" "$FIRST" || echo n/a)

cat "$EVID/4-iptables-during-block.txt"
[ -n "$BLOCKED_AT" ] && ok "$ATT_IP blocked $(elapsed "$T0" "$BLOCKED_AT") s after the flood started" || bad "$ATT_IP was never blocked"
incus exec "$MAIL" -- sh -c "tail -n +$((AR_LINES + 1)) /var/ossec/logs/active-responses.log" > "$EVID/4-active-responses.log" 2>/dev/null
grep -q "\"command\":\"add\".*$ATT_IP" "$EVID/4-active-responses.log" && ok "firewall-drop add logged on $MAIL" || bad "no firewall-drop add in $MAIL's active-responses.log"
if [ -n "$BLOCKED_AT" ] && blocked "$MAIL" "$ATT_IP"; then
  can_connect "$ATTACKER" && bad "attacker can still connect while blocked" || ok "attacker cannot connect while blocked"
fi
blocked "$MAIL" "$LEGIT_IP" && bad "legitimate sender $LEGIT_IP was blocked (false positive)" || ok "legitimate sender $LEGIT_IP not blocked"
smtp "$LEGIT" "alice@client.test" "$RCPT" "Still working" "Mail from a legitimate sender during the flood." > "$EVID/4-legit-during-block.txt"
grep -q "^250 2.0.0 Ok: queued" "$EVID/4-legit-during-block.txt" && ok "legitimate sender can still send during the block" || bad "legitimate sender could not send during the block"
mlog_since "$M" > "$EVID/4-mail.log"

# ------------------------------------------------------------------ 5. recovery
section "5. Recovery: block removed after ${BLOCK_SECS} s (skip with --no-wait)"
if [ "${1:-}" != "--no-wait" ]; then
  sleep $((BLOCK_SECS + 10))
  blocked "$MAIL" "$ATT_IP" && bad "$ATT_IP still blocked after the timeout" || ok "$ATT_IP unblocked after the timeout"
  can_connect "$ATTACKER" && ok "attacker can connect again" || bad "attacker still cannot connect"
else
  info "skipped"
fi

section "Post-mortem summary"
{
  echo "  spam content : flagged by SpamAssassin -> $(grep -q 'hold: header X-Spam-Flag' "$EVID/2-mail.log" && echo quarantined on hold || echo DELIVERED)"
  echo "  open relay   : $(grep -qi 'Relay access denied' "$EVID/3-relay-smtp.txt" && echo refused || echo ALLOWED)"
  echo "  flood        : $STARTED/$COUNT sessions reached Postfix, $SENT completed; first 100222 alert after ${DETECT} s;" \
       "blocked after $([ -n "$BLOCKED_AT" ] && elapsed "$T0" "$BLOCKED_AT" || echo never) s"
  echo "  false positive (legit sender blocked): $(grep -qw "$LEGIT_IP" "$EVID/4-iptables-during-block.txt" && echo yes || echo no)"
  echo "  limitations  : GTUBE is a test signature (real spam needs Bayes/RBL tuning); a spammer that rotates IPs or"
  echo "                 stays under 10 messages/30 s is not blocked; quarantined mail must be reviewed by an operator."
} | tee "$EVID/summary.txt"

finish
