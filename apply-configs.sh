#!/usr/bin/env bash
# Push the configuration kept in this repo into the lab containers (the reverse of
# collect-configs.sh). Each part is validated before the service is restarted.
# Run on the Incus host (the Kali VM) from the repo root:
#   ./apply-configs.sh            everything
#   ./apply-configs.sh wazuh prometheus mail dns agents     only some parts
#
# Container names can be overridden: WAZUH=... PROM=... MAIL=... DNS=...
#   SERVICES="registry storage ingestion analytics"   containers whose agent reads the access log
set -u
cd "$(dirname "$0")" || exit 1
WAZUH=${WAZUH:-wazuh-container}
PROM=${PROM:-prometheus-container}
MAIL=${MAIL:-mail-container}
DNS=${DNS:-DNS-server-container}
SERVICES=${SERVICES:-"registry storage ingestion analytics"}
PARTS=${*:-"wazuh prometheus mail dns agents"}
ERR=0
step() { echo; echo "== $1"; }
fail() { echo "  FAILED: $1"; ERR=$((ERR + 1)); }

for part in $PARTS; do case $part in

wazuh)
  step "Wazuh manager rules -> $WAZUH:/var/ossec/etc/rules/local_rules.xml"
  incus exec "$WAZUH" -- cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
  incus file push wazuh/ssle-rules.xml "$WAZUH/var/ossec/etc/rules/local_rules.xml"
  incus exec "$WAZUH" -- chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
  if incus exec "$WAZUH" -- /var/ossec/bin/wazuh-analysisd -t; then
    incus exec "$WAZUH" -- systemctl restart wazuh-manager && echo "  ok, manager restarted"
  else
    fail "rules do not load, previous file restored"
    incus exec "$WAZUH" -- cp /var/ossec/etc/rules/local_rules.xml.bak /var/ossec/etc/rules/local_rules.xml
  fi
  incus exec "$WAZUH" -- grep -q "<name>restore-dns</name>" /var/ossec/etc/ossec.conf \
    || echo "  NOTE: ossec.conf has no restore-dns command; append wazuh/manager-active-response.xml to it"
  ;;

prometheus)
  step "Prometheus config + rules -> $PROM:/etc/prometheus/"
  incus file push prometheus/prometheus.yml "$PROM/etc/prometheus/prometheus.yml"
  incus file push prometheus/ssle_rules.yml "$PROM/etc/prometheus/ssle_rules.yml"
  if incus exec "$PROM" -- promtool check config /etc/prometheus/prometheus.yml; then
    incus exec "$PROM" -- systemctl restart prometheus && echo "  ok, prometheus restarted"
  else
    fail "promtool rejected the config"
  fi
  ;;

mail)
  step "Postfix hardening -> $MAIL (mynetworks = localhost, spam to the hold queue)"
  incus exec "$MAIL" -- cp /etc/postfix/main.cf /etc/postfix/main.cf.bak
  incus file push mail/postfix-main.cf "$MAIL/etc/postfix/main.cf"
  incus file push mail/header_checks "$MAIL/etc/postfix/header_checks"
  if incus exec "$MAIL" -- postfix check; then
    incus exec "$MAIL" -- postfix reload && echo "  ok, postfix reloaded"
    incus exec "$MAIL" -- postconf -h mynetworks header_checks | sed 's/^/    /'
  else
    fail "postfix check failed, previous main.cf restored"
    incus exec "$MAIL" -- cp /etc/postfix/main.cf.bak /etc/postfix/main.cf
  fi
  ;;

dns)
  step "restore-dns active response -> $DNS"
  incus file push wazuh/active-response/restore-dns.sh "$DNS/var/ossec/active-response/bin/restore-dns.sh"
  incus exec "$DNS" -- chown root:wazuh /var/ossec/active-response/bin/restore-dns.sh
  incus exec "$DNS" -- chmod 750 /var/ossec/active-response/bin/restore-dns.sh && echo "  ok"
  ;;

agents)
  # Older install-wazuh-agents.sh runs added the access-log <localfile> to every <ossec_config>
  # block, so the agent listed the same file twice. Keep only the first one.
  step "Remove duplicated access-log entries from the service agents"
  for c in $SERVICES; do
    conf=$(incus exec "$c" -- cat /var/ossec/etc/ossec.conf 2>/dev/null) || { echo "  $c: no agent, skipped"; continue; }
    fixed=$(printf '%s\n' "$conf" | python3 -c '
import re, sys
text = sys.stdin.read()
block = re.compile(r"\n[ \t]*<localfile>\s*<log_format>json</log_format>\s*<location>/var/log/ssle/access.log</location>\s*</localfile>")
seen = []
def keep_first(m):
    seen.append(1)
    return m.group(0) if len(seen) == 1 else ""
sys.stdout.write(block.sub(keep_first, text))
')
    if [ "$(printf '%s' "$conf" | grep -c /var/log/ssle/access.log)" -gt 1 ]; then
      printf '%s\n' "$fixed" | incus exec "$c" -- sh -c 'cat > /var/ossec/etc/ossec.conf' \
        && incus exec "$c" -- systemctl restart wazuh-agent && echo "  $c: duplicate removed, agent restarted"
    else
      echo "  $c: ok (access log listed once)"
    fi
  done
  ;;

*) echo "unknown part '$part' (wazuh prometheus mail dns agents)"; ERR=$((ERR + 1)) ;;
esac; done

echo
[ "$ERR" -eq 0 ] && echo "All done." || echo "$ERR step(s) failed."
[ "$ERR" -eq 0 ]
