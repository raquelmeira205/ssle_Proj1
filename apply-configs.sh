#!/usr/bin/env bash
# Push the configuration kept in this repo into the lab containers (the reverse of
# collect-configs.sh). Each part is validated before the service is restarted.
# Run on the Incus host (the Kali VM) from the repo root:
#   ./apply-configs.sh            everything
#   ./apply-configs.sh pin wazuh prometheus mail dns agents     only some parts
#
# Container names can be overridden: WAZUH=... PROM=... MAIL=... DNS=...
#   SERVICES="registry storage ingestion analytics"   containers whose agent reads the access log
#   PLATFORM=k3s   the SSLE services run in the k3s cluster (Guide 2, k3s/): the DNS zone points at
#                  the NodePorts, the central Prometheus federates the in-cluster one, and the
#                  manager gets the k3s-block response. Default PLATFORM=incus.
set -u
cd "$(dirname "$0")" || exit 1
PLATFORM=${PLATFORM:-incus}
WAZUH=${WAZUH:-wazuh-container}
PROM=${PROM:-prometheus-container}
MAIL=${MAIL:-mail-container}
DNS=${DNS:-DNS-server-container}
K3S_MASTER=${K3S_MASTER:-k3s-master}
SERVICES=${SERVICES:-"registry storage ingestion analytics"}
# every container of the lab whose address should never change (see the "pin" part); the ones
# that do not exist (e.g. the k3s nodes on a pure Incus setup) are skipped
LAB=${LAB:-"registry storage ingestion analytics sensor $WAZUH $PROM $MAIL $DNS $K3S_MASTER k3s-node1 docker"}
PARTS=${*:-"pin wazuh prometheus mail dns agents"}
ERR=0
step() { echo; echo "== $1"; }
fail() { echo "  FAILED: $1"; ERR=$((ERR + 1)); }
ip_of() { incus list "^$1\$" -c4 --format csv 2>/dev/null | grep -oE '^[0-9.]+' | head -1; }

for part in $PARTS; do case $part in

pin)
  # Incus hands out addresses by DHCP, and after a reboot containers can swap addresses
  # (analytics got mail's old IP, the DNS server got ingestion's). Wazuh agents, the DNS zone and
  # firewall rules all refer to IPs, so make the CURRENT address of each container permanent.
  step "Pin the current IPv4 of every lab container"
  for c in $LAB; do
    ip=$(ip_of "$c")
    [ -n "$ip" ] || { echo "  $c: not running, skipped"; continue; }
    if incus config device get "$c" eth0 ipv4.address >/dev/null 2>&1; then
      incus config device set "$c" eth0 ipv4.address="$ip"
    else
      incus config device override "$c" eth0 ipv4.address="$ip" >/dev/null
    fi && echo "  $c = $ip (pinned)"
  done
  ;;

wazuh)
  # Rule 100210 ignores requests coming FROM the SSLE services themselves: one /stats call makes
  # analytics query the registry and storage, so during a flood storage and the registry blocked
  # analytics' IP and the pipeline broke itself. The list is rebuilt from the current IPs.
  step "Wazuh CDB list etc/lists/ssle-services (internal service IPs)"
  list=""
  for c in $SERVICES sensor; do ip=$(ip_of "$c"); [ -n "$ip" ] && list="$list$ip:$c\n" && echo "  $ip  $c"; done
  # k3s: pods talk to each other with pod IPs from the cluster network 10.42.0.0/16, which change
  # on every restart, so the whole prefix is listed (partial-IP key, matched as a prefix)
  list="${list}10.42.:k3s-pods\n"; echo "  10.42.*  k3s pod network"
  printf "$list" | incus exec "$WAZUH" -- sh -c 'cat > /var/ossec/etc/lists/ssle-services'
  incus exec "$WAZUH" -- chown wazuh:wazuh /var/ossec/etc/lists/ssle-services
  incus exec "$WAZUH" -- grep -q "etc/lists/ssle-services" /var/ossec/etc/ossec.conf \
    || incus exec "$WAZUH" -- sed -i '0,/<ruleset>/s#<ruleset>#<ruleset>\n    <list>etc/lists/ssle-services</list>#' /var/ossec/etc/ossec.conf

  step "Wazuh manager rules -> $WAZUH:/var/ossec/etc/rules/local_rules.xml"
  incus exec "$WAZUH" -- cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
  incus file push wazuh/ssle-rules.xml "$WAZUH/var/ossec/etc/rules/local_rules.xml"
  incus exec "$WAZUH" -- chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
  if [ "$PLATFORM" = k3s ] && ! incus exec "$WAZUH" -- grep -q "<name>k3s-block</name>" /var/ossec/etc/ossec.conf; then
    incus exec "$WAZUH" -- cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    incus exec "$WAZUH" -- sh -c 'cat >> /var/ossec/etc/ossec.conf' < wazuh/manager-active-response-k3s.xml
    echo "  k3s-block active response added to ossec.conf (backup: ossec.conf.bak)"
  fi
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
  step "Prometheus config + rules -> $PROM:/etc/prometheus/ ($PLATFORM)"
  if [ "$PLATFORM" = k3s ]; then
    # central Prometheus only federates the in-cluster one (which scrapes the pods itself)
    incus file push prometheus/prometheus-central-k3s.yml "$PROM/etc/prometheus/prometheus.yml"
  else
    incus file push prometheus/prometheus.yml "$PROM/etc/prometheus/prometheus.yml"
  fi
  incus file push prometheus/ssle_rules.yml "$PROM/etc/prometheus/ssle_rules.yml"
  # target file of the ssle-scale job: created empty once, then owned by test-scale.sh
  incus exec "$PROM" -- test -f /etc/prometheus/scale-targets.json \
    || incus file push prometheus/scale-targets.json "$PROM/etc/prometheus/scale-targets.json"
  if incus exec "$PROM" -- promtool check config /etc/prometheus/prometheus.yml; then
    # Reload (SIGHUP), not restart: on a reload Prometheus marks the series of removed targets as
    # stale at once; after a restart they stay visible for 5 min (old-IP "up == 0" ghosts).
    incus exec "$PROM" -- sh -c 'systemctl reload prometheus 2>/dev/null || pkill -HUP -x prometheus' \
      && echo "  ok, prometheus reloaded"
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

  # The zone holds the real service IPs, so it is rebuilt from `incus list`. The golden copy is
  # written FIRST: the zone change then fires FIM/rule 100230 (an expected alert for a legitimate
  # change), and restore-dns.sh sees zone == golden copy and does nothing.
  step "dnsmasq config + ssle.local zone (from the current container IPs) -> $DNS"
  zone=""
  if [ "$PLATFORM" = k3s ]; then
    # on k3s the public names point at the node that publishes the NodePorts (ingestion :30001,
    # analytics :30003); registry and storage are ClusterIP-only, so they get no public name
    entries="$K3S_MASTER:ingestion $K3S_MASTER:analytics $MAIL:mail"
  else
    entries="registry:registry ingestion:ingestion storage:storage analytics:analytics $MAIL:mail"
  fi
  for entry in $entries; do
    c=${entry%%:*}; name=${entry##*:}; ip=$(ip_of "$c")
    [ -n "$ip" ] && zone="$zone$(printf '%-15s %s.ssle.local' "$ip" "$name")\n" || echo "  WARNING: $c has no IP, $name.ssle.local left out"
  done
  printf "$zone" > dns/dnsmasq.hosts.clean
  cp dns/dnsmasq.hosts.clean dns/dnsmasq-zones/ssle.hosts
  sed 's/^/    /' dns/dnsmasq.hosts.clean
  incus file push dns/dnsmasq.conf "$DNS/etc/dnsmasq.conf"
  incus file push dns/dnsmasq.hosts.clean "$DNS/etc/dnsmasq.hosts.clean"
  incus file push dns/dnsmasq-zones/ssle.hosts "$DNS/etc/dnsmasq-zones/ssle.hosts"
  if incus exec "$DNS" -- dnsmasq --test && incus exec "$DNS" -- systemctl restart dnsmasq; then
    echo "  ok, dnsmasq restarted"
  else
    fail "dnsmasq does not start (journalctl -u dnsmasq in $DNS)"
  fi
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

*) echo "unknown part '$part' (pin wazuh prometheus mail dns agents)"; ERR=$((ERR + 1)) ;;
esac; done

echo
[ "$ERR" -eq 0 ] && echo "All done." || echo "$ERR step(s) failed."
[ "$ERR" -eq 0 ]
