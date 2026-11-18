#!/usr/bin/env bash
# Copy the lab configuration that lives only inside the Incus containers into this repo,
# so the deployment can be reproduced from git. Run on the Incus host (the Kali VM) from
# the repo root, then review with `git diff` / `git status` and commit.
#
# The Wazuh manager rules and active-response blocks are NOT pulled: they are kept by hand in
# wazuh/ssle-rules.xml and wazuh/manager-active-response.xml (see the bottom of this file to
# push them to the manager instead).
#
# Container names can be overridden: WAZUH=... PROM=... MAIL=... DNS=...
set -u
WAZUH=${WAZUH:-wazuh-container}
PROM=${PROM:-prometheus-container}
MAIL=${MAIL:-mail-container}
DNS=${DNS:-DNS-server-container}

got=0; missing=0
# pull <container> <path inside container> <destination in repo>
pull() {
  mkdir -p "$(dirname "$3")"
  if incus exec "$1" -- test -f "$2" 2>/dev/null && incus exec "$1" -- cat "$2" > "$3"; then
    echo "  ok       $1:$2 -> $3"; got=$((got + 1))
  else
    rm -f "$3"; echo "  missing  $1:$2"; missing=$((missing + 1))
  fi
}
# pull every regular file of a directory (non-recursive)
pull_dir() {
  for f in $(incus exec "$1" -- find "$2" -maxdepth 1 -type f 2>/dev/null); do
    pull "$1" "$f" "$3/$(basename "$f")"
  done
}

echo "== Prometheus ($PROM)"
pull "$PROM" /etc/prometheus/prometheus.yml prometheus/prometheus.yml
pull "$PROM" /etc/prometheus/ssle_rules.yml prometheus/ssle_rules.yml
pull "$PROM" /etc/prometheus/alertmanager.yml prometheus/alertmanager.yml
pull "$PROM" /etc/alertmanager/alertmanager.yml prometheus/alertmanager.yml

echo "== DNS server ($DNS)"
pull "$DNS" /etc/dnsmasq.conf dns/dnsmasq.conf
pull_dir "$DNS" /etc/dnsmasq.d dns/dnsmasq.d
pull_dir "$DNS" /etc/dnsmasq-zones dns/dnsmasq-zones
pull "$DNS" /etc/dnsmasq.hosts.clean dns/dnsmasq.hosts.clean
pull "$DNS" /var/ossec/active-response/bin/restore-dns.sh wazuh/active-response/restore-dns.sh
pull "$DNS" /var/ossec/etc/ossec.conf wazuh/agents/dns-ossec.conf

echo "== Mail server ($MAIL)"
pull "$MAIL" /etc/postfix/main.cf mail/postfix-main.cf
pull "$MAIL" /etc/postfix/master.cf mail/postfix-master.cf
pull "$MAIL" /etc/default/spamassassin mail/spamassassin-default
pull "$MAIL" /etc/spamassassin/local.cf mail/spamassassin-local.cf
pull "$MAIL" /var/ossec/etc/ossec.conf wazuh/agents/mail-ossec.conf

echo "== Wazuh agent on a service container (localfile for the JSON access log)"
pull analytics /var/ossec/etc/ossec.conf wazuh/agents/service-ossec.conf

echo
echo "Pulled $got files, $missing not found (not found is fine if you never created that file)."
echo "Check wazuh/agents/*.conf for secrets before committing (they should only hold the manager IP)."

# To push the repo's (fixed) manager rules back to the VM:
#   incus file push wazuh/ssle-rules.xml $WAZUH/var/ossec/etc/rules/local_rules.xml
#   incus exec $WAZUH -- chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
#   incus exec $WAZUH -- /var/ossec/bin/wazuh-analysisd -t && incus exec $WAZUH -- systemctl restart wazuh-manager
