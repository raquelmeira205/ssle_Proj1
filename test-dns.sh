#!/usr/bin/env bash
set -u
DNS_CONTAINER=${DNS_CONTAINER:-DNS-server-container}
WAZUH_CONTAINER=${WAZUH_CONTAINER:-wazuh-container}
DOMAIN=${DOMAIN:-ingestion.ssle.local}
HIJACK_IP=${HIJACK_IP:-10.255.255.42}

PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

IP=$(incus list "$DNS_CONTAINER" -c4 --format csv 2>/dev/null | cut -d' ' -f1)
[ -n "$IP" ] || { echo "Could not find the IP of container '$DNS_CONTAINER'"; exit 1; }
echo "DNS Server: $IP"

query_dns() {
  dig +short "@$IP" "$DOMAIN" 2>/dev/null
}

echo "== 1. Baseline DNS Resolution"
baseline_ip=$(query_dns)
if [ -n "$baseline_ip" ]; then
  ok "baseline resolution for $DOMAIN succeeds ($baseline_ip)"
else
  bad "baseline resolution failed for $DOMAIN"
  echo; echo "Result: $PASS passed, $FAIL failed"; exit 1
fi

echo "== 2. Wait for Wazuh Rule 100230 & Active Response to trigger"
incus exec "$DNS_CONTAINER" -- sh -c "echo '$HIJACK_IP $DOMAIN' > /etc/dnsmasq-zones/ssle.hosts"
incus exec "$DNS_CONTAINER" -- systemctl restart dnsmasq 2>/dev/null

found=""
for i in $(seq 1 15); do
  if incus exec "$WAZUH_CONTAINER" -- grep -q "Rule: 100230" /var/ossec/logs/alerts/alerts.log 2>/dev/null; then
    found=1
    break
  fi
  sleep 1
done

if [ -n "$found" ]; then
  ok "rule 100230 (DNS Hijacking) fired"
else
  bad "rule 100230 did not fire within 15s"
fi

echo "== 3. Check the active response ran on $DNS_CONTAINER"
sleep 2
if incus exec "$DNS_CONTAINER" -- journalctl -t ssle-dns-ar --since "30 seconds ago" --quiet | grep -q "Restored"; then
  ok "restore-dns active response ran on $DNS_CONTAINER"
else
  bad "no active response execution log found in journal"
fi

echo "== 4. Confirm DNS resolution automatically returned to baseline ($baseline_ip)"
restored_ip=""
for i in $(seq 1 10); do
  restored_ip=$(query_dns)
  [ "$restored_ip" = "$baseline_ip" ] && break
  sleep 1
done

if [ "$restored_ip" = "$baseline_ip" ]; then
  ok "DNS resolution restored to baseline ($baseline_ip)"
else
  bad "DNS resolution still incorrect (resolved to '$restored_ip', expected '$baseline_ip')"
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
