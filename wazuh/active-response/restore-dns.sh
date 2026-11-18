#!/bin/sh
# Only act if the zone differs from the golden copy, otherwise our own restore re-triggers the rule.
cmp -s /etc/dnsmasq.hosts.clean /etc/dnsmasq-zones/ssle.hosts && exit 0
cp /etc/dnsmasq.hosts.clean /etc/dnsmasq-zones/ssle.hosts
systemctl restart dnsmasq
logger -t ssle-dns-ar "Restored /etc/dnsmasq-zones/ssle.hosts after hijacking alert"
