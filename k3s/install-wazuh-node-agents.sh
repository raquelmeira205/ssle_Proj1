#!/usr/bin/env bash
# One Wazuh agent per k3s NODE (not per pod: a sidecar agent per pod would enrol a new agent on
# every restart). Each agent:
#   - is named after the node's place in the hierarchy, e.g. k3s-node-01.k3s-node1.rack1.dc2.centro.pt
#     (each log line still carries the full ID of the pod that wrote it, in data.id)
#   - reads the JSON access log of every pod on that node: /var/log/ssle/<pod>/access.log
#     (hostPath mount in k8s/ssle.yaml)
#   - has the k3s-block active response (wazuh/active-response/k3s-block.py)
#
# Run on the Incus host from the repo root, after k3s/deploy.sh. Safe to re-run.
#   WAZUH_CONTAINER=wazuh-container  NODES="k3s-master k3s-node1"  COUNTRY=pt REGION=centro
set -euo pipefail
cd "$(dirname "$0")/.."
WAZUH_CONTAINER=${WAZUH_CONTAINER:-wazuh-container}
MASTER=${MASTER:-k3s-master}
NODES=${NODES:-"k3s-master k3s-node1"}
COUNTRY=${COUNTRY:-pt}
REGION=${REGION:-centro}
OSSEC=/var/ossec/etc/ossec.conf
LOGS='/var/log/ssle/*/access.log'
part() { echo "$1" | tr 'A-Z.' 'a-z-'; }

WAZUH_IP=${WAZUH_IP:-$(incus list "^$WAZUH_CONTAINER\$" -c4 --format csv | grep -oE '[0-9]+(\.[0-9]+){3} \(eth0\)' | head -1 | cut -d' ' -f1)}
[ -n "$WAZUH_IP" ] || { echo "Could not find the IP of $WAZUH_CONTAINER (set WAZUH_IP)"; exit 1; }
VER=$(incus exec "$WAZUH_CONTAINER" -- /var/ossec/bin/wazuh-control info -v 2>/dev/null \
      | sed -n 's/^WAZUH_VERSION="v\(.*\)"/\1/p' | head -1)
PIN=${VER:+=${VER}-1}
echo "Wazuh manager: $WAZUH_IP (version ${VER:-unknown})"

for node in $NODES; do
  dc=$(incus exec "$MASTER" -- k3s kubectl get node "$node" -o jsonpath='{.metadata.labels.ssle\.dc}')
  rack=$(incus exec "$MASTER" -- k3s kubectl get node "$node" -o jsonpath='{.metadata.labels.ssle\.rack}')
  agent="k3s-node-01.$(part "$node").$(part "${rack:-rack0}").$(part "${dc:-dc0}").$(part "$REGION").$(part "$COUNTRY")"
  echo "=== $node -> agent '$agent'"

  if ! incus exec "$node" -- test -x /var/ossec/bin/wazuh-control; then
    incus exec "$node" --env DEBIAN_FRONTEND=noninteractive -- sh -c '
      apt-get update -qq && apt-get install -y -qq curl gpg ca-certificates python3 iptables >/dev/null
      curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
      chmod 644 /usr/share/keyrings/wazuh.gpg
      echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
      apt-get update -qq'
    incus exec "$node" --env DEBIAN_FRONTEND=noninteractive \
      --env WAZUH_MANAGER="$WAZUH_IP" --env WAZUH_AGENT_NAME="$agent" \
      -- apt-get install -y -qq "wazuh-agent${PIN}"
  else
    echo "    agent already installed"
  fi

  # read every pod's access log on this node (one extra <ossec_config> block, added once)
  incus exec "$node" -- mkdir -p /var/log/ssle
  incus exec "$node" -- sh -c "grep -q '/var/log/ssle/\*/access.log' $OSSEC || printf '\n<ossec_config>\n  <localfile>\n    <log_format>json</log_format>\n    <location>$LOGS</location>\n  </localfile>\n</ossec_config>\n' >> $OSSEC"

  # active response that works for NodePort traffic
  incus file push wazuh/active-response/k3s-block.py "$node/var/ossec/active-response/bin/k3s-block"
  incus exec "$node" -- chown root:wazuh /var/ossec/active-response/bin/k3s-block
  incus exec "$node" -- chmod 750 /var/ossec/active-response/bin/k3s-block

  incus exec "$node" -- systemctl daemon-reload
  incus exec "$node" -- systemctl enable -q wazuh-agent
  incus exec "$node" -- systemctl restart wazuh-agent
done

echo
echo "Agents known to the manager (give them ~30 s to connect):"
sleep 30
incus exec "$WAZUH_CONTAINER" -- /var/ossec/bin/agent_control -l
echo
echo "Next: PLATFORM=k3s ./apply-configs.sh wazuh   (k3s-block binding + pod network in the service list)"
