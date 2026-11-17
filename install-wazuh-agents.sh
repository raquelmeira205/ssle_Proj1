#!/usr/bin/env bash
# Install a Wazuh agent in every SSLE Incus container, named after the service's hierarchical ID
# (e.g. storage-service-01.node1.rack1.dc1.centro.pt), and make it read the JSON access log.
# Run on the Incus host (the Kali/Debian VM) AFTER deploy-incus.sh.
#
#   WAZUH_CONTAINER=wazuh-container   Incus container running the Wazuh manager
#   WAZUH_IP=<ip>                     override the manager IP (default: taken from `incus list`)
#
# COUNTRY / REGION / DC / RACK / NODE must be the same values you used for deploy-incus.sh.
# Safe to re-run: containers that already have the agent are not reinstalled.
set -euo pipefail

WAZUH_CONTAINER=${WAZUH_CONTAINER:-wazuh-container}
COUNTRY=${COUNTRY:-pt}
REGION=${REGION:-centro}
DC=${DC:-dc1}
RACK=${RACK:-rack1}
NODE=${NODE:-$(hostname)}
INSTANCE=01
ACCESS_LOG=/var/log/ssle/access.log
OSSEC=/var/ossec/etc/ossec.conf

# container:service name used in the hierarchical ID
SERVICES=(
  "registry:registry-service"
  "storage:storage-service"
  "ingestion:ingestion-service"
  "analytics:analytics-service"
  "sensor:temperature-sensor"
)

# same normalisation as common.py: lowercase, dots become dashes
part() { echo "$1" | tr 'A-Z.' 'a-z-'; }

WAZUH_IP=${WAZUH_IP:-$(incus list "$WAZUH_CONTAINER" -c4 --format csv | head -1 | cut -d' ' -f1)}
[ -n "$WAZUH_IP" ] || { echo "Could not find the IP of $WAZUH_CONTAINER (set WAZUH_IP)"; exit 1; }

# An agent must not be newer than its manager, so pin the agent to the manager's version.
VER=$(incus exec "$WAZUH_CONTAINER" -- /var/ossec/bin/wazuh-control info -v 2>/dev/null \
      | sed -n 's/^WAZUH_VERSION="v\(.*\)"/\1/p' | head -1)
if [ -n "$VER" ]; then PIN="=${VER}-1"; else PIN=""; echo "WARNING: manager version not found, installing the latest agent"; fi
echo "Wazuh manager: $WAZUH_IP (version ${VER:-unknown})"

for entry in "${SERVICES[@]}"; do
  IFS=: read -r name svc <<<"$entry"
  agent="${svc}-${INSTANCE}.$(part "$NODE").$(part "$RACK").$(part "$DC").$(part "$REGION").$(part "$COUNTRY")"
  echo "=== $name -> agent '$agent'"

  if ! incus exec "$name" -- test -x /var/ossec/bin/wazuh-control; then
    incus exec "$name" --env DEBIAN_FRONTEND=noninteractive -- sh -c '
      apt-get update -qq && apt-get install -y -qq curl gpg ca-certificates
      curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
      chmod 644 /usr/share/keyrings/wazuh.gpg
      echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
      apt-get update -qq'
    incus exec "$name" --env DEBIAN_FRONTEND=noninteractive \
      --env WAZUH_MANAGER="$WAZUH_IP" --env WAZUH_AGENT_NAME="$agent" \
      -- apt-get install -y -qq "wazuh-agent${PIN}"
  else
    echo "    agent already installed"
  fi

  # the sensor has no HTTP API, so it has no access log to read
  if [ "$name" != "sensor" ]; then
    incus exec "$name" -- sh -c "grep -q '$ACCESS_LOG' $OSSEC || sed -i 's#</ossec_config>#  <localfile>\n    <log_format>json</log_format>\n    <location>$ACCESS_LOG</location>\n  </localfile>\n</ossec_config>#' $OSSEC"
  fi

  incus exec "$name" -- systemctl daemon-reload
  incus exec "$name" -- systemctl enable wazuh-agent
  incus exec "$name" -- systemctl restart wazuh-agent
done

echo
echo "Agents known to the manager (give them ~30 s to connect):"
sleep 30
incus exec "$WAZUH_CONTAINER" -- /var/ossec/bin/agent_control -l
