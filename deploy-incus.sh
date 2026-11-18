#!/usr/bin/env bash
# Guide 2, section 5.1 - one Incus container per service.
# Run on the Debian VM (the Incus host), from the folder that contains common.py and the service folders.
# Location of these containers (country > region > dc > rack > node). Override from the shell, e.g.
#   DC=dc2 RACK=rack3 ./deploy-incus.sh
# Safe to re-run: it pushes the latest code and RESTARTS each service.
set -euo pipefail

COUNTRY=${COUNTRY:-pt}
REGION=${REGION:-centro}
DC=${DC:-dc1}
RACK=${RACK:-rack1}
NODE=${NODE:-$(hostname)}

# name:port:entry-script   (the sensor has no port)
SERVICES=(
  "registry:5050:app.py"
  "storage:5002:app.py"
  "ingestion:5001:app.py"
  "analytics:5003:app.py"
  "sensor:0:sensor.py"
)

for entry in "${SERVICES[@]}"; do
  IFS=: read -r name port script <<<"$entry"
  echo "=== $name"

  incus info "$name" >/dev/null 2>&1 || incus launch images:debian/trixie "$name"
  until incus exec "$name" -- getent hosts deb.debian.org >/dev/null 2>&1; do sleep 2; done

  incus exec "$name" --env DEBIAN_FRONTEND=noninteractive -- sh -c \
    'apt-get update -qq && apt-get install -y -qq python3-flask python3-requests python3-prometheus-client'

  incus exec "$name" -- mkdir -p /opt/app /var/lib/app /var/log/ssle
  incus file push common.py "$name/opt/app/common.py"
  incus file push "$name/$script" "$name/opt/app/$script"

  incus exec "$name" -- tee /etc/systemd/system/ssle.service >/dev/null <<EOF
[Unit]
Description=SSLE $name
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/app
ExecStart=/usr/bin/python3 /opt/app/$script
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/app
Environment=REGISTRY_URL=http://registry.incus:5050
Environment=SERVICE_URL=http://$name.incus:$port
Environment=DB_PATH=/var/lib/app/temp_data.db
Environment=ACCESS_LOG=/var/log/ssle/access.log
Environment=COUNTRY=$COUNTRY
Environment=REGION=$REGION
Environment=DC=$DC
Environment=RACK=$RACK
Environment=NODE=$NODE
Environment=INSTANCE=01

[Install]
WantedBy=multi-user.target
EOF

  incus exec "$name" -- systemctl daemon-reload
  incus exec "$name" -- systemctl enable ssle
  incus exec "$name" -- systemctl restart ssle     # restart (not just start) so new code is picked up
done

echo; incus list
