#!/usr/bin/env bash
# Guide 2, section 5.1 - one Incus container per service.
# Run on the Debian VM (the Incus host), from the folder that contains common.py and the service folders.
set -euo pipefail

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
    'apt-get update -qq && apt-get install -y -qq python3-flask python3-requests'

  incus exec "$name" -- mkdir -p /opt/app /var/lib/app
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

[Install]
WantedBy=multi-user.target
EOF

  incus exec "$name" -- systemctl daemon-reload
  incus exec "$name" -- systemctl enable --now ssle
done

echo; incus list
