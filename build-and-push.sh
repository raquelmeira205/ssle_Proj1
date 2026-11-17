#!/usr/bin/env bash
# Guide 2, section 5.2 - build the Docker images and push them to a private registry.
# Run INSIDE the "docker" Incus container, from the folder that contains the Dockerfile.
set -euo pipefail
REG=docker.incus:5000
TAG=1.0

# 1) private registry (restarts automatically)
docker inspect registry >/dev/null 2>&1 || \
  docker run -d --restart=always --name registry -p 5000:5000 registry:2

# 2) allow pushing to it over plain HTTP (lab only - use TLS in production)
if ! grep -qs "$REG" /etc/docker/daemon.json; then
  echo "{\"insecure-registries\": [\"$REG\"]}" > /etc/docker/daemon.json
  systemctl restart docker
  sleep 3
fi

# 3) build + push one image per service
for svc in registry storage ingestion analytics sensor; do
  case $svc in
    registry) port=5050 ;; storage) port=5002 ;; ingestion) port=5001 ;;
    analytics) port=5003 ;; *) port=5000 ;;
  esac
  docker build --build-arg SERVICE=$svc --build-arg PORT=$port -t $REG/ssle/$svc:$TAG .
  docker push $REG/ssle/$svc:$TAG
done

curl -s http://$REG/v2/_catalog; echo
