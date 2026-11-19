#!/usr/bin/env bash
# Guide 2, section 5.2, applied to SSLE: package the services as Docker images and deploy them in
# the k3s cluster created by k3s/setup-cluster.sh, together with the in-cluster Prometheus.
#
#   1. copy the sources into the "docker" container, build one image per service and push them to
#      the private registry docker.incus:5000 (build-and-push.sh), tagged with the git commit so
#      the nodes always pull the new code (a fixed tag + IfNotPresent would keep the old image)
#   2. apply k8s/ssle.yaml (services, one Deployment per location)
#   3. load prometheus-k8s.yml + ssle_rules.yml into a ConfigMap and apply k8s/monitoring.yaml
#   4. wait for every rollout and show where each pod runs
#
# Run on the Incus host from the repo root:   ./k3s/deploy.sh      (TAG=... to choose the tag)
set -euo pipefail
cd "$(dirname "$0")/.."
MASTER=${MASTER:-k3s-master}
DOCKER=${DOCKER:-docker}
TAG=${TAG:-$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}
[ -z "$(git status --porcelain -- common.py registry storage ingestion analytics sensor Dockerfile 2>/dev/null)" ] \
  || TAG="$TAG-dirty-$(date +%H%M%S)"        # uncommitted code: never reuse a tag
k() { incus exec "$MASTER" -- k3s kubectl "$@"; }
step() { echo; echo "== $1"; }
# retry <tries> <cmd...>: a busy VM can drop the connection to the Incus daemon
# ("write unix @->/var/lib/incus/unix.socket: i/o timeout"); try again instead of aborting
retry() {
  local n=$1 i; shift
  for i in $(seq 1 "$n"); do
    "$@" && return 0
    [ "$i" -lt "$n" ] && { echo "  (attempt $i failed, retrying in 10 s)"; sleep 10; }
  done
  return 1
}
# pushed <svc>: is the image with this tag already in the private registry?
pushed() {
  incus exec "$DOCKER" -- curl -sf "http://$REG/v2/ssle/$1/tags/list" 2>/dev/null | grep -q "\"$TAG\""
}
REG=${REG:-docker.incus:5000}

step "1. Build and push the images (tag $TAG) in $DOCKER"
retry 3 incus exec "$DOCKER" -- sh -c 'rm -rf /root/ssle && mkdir -p /root/ssle'
tar -cf - Dockerfile requirements.txt common.py build-and-push.sh registry storage ingestion analytics sensor \
  | incus exec "$DOCKER" -- tar -xf - -C /root/ssle
# one image per `incus exec` (short connections), skipping images already pushed: re-running
# after an interruption resumes where it stopped
for svc in registry storage ingestion analytics sensor; do
  if pushed "$svc"; then
    echo "  $svc:$TAG already in $REG, skipped"
  else
    retry 3 incus exec "$DOCKER" -- sh -c "cd /root/ssle && TAG=$TAG SERVICES=$svc bash build-and-push.sh" \
      || { echo "building $svc failed 3 times; check the VM's free memory (free -h) and re-run"; exit 1; }
  fi
done

step "2. SSLE services (k8s/ssle.yaml)"
apply_services() { sed "s/__TAG__/$TAG/g" k8s/ssle.yaml | k apply -f -; }
retry 3 apply_services

step "3. In-cluster Prometheus (k8s/monitoring.yaml)"
HASH=$(cat k8s/prometheus-k8s.yml prometheus/ssle_rules.yml | sha256sum | cut -c1-12)
# The config files go to a root-only folder through stdin. Pushing them into /tmp with
# `incus file push` failed on the second run: the first push kept the host user's ownership, and
# /tmp (sticky, protected_regular) refuses to let even root overwrite another user's file there.
DIR=/root/ssle-k8s
apply_monitoring() {
  incus exec "$MASTER" -- mkdir -p "$DIR" &&
  incus exec "$MASTER" -- sh -c "cat > $DIR/prometheus.yml" < k8s/prometheus-k8s.yml &&
  incus exec "$MASTER" -- sh -c "cat > $DIR/ssle_rules.yml" < prometheus/ssle_rules.yml &&
  k -n ssle create configmap prometheus-config \
    --from-file=prometheus.yml=$DIR/prometheus.yml --from-file=ssle_rules.yml=$DIR/ssle_rules.yml \
    --dry-run=client -o yaml | k apply -f - &&
  sed "s/__CONFIG_HASH__/$HASH/" k8s/monitoring.yaml | k apply -f -
}
retry 3 apply_monitoring

step "4. Rollouts"
for d in $(retry 3 k -n ssle get deploy -o name); do
  retry 2 k -n ssle rollout status "$d" --timeout=180s
done
k -n ssle get pods -o wide
echo
echo "Published: ingestion  http://<any node>:30001   analytics  http://<any node>:30003"
echo "           prometheus http://$MASTER.incus:30090 (in-cluster)"
echo "Next: ./k3s/install-wazuh-node-agents.sh, then PLATFORM=k3s ./apply-configs.sh, then"
echo "      PLATFORM=k3s ./test-k3s.sh and the threat tests with PLATFORM=k3s"
