#!/usr/bin/env bash
# Guide 2, sections 3.1-3.4, applied to SSLE: networking, the privileged "k3s" profile, a two-node
# k3s cluster and the "docker" container that builds the images and runs the private registry.
#
# Each k3s node is one LOCATION of the SSLE naming scheme (labels read by k8s/ssle.yaml):
#     k3s-master -> ssle.dc=dc1     k3s-node1 -> ssle.dc=dc2     (both rack1, region centro, pt)
#
# Run on the Incus host (the Debian/Kali VM) from the repo root. Safe to re-run: every step checks
# whether it is already done. It never deletes networks or containers.
set -euo pipefail
cd "$(dirname "$0")/.."

NET=${NET:-incus-default}
MASTER=${MASTER:-k3s-master}
NODE1=${NODE1:-k3s-node1}
DOCKER=${DOCKER:-docker}
REG=${REG:-docker.incus:5000}
step() { echo; echo "== $1"; }
wait_net() { until incus exec "$1" -- getent hosts deb.debian.org >/dev/null 2>&1; do sleep 2; done; }

# ------------------------------------------------------------------ 3.1 networking
step "3.1 Networking: everything on $NET (10.255.255.0/24)"
if incus network show "$NET" >/dev/null 2>&1; then
  echo "  $NET exists"
else
  cat <<EOF
  Network $NET does not exist. Guide 2 section 3.1 recreates the default network; this script
  will not delete networks for you. Run (it detaches the default profile from incusbr0):
    incus profile device remove default eth0
    incus network delete incusbr0
    incus network create $NET ipv4.address=10.255.255.1/24 ipv4.nat=true ipv6.address=none
    incus profile device add default eth0 nic network=$NET name=eth0
EOF
  exit 1
fi

# ------------------------------------------------------------------ 3.2 privileged profile
step "3.2 Profile k3s (privileged + nesting, needed to run k3s/Docker inside a container)"
incus profile show k3s >/dev/null 2>&1 || incus profile create k3s
incus profile set k3s security.privileged=true security.nesting=true \
  linux.kernel_modules=ip_tables,ip6_tables,nf_nat,overlay,br_netfilter
incus profile set k3s raw.lxc="$(printf 'lxc.apparmor.profile=unconfined\nlxc.cgroup.devices.allow=a *:* rwm\nlxc.cap.drop=')"
incus profile device show k3s | grep -q '^kmsg:' || incus profile device add k3s kmsg unix-char source=/dev/kmsg path=/dev/kmsg
incus profile device show k3s | grep -q '^eth0:' || incus profile device add k3s eth0 nic network="$NET" name=eth0
incus profile device show k3s | grep -q '^root:' || incus profile device add k3s root disk path=/ pool=default
echo "  ok (note for the report: privileged containers widen the attack surface of the host)"

# ------------------------------------------------------------------ 3.3 k3s cluster
step "3.3 Kernel options for k3s (on this VM)"
sudo sysctl -q -w vm.overcommit_memory=1 kernel.panic=10 kernel.panic_on_oops=1
echo "  ok"

# The nodes pull the SSLE images from the private registry over plain HTTP (lab only).
REGISTRIES="mirrors:
  \"$REG\":
    endpoint:
      - \"http://$REG\""

# node_up <container> <dc> <rack> [k3s join env]: launch, prepare and install k3s with location labels
node_up() {
  local c=$1 dc=$2 rack=$3 join=${4:-}
  incus info "$c" >/dev/null 2>&1 || incus launch images:debian/trixie "$c" --profile k3s
  wait_net "$c"
  incus exec "$c" --env DEBIAN_FRONTEND=noninteractive -- sh -c \
    'command -v curl >/dev/null && command -v python3 >/dev/null && command -v iptables >/dev/null \
     || (apt-get update -qq && apt-get install -y -qq curl python3 iptables ca-certificates >/dev/null)'
  incus exec "$c" -- mkdir -p /etc/rancher/k3s /var/log/ssle
  printf '%s\n' "$REGISTRIES" | incus exec "$c" -- sh -c 'cat > /etc/rancher/k3s/registries.yaml'
  local labels="--node-label ssle.dc=$dc --node-label ssle.rack=$rack"
  if incus exec "$c" -- test -x /usr/local/bin/k3s; then
    echo "  $c: k3s already installed"
  elif [ -z "$join" ]; then
    incus exec "$c" -- sh -c "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --write-kubeconfig-mode 644 $labels' sh -"
  else
    incus exec "$c" -- sh -c "curl -sfL https://get.k3s.io | $join INSTALL_K3S_EXEC='agent $labels' sh -"
  fi
}

step "3.3 Master node $MASTER (dc1)"
node_up "$MASTER" dc1 rack1
until incus exec "$MASTER" -- k3s kubectl get nodes >/dev/null 2>&1; do sleep 3; done
TOKEN=$(incus exec "$MASTER" -- cat /var/lib/rancher/k3s/server/node-token)

step "3.3 Worker node $NODE1 (dc2)"
node_up "$NODE1" dc2 rack1 "K3S_URL=https://$MASTER.incus:6443 K3S_TOKEN=$TOKEN"
for i in $(seq 1 60); do
  incus exec "$MASTER" -- k3s kubectl get node "$NODE1" >/dev/null 2>&1 && break; sleep 3
done

# registries.yaml is only read when k3s starts
incus exec "$MASTER" -- systemctl restart k3s
incus exec "$NODE1" -- systemctl restart k3s-agent

# ------------------------------------------------------------------ 3.4 docker
step "3.4 Docker container $DOCKER (builds the images, hosts the private registry)"
incus info "$DOCKER" >/dev/null 2>&1 || incus launch images:debian/trixie "$DOCKER" --profile k3s
wait_net "$DOCKER"
if ! incus exec "$DOCKER" -- sh -c 'command -v docker >/dev/null'; then
  incus exec "$DOCKER" --env DEBIAN_FRONTEND=noninteractive -- sh -c '
    apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq && apt-get install -y -qq docker-ce docker-ce-cli >/dev/null'
fi
incus exec "$DOCKER" -- docker run --rm hello-world >/dev/null && echo "  docker works"

# ------------------------------------------------------------------ 4. checking
step "4. Checking"
incus list "^($MASTER|$NODE1|$DOCKER)\$"
for i in $(seq 1 40); do
  [ "$(incus exec "$MASTER" -- k3s kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready')" -ge 2 ] && break; sleep 3
done
incus exec "$MASTER" -- k3s kubectl get nodes -L ssle.dc,ssle.rack
echo
echo "Next: ./apply-configs.sh pin   (fix the IPs of the new containers)"
echo "      ./k3s/deploy.sh           (section 5.2: build, push and deploy SSLE)"
