# SSLE on Docker + Kubernetes (Practical Guide 2, applied to the project)

This folder follows the structure of *Practical Guide 2 – Telecom and Cloud Operator
Architectures*. Each section of the guide becomes a script or file of the project, and the security
and monitoring of Project 1 are kept working when the services run as pods.

| Guide section | In this project |
|---|---|
| 3.1 Networking | `setup-cluster.sh`: checks for `incus-default` (10.255.255.0/24); never deletes networks |
| 3.2 Privileged profile | `setup-cluster.sh`: `k3s` profile (privileged, nesting, kernel modules, kmsg) |
| 3.3 Kubernetes cluster | `setup-cluster.sh`: `k3s-master` + `k3s-node1`, **each node = one location** |
| 3.4 Docker | `setup-cluster.sh`: `docker` container (builds images, private registry `docker.incus:5000`) |
| 4. Checking | `../test-k3s.sh` |
| 5.1 Apps as Incus containers | `../deploy-incus.sh` (the Project 1 deployment) |
| 5.2 Apps as Docker images in Kubernetes | `deploy.sh`, `../Dockerfile`, `../build-and-push.sh`, `../k8s/ssle.yaml` |
| "Next class: monitoring" | `../k8s/monitoring.yaml`, `../k8s/prometheus-k8s.yml`, central federation |
| Project 1: SIEM | `install-wazuh-node-agents.sh`, `../wazuh/active-response/k3s-block.py` |

## 1. Architecture

```
Incus host (Kali/Debian VM), network incus-default 10.255.255.0/24
├── k3s-master  (dc1)  registry, storage, ingestion-dc1, analytics-dc1, sensor-dc1, prometheus
│                      Wazuh agent "k3s-node-01.k3s-master.rack1.dc1.centro.pt"
├── k3s-node1   (dc2)  ingestion-dc2, analytics-dc2, sensor-dc2
│                      Wazuh agent "k3s-node-01.k3s-node1.rack1.dc2.centro.pt"
├── docker             docker build + private registry :5000
├── wazuh-container    Wazuh manager (unchanged)
├── prometheus-container  central Prometheus: federates the in-cluster one
└── mail-container, DNS-server-container   (unchanged, outside the cluster)
```

## 3. Creating the cluster (guide 3.1–3.4)

```bash
./k3s/setup-cluster.sh
./apply-configs.sh pin          # make the new containers' IPs permanent
```

What the script adds to the guide:
- **Locations as node labels.** k3s is installed with `--node-label ssle.dc=dc1|dc2` and
  `ssle.rack=rack1`. The manifest places each location's pods with a `nodeSelector`, so "dc2" is a
  real, different node.
- **Private registry over HTTP.** `/etc/rancher/k3s/registries.yaml` on each node mirrors
  `docker.incus:5000` with an `http://` endpoint. Without it the nodes refuse the plain-HTTP
  registry.
- `python3` and `iptables` on the nodes, for the Wazuh active response and the benchmarks.

## 4. Checking

```bash
./test-k3s.sh
```
It checks the nodes, workloads, registry entries per pod, data flow per location, client-IP
preservation, monitoring, the SIEM pipeline and self-healing. Evidence goes to
`evidence/k3s/cluster/`.

## 5. Packaging the applications

### 5.1 As Incus containers
`../deploy-incus.sh`: one container per service with a systemd unit (the Project 1 setup).

### 5.2 As Docker images deployed in Kubernetes

```bash
./k3s/deploy.sh
```
1. Copies the sources into the `docker` container and runs `build-and-push.sh`. That builds one
   image per service from the single `Dockerfile` and pushes it to `docker.incus:5000`. The tag is
   the **git commit**. A fixed tag with `imagePullPolicy: IfNotPresent` would keep running the old
   image after a rebuild.
2. Applies `k8s/ssle.yaml` with that tag.
3. Loads the Prometheus config and `ssle_rules.yml` into a ConfigMap and applies
   `k8s/monitoring.yaml`.
4. Waits for every rollout.

Manifest decisions (`k8s/ssle.yaml`):

| Decision | Why |
|---|---|
| `SERVICE_URL=http://$(POD_IP):port` (downward API) | Each pod registers **itself**. With the Service name, all replicas had the same URL and collapsed into a single registry entry. |
| `NODE=spec.nodeName`, `INSTANCE=metadata.name`, `DC` per Deployment | Same hierarchical ID as on Incus: the k3s node is the physical level, the pod the logical one, e.g. `ingestion-service-ingestion-dc2-<hash>.k3s-node1.rack1.dc2.centro.pt` |
| one Deployment per location (`ingestion-dc1`, `ingestion-dc2`, …) | A pod can't read its node's labels, so the location is fixed per Deployment and enforced with `nodeSelector` |
| access log on a `hostPath` (`/var/log/ssle/<pod>/access.log`, `subPathExpr`) | Read by **one Wazuh agent per node**. stdout would get the container runtime's prefix and break the JSON decoder. |
| ingestion/analytics: NodePort 30001/30003, `externalTrafficPolicy: Local` | Keeps the **client's real IP**, which Wazuh needs to block. Each node serves only its own location. |
| registry/storage: `ClusterIP` | Internal only. The registry has no authentication, so it must never be exposed. |
| storage: 1 replica, `Recreate`, PVC | SQLite is a single writer |
| requests/limits, readiness + liveness probes, no privilege escalation, all capabilities dropped | Self-healing, and a flood can't take the whole node (DoS containment) |

## 6. Monitoring (two levels)

- **Inside the cluster** (`k8s/monitoring.yaml`): Prometheus discovers the pods through the
  Kubernetes API (`kubernetes_sd_configs`, role pod, read-only `Role`). It scrapes pods annotated
  `prometheus.io/scrape`. Relabelling sets `job=ssle-<app>`, the **same job names as on Incus**, so
  every alert, root-cause and per-location rule of `prometheus/ssle_rules.yml` works unchanged.
  Published on NodePort 30090.
- **Central** (`prometheus-container`, `prometheus/prometheus-central-k3s.yml`): federates only
  `location:*` and `ALERTS` from the cluster. The measured design of the bonus: traffic between the
  sites grows with the number of locations, not with the number of pods.
- The root-cause rules use `or vector(0)`. On k3s a stopped storage pod disappears from discovery,
  so it has no `up` series at all, instead of `up == 0`.

## 7. Security (Wazuh)

```bash
./k3s/install-wazuh-node-agents.sh
PLATFORM=k3s ./apply-configs.sh
```
- **One agent per node**, named after the node's place in the hierarchy. It reads
  `/var/log/ssle/*/access.log`. Each event still carries the pod's full ID in `data.id`, so you can
  still tell which pod and location raised it.
- **`k3s-block` active response.** The stock `firewall-drop` adds a DROP to `INPUT`, but NodePort
  traffic is DNAT-ed by kube-proxy and *forwarded* to the pod, so it never crosses `INPUT`.
  `k3s-block` inserts `iptables -t raw -I PREROUTING -s <ip> -j DROP`, which runs before kube-proxy.
  It implements the Wazuh 4.x active-response protocol (check_keys, add, delete after 60 s).
  `apply-configs.sh` binds it to rule 100210 on the manager.
- **Internal traffic.** Pods call each other with pod IPs (10.42.0.0/16) that change on every
  restart, so they can't be listed one by one in the `ssle-services` CDB list (a `10.42.` prefix
  key never matched, and `<srcip>!10.42.0.0/16</srcip>` behaved as a positive match). Rule 100209,
  a level-0 child of 100200 for `srcip` 10.42.0.0/16, ends successful pod-to-pod requests before
  100210 counts them, so the services never block their own calls. That fixes the self-inflicted
  outage found on Incus. 100209 is defined after 100201, so internal 5xx errors still reach the
  root-cause correlation.
- **DNS and mail** stay outside the cluster. `PLATFORM=k3s ./apply-configs.sh dns` points
  `ingestion.ssle.local` and `analytics.ssle.local` at the node publishing the NodePorts. Registry
  and storage get no public name.

## 8. Running the tests on k3s

The tests share a platform layer (`test-lib.sh`: `public_url`, `internal_url`, `near`, `agent_box`,
`svc_stop`, …). The same scripts run on both platforms:

```bash
./test-k3s.sh                       # functional check of the cluster
PLATFORM=k3s ./test-ddos.sh         # flood on the dc1 NodePort, k3s-block on k3s-master
PLATFORM=k3s ./test-rootcause.sh    # storage Deployment scaled to 0
PLATFORM=k3s ./test-scale.sh        # dc1 vs dc1+dc2 through each node's NodePort
PLATFORM=k3s ./test-dns.sh          # zone now points at the NodePort node
```
Evidence goes to `evidence/k3s/<test>/`, so the Incus evidence is never overwritten.

To go back to monitoring the Incus deployment from the central Prometheus:
`./apply-configs.sh prometheus dns`.

## 9. Limitations and report points

- The `k3s` profile is **privileged** with AppArmor unconfined. A container escape is a host
  compromise, so this belongs in the attack-surface analysis.
- The registry and Kubernetes Services both load-balance. Kubernetes handles the Service traffic,
  and the registry remains for location-aware lookups.
- `k3s-block` blocks on the node that saw the flood. With `externalTrafficPolicy: Local` that's the
  node the attacker uses. An attacker using both nodes is blocked separately on each.
- Rule 100209 exempts the whole pod network, so a **compromised pod** flooding another one isn't
  blocked by Wazuh. Only Prometheus would see it.
- On k3s, DNS hijacking of the cluster itself would mean tampering with the CoreDNS ConfigMap.
  File-integrity monitoring can't see that; it would need Kubernetes audit logs sent to Wazuh.
  Future work.
- Storage is still a single SQLite pod, so scaling ingestion still doesn't add write capacity.
- **Probes can amplify an overload.** On the first deploy the VM ran out of memory and swapped.
  Liveness probes with a 1 s timeout made the kubelet kill healthy but slow pods (exit 137). During a
  flood the same thing would restart the attacked pod. The probes now allow a 5 s timeout and
  restart a pod only after about 60 s without answers. Readiness (3 s timeout) still takes a
  struggling pod out of the Service.
