# Commands

Quick reference for every script in this repo. Run everything **on the Incus host (the Kali VM),
from the repo root**, unless it says otherwise.

Most scripts take `PLATFORM=k3s` in front to work on the Kubernetes version instead of the Incus
one. k3s evidence goes to `evidence/k3s/<test>/`, so it never overwrites the Incus evidence.

---

## 1. Setting up

### Incus version (one container per service)
| Command | Purpose |
|---|---|
| `./deploy-incus.sh` | Create/update one Incus container per service (registry, storage, ingestion, analytics, sensor). Safe to re-run: pushes the latest code and restarts the services. Location via env, e.g. `DC=dc2 RACK=rack3 ./deploy-incus.sh` |
| `./install-wazuh-agents.sh` | Install a Wazuh agent in each service container, named after its hierarchical ID. Run after `deploy-incus.sh`. `WAZUH_IP=<ip>` to override the manager address |
| `./apply-configs.sh` | Push all repo configs to the lab (see section 2) |
| `./test-incus.sh` | Smoke test of the Incus deployment. `--failure` also stops/restarts `storage` |

### k3s version (Docker images in Kubernetes)
| Command | Purpose |
|---|---|
| `./k3s/setup-cluster.sh` | Create the `k3s` profile, the 2-node cluster (`k3s-master` = dc1, `k3s-node1` = dc2) and the `docker` container with the private registry. Safe to re-run, never deletes anything |
| `./apply-configs.sh pin` | Make the new containers' IPs permanent (run after creating the cluster) |
| `./k3s/deploy.sh` | Build the images, push them to `docker.incus:5000` (tagged with the git commit), apply `k8s/ssle.yaml` + in-cluster Prometheus, wait for the rollouts. `TAG=...` to choose the tag |
| `./k3s/install-wazuh-node-agents.sh` | One Wazuh agent per k3s node (reads every pod's access log) + the `k3s-block` active response. Safe to re-run |
| `PLATFORM=k3s ./apply-configs.sh` | Point DNS, Wazuh and the central Prometheus at the cluster |
| `./test-k3s.sh` | Full check of the cluster: nodes, pods, registry per pod, data flow per location, exposure, monitoring, SIEM, self-healing. Evidence: `evidence/k3s/cluster/` |

Full k3s setup in one go:
```bash
./k3s/setup-cluster.sh && ./apply-configs.sh pin && ./k3s/deploy.sh
./k3s/install-wazuh-node-agents.sh && PLATFORM=k3s ./apply-configs.sh && ./test-k3s.sh
```

### Docker Compose (quick local run, optional)
| Command | Purpose |
|---|---|
| `docker compose up -d` | Run all services locally with published ports |
| `./test-system_docker.sh` | Smoke test of the compose setup. `HOST=<ip>`, `--failure` |

---

## 2. Configuration

| Command | Purpose |
|---|---|
| `./apply-configs.sh` | Push every config in the repo to the containers (validated before each restart) |
| `./apply-configs.sh pin` | Pin the current IPv4 of every lab container (Incus DHCP can swap IPs after a reboot) |
| `./apply-configs.sh wazuh` | Wazuh rules (`wazuh/ssle-rules.xml`), the internal-services list, and the `k3s-block` response on k3s. Restarts the manager |
| `./apply-configs.sh prometheus` | Prometheus config + alert/recording rules (on k3s: the federation-only central config) |
| `./apply-configs.sh mail` | Postfix hardening (no open relay, spam to the hold queue) + SpamAssassin |
| `./apply-configs.sh dns` | dnsmasq config, the `ssle.local` zone and its golden copy, `restore-dns` response |
| `./apply-configs.sh agents` | Clean up duplicated access-log blocks in the agents' `ossec.conf` |
| `./collect-configs.sh` | The reverse: pull configs from the containers into the repo (then `git diff`) |

Parts can be combined: `./apply-configs.sh wazuh dns`. Container names can be overridden with
`WAZUH=... PROM=... MAIL=... DNS=...`.

---

## 3. Threat and evaluation tests

Each test prints a threat card, runs the attack, checks detection/response/recovery, and ends with
a post-mortem summary. Evidence: `evidence/<test>/` (Incus) or `evidence/k3s/<test>/` (k3s).

| Command | Threat / purpose | Time |
|---|---|---|
| `./test-ddos.sh` | **DoS (HTTP flood)**: baseline → attack without protection → attack with Wazuh 100210 + block → unblock after 60 s | ~3 min |
| `./test-spam.sh` | **Junk email**: legit mail delivered, spam quarantined (100220/100223), open relay refused, mail flood blocked (100222) | ~3 min |
| `./test-dns.sh` | **DNS hijacking**: zone tampered → FIM (550 → 100230) → `restore-dns` puts the zone back | ~1 min |
| `./test-rootcause.sh` | **Root cause**: storage stopped → symptoms correlated into one `SSLERootCauseStorageDown` alert | ~3 min |
| `./test-scale.sh` | **Scalability**: 1 vs 2 instances across locations, registry with 2000 instances, monitoring bandwidth by location (bonus) | ~6 min |

Options:
- `--no-wait` (`test-ddos.sh`, `test-spam.sh`): skip the 60 s wait for the unblock check
- `--control` (`test-dns.sh`): also show the hijack staying in place without Wazuh
- `--keep` (`test-scale.sh`, Incus only): leave the dc2 instances running afterwards
- `PLATFORM=k3s` (all of them): run against the k3s cluster

Run everything on k3s:
```bash
PLATFORM=k3s ./test-ddos.sh
PLATFORM=k3s ./test-spam.sh
PLATFORM=k3s ./test-dns.sh --control
PLATFORM=k3s ./test-rootcause.sh
PLATFORM=k3s ./test-scale.sh
./test-k3s.sh
```

Useful overrides (env vars):
- DDoS: `TARGET=analytics ENDPOINT='/stats?limit=1000' ATTACK_SECS=25 ATTACK_WORKERS=20`
- Spam: `ATTACKER=attacker1 LEGIT=legit-client COUNT=12`
- DNS: `DOMAIN=ingestion.ssle.local HIJACK_IP=10.255.255.42`
- Scale: `WORKERS=8 DURATION=20 SIZES=0,100,500,2000`

### Tools used by the tests (can also be run by hand)
| Command | Purpose |
|---|---|
| `python3 ddos-poc.py --url <url> --duration 15 --workers 20` | HTTP flood / load generator. Also `--delay`, `--timeout`, `--label` |
| `python3 scale-tool.py load --urls <u1,u2> --workers 10 --duration 20` | Closed-loop load against one or more URLs (round-robin). `--method POST --body '<json>'` |
| `python3 scale-tool.py registry --registry http://<ip>:5050 --sizes 0,100,500,2000` | Registry growth benchmark |

---

## 4. Checking and troubleshooting

```bash
incus list                                                    # containers, state and IPs
df -h / && free -h                                            # VM disk and RAM (k3s evicts pods below 5% free disk)
```

k3s:
```bash
incus exec k3s-master -- k3s kubectl get nodes -L ssle.dc    # nodes and their location
incus exec k3s-master -- k3s kubectl -n ssle get pods -o wide # where each pod runs
incus exec k3s-master -- k3s kubectl describe nodes | grep -E 'Name:|Pressure|Taints'
incus exec k3s-master -- k3s kubectl -n ssle delete pod --field-selector=status.phase=Failed
incus exec k3s-master -- k3s kubectl -n ssle rollout restart deploy   # restart every pod
```

Wazuh:
```bash
incus exec wazuh-container -- /var/ossec/bin/agent_control -l          # agents and status
incus exec wazuh-container -- tail -f /var/ossec/logs/alerts/alerts.log # live alerts
incus exec <container> -- tail /var/ossec/logs/active-responses.log    # blocks applied
```

Firewall blocks:
```bash
incus exec <service-container> -- iptables -L INPUT -n         # Incus (firewall-drop)
incus exec k3s-master -- iptables -t raw -L PREROUTING -n      # k3s (k3s-block)
```

Prometheus: `http://<prometheus-container-ip>:9090` (central) or `http://<k3s-master-ip>:30090` (in-cluster).
