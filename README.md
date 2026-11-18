# SSLE Project 1 – Threat detection, monitoring and prevention

A small service-based IoT pipeline (temperature sensors → ingestion → storage → analytics, plus a
service registry) deployed as Incus containers. It's monitored by **Prometheus** and protected by
**Wazuh** (SIEM), with detection and automatic action-responses for three threats from the syllabus:

| # | Threat (syllabus) | Detection | Action-response | Test | Evidence |
|---|---|---|---|---|---|
| 1 | Massive denial-of-service (HTTP flood) | Wazuh 100210: 15 requests in 10 s from one IP. Prometheus request-rate, latency and backlog alerts | `firewall-drop` of the source IP for 60 s on the attacked service | [test-ddos.sh](test-ddos.sh) | `evidence/ddos/` |
| 2 | Junk email (spam content and mail flood) | Wazuh 100220 (SpamAssassin), 100223 (quarantined), 100222 (10 mails in 30 s from one IP) | Spam put on hold (quarantine); flood source `firewall-drop` for 60 s; relaying refused | [test-spam.sh](test-spam.sh) | `evidence/spam/` |
| 3 | Route / signal hijacking (DNS hijacking) | Wazuh FIM (real time) on the DNS zone: rule 550 → 100230 | `restore-dns.sh` puts the golden zone back and restarts dnsmasq | [test-dns.sh](test-dns.sh) | `evidence/dns/` |
| – | Scalability (horizontal scaling across locations, registry growth, monitoring bandwidth) | Throughput and latency with 1 vs 2 instances, per-location Prometheus aggregates | – | [test-scale.sh](test-scale.sh) | `evidence/scale/` |
| – | Fault management: anomaly events + root cause | Prometheus correlation rules (`ssle-root-cause` group); Wazuh 100201 (HTTP 5xx) per service | One root-cause alert instead of many symptoms; the registry drops dead instances | [test-rootcause.sh](test-rootcause.sh) | `evidence/rootcause/` |

## Architecture

| Service | Port | Code | Role |
|---|---|---|---|
| registry | 5050 | [registry/app.py](registry/app.py) | registration (with heartbeat), discovery by location, round-robin, health checks |
| ingestion | 5001 | [ingestion/app.py](ingestion/app.py) | validates readings and forwards them to storage |
| storage | 5002 | [storage/app.py](storage/app.py) | SQLite persistence plus a read API |
| analytics | 5003 | [analytics/app.py](analytics/app.py) | average/min/max over the stored readings |
| sensor | 8000 (metrics) | [sensor/sensor.py](sensor/sensor.py) | sends a reading every 5 s |

**Naming and location** ([common.py](common.py)): every instance has a hierarchical ID, most specific
part first, like DNS, e.g. `storage-service-01.node1.rack1.dc1.centro.pt` (country > region > dc >
rack > node). The same ID is used for:
- the registry entry (`GET /services?dc=dc1`, `GET /tree`)
- the Prometheus `service_info` series, which can be joined onto any metric to get its location
- the **Wazuh agent name**, so every alert says where it came from
- every JSON access-log line (`/var/log/ssle/access.log`, read by the Wazuh agent)

**Extra containers:** `wazuh-container` (manager), `prometheus-container`, `mail-container`
(Postfix + SpamAssassin + Dovecot), `DNS-server-container` (dnsmasq, `*.ssle.local`). The tests create
`attacker1`, `attacker2` and `legit-client` themselves.

## Repository map

| Path | What |
|---|---|
| `deploy-incus.sh` | one Incus container per service (systemd unit, location env vars) |
| `install-wazuh-agents.sh` | Wazuh agent in each service container, named after its hierarchical ID |
| `wazuh/ssle-rules.xml` | manager `local_rules.xml` (100200–100230) |
| `wazuh/manager-active-response.xml` | `<active-response>` blocks appended to the manager's `ossec.conf` |
| `wazuh/active-response/restore-dns.sh` | custom active response on the DNS agent |
| `wazuh/agents/*.conf` | agent `ossec.conf` of the DNS, mail and service containers (FIM, log sources) |
| `prometheus/` | `prometheus.yml` (scrape targets) and `ssle_rules.yml` (load and root-cause alerts) |
| `mail/` | Postfix `main.cf`/`master.cf`, `header_checks` (quarantine), SpamAssassin config |
| `dns/` | dnsmasq config, the zone and its golden copy |
| `apply-configs.sh` / `collect-configs.sh` | push the repo configs to the VM / pull them from the VM |
| `test-incus.sh`, `test-system_docker.sh` | functional tests of the base architecture |
| `test-lib.sh` | helpers shared by the threat tests |
| `ddos-poc.py` | HTTP load generator used by the DDoS test |
| `scale-tool.py` | load generator and registry benchmark used by the scalability test |
| `prometheus/federation-example.yml` | how a central Prometheus would federate only the per-location aggregates |
| `Dockerfile`, `build-and-push.sh`, `docker-compose.yml` | one Docker image per service (Guide 2); compose for a quick local run |
| `k3s/` | **Docker + Kubernetes version (Guide 2)**: cluster setup, build and deploy, Wazuh node agents; see [k3s/README.md](k3s/README.md) |
| `k8s/ssle.yaml`, `k8s/monitoring.yaml`, `k8s/prometheus-k8s.yml` | the SSLE pods (one Deployment per location) and the in-cluster Prometheus |
| `wazuh/active-response/k3s-block.py`, `wazuh/manager-active-response-k3s.xml` | active response that blocks NodePort traffic on the k3s nodes |
| `prometheus/prometheus-central-k3s.yml` | central Prometheus when the services run in k3s (federation only) |
| `test-k3s.sh` | functional test of the k3s deployment; every other test runs on k3s with `PLATFORM=k3s` |

## Deploying (on the Incus host, from the repo root)

```bash
./deploy-incus.sh                   # 1. services
./install-wazuh-agents.sh           # 2. Wazuh agents (manager container must exist)
./apply-configs.sh                  # 3. pin IPs, Wazuh rules + service list, Prometheus, mail hardening, DNS zone
./test-incus.sh                     # 4. check the base architecture
```

The manager, Prometheus, mail and DNS containers were set up by hand following the practical
guides; their configs are in `wazuh/`, `prometheus/`, `mail/` and `dns/`. The `<active-response>`
blocks in `wazuh/manager-active-response.xml` must be appended to the manager's `ossec.conf` once.

## Docker + Kubernetes version (Guide 2)

The same system also runs as Docker images in a two-node k3s cluster: `k3s-master` = dc1,
`k3s-node1` = dc2. Prometheus runs inside the cluster and is federated by the central one, and a
Wazuh agent on each node blocks NodePort traffic. Every test runs on it with `PLATFORM=k3s`:

```bash
./k3s/setup-cluster.sh && ./apply-configs.sh pin && ./k3s/deploy.sh
./k3s/install-wazuh-node-agents.sh && PLATFORM=k3s ./apply-configs.sh && ./test-k3s.sh
```
Details, design decisions and limitations: [k3s/README.md](k3s/README.md).

## Running the threat tests

```bash
./test-ddos.sh          # about 3 min (add --no-wait to skip the 60 s unblock check)
./test-spam.sh          # about 3 min (--no-wait)
./test-dns.sh --control # about 1 min, --control also shows the hijack without Wazuh
./test-rootcause.sh     # about 3 min
./test-scale.sh         # about 6 min the first time (it deploys ingestion/analytics in dc2)
```

**Monitoring by location (bonus).** The recording rules in the `ssle-location-aggregates` group
(`location:http_requests:rate1m`, `location:http_errors:rate1m`,
`location:http_request_duration_seconds:p95`, `location:instances:count`) join every metric with
`service_info` and sum it per country/region/dc. One Prometheus per data centre scrapes its own
services, and a central one federates only the `location:*` series
([prometheus/federation-example.yml](prometheus/federation-example.yml)). Traffic over the
long-distance links between locations then grows with the number of locations, not with the number
of instances. `test-scale.sh` measures the byte difference.

Each test prints a **threat card**: description, why it matters for this system, how it's exploited,
what's monitored and what the action-response is. It then runs the PoC and checks detection,
response, absence of false positives and recovery, and ends with a **post-mortem summary** (detection
time, time to block or restore, success rate of legitimate traffic, limitations). The whole run and
the raw excerpts (Wazuh alert JSON, iptables, mail/DNS logs, Prometheus queries and alerts) are saved
in `evidence/<threat>/`.

`evidence/first-manual-run/` holds the first, manual run before the tests were automated, kept for
comparison.

## Known limitations

- **Addresses:** Incus assigns IPs by DHCP and they changed after a reboot (services swapped
  addresses). That broke the Prometheus targets and stopped dnsmasq from starting. Prometheus now
  scrapes `<container>.incus` names, dnsmasq listens on interfaces, and `apply-configs.sh pin` makes
  the current addresses permanent. The DNS zone and the Wazuh service list are rebuilt from
  `incus list`.
- **DoS, internal traffic:** one `/stats` call makes analytics call the registry and storage. In the
  first automated run, storage and the registry blocked analytics itself, so the defence caused an
  outage. Rule 100210 now ignores sources in `etc/lists/ssle-services`. The trade-off: a compromised
  service flooding another one isn't blocked, and only Prometheus would see it.
- **DoS:** detection is per source IP. A flood spread over many IPs, each below 15 requests in 10 s,
  isn't caught by 100210. Only the Prometheus rate/latency alerts see it, and they have no automatic
  response. `firewall-drop` only protects the container that raised the alert.
- **Spam:** GTUBE is a test signature, so real spam needs Bayes training and RBLs. A sender that
  rotates IPs or stays under 10 messages in 30 s isn't blocked. Quarantined mail needs an operator.
- **DNS:** only tampering with the zone file is detected, not cache poisoning, a rogue DNS/DHCP server
  or on-path spoofing. Clients can keep a bad answer for its TTL. Root on the DNS host can also change
  the golden copy or stop the agent.
- **Platform:** the registry has no authentication (anyone can register a fake instance), there's a
  single registry and a single SQLite writer, and Prometheus uses static scrape targets.
