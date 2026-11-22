# FACTS: verified from the repository

Every fact below was read from the file given in brackets, or measured on the lab VM. These are
the only statements about our system the report may make. IP addresses and hostnames that
identify the lab are left out on purpose (the report must not contain them).

Evidence dates: Incus runs 2026-11-18, 11:36–12:15; k3s runs 2026-11-18, 21:51–22:02 (first line of
each `run.log`).

---

## 1. Platform and software versions

- Single Kali Linux VM (kernel 6.19), 4 vCPUs, 7.7 GiB RAM, 79 GB disk, acting as the Incus host. Every element is a container on it [measured: `nproc`, `free -h`, `df -h`].
- Incus 7.0.1, network `incus-default` (a /24 lab network), `dir` storage pool [measured; `k3s/setup-cluster.sh`].
- Wazuh manager v4.14.9 in `wazuh-container` [measured: `wazuh-control info`].
- Central Prometheus 2.53.3 in `prometheus-container` [measured]; in-cluster Prometheus image `prom/prometheus:v2.53.0` [`k8s/monitoring.yaml`].
- Postfix 3.6.4 + SpamAssassin 3.4.6 in `mail-container`; dnsmasq 2.91 in `DNS-server-container` [measured].
- Services: Python, Flask ≥3.0, requests ≥2.31, prometheus-client [`requirements.txt`]; Docker image base `python:3.12-slim` [`Dockerfile`].
- k3s v1.37.2+k3s1, containerd 2.3.7, nodes on Debian 13 (trixie) [`evidence/k3s/cluster/0-nodes.txt`].
- Two deployments of the same code: **Incus** (one container per service, `deploy-incus.sh`) and **k3s** (Docker images in a 2-node Kubernetes cluster, `k3s/`). A Docker Compose file also exists for local runs [`docker-compose.yml`, `README.md`].

## 2. Services (application layer)

IoT temperature pipeline: sensor → ingestion → storage ← analytics, plus a service registry [`README.md`].

| Service | Port | Main endpoints | Own metrics | Source |
|---|---|---|---|---|
| registry-service | 5050 | `POST /register`, `DELETE /unregister`, `GET /services[?country&region&dc&rack&node]`, `GET /services/<name>` (one instance, round-robin), `GET /tree`, `/health` | `registry_registrations_total`, `registry_removals_total{reason}`, `registry_health_check_failures_total`, `registry_instances{service,country,region,dc,rack,node}` | `registry/app.py` |
| ingestion-service | 5001 | `POST /ingest` (validates `device_id` + numeric `temperature`, forwards to storage) | `ingestion_readings_total{result=accepted\|invalid\|storage_error}` | `ingestion/app.py` |
| storage-service | 5002 | `POST /store`, `GET /temperatures?device_id&limit` (max 10000) | `storage_readings_stored_total`, `storage_readings_rejected_total`, `storage_rows` | `storage/app.py` |
| analytics-service | 5003 | `GET /average`, `GET /stats` (count/avg/min/max/latest, reads via storage API) | `analytics_storage_errors_total` | `analytics/app.py` |
| temperature-sensor | 8000 (metrics only) | posts a random 20–30 °C reading every 5 s (`INTERVAL`) | `sensor_readings_sent_total{result}`, `sensor_last_temperature_celsius` | `sensor/sensor.py` |

- Storage persists in SQLite (single writer) [`storage/app.py`].
- Ingestion → 502 when storage fails; analytics → 502 "storage unavailable" [`ingestion/app.py`, `analytics/app.py`].
- Device IDs are intentionally not metric labels (unauthenticated input would blow up series cardinality) [`ingestion/app.py`].
- Common instrumentation for every HTTP service: `http_requests_total{service,method,endpoint,status}`, `http_request_duration_seconds` histogram (buckets 5 ms–10 s), `http_requests_in_progress`, and `service_info{service,id,country,region,dc,rack,node}` = 1 [`common.py`].
- Endpoint label is the route pattern, not the URL (bounded cardinality) [`common.py`].

## 3. Naming, registration and location

- Location levels, coarse → fine: `country > region > dc > rack > node` [`common.py: LOCATION_LEVELS`].
- Hierarchical instance ID, most specific first like DNS: `<service>-<instance>.<node>.<rack>.<dc>.<region>.<country>`, e.g. `storage-service-01.node1.rack1.dc1.centro.pt` [`common.py: instance_id`].
- Dots inside a level are replaced by `-`, values lower-cased [`common.py: _part`].
- Location comes from env vars `COUNTRY, REGION, DC, RACK, NODE, INSTANCE` [`common.py`; `deploy-incus.sh`].
- Self-registration: each instance POSTs `{name, url, id, location}` to the registry every 10 s; registration is an idempotent upsert, so it doubles as a heartbeat and survives registry restarts [`common.py: _register_loop`].
- Health checker: every 10 s pings each instance's `/health` (2 s timeout); 2 consecutive failures remove the instance [`registry/app.py: HEALTH_INTERVAL, MAX_FAILURES`].
- Location-aware discovery: `lookup()` asks for an instance filtered by the caller's own location up to `PREFER_SCOPE` (default `dc`), then any instance, then a static fallback URL [`common.py: lookup`].
- `/tree` returns instance counts as country > region > dc > rack > node [`registry/app.py`].
- The **same ID** appears in: the registry entry, the Prometheus `service_info` series, the Wazuh agent name, and every JSON access-log line (`id` field) [`README.md`, `common.py`, `install-wazuh-agents.sh`].
- On k3s: `NODE = spec.nodeName` (physical level = k3s node), `INSTANCE = pod name` (logical level), `DC` fixed per Deployment and enforced with `nodeSelector ssle.dc`; each pod registers its own pod IP (`SERVICE_URL=http://$(POD_IP):port`), otherwise replicas collapsed into one registry entry [`k8s/ssle.yaml`, `k3s/README.md §5`]. Example: `ingestion-service-ingestion-dc2-<hash>.k3s-node1.rack1.dc2.centro.pt` [`evidence/k3s/scale/summary.txt`, `evidence/k3s/cluster/2-registry-check.txt`].
- k3s nodes: `k3s-master` = dc1, `k3s-node1` = dc2, both rack1, region centro, pt (node labels `ssle.dc`, `ssle.rack`) [`k3s/setup-cluster.sh`].
- Wazuh agent names on k3s: one per node, e.g. `k3s-node-01.k3s-master.rack1.dc1.centro.pt`; the pod ID still travels in `data.id` [`k3s/install-wazuh-node-agents.sh`].
- Known limitation: the registry has no authentication (anyone can register a fake instance); single registry instance [`README.md: Known limitations`].

## 4. Deployment and trust boundaries

- Incus: one container per service with a systemd unit; extra containers `wazuh-container`, `prometheus-container`, `mail-container` (Postfix + SpamAssassin + Dovecot), `DNS-server-container` (dnsmasq, `*.ssle.local`); test clients `attacker1`, `attacker2`, `legit-client` are created by the tests [`README.md`, `deploy-incus.sh`, `test-lib.sh: ensure_client`].
- Incus DHCP once swapped container IPs after a reboot; fixed by scraping `<container>.incus` names, dnsmasq binding to interfaces, and `apply-configs.sh pin` (static IPs) [`README.md: Known limitations`, `apply-configs.sh`].
- k3s: privileged `k3s` Incus profile (nesting, AppArmor unconfined, `/dev/kmsg`) [`k3s/setup-cluster.sh`]; noted as attack-surface item: container escape = host compromise [`k3s/README.md §9`].
- k3s images built in the `docker` container and pushed to a private plain-HTTP registry `docker.incus:5000`, tag = git commit [`k3s/deploy.sh`, `build-and-push.sh`].
- k3s exposure: ingestion and analytics on NodePorts 30001/30003 with `externalTrafficPolicy: Local` (keeps the client IP that Wazuh must block; each node serves its own location); registry and storage are `ClusterIP` only; in-cluster Prometheus on NodePort 30090 [`k8s/ssle.yaml`, `k3s/README.md`; checked in `evidence/k3s/cluster/run.log §4`].
- k3s pods: resource requests 50m CPU/64 Mi, limits 500m/256 Mi ("also caps what a flood can take from the node"), readiness (3 s timeout) and liveness (5 s timeout, 6 failures ≈ 60 s) probes, storage = 1 replica `Recreate` + 1 Gi PVC [`k8s/ssle.yaml`].
- Access logs on k3s: `hostPath /var/log/ssle/<pod>/access.log` (via `subPathExpr`), read by the node's Wazuh agent [`k8s/ssle.yaml`, `k3s/README.md`].
- Mail and DNS stay outside the cluster on both platforms [`k3s/README.md §7`].

## 5. Monitoring (Prometheus)

- Scrape and evaluation interval 5 s; jobs `ssle-registry|ingestion|storage|analytics|sensor` + `ssle-scale` (file SD for extra instances) [`prometheus/prometheus.yml`].
- On k3s, Prometheus discovers pods via `kubernetes_sd_configs` (role pod) and relabels to the same `ssle-<app>` job names, so the same rules apply unchanged [`k3s/README.md §6`].
- Load/DoS alerts (group `ssle-ddos-alerts`, 5 s): `SSLEHighRequestRate` (rate > 5 req/s per job, 15 s window), `SSLEHighP95Latency` (p95 > 50 ms), `SSLEHighConcurrentRequests` (in-flight > 3) [`prometheus/ssle_rules.yml`].
- Root-cause group `ssle-root-cause` with labels `kind=symptom|root-cause` and `root_cause=<component>`: `SSLEInstanceDown`, `SSLEStorageErrorsSymptom`, `SSLERootCauseStorageDown` (errors in dependents AND storage `up` == 0 or absent), `SSLERootCauseStorageUnreachable` (errors while storage is up, suppressed during a request flood), `SSLEStorageNotRegistered`, `SSLERootCauseIngestionDown`, `SSLERootCauseRequestFlood` (slow AND flooded; points to Wazuh 100210 for source IPs) [`prometheus/ssle_rules.yml`].
- `or vector(0)` because on k3s a pod scaled to zero has no `up` series at all [`prometheus/ssle_rules.yml` comment].
- `SSLERootCauseStorageUnreachable` was changed after it wrongly blamed the network during the DDoS test [`prometheus/ssle_rules.yml` comment].
- Location aggregates (group `ssle-location-aggregates`, 15 s): `location:http_requests:rate1m`, `location:http_errors:rate1m`, `location:http_request_duration_seconds:p95`, `location:instances:count`, each joined with `service_info` and summed by country/region/dc [`prometheus/ssle_rules.yml`].
- Federation design: one Prometheus per DC scrapes locally; central Prometheus federates only `{__name__=~"location:.+"}` (on k3s also `ALERTS`) [`prometheus/federation-example.yml` (example, not deployed on Incus), `prometheus/prometheus-central-k3s.yml` (deployed for k3s), `k3s/README.md §6`]. Central federation of dc1+dc2 aggregates verified [`evidence/k3s/cluster/5-central-federation.txt`].

## 6. SIEM (Wazuh): rules and active responses

Rules in `wazuh/ssle-rules.xml` (manager `local_rules.xml`); responses in `wazuh/manager-active-response.xml` and `wazuh/manager-active-response-k3s.xml`.

| Rule | Level | Logic | Response |
|---|---|---|---|
| 100200 | 3 | any SSLE JSON access-log line (`decoded_as json`, field `service`) | — |
| 100202 | 4 | child of 100200, `http_status` 4xx | — |
| 100201 | 7 | child of 100200, `http_status` 5xx (used for root-cause symptoms) | — |
| 100209 | 0 | child of 100200, `srcip` in 10.42.0.0/16 (k3s pod-to-pod traffic), defined after 100201 | silences internal requests so 100210 never counts them |
| 100210 | 10 | 15 × 100200 in 10 s, same `srcip`, `srcip` not in CDB list `etc/lists/ssle-services` | `firewall-drop` (Incus, INPUT) and `k3s-block` (k3s, `raw/PREROUTING`), local, 60 s |
| 100220 | 7 | `spamd: identified spam` | alert only |
| 100223 | 6 | Postfix `hold: header X-Spam-Flag` (quarantined) | alert only |
| 100221 | 5 | Postfix `client=` (message accepted) | building block |
| 100222 | 10 | 10 × 100221 in 30 s, same `srcip` | `firewall-drop` on mail-container, 60 s |
| 100230 | 12 | child of 550 (syscheck checksum changed) matching `ssle.hosts` | `restore-dns` (custom), local |

- Rule 651 = Wazuh's own "host blocked by firewall-drop" alert, used as evidence [`evidence/ddos/3-wazuh-alerts-651.json`].
- `etc/lists/ssle-services` is rebuilt from the current service container IPs by `apply-configs.sh wazuh`, so services don't block each other [`apply-configs.sh`].
- Why: during the first automated DoS run storage and registry blocked analytics (each `/stats` makes analytics call registry + storage) → self-inflicted outage [`wazuh/ssle-rules.xml` comment, `README.md: Known limitations`].
- On k3s, a CDB prefix key `10.42.` did not match and `<srcip>!10.42.0.0/16</srcip>` behaved as a positive match; replaced by rule 100209 [`wazuh/ssle-rules.xml` comment, `README.md` k3s section].
- `k3s-block`: stock `firewall-drop` writes to `INPUT`, which NodePort traffic (DNAT by kube-proxy, then forwarded) never crosses; `k3s-block` inserts `iptables -t raw -I PREROUTING -s <ip> -j DROP`; implements the Wazuh 4.x AR protocol (check_keys, add, delete after timeout) [`wazuh/active-response/k3s-block.py`].
- `restore-dns.sh`: if zone ≠ golden copy, copy `/etc/dnsmasq.hosts.clean` over `/etc/dnsmasq-zones/ssle.hosts`, restart dnsmasq, log; the equality check prevents its own restore re-triggering [`wazuh/active-response/restore-dns.sh`].
- DNS agent: FIM `realtime="yes" check_all="yes"` on `/etc/dnsmasq-zones` [`wazuh/agents/dns-ossec.conf`].
- k3s node agents scan for new pod log files every 5 s (`logcollector.vcheck_files=5`; default 64 s missed the first minute of a new pod's traffic) [`k3s/install-wazuh-node-agents.sh`].
- Operational (not in repo): vulnerability detection was disabled on the manager on 2026-11-18 to free 11 GB of disk; it is not used by any rule.

## 7. Mail hardening

- `mynetworks = 127.0.0.0/8 …` only and `smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination` → no open relay [`mail/postfix-main.cf`].
- All SMTP goes through `content_filter=spamassassin` (spamc pipe) [`mail/postfix-master.cf`].
- SpamAssassin `required_score 5.0`, Bayes on, auto-learn on, subject rewrite `*****SPAM*****` [`mail/spamassassin-local.cf`].
- `header_checks`: `/^X-Spam-Flag: YES/ HOLD` → spam quarantined in the hold queue (operator release with `postsuper -H`) [`mail/header_checks`].

## 8. Threat PoCs (how each was run)

All tests run from the Incus host; each prints a threat card (description, relevance, exploitation, monitoring, response), runs the PoC, checks detection/response/false positives/recovery, writes a post-mortem summary [`test-lib.sh`, `README.md`].

- **DoS (HTTP flood)** [`test-ddos.sh`, `ddos-poc.py`]: target `analytics /stats?limit=1000` (each call fans out to registry + storage); 2 attacker containers × 20 workers, 25 s; legitimate client ~1 req/s (below the threshold). Phases: 1 baseline (15 s), 2 unmitigated (Wazuh agent on the target stopped), 3 mitigated, 4 recovery after the 60 s block. On k3s the target is the dc1 NodePort.
- **Junk email** [`test-spam.sh`]: 1 legit mail; 2 GTUBE spam; 3 relay attempt to an outside domain; 4 flood of 12 messages from one attacker; 5 recovery.
- **DNS hijacking** [`test-dns.sh`]: overwrites the zone so `ingestion.ssle.local` points to an attacker IP; a client resolves every 0.25 s; optional control phase with the agent stopped.
- **Fault / root cause** [`test-rootcause.sh`]: stops storage (Incus: container; k3s: Deployment scaled to 0) and checks symptoms, correlation, registry removal and recovery.
- **Scalability** [`test-scale.sh`, `scale-tool.py`]: 3 load generators × 8 workers, 20 s per phase, closed loop; 1 vs 2 instances (second in dc2); registry with 0/100/500/2000 fake instances over 2 countries × 3 regions × 4 DCs × 5 racks; scrape and federation sizes. Wazuh agents are stopped during the benchmark.

## 9. Results (all from evidence files)

### 9.1 Pass/fail
| Test | Incus | k3s |
|---|---|---|
| DoS | 17/17 | 17/17 |
| Junk email | 18/18 | 18/18 |
| DNS hijacking | 10/10 | 10/10 |
| Root cause | 8/8 | 8/8 |
| Scale | 9/9 | 9/9 |
| Cluster functional (`test-k3s.sh`) | – | 40/40 |
[`evidence/*/run.log`, `evidence/k3s/*/run.log`]

### 9.2 DoS — legitimate client
| Phase | Incus success / p50 / p95 | k3s success / p50 / p95 |
|---|---|---|
| Baseline | 100% / 11 ms / 14 ms | 100% / 13 ms / 32 ms |
| Unmitigated | 0% / 2003 ms / 2003 ms | 91% / 900 ms / 1890 ms |
| Mitigated | 77% / 10 ms / 2002 ms | 100% / 12 ms / 22 ms |

- Detection (attack start → first 100210): Incus 12.0 s; k3s 2.2 s.
- Time to block: Incus 13.8 s / 12.4 s (attacker1/2); k3s 2.8 s / 2.9 s.
- False positives (legit client flagged/blocked): none on either platform.
- Both attackers unblocked after the 60 s timeout and could reach the service again.
- `SSLEHighRequestRate` fired during the unmitigated attack.
[`evidence/ddos/summary.txt`, `evidence/k3s/ddos/summary.txt`, `run.log`s]

### 9.3 Junk email
- Legit mail delivered and scored clean; GTUBE spam flagged (100220), quarantined on hold (100223), nothing delivered; relay refused ("Relay access denied").
- Flood: Incus first 100222 after 1.7 s, blocked after 2.0 s (12/12 sessions reached Postfix, 2 completed); k3s first alert 2.2 s, blocked 2.8 s (12 completed).
- Legit sender never blocked and could send during the block; attacker unblocked after timeout.
[`evidence/spam/summary.txt`, `evidence/k3s/spam/summary.txt`]

### 9.4 DNS hijacking
- Hijack → 100230 alert: 0.1 s (both). Hijack → zone restored: 0.3 s (Incus), 0.2 s (k3s).
- Exposure window seen by the client: 0.00 s. Control without Wazuh: hijack still in place after 15 s.
[`evidence/dns/summary.txt`, `evidence/k3s/dns/summary.txt`]

### 9.5 Root cause
- Incus: `SSLERootCauseStorageDown` firing 11.3 s after storage stopped; network not blamed; registry removed storage after 20.8 s; 3 Prometheus symptom alerts + 3 Wazuh 5xx → 1 root cause; alert cleared 10.8 s after restart [`evidence/rootcause/run.log`, `summary.txt`].
- k3s: firing after 43.4 s; registry removal 54.1 s; 4 alerts + 4 Wazuh 5xx → 1 root cause; cleared 7.1 s after restart [`evidence/k3s/rootcause/run.log`, `summary.txt`].

### 9.6 Scalability
| | Incus | k3s |
|---|---|---|
| ingestion 1 → 2 instances (req/s) | 189.9 → 184.3 (0.97x) | 85.8 → 114.8 (1.34x) |
| ingestion p95 (ms) | 199 → 540 | 426 → 475 |
| analytics 1 → 2 (req/s) | 194.3 → 207.9 (1.07x) | 119.4 → 133.6 (1.12x) |
| analytics p95 (ms) | 175 → 234 | 285 → 383 |
- Incus storage writes/s: 198 with 1 ingestion vs 184.7 with 2 → the single SQLite storage is the bottleneck [`evidence/scale/run.log`].
- Registry (Incus) at 0/100/500/2000 instances: register/s –/753/851/747; lookup p50 0.8/1.1/1.3/1.9 ms; p95 1.6/2.3/2.6/3.4 ms; `/tree` 0.8/1.7/2.5/3.7 ms; unfiltered `/services` 1226/21209/101473/403593 B; one DC 3/1024/4240/16950 B; one rack 3/224/1028/3449 B [`evidence/scale/3-registry.txt`].
- Registry (k3s, 2000): 298 register/s, lookup p50 4.1 ms, p95 38.7 ms, `/tree` 10.0 ms [`evidence/k3s/scale/summary.txt`].
- One full `/metrics` scrape: registry 14620 B, storage 9254 B, ingestion 7242 B, analytics 7098 B [`evidence/scale/4-monitoring-bandwidth.txt`].
- Federation: raw 326515 B (10760 B gzip) vs `location:*` only 2760 B (420 gzip) on Incus; k3s 403553 B vs 2878 B (0.7%) [`evidence/scale/4-monitoring-bandwidth.txt`, `evidence/k3s/scale/summary.txt`].
- Self-healing on k3s: deleted ingestion-dc1 pod replaced, new pod registered itself, old one removed by the health checker (15.8 s after the new pod registered) [`evidence/k3s/cluster/run.log`].

### 9.7 Earlier manual run
- `evidence/first-manual-run/` holds the first manual PoCs (DoS phases, spam, DNS hijack + control) before automation [`README.md`].

## 10. Limitations already documented in the repo

[`README.md: Known limitations`, `k3s/README.md §9`, `evidence/*/summary.txt`]
- DoS: per-source threshold; a flood from many IPs each under 15 req/10 s is missed by 100210 (only Prometheus sees it, no automatic response); `firewall-drop` protects only the container that alerted.
- DoS: internal sources are whitelisted, so a compromised service/pod flooding another is not blocked.
- Spam: GTUBE is a test signature; real spam needs Bayes training/RBLs; IP rotation or < 10 msgs/30 s evades 100222; quarantine needs an operator.
- DNS: only zone-file tampering is detected (not cache poisoning, rogue DNS/DHCP, on-path spoofing); clients keep a bad answer for its TTL; root on the DNS host can alter the golden copy or stop the agent; on k3s, CoreDNS ConfigMap tampering is not covered (needs Kubernetes audit logs).
- Root cause: rules written per dependency; a dependency graph or Alertmanager inhibition would generalise; 1 min `increase()` delays clearing.
- Platform: no registry authentication; single registry; single SQLite writer; static scrape targets on Incus; privileged k3s profile; all "locations" are logical (one physical host).
- k3s: liveness probes with 1 s timeout killed slow pods during overload (exit 137); relaxed to 5 s / ~60 s.
- Shared VM disk: below 5% free the kubelet evicted all pods and tainted both nodes.

---

## 11. Experiments added on 2026-11-21 (report/experiments/, evidence/k3s/)

- **Exposure** (measured from `legit-client`): Wazuh dashboard 443 reachable (login page); Wazuh API 55000 and indexer 9200 not reachable; central Prometheus 9090 and in-cluster 30090 reachable, API answers without authentication.
- **Incus DoS detection delay**: first 100210 alert 0.26 s after the 15th logged request (Incus) and 1.1 s (k3s); the last logged request in the alert took 2331 ms (Incus) vs 614 ms (k3s); the Incus log lines started ~9.4 s after attack start [`evidence/ddos/3-wazuh-alerts-100210.json`, `evidence/k3s/ddos/3-wazuh-alerts-100210.json`]. Requests are logged on completion [`common.py: _finish`].
- **Spam corpus** [`evidence/k3s/spam-corpus/`]: SpamAssassin public corpus 20030228, 500 spam + first 500 easy_ham, through production `spamc -u spamd`; threshold 5.0: 349/500 spam (69.8%), 52/500 ham flagged (10.4%); threshold 3.0: 438/500 (87.6%), 226/500 (45.2%); median score spam 9.6, ham 1.8. No Bayes DB existed before or after.
- **Distributed flood** [`evidence/k3s/distributed-flood/`, `report/experiments/distributed-flood.sh`]: 40 source addresses × 1.0 req/s × 40 s on the dc1 analytics NodePort; Prometheus rate 39.6 req/s; Wazuh 100210 alerts 0, DROP rules 0; Prometheus firing SSLEHighRequestRate (registry, storage, analytics) and SSLERootCauseRequestFlood (storage, analytics); legit p50 15→13 ms, p95 46→226 ms. (An earlier attempt with catch-up bursts in the generator did cross the threshold and was discarded; an attempt while Wazuh was down was discarded.)
- **Wazuh throughput** [`evidence/k3s/wazuh-eps/`, `report/experiments/wazuh-eps.sh`]: synthetic lines on k3s-master, 30 s per rate. 100/250/500 lines/s: 0% lost, p50 latency 1.05/1.07/2.27 s; 1000/s: 40.7% lost, 593 alerts/s, p50 11.2 s; 2000/s: 71.8% lost, 563 alerts/s, p50 11.5 s, p95 15.2 s; agent logged "Agent buffer is full: Events may be lost". Agent `client_buffer`: queue_size 5000, events_per_second 500.
- **Operations**: after the VM reboot of 2026-11-21 10:44 the `wazuh-manager` unit failed with "Result: timeout"; it was started manually; no alert reported it.

- **Repeated k3s runs** [`evidence/k3s/repeats/`, `summary.txt`, `report/experiments/repeat-tests.sh`], 2026-11-21, back to back: DNS (5) alert 0.12±0.04 s, restored 0.28±0.08 s, exposure 0; spam flood (5) first 100222 1.8±0.66 s, blocked 2.98±2.5 s (1.5–7.3); root cause (5) firing 40.9±2.6 s, registry removal 52.7±2.2 s, cleared 5.3±2.5 s; root-cause pre-check failed in runs 2–5 (previous run's symptom alert still active); DoS (5) detection 1.8 / none / 17.4 / 1.6 / 1.8 s, legit mitigated success 100/0/38/100/100%, run 2: 0 requests completed in the mitigated phase, no access-log events, no detection; run 3 baseline already failing; scale (3) ingestion speed-up 0.37/1.37/1.27×, analytics 5.66/1.16/1.22×, location:* = 0.71±0.01% of raw federation, registry lookup (2000) p50 4.4±0.6 ms, p95 47.5±10.4 ms; registry pod killed by liveness (exit 137) at end of scale run 1.
- **Resources during scale runs** [`evidence/k3s/repeats/scale/run*/resources.txt`]: in-cluster Prometheus pod ≤44 millicores, 51–109 MiB, head series ~2224; central Prometheus container 59–143 MiB; Wazuh container 2.0–2.6 GiB; analytics pod up to 436m CPU (limit 500m), storage up to 350m.

## GAPS (status after the 2026-11-21 experiments)

Resolved by the experiments of section 11: 6 (repeated runs), 7 (resource usage), 8 (Wazuh throughput), 9 (distributed flood), 10 (spam corpus), 12 (Incus detection delay). Screenshots (5) replaced by evidence excerpts in the appendix. Still open: 1 (names, template), AI-use statement.


1. **Group member names, report template/format, page limit**: not stated anywhere.
2. **Architecture diagram**: none in the repo (will be generated as source in `report/figures/`).
3. **Attack-surface analysis and attack/defense trees**: not in the repo; must be written for the report (can be derived from facts above, but the analysis itself is new content you should review).
4. **State of the art**: no sources/bibliography in the repo; needs verified external references.
5. **Screenshots**: none (Wazuh dashboard alerts, Prometheus alerts/graphs, `/tree` output, iptables during block).
6. **Statistical robustness**: every measurement is a single run (no repetitions, no variance/confidence intervals).
7. **Resource usage**: no CPU/RAM measurements of Prometheus, the Wazuh manager or the services under load.
8. **Wazuh scalability**: no events-per-second or agent-count measurement of the manager/indexer.
9. **Distributed (multi-source) DoS / botnet-style flood**: described as a limitation, never tested.
10. **Spam false negatives**: only GTUBE tested; no real spam/ham corpus, so detection rate is unknown.
11. **Incus evidence vs current code**: Incus runs (Nov 18 morning) predate later changes to `test-lib.sh`, the threat tests and the Wazuh rules; the Incus suite was not rerun afterwards.
12. **Why Incus DoS detection was 12 s vs 2.2 s on k3s**: not explained by any evidence.

## INCONSISTENCIES (status after the 2026-11-21 fixes)

- FIXED: `k3s/README.md` sections 7 and 9 now describe rule 100209 instead of the `10.42.` CDB prefix.
- FIXED: `README.md` threat table now separates the Wazuh response (firewall-drop, 100222) from the mail-server controls (Postfix hold, relay refusal).
- EXPLAINED: spam flood "2 completed" (Incus) vs "12 completed" (k3s) is a race between the 12 parallel sessions and the block (threshold 10 messages); mail runs outside the cluster on both. `test-spam.sh` now prints an accurate message for both outcomes.
- FIXED: `test-scale.sh` header comment mentions `evidence/k3s/scale/`.
- LEFT AS IS (minor): central Prometheus 2.53.3 vs in-cluster image 2.53.0.
- LEFT AS IS: stock Wazuh example rules 100001/100100 (already labelled as stock examples).
