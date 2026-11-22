# Report outline (stage 2)

**Format:** LaTeX, `article` class, A4, 11 pt, two-level numbering, BibTeX (`plainnat`-style
numeric citations). Builds with `pdflatex` + `bibtex` (installed on the VM; no IEEEtran/biblatex).
**Layout:** `report/main.tex`, one file per section in `report/sections/`, figures as TikZ
sources in `report/figures/*.tex` (compiled with the report, no external tools), bibliography in
`report/references.bib`.
**Page limit:** none stated → target **16–18 pages** of body + references/appendix.
Adjust the budgets below if a limit is given.

Every statement about our system cites a FACTS.md section; `TODO(...)` marks gaps.

---

| # | Section | Pages | Content (FACTS §) | Figures / tables |
|---|---|---|---|---|
| – | Title page, abstract | 1 | group `TODO(names)`, course, date; 150-word abstract with headline numbers (§9) | – |
| 1 | Introduction | 1 | problem (scalable IoT service platform under attack), objectives from the brief, contributions (naming scheme, two deployments, 3 threats + SIEM AR, root-cause correlation, per-location monitoring), report overview | – |
| 2 | Relevant State of the Art | 2 | large-scale monitoring (Prometheus pull model, federation, recording rules); SIEM/XDR (Wazuh/OSSEC, correlation); hierarchical naming (DNS, X.500/LDAP DNs, service discovery e.g. Consul/K8s); DoS detection & mitigation (rate thresholds, RTBH, scrubbing); spam filtering (SpamAssassin, Bayes, RBL, rate limiting); DNS hijacking (FIM, DNSSEC); FCAPS fault management | Table: our choice vs. common alternatives |
| 3 | Service Architecture Used | 3 | services and data flows (§2); naming/registration/discovery (§3); physical vs logical location, Incus vs k3s mapping (§3, §4); geographic location & delegation (per-DC Prometheus, per-node agents, `PREFER_SCOPE`); bonus monitoring by location (§5, §9.6); locating an incident source (same ID in registry/metrics/alerts/logs) (§3); trust boundaries & exposure (§4) | **Fig 1** architecture + trust boundaries (Incus/k3s); **Fig 2** ID hierarchy (country→…→node→instance) with the k3s mapping; **Table 1** services/ports/metrics |
| 4 | Risk Management and Mitigation | 3 | attack-surface analysis (network-exposed endpoints, unauthenticated registry, privileged k3s profile, SMTP, DNS zone, Wazuh/Prom management planes) (§4, §10); attack & defense trees; monitoring strategy (metrics, alert/root-cause/aggregate rules) (§5); FCAPS workflow mapped to our tools, and how Wazuh covers explicit security events FCAPS omits | **Table 2** attack surface (entry point, exposure, threat, control); **Fig 3** attack–defense tree "disrupt the temperature service" (DoS / DNS hijack / registry poisoning / spam branches, our defences as nodes); **Fig 4** FCAPS pipeline → Prometheus/Wazuh/AR/evidence |
| 5 | Approach to the three threats | 5 (≈1.6 each) | per threat, the 6 required items: description, relevance, exploitation/PoC run, monitoring & metrics (rules/IDs), action-response, post-mortem (detection & response times, FP/FN, what failed: self-inflicted outage, k3s pod blocking, liveness kills) (§6–§9) | **Table 3** threats × detection × response × result (Incus + k3s); per threat: **Table** of phase results (DoS legit success/latency; spam phases; DNS timeline); optional **Fig 5** DoS timeline (attack start → alert → block → unblock) |
| 6 | Evaluation of approaches and scalability | 2.5 | reproducible setup (VM, generators, durations, single-run caveat) (§1, §8); horizontal scaling 1→2 instances and SQLite bottleneck (§9.6); registry growth 0→2000 and filtered vs unfiltered payload; monitoring bandwidth (raw vs `location:*`); self-healing; root-cause timing (§9.5); scaling limits per component (registry O(N) health sweep, single writer, Prometheus single node, Wazuh single manager); `TODO` + proposed experiments for gaps 6–9 | **Table 4** scaling 1 vs 2; **Fig 6** registry lookup latency / payload vs instances (pgfplots from §9.6); **Table 5** bandwidth |
| 7 | Conclusions | 1.5 | findings & contributions; why it is not perfect (§10 + gaps 9–12); future work (registry auth/HA, distributed-DoS detection with Prometheus→Wazuh, K8s audit logs for CoreDNS, Alertmanager inhibition / dependency graph, Wazuh cluster, Proj2 tolerance) | – |
| – | AI-use declaration | 0.1 | `TODO(keep or delete)` | – |
| – | References | 1 | verified sources only | – |
| A | Appendix: reproduction | 1 | commands to deploy and run every test (from `commands.md`), evidence folder map | – |

**Total:** ≈ 17 body pages + ≈ 2 back matter.

## Screenshots for you to capture (placeholders in the LaTeX)
1. Wazuh dashboard: a 100210 alert showing the agent name (hierarchical ID) and `srcip`.
2. Wazuh: the 100230 DNS-hijack alert and the restore entry.
3. Prometheus `/alerts` during `test-rootcause.sh`: `SSLERootCauseStorageDown` firing with symptoms.
4. Prometheus graph of `location:http_requests:rate1m` split by dc1/dc2.
5. `curl …/tree` output (registry hierarchy).
6. `iptables -t raw -L PREROUTING` on a k3s node during a block (or use `evidence/k3s/ddos/3-iptables-during-block.txt` as a listing instead).

## Decisions to confirm
- Platform emphasis: present **Incus as the main deployment** and k3s as the scaled-out/Kubernetes version (both have full evidence), or the reverse?
- Group names, page limit, AI declaration: still open (they will be `TODO`s until given).
- The repo inconsistencies in FACTS.md: fix in the repo before writing (recommended, ~5 min), or only describe correctly in the report?
