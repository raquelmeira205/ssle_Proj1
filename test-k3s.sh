#!/usr/bin/env bash
# Functional test of the k3s deployment (Guide 2 "4. Checking", applied to SSLE). Checks that
# the Kubernetes version keeps every property of the Incus one:
#   0. cluster: 2 nodes Ready, each labelled with its location (dc1 / dc2)
#   1. workloads: every Deployment available, each pod on the node of its location, images
#      from the private registry
#   2. naming/registry: one registry entry PER POD (pod IP, not the Service), hierarchical IDs
#      with the k3s node as the physical level
#   3. data flow and location-aware discovery: the dc2 sensor feeds the dc2 ingestion pod
#   4. exposure: NodePorts keep the client IP (what Wazuh blocks); registry/storage not exposed
#   5. monitoring: in-cluster Prometheus scrapes every pod; the central one federates the
#      per-location aggregates
#   6. SIEM: node agents active, pod access logs reach the manager with the pod's ID
#   7. self-healing: a deleted pod is replaced and the new one registers itself
# Saved under evidence/k3s/cluster/. Run on the Incus host from the repo root: ./test-k3s.sh
set -u
PLATFORM=k3s
source "$(dirname "$0")/test-lib.sh"
CLIENT=${CLIENT:-legit-client}

start_evidence cluster
MASTER_IP=$(ip_of "$K3S_MASTER"); NODE1_IP=$(ip_of "$K3S_NODE1")
info "k3s-master $MASTER_IP, k3s-node1 $NODE1_IP"

section "0. Cluster"
kctl get nodes -L ssle.dc,ssle.rack -o wide | tee "$EVID/0-nodes.txt"
[ "$(grep -c ' Ready' "$EVID/0-nodes.txt")" -ge 2 ] && ok "2 nodes Ready" || bad "fewer than 2 nodes Ready"
for pair in "$K3S_MASTER:dc1" "$K3S_NODE1:dc2"; do
  n=${pair%%:*}; dc=${pair##*:}
  [ "$(kctl get node "$n" -o jsonpath='{.metadata.labels.ssle\.dc}')" = "$dc" ] \
    && ok "$n is location $dc" || bad "$n has no ssle.dc=$dc label"
  # Both nodes share the VM's disk and RAM: when it runs low the kubelet evicts every pod and
  # taints the node, so nothing can be scheduled (pods "Evicted" / "Pending").
  cond=$(kctl get node "$n" -o jsonpath='{range .status.conditions[*]}{.type}={.status} {end}')
  echo "    $n: $cond" | tee -a "$EVID/0-nodes.txt"
  if echo "$cond" | grep -qE '(Memory|Disk|PID)Pressure=True'; then
    bad "$n is under resource pressure ($(echo "$cond" | grep -oE '[A-Za-z]+Pressure=True' | tr '\n' ' ')) - free memory/disk on the VM"
  else
    ok "$n has no memory/disk pressure"
  fi
done

section "1. Workloads"
kctl get deploy,pods,svc -o wide | tee "$EVID/1-workloads.txt"
for d in $(kctl get deploy -o jsonpath='{.items[*].metadata.name}'); do
  kctl rollout status deploy "$d" --timeout=60s >/dev/null 2>&1 && ok "deployment $d available" || bad "deployment $d not available"
done
for dc in dc1 dc2; do
  want=$( [ "$dc" = dc1 ] && echo "$K3S_MASTER" || echo "$K3S_NODE1")
  got=$(kctl get pods -l dc=$dc,app=ingestion --field-selector=status.phase=Running -o jsonpath='{.items[*].spec.nodeName}')
  [ "$got" = "$want" ] && ok "ingestion-$dc runs on $want" || bad "ingestion-$dc runs on '$got' (expected $want)"
done
kctl get pods -l 'app in (registry,storage,ingestion,analytics,sensor)' -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' \
  | grep -v '^docker.incus:5000/ssle/' | grep -q . && bad "some pods do not use the private registry" || ok "every SSLE image comes from docker.incus:5000"

section "2. Registry: one entry per pod, hierarchical IDs"
REG=$(internal_url registry)
near curl -s --max-time 5 "$REG/services" | python3 -m json.tool > "$EVID/2-registry-services.json" 2>/dev/null \
  || echo '{}' > "$EVID/2-registry-services.json"
python3 - "$EVID/2-registry-services.json" <<'EOF' | tee "$EVID/2-registry-check.txt"
import json, sys
d = json.load(open(sys.argv[1]))
if not d:
    print("registry did not answer")
for name in ("ingestion-service", "analytics-service"):
    insts = d.get(name, [])
    urls = {i["url"] for i in insts}
    dcs = sorted({i["location"]["dc"] for i in insts})
    print(f"{name}: {len(insts)} instances, dcs={','.join(dcs)}")
    for i in insts:
        print(f"    {i['id']}  ->  {i['url']}")
    ok = len(urls) >= 2 and dcs == ["dc1", "dc2"] and all(":5" in u and "10.42." in u for u in urls)
    print(f"RESULT {name} {'OK' if ok else 'BAD'}")
EOF
for s in ingestion-service analytics-service; do
  grep -q "RESULT $s OK" "$EVID/2-registry-check.txt" \
    && ok "$s: one entry per pod (pod IPs), in dc1 and dc2" || bad "$s: replicas collapse or locations missing"
done
grep -q "\.$K3S_MASTER\.rack1\.dc1\.centro\.pt" "$EVID/2-registry-services.json" \
  && ok "IDs carry the k3s node as physical location (…$K3S_MASTER.rack1.dc1.centro.pt)" || bad "IDs do not contain the node name"

section "3. Data flow and location-aware discovery"
q='sum by (dc) (increase(ingestion_readings_total{result="accepted"}[1m]) * on(instance) group_left(dc) max by (instance, dc) (service_info))'
info "waiting 30 s for readings"; sleep 30
prom_query "$q" | tee "$EVID/3-readings-per-dc.txt"
for dc in dc1 dc2; do
  v=$(grep "dc=$dc" "$EVID/3-readings-per-dc.txt" | awk '{print $NF}')
  python3 -c "import sys; sys.exit(0 if float('${v:-0}') > 0 else 1)" \
    && ok "ingestion-$dc accepted readings (${v%.*} in 1 min): the $dc sensor uses its own location" \
    || bad "no readings accepted by ingestion-$dc"
done
prom_query 'storage_rows' | tee "$EVID/3-storage-rows.txt"
grep -qE '\} [1-9]' "$EVID/3-storage-rows.txt" && ok "storage holds readings" || bad "storage is empty"

section "4. Exposure"
ensure_client "$CLIENT"; CIP=$(ip_of "$CLIENT")
code=$(incus exec "$CLIENT" -- python3 -c "import urllib.request; print(urllib.request.urlopen('$(public_url analytics)/stats', timeout=5).status)" 2>/dev/null)
[ "$code" = 200 ] && ok "analytics answers on NodePort 30003" || bad "analytics NodePort did not answer ($code)"
sleep 1
incus exec "$K3S_MASTER" -- sh -c 'tail -n 20 /var/log/ssle/analytics-dc1-*/access.log' > "$EVID/4-access-log.txt" 2>/dev/null
grep -q "\"srcip\": \"$CIP\"\|\"srcip\":\"$CIP\"" "$EVID/4-access-log.txt" \
  && ok "the pod logged the real client IP $CIP (externalTrafficPolicy Local)" || bad "client IP $CIP not in the pod's log (SNAT?)"
[ "$(kctl get svc registry -o jsonpath='{.spec.type}')" = ClusterIP ] && ok "registry is ClusterIP only" || bad "registry is exposed"
[ "$(kctl get svc storage -o jsonpath='{.spec.type}')" = ClusterIP ] && ok "storage is ClusterIP only" || bad "storage is exposed"

section "5. Monitoring"
prom_query 'count by (job) (up{job=~"ssle-.+"} == 1)' | tee "$EVID/5-targets-up.txt"
for j in registry storage ingestion analytics sensor; do
  grep -q "job=ssle-$j}" "$EVID/5-targets-up.txt" && ok "in-cluster Prometheus scrapes ssle-$j" || bad "ssle-$j not scraped"
done
CENTRAL="http://$(ip_of "$PROM_CONTAINER"):9090"
PROM_URL=$CENTRAL prom_query 'location:instances:count{cluster="k3s"}' | tee "$EVID/5-central-federation.txt"
grep -q "dc=dc2" "$EVID/5-central-federation.txt" \
  && ok "central Prometheus federates the per-location aggregates (dc1 + dc2)" \
  || bad "central Prometheus has no k3s aggregates (PLATFORM=k3s ./apply-configs.sh prometheus)"

section "6. SIEM"
for n in "$K3S_MASTER" "$K3S_NODE1"; do
  incus exec "$n" -- systemctl is-active -q wazuh-agent && ok "Wazuh agent active on $n" || bad "no Wazuh agent on $n (k3s/install-wazuh-node-agents.sh)"
done
# A pod's access.log only exists after its first request, and the agent only reads it once its
# logcollector has picked the new file up. Warm up the dc2 pod and wait for that, otherwise a
# freshly (re)started pod makes this check race the agent.
POD2=$(kctl get pod -l app=analytics,dc=dc2 --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
incus exec "$CLIENT" -- python3 -c "import urllib.request; urllib.request.urlopen('$(public_url analytics "$K3S_NODE1")/stats', timeout=5)" 2>/dev/null
for i in $(seq 1 75); do
  incus exec "$K3S_NODE1" -- grep -q "/var/log/ssle/$POD2/access.log" /var/ossec/logs/ossec.log 2>/dev/null && break; sleep 1
done
MARK=$(alerts_mark)
for i in 1 2 3; do incus exec "$CLIENT" -- python3 -c "import urllib.request; urllib.request.urlopen('$(public_url analytics "$K3S_NODE1")/stats', timeout=5)" 2>/dev/null; done
if wait_alert "$MARK" 100200 20 "\"srcip\":\"$CIP\"" > "$EVID/6-wazuh-100200.json"; then
  ok "pod access log reached the manager through the node agent"
  alert_summary < "$EVID/6-wazuh-100200.json" | head -4
  grep -q '"id":"analytics-service-analytics-dc2' "$EVID/6-wazuh-100200.json" && ok "the event carries the pod's hierarchical ID (dc2)" || bad "no pod ID in the event"
else
  bad "no rule 100200 event from the k3s pods"
fi

section "7. Self-healing"
running() { kctl get pod -l "$1" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
OLD=$(running app=ingestion,dc=dc1)
if [ -z "$OLD" ]; then
  bad "no running ingestion-dc1 pod to delete (cluster not healthy, see sections 0-1)"
else
  OLDIP=$(kctl get pod "$OLD" -o jsonpath='{.status.podIP}')
  kctl delete pod "$OLD" --wait=false >/dev/null
  kctl rollout status deploy ingestion-dc1 --timeout=90s >/dev/null
  NEW=""; for i in $(seq 1 30); do NEW=$(running app=ingestion,dc=dc1); [ -n "$NEW" ] && [ "$NEW" != "$OLD" ] && break; sleep 2; done
  if [ -n "$NEW" ] && [ "$NEW" != "$OLD" ]; then
    NEWIP=$(kctl get pod "$NEW" -o jsonpath='{.status.podIP}')
    ok "pod $OLD replaced by $NEW ($NEWIP)"
    svcs=""
    for i in $(seq 1 40); do
      svcs=$(near curl -s "$REG/services/ingestion-service?dc=dc1&node=$K3S_MASTER")
      echo "$svcs" | grep -q "$NEWIP:" && break; sleep 1
    done
    echo "$svcs" | grep -q "$NEWIP:" && ok "the new pod ($NEWIP) registered itself" || bad "new pod $NEWIP not in the registry"
    # Removal needs MAX_FAILURES=2 failed sweeps, 10 s apart, and a deleted pod's IP does not
    # answer, so each check waits its 2 s timeout: up to ~1 min in practice (test-rootcause: 54 s).
    T_DEL=$(now)
    for i in $(seq 1 90); do near curl -s "$REG/services" | grep -q "$OLDIP:" || break; sleep 1; done
    near curl -s "$REG/services" | grep -q "$OLDIP:" && bad "old pod ($OLDIP) still registered after 90 s" \
      || ok "old pod ($OLDIP) removed by the health checker ($(elapsed "$T_DEL" "$(now)") s after the new pod registered)"
  else
    bad "pod $OLD was not replaced by a running pod"
  fi
fi

finish
