#!/usr/bin/env bash
# Experiment for the report (TODO: repeated runs + Prometheus resources). Not part of the platform.
# Runs each k3s threat test N times and keeps every run under evidence/k3s/repeats/<test>/runN/.
# The single-run evidence in evidence/k3s/<test>/ is restored afterwards, so the report's
# references stay valid. During the scale runs, resources are sampled every 5 s
# (kubectl top for every pod, Prometheus head series and memory, Incus containers' memory).
# Run on the Incus host from the repo root:  report/experiments/repeat-tests.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
N=${N:-5}; N_SCALE=${N_SCALE:-3}
TESTS=${TESTS:-"ddos spam dns rootcause scale"}
R=evidence/k3s/repeats; mkdir -p "$R"
BK=$(mktemp -d)
for t in $TESTS; do [ -d "evidence/k3s/$t" ] && cp -a "evidence/k3s/$t" "$BK/$t"; done
restore() { for t in $TESTS; do [ -d "$BK/$t" ] && rm -rf "evidence/k3s/$t" && cp -a "$BK/$t" "evidence/k3s/$t"; done; rm -rf "$BK"; }
trap restore EXIT

MASTER_IP=$(incus list '^k3s-master$' -c4 --format csv | grep -oE '[0-9.]+ \(eth0\)' | cut -d' ' -f1)
wait_unblocked() {   # previous run's 60 s blocks must expire, or the next attack starts blocked
  until [ "$(incus exec k3s-master -- iptables -t raw -S PREROUTING | grep -c DROP)" -eq 0 ] \
     && [ "$(incus exec mail-container -- iptables -S INPUT | grep -c DROP)" -eq 0 ]; do sleep 3; done
}
sampler() {   # $1 = output file; runs until killed
  while true; do
    echo "## $(date -Is)"
    incus exec k3s-master -- k3s kubectl -n ssle top pods --no-headers 2>/dev/null
    curl -s --max-time 3 "http://$MASTER_IP:30090/metrics" | grep -E '^(prometheus_tsdb_head_series|process_resident_memory_bytes|process_cpu_seconds_total) ' | sed 's/^/prom-incluster /'
    for c in prometheus-container wazuh-container; do
      printf "incus %s memory_MiB " "$c"; incus info "$c" | awk '/Memory \(current\)/{print $3}'
    done
    sleep 5
  done
}

for t in $TESTS; do
  n=$N; [ "$t" = scale ] && n=$N_SCALE
  for i in $(seq 1 "$n"); do
    wait_unblocked
    d="$R/$t/run$i"; mkdir -p "$d"
    args=""; case $t in ddos|spam) args="--no-wait" ;; esac
    echo "$(date +%T) $t run $i/$n"
    if [ "$t" = scale ]; then sampler > "$d/resources.txt" 2>&1 & SP=$!; fi
    PLATFORM=k3s "./test-$t.sh" $args > /dev/null 2>&1
    [ "$t" = scale ] && kill "$SP" 2>/dev/null
    cp "evidence/k3s/$t/run.log" "$d/" 2>/dev/null
    cp "evidence/k3s/$t/summary.txt" "$d/" 2>/dev/null
    grep '^Result' "$d/run.log" | sed "s/^/    /"
  done
done
echo "done $(date +%T)"
