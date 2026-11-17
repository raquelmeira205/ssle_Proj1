#!/usr/bin/env python3
import argparse, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

def send_req(url, timeout):
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            r.read()
            return (time.perf_counter() - t0) * 1000.0, r.status
    except urllib.error.HTTPError as e:
        return (time.perf_counter() - t0) * 1000.0, e.code
    except Exception:
        return (time.perf_counter() - t0) * 1000.0, 0

def run_phase(name, url, duration, workers, delay, timeout):
    latencies, ok, failed = [], 0, 0
    stop_at = time.time() + duration

    def worker():
        nonlocal ok, failed
        while time.time() < stop_at:
            ms, status = send_req(url, timeout)
            latencies.append(ms)
            if 200 <= status < 400:
                ok += 1
            else:
                failed += 1
            if delay > 0:
                time.sleep(delay)

    t_start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for _ in range(workers):
            ex.submit(worker)
    elapsed = max(time.time() - t_start, 0.001)

    total = ok + failed
    s_lat = sorted(latencies) if latencies else [0.0]
    p50 = s_lat[int(0.50 * (len(s_lat) - 1))]
    p95 = s_lat[int(0.95 * (len(s_lat) - 1))]
    print(f"=== {name} ({elapsed:.1f}s) ===")
    print(f"  Total requests : {total} (OK: {ok}, Failed/Blocked: {failed})")
    print(f"  Throughput     : {ok / elapsed:.2f} ok req/s ({total / elapsed:.2f} total req/s)")
    print(f"  Latency p50    : {p50:.2f} ms")
    print(f"  Latency p95    : {p95:.2f} ms\n")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://10.255.255.133:5003/stats?limit=10000")
    ap.add_argument("--duration", type=int, default=15)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--label", default="Phase")
    args = ap.parse_args()
    run_phase(args.label, args.url, args.duration, args.workers, args.delay, args.timeout)
