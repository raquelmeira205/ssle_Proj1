#!/usr/bin/env python3
"""Scalability measurements for test-scale.sh (stdlib only, runs in any container).

  load      closed-loop HTTP load against one or more instances (round-robin), e.g.
            scale-tool.py load --urls http://a:5001/ingest,http://b:5001/ingest --method POST
  registry  grows the service registry with N fake instances spread over many locations and
            measures registration rate, filtered lookup latency, /tree latency and the payload
            size of an unfiltered vs a location-filtered query.

Both print a human summary and machine-readable "RESULT key=value ..." lines.
"""
import argparse
import itertools
import json
import random
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def http(method, url, body=None, timeout=5.0):
    """Returns (status, bytes, seconds). Status 0 = no answer."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
            return r.status, len(payload), time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        return e.code, 0, time.perf_counter() - t0
    except Exception:
        return 0, 0, time.perf_counter() - t0


def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    return s[int(p * (len(s) - 1))]


# ---------------------------------------------------------------- load
def cmd_load(a):
    urls = [u for u in a.urls.split(",") if u]
    body = json.loads(a.body) if a.body else None
    rr = itertools.cycle(urls)
    lock = threading.Lock()
    lat, ok, failed = [], 0, 0
    stop_at = time.time() + a.duration

    def worker():
        nonlocal ok, failed
        while time.time() < stop_at:
            with lock:
                url = next(rr)
            status, _, sec = http(a.method, url, body, a.timeout)
            with lock:
                lat.append(sec * 1000)
                if 200 <= status < 300:
                    ok += 1
                else:
                    failed += 1

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for _ in range(a.workers):
            ex.submit(worker)
    elapsed = max(time.time() - t0, 0.001)
    print(f"=== {a.label}: {a.workers} workers, {len(urls)} instance(s), {elapsed:.1f}s ===")
    print(f"  ok {ok}, failed {failed}, {ok / elapsed:.1f} ok req/s, "
          f"p50 {pct(lat, .5):.0f} ms, p95 {pct(lat, .95):.0f} ms")
    print(f"RESULT ok={ok} failed={failed} rps={ok / elapsed:.1f} p50={pct(lat, .5):.0f} p95={pct(lat, .95):.0f}")


# ---------------------------------------------------------------- registry
COUNTRIES = ["pt", "es"]
REGIONS = ["norte", "centro", "sul"]


def fake_location(i):
    """Deterministic spread: 2 countries x 3 regions x 4 dcs x 5 racks x 10 nodes."""
    return {"country": COUNTRIES[i % 2], "region": REGIONS[(i // 2) % 3], "dc": f"dc{(i // 6) % 4 + 1}",
            "rack": f"rack{(i // 24) % 5 + 1}", "node": f"node{(i // 120) % 10 + 1}"}


def cmd_registry(a):
    base = a.registry.rstrip("/")
    name = "scale-fake-service"
    # The registry health-checks <url>/health. "<registry>/health?i=N" + "/health" still hits the
    # registry's own /health (the rest is query string), so fake instances stay healthy and
    # every URL is unique.
    fake_url = lambda i: f"{base}/health?i={i}"
    registered = 0
    print(f"{'instances':>9} {'register/s':>11} {'lookup p50':>11} {'lookup p95':>11} "
          f"{'/tree ms':>9} {'all bytes':>10} {'1 dc bytes':>11} {'1 rack bytes':>13}")
    try:
        for size in [int(s) for s in a.sizes.split(",")]:
            todo = list(range(registered, size))
            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=16) as ex:
                list(ex.map(lambda i: http("POST", f"{base}/register", {
                    "name": name, "url": fake_url(i), "id": f"fake-{i:05d}", "location": fake_location(i)}), todo))
            reg_rate = len(todo) / max(time.perf_counter() - t0, 1e-6) if todo else 0
            registered = size

            rnd = random.Random(size)
            lookups = []
            for _ in range(a.lookups):
                loc = fake_location(rnd.randrange(max(size, 1)))
                q = f"country={loc['country']}&region={loc['region']}&dc={loc['dc']}"
                lookups.append(http("GET", f"{base}/services/{name}?{q}")[2] * 1000)
            tree = [http("GET", f"{base}/tree")[2] * 1000 for _ in range(10)]
            all_b = http("GET", f"{base}/services")[1]
            dc_b = http("GET", f"{base}/services?country=pt&region=norte&dc=dc1")[1]
            rack_b = http("GET", f"{base}/services?country=pt&region=norte&dc=dc1&rack=rack1")[1]
            print(f"{size:>9} {reg_rate:>11.0f} {pct(lookups, .5):>9.1f}ms {pct(lookups, .95):>9.1f}ms "
                  f"{sum(tree) / len(tree):>9.1f} {all_b:>10} {dc_b:>11} {rack_b:>13}")
            print(f"RESULT instances={size} register_per_s={reg_rate:.0f} lookup_p50_ms={pct(lookups, .5):.1f} "
                  f"lookup_p95_ms={pct(lookups, .95):.1f} tree_ms={sum(tree) / len(tree):.1f} "
                  f"all_bytes={all_b} dc_bytes={dc_b} rack_bytes={rack_b}")
    finally:
        http("DELETE", f"{base}/unregister", {"name": name})   # removes every fake instance at once
        print(f"  cleaned up: all {name} instances unregistered")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("load")
    l.add_argument("--urls", required=True, help="comma separated, used round-robin")
    l.add_argument("--method", default="GET")
    l.add_argument("--body", default="", help="JSON body for POST")
    l.add_argument("--workers", type=int, default=10)
    l.add_argument("--duration", type=int, default=20)
    l.add_argument("--timeout", type=float, default=5.0)
    l.add_argument("--label", default="load")
    r = sub.add_parser("registry")
    r.add_argument("--registry", required=True, help="e.g. http://10.255.255.208:5050")
    r.add_argument("--sizes", default="0,100,500,2000")
    r.add_argument("--lookups", type=int, default=200)
    a = ap.parse_args()
    cmd_load(a) if a.cmd == "load" else cmd_registry(a)
