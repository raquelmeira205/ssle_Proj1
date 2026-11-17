"""2.1 Service Registry (port 5050): registration, discovery, health checking, load balancing.

Every instance registers a hierarchical ID and a location (country > region > dc > rack > node),
so services can be found, filtered and counted by place:
    GET /services?dc=dc1&rack=rack2      GET /services/<name>?region=centro      GET /tree
"""
import itertools
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request
from prometheus_client import Counter
from prometheus_client.core import REGISTRY as PROM_REGISTRY, GaugeMetricFamily

from common import LOCATION_LEVELS, instrument

app = Flask(__name__)
instrument(app, "registry-service")

HEALTH_INTERVAL = 10      # seconds between health sweeps
MAX_FAILURES = 2          # consecutive failed checks before an instance is removed

# registry[name] = {url: {"timestamp": iso8601, "failures": int, "id": str, "location": {level: str}}}
registry = {}
counters = {}             # round-robin counter per service name
lock = threading.Lock()

# Metrics. Labels are kept free of client-controlled values (no service names) to bound cardinality.
REGISTRATIONS = Counter("registry_registrations_total", "Register calls accepted (heartbeats included)")
REMOVALS = Counter("registry_removals_total", "Instances removed from the registry", ["reason"])
HEALTH_FAILURES = Counter("registry_health_check_failures_total", "Failed instance health checks")


class InstanceCollector:
    """Computed at scrape time: how many instances are registered, per service and place."""

    def collect(self):
        fam = GaugeMetricFamily("registry_instances", "Registered service instances",
                                labels=["service", *LOCATION_LEVELS])
        counts = {}
        with lock:
            for name, insts in registry.items():
                for info in insts.values():
                    key = (name, *(info["location"][lvl] for lvl in LOCATION_LEVELS))
                    counts[key] = counts.get(key, 0) + 1
        for key, n in counts.items():
            fam.add_metric(list(key), n)
        yield fam


PROM_REGISTRY.register(InstanceCollector())


def now():
    return datetime.now(timezone.utc).isoformat()


def clean_location(raw):
    raw = raw if isinstance(raw, dict) else {}
    return {lvl: str(raw.get(lvl) or "unknown")[:64] for lvl in LOCATION_LEVELS}


def location_filters():
    """?country=&region=&dc=&rack=&node= from the query string."""
    return {lvl: request.args[lvl] for lvl in LOCATION_LEVELS if request.args.get(lvl)}


def matches(info, filters):
    return all(info["location"][lvl] == value for lvl, value in filters.items())


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    name, url = data.get("name"), data.get("url")
    if not isinstance(name, str) or not isinstance(url, str) or not name or not url:
        return jsonify({"error": "Missing name or url"}), 400
    info = {
        "timestamp": now(),
        "failures": 0,
        "id": str(data.get("id") or name)[:200],
        "location": clean_location(data.get("location")),
    }
    with lock:
        registry.setdefault(name, {})[url.rstrip("/")] = info
    REGISTRATIONS.inc()
    return jsonify({"message": f"{name} registered"}), 200


@app.route("/unregister", methods=["DELETE"])
def unregister():
    data = request.get_json(silent=True) or {}
    name, url = data.get("name"), data.get("url")
    with lock:
        if name in registry:
            if url:                                    # remove one instance
                if registry[name].pop(url.rstrip("/"), None) is None:
                    return jsonify({"error": "Not found"}), 404
                removed = 1
                if not registry[name]:
                    del registry[name]
            else:                                      # remove every instance
                removed = len(registry.pop(name))
            REMOVALS.labels("unregister").inc(removed)
            return jsonify({"message": f"{name} unregistered"}), 200
    return jsonify({"error": "Not found"}), 404


@app.route("/services", methods=["GET"])
def services():
    filters = location_filters()
    out = {}
    with lock:
        for name, insts in registry.items():
            items = [{"url": u, "id": i["id"], "location": i["location"], "timestamp": i["timestamp"]}
                     for u, i in insts.items() if matches(i, filters)]
            if items:
                out[name] = items
    return jsonify(out)


@app.route("/services/<name>", methods=["GET"])
def get_service(name):
    """Discovery + load balancing: returns ONE instance, rotating round-robin.
    Optional location filters restrict the candidates (e.g. ?dc=dc1)."""
    filters = location_filters()
    with lock:
        insts = sorted(u for u, i in registry.get(name, {}).items() if matches(i, filters))
        if not insts:
            return jsonify({"error": "Not found"}), 404
        url = insts[next(counters.setdefault(name, itertools.count())) % len(insts)]
        info = registry[name][url]
        return jsonify({"name": name, "url": url, "id": info["id"],
                        "location": info["location"], "timestamp": info["timestamp"]})


@app.route("/tree", methods=["GET"])
def tree():
    """Instance counts as a hierarchy: country > region > dc > rack > node."""
    root = {"count": 0, "children": {}}
    with lock:
        for insts in registry.values():
            for info in insts.values():
                cur = root
                for lvl in LOCATION_LEVELS:
                    cur = cur["children"].setdefault(
                        info["location"][lvl], {"level": lvl, "count": 0, "children": {}})
                    cur["count"] += 1
    return jsonify(root["children"])


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


def health_checker():
    """Periodically ping every instance's /health; drop the ones that stop answering."""
    while True:
        time.sleep(HEALTH_INTERVAL)
        with lock:
            targets = [(n, u) for n, insts in registry.items() for u in insts]
        for name, url in targets:
            try:
                ok = requests.get(f"{url}/health", timeout=2).status_code == 200
            except requests.RequestException:
                ok = False
            if not ok:
                HEALTH_FAILURES.inc()
            with lock:
                inst = registry.get(name, {}).get(url)
                if inst is None:
                    continue
                inst["failures"] = 0 if ok else inst["failures"] + 1
                if inst["failures"] >= MAX_FAILURES:
                    del registry[name][url]
                    if not registry[name]:
                        del registry[name]
                    REMOVALS.labels("unhealthy").inc()
                    print(f"removed unhealthy {name} @ {url}", flush=True)


if __name__ == "__main__":
    threading.Thread(target=health_checker, daemon=True).start()
    app.run(host="0.0.0.0", port=5050)
