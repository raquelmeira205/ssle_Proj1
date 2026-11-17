"""2.1 Service Registry (port 5050): registration, discovery, health checking, load balancing."""
import itertools
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

HEALTH_INTERVAL = 10      # seconds between health sweeps
MAX_FAILURES = 2          # consecutive failed checks before an instance is removed

# registry[name] = {url: {"timestamp": iso8601, "failures": int}}
registry = {}
counters = {}             # round-robin counter per service name
lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    name, url = data.get("name"), data.get("url")
    if not name or not url:
        return jsonify({"error": "Missing name or url"}), 400
    with lock:
        registry.setdefault(name, {})[url.rstrip("/")] = {"timestamp": now(), "failures": 0}
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
                if not registry[name]:
                    del registry[name]
            else:                                      # remove every instance
                del registry[name]
            return jsonify({"message": f"{name} unregistered"}), 200
    return jsonify({"error": "Not found"}), 404


@app.route("/services", methods=["GET"])
def services():
    with lock:
        return jsonify({
            n: [{"url": u, "timestamp": i["timestamp"]} for u, i in insts.items()]
            for n, insts in registry.items()
        })


@app.route("/services/<name>", methods=["GET"])
def get_service(name):
    """Discovery + load balancing: returns ONE instance, rotating round-robin."""
    with lock:
        insts = sorted(registry.get(name, {}))
        if not insts:
            return jsonify({"error": "Not found"}), 404
        url = insts[next(counters.setdefault(name, itertools.count())) % len(insts)]
        return jsonify({"name": name, "url": url, "timestamp": registry[name][url]["timestamp"]})


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
            with lock:
                inst = registry.get(name, {}).get(url)
                if inst is None:
                    continue
                inst["failures"] = 0 if ok else inst["failures"] + 1
                if inst["failures"] >= MAX_FAILURES:
                    del registry[name][url]
                    if not registry[name]:
                        del registry[name]
                    print(f"removed unhealthy {name} @ {url}", flush=True)


if __name__ == "__main__":
    threading.Thread(target=health_checker, daemon=True).start()
    app.run(host="0.0.0.0", port=5050)
