"""Helpers shared by the services: hierarchical location identity, self-registration
(with heartbeat), location-aware discovery and Prometheus instrumentation."""
import os
import socket
import threading
import time

import requests
from flask import Response, g, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:5050").rstrip("/")

# ------------------------------------------------------------------ location / naming
LOCATION_LEVELS = ("country", "region", "dc", "rack", "node")   # coarse -> fine


def _part(value):
    # Dots separate the levels of the hierarchical ID, so they cannot appear inside one.
    return str(value).strip().lower().replace(".", "-") or "unknown"


LOCATION = {
    "country": _part(os.getenv("COUNTRY", "pt")),
    "region": _part(os.getenv("REGION", "region0")),
    "dc": _part(os.getenv("DC", "dc0")),
    "rack": _part(os.getenv("RACK", "rack0")),
    "node": _part(os.getenv("NODE", socket.gethostname())),
}
INSTANCE = _part(os.getenv("INSTANCE", "01"))


def instance_id(service_name):
    """Hierarchical ID, most specific first (like DNS):
    storage-service-01.node1.rack1.dc1.centro.pt"""
    return ".".join([f"{service_name}-{INSTANCE}"] + [LOCATION[lvl] for lvl in reversed(LOCATION_LEVELS)])


# PREFER_SCOPE = how close a discovered instance should be: node | rack | dc | region | country | none
PREFER_SCOPE = os.getenv("PREFER_SCOPE", "dc").lower()


def _preferred_filters():
    if PREFER_SCOPE not in LOCATION_LEVELS:
        return {}
    last = LOCATION_LEVELS.index(PREFER_SCOPE)
    return {lvl: LOCATION[lvl] for lvl in LOCATION_LEVELS[: last + 1]}


# ------------------------------------------------------------------ registry client
def _register_loop(name, url, interval):
    # Registering is an idempotent upsert, so repeating it works as a heartbeat and
    # also recovers automatically if the registry starts late or restarts.
    payload = {"name": name, "url": url, "id": instance_id(name), "location": LOCATION}
    while True:
        try:
            requests.post(f"{REGISTRY_URL}/register", json=payload, timeout=3)
        except requests.RequestException as exc:
            print(f"[{name}] registry unreachable: {exc}", flush=True)
        time.sleep(interval)


def register_in_background(name, port, interval=10):
    """Advertise this service (and where it lives) to the registry. SERVICE_URL overrides
    the advertised address (needed inside containers, e.g. http://storage:5002)."""
    url = os.getenv("SERVICE_URL", f"http://localhost:{port}").rstrip("/")
    threading.Thread(target=_register_loop, args=(name, url, interval), daemon=True).start()
    return url


def lookup(name, fallback):
    """Ask the registry for a healthy instance of `name` (round-robin), preferring the
    closest ones (PREFER_SCOPE). Widens to any instance, then to the `fallback` URL."""
    preferred = _preferred_filters()
    for params in ([preferred, {}] if preferred else [{}]):
        try:
            r = requests.get(f"{REGISTRY_URL}/services/{name}", params=params, timeout=3)
        except requests.RequestException:
            break
        if r.status_code == 200:
            return r.json()["url"].rstrip("/")
    return fallback.rstrip("/")


# ------------------------------------------------------------------ Prometheus metrics
HTTP_REQUESTS = Counter("http_requests_total", "HTTP requests handled",
                        ["service", "method", "endpoint", "status"])
HTTP_LATENCY = Histogram("http_request_duration_seconds", "HTTP request latency",
                         ["service", "method", "endpoint"],
                         buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10))
HTTP_INFLIGHT = Gauge("http_requests_in_progress", "Requests currently being handled", ["service"])
# Always 1. Join it onto other series to get the location of an instance:
#   <metric> * on(instance) group_left(id, node, rack, dc, region, country) service_info
SERVICE_INFO = Gauge("service_info", "Identity and location of this instance",
                     ["service", "id", *LOCATION_LEVELS])

_KNOWN_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def publish_identity(service_name):
    SERVICE_INFO.labels(service=service_name, id=instance_id(service_name), **LOCATION).set(1)


def instrument(app, service_name):
    """Expose GET /metrics and record request count, latency and in-flight requests.
    The endpoint label is the route pattern, not the URL, so cardinality stays bounded."""
    publish_identity(service_name)

    @app.route("/metrics", methods=["GET"])
    def metrics():
        return Response(generate_latest(), content_type=CONTENT_TYPE_LATEST)

    @app.before_request
    def _begin():
        if request.path == "/metrics":
            return
        g._started = time.perf_counter()
        HTTP_INFLIGHT.labels(service_name).inc()

    @app.after_request
    def _finish(resp):
        if hasattr(g, "_started"):
            endpoint = request.url_rule.rule if request.url_rule else "unmatched"
            method = request.method if request.method in _KNOWN_METHODS else "OTHER"
            HTTP_REQUESTS.labels(service_name, method, endpoint, resp.status_code).inc()
            HTTP_LATENCY.labels(service_name, method, endpoint).observe(time.perf_counter() - g._started)
        return resp

    @app.teardown_request
    def _end(_exc):
        if hasattr(g, "_started"):
            HTTP_INFLIGHT.labels(service_name).dec()
