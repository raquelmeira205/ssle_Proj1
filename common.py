"""Helpers shared by the services: self-registration (with heartbeat) and discovery."""
import os
import threading
import time

import requests

REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:5050").rstrip("/")


def _register_loop(name, url, interval):
    # Registering is an idempotent upsert, so repeating it works as a heartbeat and
    # also recovers automatically if the registry starts late or restarts.
    while True:
        try:
            requests.post(f"{REGISTRY_URL}/register", json={"name": name, "url": url}, timeout=3)
        except requests.RequestException as exc:
            print(f"[{name}] registry unreachable: {exc}", flush=True)
        time.sleep(interval)


def register_in_background(name, port, interval=10):
    """Advertise this service to the registry. SERVICE_URL overrides the advertised
    address (needed inside containers, e.g. http://storage:5002)."""
    url = os.getenv("SERVICE_URL", f"http://localhost:{port}").rstrip("/")
    threading.Thread(target=_register_loop, args=(name, url, interval), daemon=True).start()
    return url


def lookup(name, fallback):
    """Ask the registry for a healthy instance of `name` (round-robin).
    Falls back to a configured URL if the registry has nothing."""
    try:
        r = requests.get(f"{REGISTRY_URL}/services/{name}", timeout=3)
        if r.status_code == 200:
            return r.json()["url"].rstrip("/")
    except requests.RequestException:
        pass
    return fallback.rstrip("/")
