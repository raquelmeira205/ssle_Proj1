"""2.5 Analytics Service (port 5003): turns stored readings into averages / min / max.

It reads through the Storage service API (found via the registry) instead of opening the
SQLite file directly, so it keeps working when the services run in separate containers.
"""
import os

import requests
from flask import Flask, jsonify, request

from common import lookup, register_in_background

PORT = 5003
SERVICE_NAME = "analytics-service"

app = Flask(__name__)


def fetch_values():
    """Return temperature values (newest first) for ?device_id= / ?limit=, or raise."""
    params = {"limit": request.args.get("limit", default=1000, type=int)}
    if request.args.get("device_id"):
        params["device_id"] = request.args["device_id"]
    storage_url = lookup("storage-service", os.getenv("STORAGE_URL", "http://localhost:5002"))
    r = requests.get(f"{storage_url}/temperatures", params=params, timeout=5)
    r.raise_for_status()
    return [row["temperature"] for row in r.json()]


@app.route("/average", methods=["GET"])
def average_temp():
    try:
        values = fetch_values()
    except requests.RequestException as e:
        return jsonify({"error": f"storage unavailable: {e}"}), 502
    avg = sum(values) / len(values) if values else None
    return jsonify({"average_temperature": round(avg, 2) if avg is not None else None})


@app.route("/stats", methods=["GET"])
def stats():
    try:
        values = fetch_values()
    except requests.RequestException as e:
        return jsonify({"error": f"storage unavailable: {e}"}), 502
    if not values:
        return jsonify({"count": 0})
    return jsonify({
        "count": len(values),
        "average": round(sum(values) / len(values), 2),
        "min": min(values),
        "max": max(values),
        "latest": values[0],
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    register_in_background(SERVICE_NAME, PORT)
    app.run(host="0.0.0.0", port=PORT)
