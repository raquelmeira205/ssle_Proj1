"""2.2 Ingestion Service (port 5001): entry point that validates data and routes it to Storage."""
import os

import requests
from flask import Flask, jsonify, request
from prometheus_client import Counter

from common import instrument, lookup, register_in_background

PORT = 5001
SERVICE_NAME = "ingestion-service"

app = Flask(__name__)
instrument(app, SERVICE_NAME)

# No per-device label on purpose: device_id comes from unauthenticated clients, so it would
# let anyone blow up the number of time series.
READINGS = Counter("ingestion_readings_total", "Readings received, by outcome", ["result"])


@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json(silent=True) or {}
    print("Received:", data, flush=True)

    # Normalisation / validation
    try:
        payload = {"device_id": str(data["device_id"]), "temperature": float(data["temperature"])}
    except (KeyError, TypeError, ValueError):
        READINGS.labels("invalid").inc()
        return jsonify({"error": "device_id and numeric temperature are required"}), 400

    # Routing: find a Storage instance through the registry (re-resolved on every call)
    storage_url = lookup("storage-service", os.getenv("STORAGE_URL", "http://localhost:5002"))
    try:
        res = requests.post(f"{storage_url}/store", json=payload, timeout=5)
        res.raise_for_status()
        READINGS.labels("accepted").inc()
        return jsonify({"stored": True}), res.status_code
    except requests.RequestException as e:
        READINGS.labels("storage_error").inc()
        return jsonify({"error": str(e)}), 502


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    register_in_background(SERVICE_NAME, PORT)
    app.run(host="0.0.0.0", port=PORT)
