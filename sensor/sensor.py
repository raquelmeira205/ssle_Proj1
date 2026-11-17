"""2.3 Temperature sensor (Celsius): finds the Ingestion service via the registry and posts readings.

It has no HTTP API, so it exposes its own metrics on METRICS_PORT (default 8000)."""
import os
import random
import time

import requests
from prometheus_client import Counter, Gauge, start_http_server

from common import lookup, publish_identity

SERVICE_NAME = "temperature-sensor"
DEVICE_ID = os.getenv("DEVICE_ID", "sensor-001")
INTERVAL = float(os.getenv("INTERVAL", "5"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "8000"))

SENT = Counter("sensor_readings_sent_total", "Readings sent to ingestion, by outcome", ["result"])
LAST_TEMP = Gauge("sensor_last_temperature_celsius", "Last generated reading")


def send_temp():
    while True:
        temp = round(random.uniform(20.0, 30.0), 2)
        LAST_TEMP.set(temp)
        payload = {"device_id": DEVICE_ID, "temperature": temp}
        url = lookup("ingestion-service", os.getenv("INGESTION_URL", "http://localhost:5001"))
        try:
            r = requests.post(f"{url}/ingest", json=payload, timeout=5)
            SENT.labels("ok" if r.ok else "rejected").inc()
            print("Sent:", payload, "->", url, flush=True)
        except Exception as e:
            SENT.labels("error").inc()
            print("Error:", e, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    publish_identity(SERVICE_NAME)
    start_http_server(METRICS_PORT)
    send_temp()
