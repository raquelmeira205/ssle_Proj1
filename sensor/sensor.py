"""2.3 Temperature sensor (Celsius): finds the Ingestion service via the registry and posts readings."""
import os
import random
import time

import requests

from common import lookup

DEVICE_ID = os.getenv("DEVICE_ID", "sensor-001")
INTERVAL = float(os.getenv("INTERVAL", "5"))


def send_temp():
    while True:
        temp = round(random.uniform(20.0, 30.0), 2)
        payload = {"device_id": DEVICE_ID, "temperature": temp}
        url = lookup("ingestion-service", os.getenv("INGESTION_URL", "http://localhost:5001"))
        try:
            requests.post(f"{url}/ingest", json=payload, timeout=5)
            print("Sent:", payload, "->", url, flush=True)
        except Exception as e:
            print("Error:", e, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    send_temp()
