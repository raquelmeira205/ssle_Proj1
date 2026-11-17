"""2.4 Storage Service (port 5002): persists temperature readings in SQLite and exposes them via an API."""
import os
import sqlite3

from flask import Flask, jsonify, request

from common import register_in_background

PORT = 5002
SERVICE_NAME = "storage-service"
DB = os.getenv("DB_PATH", "temp_data.db")

app = Flask(__name__)


def connect():
    return sqlite3.connect(DB, timeout=10)


def init_db():
    conn = connect()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS temperatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            temperature REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


@app.route("/store", methods=["POST"])
def store():
    data = request.get_json(silent=True) or {}
    try:
        device_id, temperature = str(data["device_id"]), float(data["temperature"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "device_id and numeric temperature are required"}), 400
    conn = connect()
    c = conn.cursor()
    c.execute("INSERT INTO temperatures (device_id, temperature) VALUES (?, ?)", (device_id, temperature))
    conn.commit()
    conn.close()
    return jsonify({"status": "stored"}), 200


@app.route("/temperatures", methods=["GET"])
def temperatures():
    """Data retrieval: newest first. Optional ?device_id=...&limit=N (max 10000)."""
    device_id = request.args.get("device_id")
    limit = min(request.args.get("limit", default=100, type=int), 10000)
    query, params = "SELECT id, device_id, temperature, timestamp FROM temperatures", []
    if device_id:
        query += " WHERE device_id = ?"
        params.append(device_id)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    conn = connect()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    keys = ("id", "device_id", "temperature", "timestamp")
    return jsonify([dict(zip(keys, r)) for r in rows])


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    register_in_background(SERVICE_NAME, PORT)
    app.run(host="0.0.0.0", port=PORT)
