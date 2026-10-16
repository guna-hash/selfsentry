"""Durable gate-decision journal. HTTP replays use the backend's audit event key."""

import json
import os
from pathlib import Path
import sqlite3
import uuid

import requests
from backend_auth import backend_headers

ROOT = Path(__file__).resolve().parents[1]


def connect():
    path = Path(os.environ.get("SELFSENTRY_STATE_DIR", ROOT / "state")) / "deployments.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=1)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS decisions (key TEXT PRIMARY KEY, body TEXT)")
    return db


def enqueue(record):
    record.setdefault("event_key", uuid.uuid4().hex)
    db = connect()
    try:
        with db:
            db.execute(
                "INSERT OR IGNORE INTO decisions VALUES (?,?)",
                (record["event_key"], json.dumps(record)),
            )
    finally:
        db.close()


def acknowledge(key):
    db = connect()
    try:
        with db:
            db.execute("DELETE FROM decisions WHERE key=?", (key,))
    finally:
        db.close()


def flush(backend_url):
    db = connect()
    try:
        rows = db.execute("SELECT key,body FROM decisions ORDER BY rowid LIMIT 20").fetchall()
    finally:
        db.close()
    for key, body in rows:
        try:
            result = requests.post(
                backend_url + "/deployments/",
                json=json.loads(body),
                timeout=5,
                headers=backend_headers(),
            )
            if result.status_code != 201:
                break  # Retain rejected records too: visible for operator inspection.
        except requests.RequestException:
            break
        acknowledge(key)
