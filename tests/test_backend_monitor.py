"""Real HTTP/ORM tests for additive metadata, idempotency and AI failure isolation."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import database
from models.db_models import Incident, MonitorIncident
from routes import incidents, monitor
import pytest


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    database.Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)

    def get_db():
        with session() as db:
            yield db

    app = FastAPI()
    app.include_router(incidents.router)
    app.include_router(monitor.router)
    app.dependency_overrides[database.get_db] = get_db
    with TestClient(app) as client:
        yield client, session
    engine.dispose()


def body():
    return {
        "container_id": "a" * 12,
        "risk_score": 50,
        "confidence": "low",
        "event_key": "key",
        "defer_ai": True,
        "monitor_evidence": {"anomaly_status": "learning"},
    }


def test_replay_creates_one_incident_with_evidence(client):
    http, session = client
    first = http.post("/incidents/", json=body()).json()
    second = http.post("/incidents/", json=body()).json()
    assert first["id"] == second["id"]
    with session() as db:
        assert db.query(Incident).count() == db.query(MonitorIncident).count() == 1
    assert http.get("/incidents/").json()[0]["monitor_evidence"]["anomaly_status"] == "learning"


def test_ai_failure_preserves_legacy_incident(client):
    http, _ = client
    item = body()
    item.pop("defer_ai")
    with patch.object(incidents, "summarize_incident", side_effect=RuntimeError("offline")):
        response = http.post("/incidents/", json=item)
    assert response.status_code == 200
    assert response.json()["ai_summary"]["status"] == "unavailable"


def test_auto_confirmation_rejects_missing_anomaly(client):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    result = http.post(
        f"/incidents/{saved['id']}/confirm", params={"confirmed_by": "selfsentry-auto"}
    )
    assert result.status_code == 409


def test_human_confirmation_is_preserved(client):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    path = f"/incidents/{saved['id']}/confirm"
    http.post(path, params={"confirmed_by": "alice"})
    result = http.post(path, params={"confirmed_by": "selfsentry-auto"}).json()
    assert result["confirmed_by"] == "alice"


def test_response_state_round_trip(client):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    response = http.post(
        f"/monitor/incidents/{saved['id']}/workflow",
        json={"response": {"status": "isolation_failed"}},
    )
    assert response.status_code == 200
    assert (
        http.get(f"/incidents/{saved['id']}").json()["monitor_workflow"]["response"]["status"]
        == "isolation_failed"
    )


def test_health_readout_reports_stale_state(client, tmp_path, monkeypatch):
    from monitor_status import StatusBoard

    http, _ = client
    monkeypatch.setenv("MONITOR_STATE_DIR", str(tmp_path))
    board = StatusBoard(tmp_path / "status.json")
    board.set_running(True)
    board.write()
    assert http.get("/monitor/status").json()["healthy"] is True
    import json

    file = tmp_path / "status.json"
    state = json.loads(file.read_text())
    state["updated_at"] = "2000-01-01T00:00:00+00:00"
    file.write_text(json.dumps(state))
    assert http.get("/monitor/status").json()["healthy"] is False


def test_valid_dual_layer_auto_confirmation_persists_once(client):
    from datetime import datetime, timezone, timedelta
    from models.db_models import ConfirmedIncident

    http, session = client
    now = datetime.now(timezone.utc)
    ts = now.isoformat()
    data = body()
    data.update(
        risk_score=100,
        confidence="high",
        falco_alert={
            "container_id": "a" * 12,
            "timestamp": ts,
            "rule": "Shell",
            "priority": "Warning",
        },
        anomaly_features={"container_id": "a" * 12, "timestamp": ts, "anomaly_score": 0.99},
        monitor_evidence={
            "baseline_state": "MODEL_READY",
            "anomaly_status": "used",
            "window_start": (now - timedelta(seconds=10)).isoformat(),
            "window_end": (now + timedelta(seconds=10)).isoformat(),
        },
    )
    saved = http.post("/incidents/", json=data).json()
    path = f"/incidents/{saved['id']}/confirm"
    first = http.post(path, params={"confirmed_by": "selfsentry-auto"})
    assert first.status_code == 200
    second = http.post(path, params={"confirmed_by": "selfsentry-auto"})
    assert second.json()["status"] == "already_confirmed"
    with session() as db:
        assert db.query(ConfirmedIncident).count() == 1
        assert db.query(ConfirmedIncident).first().confirmed_by == "selfsentry-auto"


def test_dismissed_monitor_incident_cannot_be_auto_confirmed(client):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    http.post(f"/incidents/{saved['id']}/dismiss")
    assert (
        http.get(f"/incidents/{saved['id']}").json()["monitor_workflow"]["disposition"]["status"]
        == "benign"
    )
    assert (
        http.post(
            f"/incidents/{saved['id']}/confirm", params={"confirmed_by": "selfsentry-auto"}
        ).status_code
        == 409
    )
