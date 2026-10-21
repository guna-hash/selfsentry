"""Real HTTP/ORM tests for additive metadata, idempotency and AI failure isolation."""

import os
import sys
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
import database  # noqa: E402
from models.db_models import Incident, MonitorIncident  # noqa: E402
from routes import incidents, monitor  # noqa: E402
import pytest  # noqa: E402


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
    response = http.post("/incidents/", json=item)
    assert response.status_code == 200
    assert response.json()["risk_explanation"]["source"] == "deterministic"


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


@pytest.mark.parametrize("auto_confirm_enabled", ["true", "false"])
def test_valid_dual_layer_auto_confirmation_persists_once(
    client, monkeypatch, auto_confirm_enabled
):
    from datetime import datetime, timezone, timedelta
    from models.db_models import ConfirmedIncident

    # Exercise policy explicitly, independently of operator .env/runtime settings.
    # monkeypatch restores the test-process environment after each parameter case.
    for key, value in {
        "AUTO_CONFIRM_ENABLED": auto_confirm_enabled,
        "AUTO_CONFIRM_THRESHOLD": "90",
        "MONITOR_ANOMALY_THRESHOLD": "0.8",
        "MONITOR_CORRELATION_SECONDS": "60",
        "MONITOR_RESPONSE_MAX_AGE_SECONDS": "120",
    }.items():
        monkeypatch.setenv(key, value)

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
    if auto_confirm_enabled == "false":
        assert first.status_code == 409
        assert first.json()["detail"] == "auto-confirm disabled"
        second = http.post(path, params={"confirmed_by": "selfsentry-auto"})
        assert second.status_code == 409
        with session() as db:
            assert db.query(ConfirmedIncident).count() == 0
        return
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


def test_observed_timeline_persists_in_database_without_ai(client):
    http, session = client
    data = body()
    timeline = [
        {
            "step": 1,
            "source": "falco",
            "timestamp": "2026-10-12T10:00:00Z",
            "description": "Terminal shell in container",
            "event_key": "observed",
        }
    ]
    data["monitor_evidence"]["observed_timeline"] = timeline
    saved = http.post("/incidents/", json=data).json()
    with session() as db:
        meta = db.query(MonitorIncident).filter_by(incident_id=saved["id"]).one()
        assert meta.evidence["observed_timeline"] == timeline
    fetched = http.get(f"/incidents/{saved['id']}").json()
    assert fetched["monitor_evidence"]["observed_timeline"] == timeline
    assert fetched["ai_summary"]["risk_explanation"]["suggested_fixes"]
