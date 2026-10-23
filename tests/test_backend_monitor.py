"""Real HTTP/ORM tests for additive metadata, idempotency and AI failure isolation."""

import os
import sys
import time
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


def test_stale_workflow_session_preserves_a_committed_benign_disposition(client):
    http, session = client
    saved = http.post("/incidents/", json=body()).json()
    with session() as stale:
        cached = stale.query(MonitorIncident).filter_by(incident_id=saved["id"]).one()
        assert cached.workflow == {}
        assert http.post(f"/incidents/{saved['id']}/dismiss").status_code == 200
        result = monitor.workflow(saved["id"], {"response": {"status": "not_attempted"}}, stale)
        assert result["disposition"]["status"] == "benign"
    result = http.get(f"/incidents/{saved['id']}").json()["monitor_workflow"]
    assert result["disposition"]["status"] == "benign"
    assert result["response"]["status"] == "not_attempted"


def test_stale_dismiss_session_preserves_a_committed_response(client):
    http, session = client
    saved = http.post("/incidents/", json=body()).json()
    with session() as stale:
        cached = stale.query(MonitorIncident).filter_by(incident_id=saved["id"]).one()
        assert cached.workflow == {}
        path = f"/monitor/incidents/{saved['id']}/workflow"
        assert http.post(path, json={"response": {"status": "isolation_failed"}}).status_code == 200
        incidents.dismiss_incident(saved["id"], stale)
    result = http.get(f"/incidents/{saved['id']}").json()["monitor_workflow"]
    assert result["response"]["status"] == "isolation_failed"
    assert result["disposition"]["status"] == "benign"


def test_dismissal_is_audited_once_without_inventing_an_actor(client):
    from models.db_models import AuditEvent

    http, session = client
    saved = http.post("/incidents/", json=body()).json()
    path = f"/incidents/{saved['id']}/dismiss"
    assert http.post(path).status_code == 200
    assert http.post(path).status_code == 200
    with session() as db:
        audit = db.query(AuditEvent).filter_by(event_type="INCIDENT_DISMISSED").one()
        assert audit.detail == {"incident_id": saved["id"], "disposition": "benign", "actor": None}
        workflow = db.query(MonitorIncident).filter_by(incident_id=saved["id"]).one().workflow
        assert workflow["disposition"]["dismissed_at"].endswith("+00:00")


@pytest.mark.parametrize("name", ["confirmation", "response", "candidate", "confirmation_policy"])
@pytest.mark.parametrize("value", [None, [], "ready"])
def test_workflow_fields_require_objects(client, name, value):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    response = http.post(f"/monitor/incidents/{saved['id']}/workflow", json={name: value})
    assert response.status_code == 422
    assert name not in http.get(f"/incidents/{saved['id']}").json()["monitor_workflow"]


@pytest.mark.parametrize("actor", ["", " ", "\t"])
def test_confirmation_requires_a_nonblank_actor(client, actor):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    result = http.post(f"/incidents/{saved['id']}/confirm", params={"confirmed_by": actor})
    assert result.status_code == 422
    assert http.get(f"/incidents/{saved['id']}").json()["confirmation"] is None


def test_whitespace_does_not_bypass_auto_confirmation_policy(client, monkeypatch):
    monkeypatch.setenv("AUTO_CONFIRM_ENABLED", "false")
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    result = http.post(
        f"/incidents/{saved['id']}/confirm", params={"confirmed_by": " selfsentry-auto "}
    )
    assert result.status_code == 409
    assert http.get(f"/incidents/{saved['id']}").json()["confirmation"] is None


@pytest.mark.parametrize("writer", ["workflow", "dismiss", "confirm"])
def test_workflow_writers_lock_the_parent_before_metadata_access(client, writer):
    from sqlalchemy import event
    from sqlalchemy.dialects import postgresql

    http, session = client
    saved = http.post("/incidents/", json=body()).json()
    statements = []
    with session() as db:
        def record(state):
            if state.is_select:
                statements.append(str(state.statement.compile(dialect=postgresql.dialect())))

        event.listen(db, "do_orm_execute", record)
        if writer == "workflow":
            monitor.workflow(saved["id"], {"response": {"status": "not_attempted"}}, db)
        elif writer == "dismiss":
            incidents.dismiss_incident(saved["id"], db)
        else:
            incidents.confirm_incident(saved["id"], "alice", db)
    assert "FROM incidents" in statements[0]
    assert "FOR UPDATE" in statements[0]
    # This compiles PostgreSQL syntax; SQLite execution does not prove native locking.


def test_incident_request_rejects_empty_event_key(client):
    http, _ = client
    assert http.post("/incidents/", json={**body(), "event_key": ""}).status_code == 422


@pytest.mark.parametrize("explanation", [
    None, [], "ready", {"status": "ready"}, {"status": "ready", "result": []},
])
def test_invalid_explanation_refused_without_workflow_update(client, explanation):
    http, _ = client
    saved = http.post("/incidents/", json=body()).json()
    response = http.post(
        f"/monitor/incidents/{saved['id']}/workflow", json={"explanation": explanation}
    )
    assert response.status_code == 422
    result = http.get(f"/incidents/{saved['id']}").json()
    assert "explanation" not in result["monitor_workflow"]


def test_explanation_for_orphan_metadata_returns_conflict(client):
    http, session = client
    with session() as db:
        db.add(MonitorIncident(event_key="orphan", incident_id=999, workflow={}))
        db.commit()
    response = http.post(
        "/monitor/incidents/999/workflow",
        json={"explanation": {"status": "ready", "result": {}}},
    )
    assert response.status_code == 409
    with session() as db:
        assert db.query(MonitorIncident).filter_by(event_key="orphan").one().workflow == {}


def test_health_readout_reports_stale_state(client, tmp_path, monkeypatch):
    from monitor_status import StatusBoard

    http, _ = client
    monkeypatch.setenv("MONITOR_STATE_DIR", str(tmp_path))
    board = StatusBoard(tmp_path / "status.json")
    board.set_running(True)
    board.set_value("control_updated_at", time.time())
    for name in ("docker", "falco_ingest", "control", "backend"):
        board.set_component(name, "ok")
    board.write()
    fresh = http.get("/monitor/status").json()
    assert fresh["healthy"] is True
    assert fresh["heartbeat_fresh"] is True
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


def test_legacy_incident_dismissal_does_not_report_an_unpersisted_success(client):
    http, _ = client
    data = body()
    data.pop("event_key")
    saved = http.post("/incidents/", json=data).json()
    result = http.post(f"/incidents/{saved['id']}/dismiss")
    assert result.status_code == 409
    assert "cannot be recorded" in result.json()["detail"]


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


def test_status_preserves_runtime_config_and_marks_older_monitor_unknown(client, monkeypatch):
    from datetime import datetime, timezone
    http, _ = client
    state = {"running": True, "updated_at": datetime.now(timezone.utc).isoformat(),
             "configuration": {"auto_isolation_enabled": True}}
    monkeypatch.setenv("AUTO_ISOLATION_ENABLED", "false")
    monkeypatch.setattr(monitor, "read_status", lambda _: dict(state))
    result = http.get("/monitor/status").json()
    assert result["configuration"]["auto_isolation_enabled"] is True
    assert result["backend_configuration"]["auto_isolation_enabled"] is False
    del state["configuration"]
    assert http.get("/monitor/status").json()["configuration"] == {}


@pytest.fixture
def fresh_health_snapshot(client, tmp_path, monkeypatch):
    from monitor_status import StatusBoard

    monkeypatch.setenv("MONITOR_STATE_DIR", str(tmp_path))
    board = StatusBoard(tmp_path / "status.json")
    board.set_running(True)
    board.set_value("control_updated_at", time.time())
    for name in ("docker", "falco_ingest", "control", "backend"):
        board.set_component(name, "ok")
    board.write()
    return client[0], board, tmp_path / "status.json"


@pytest.mark.parametrize("name", ["docker", "falco_ingest", "control", "backend", "optional"])
def test_fresh_heartbeat_does_not_hide_reported_component_failure(fresh_health_snapshot, name):
    http, board, _ = fresh_health_snapshot
    board.set_component(name, "unavailable", "offline")
    board.write()
    state = http.get("/monitor/status").json()
    assert state["heartbeat_fresh"] is True
    assert state["healthy"] is False
    assert state["degraded_components"] == [name]
    assert name in state["health_reason"]


@pytest.mark.parametrize("name", ["docker", "falco_ingest", "control", "backend"])
def test_missing_required_component_is_not_proof_of_health(fresh_health_snapshot, name):
    import json

    http, _, path = fresh_health_snapshot
    state = json.loads(path.read_text())
    del state["components"][name]
    path.write_text(json.dumps(state))
    result = http.get("/monitor/status").json()
    assert result["healthy"] is False
    assert result["heartbeat_fresh"] is True
    assert result["degraded_components"] == [name]
    assert name not in result["components"]  # No invented observation for the missing service.


def test_disabled_optional_component_is_distinct_from_disabled_core(fresh_health_snapshot):
    http, board, _ = fresh_health_snapshot
    board.set_component("optional", "disabled")
    board.write()
    assert http.get("/monitor/status").json()["healthy"] is True
    board.set_component("falco_ingest", "disabled")
    board.write()
    state = http.get("/monitor/status").json()
    assert state["healthy"] is False
    assert state["degraded_components"] == ["falco_ingest"]


@pytest.mark.parametrize("raw", [[], None, 42, {}, {"running": "false"},
                                 {"running": True, "components": None},
                                 {"running": True, "components": []}])
def test_invalid_status_shape_reports_unknown_process_state(fresh_health_snapshot, raw):
    import json

    http, _, path = fresh_health_snapshot
    path.write_text(json.dumps(raw))
    response = http.get("/monitor/status")
    assert response.status_code == 200
    state = response.json()
    assert state["status_available"] is False
    assert state["running"] is None
    assert state["healthy"] is False
    assert state["heartbeat_fresh"] is False
    assert "unknown" in state["reason"]


@pytest.mark.parametrize("item", [None, [], "ok", {"state": []}, {}])
def test_bad_component_entry_is_explicitly_unknown_without_losing_other_data(
    fresh_health_snapshot, item
):
    import json

    http, _, path = fresh_health_snapshot
    state = json.loads(path.read_text())
    state["components"]["docker"] = item
    path.write_text(json.dumps(state))
    result = http.get("/monitor/status").json()
    assert result["healthy"] is False
    assert result["components"]["docker"]["state"] == "unknown"
    assert result["components"]["falco_ingest"]["state"] == "ok"
    assert result["degraded_components"] == ["docker"]
    assert "Invalid recorded" in result["components"]["docker"]["detail"]


@pytest.mark.parametrize("timestamp", ["invalid", "2026-10-22T10:00:00",
                                       "2099-01-01T00:00:00+00:00"])
def test_invalid_or_future_heartbeat_is_not_healthy(fresh_health_snapshot, timestamp):
    import json

    http, _, path = fresh_health_snapshot
    state = json.loads(path.read_text())
    state["updated_at"] = timestamp
    path.write_text(json.dumps(state))
    result = http.get("/monitor/status").json()
    assert result["healthy"] is False
    assert result["heartbeat_fresh"] is False


def test_backend_database_failure_prevents_healthy_response(fresh_health_snapshot, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    http, _, _ = fresh_health_snapshot

    def unavailable(*args, **kwargs):
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(Session, "query", unavailable)
    result = http.get("/monitor/status").json()
    assert result["healthy"] is False
    assert result["heartbeat_fresh"] is True
    assert result["unconfirmed_incidents"] is None
    assert result["degraded_components"] == ["database"]


def test_missing_status_reports_unavailable_instead_of_stopped(fresh_health_snapshot):
    http, _, path = fresh_health_snapshot
    path.unlink()  # Disposable fixture only.
    result = http.get("/monitor/status").json()
    assert result["status_available"] is False
    assert result["running"] is None


@pytest.mark.parametrize("progress", [None, True, "recent", 0, -10, 10 ** 400])
def test_fresh_global_heartbeat_does_not_hide_missing_or_invalid_control_progress(
    fresh_health_snapshot, progress
):
    import json

    http, _, path = fresh_health_snapshot
    state = json.loads(path.read_text())
    state["control_updated_at"] = progress
    path.write_text(json.dumps(state))
    result = http.get("/monitor/status").json()
    assert result["heartbeat_fresh"] is True
    assert result["healthy"] is False
    assert result["control_progress_fresh"] is False
    assert "control" in result["degraded_components"]
    assert "completed control cycle" in result["health_reason"]


def test_finished_control_cycle_restores_health_after_stale_progress(fresh_health_snapshot):
    http, board, _ = fresh_health_snapshot
    board.set_value("control_updated_at", time.time() - 60)
    board.write()
    assert http.get("/monitor/status").json()["healthy"] is False
    board.set_value("control_updated_at", time.time())
    board.write()
    result = http.get("/monitor/status").json()
    assert result["control_progress_fresh"] is True
    assert result["healthy"] is True


@pytest.mark.parametrize("raw", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_status_telemetry_is_unavailable_not_an_http_serialization_error(
    fresh_health_snapshot, raw
):
    import json

    http, _, path = fresh_health_snapshot
    state = json.loads(path.read_text())
    state["control_updated_at"] = raw
    path.write_text(json.dumps(state))
    result = http.get("/monitor/status")
    assert result.status_code == 200
    assert result.json()["status_available"] is False
    assert result.json()["running"] is None


def test_cli_and_api_share_snapshot_rules_with_separate_database_probe(
    fresh_health_snapshot, capsys
):
    import dataclasses
    import monitor_service
    from monitor_config import MonitorConfig

    http, board, path = fresh_health_snapshot
    config = dataclasses.replace(MonitorConfig(), state_dir=path.parent)
    assert monitor_service.print_status(config) == 0
    capsys.readouterr()
    assert http.get("/monitor/status").json()["healthy"] is True
    board.set_value("control_updated_at", time.time() + 60)
    board.write()
    assert monitor_service.print_status(config) == 1
    assert '"control_progress_fresh": false' in capsys.readouterr().out
    assert http.get("/monitor/status").json()["healthy"] is False
