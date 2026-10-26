"""Idle startup health must use a real read-only probe, never synthetic audit delivery."""

import dataclasses
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend-api"), str(ROOT / "monitor-service")]
os.environ.setdefault("DATABASE_URL", "sqlite://")
import main as backend  # noqa: E402
from database import Base, get_db  # noqa: E402
from audit_client import DurableAuditClient  # noqa: E402
from control_worker import ControlWorker  # noqa: E402
from monitor_config import MonitorConfig  # noqa: E402
from monitor_status import StatusBoard  # noqa: E402
from tests.test_monitor_service import ServiceTestCase  # noqa: E402


@pytest.fixture
def ready_api(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def session():
        with sessions() as db:
            yield db

    prior = dict(backend.app.dependency_overrides)
    backend.app.dependency_overrides[get_db] = session
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "readiness-test-token")
    try:
        with TestClient(backend.app) as client:
            yield client, sessions
    finally:
        backend.app.dependency_overrides.clear()
        backend.app.dependency_overrides.update(prior)
        engine.dispose()


def test_authenticated_readiness_checks_database_without_creating_audit(ready_api):
    client, sessions = ready_api
    response = client.get(
        "/health/ready", headers={"Authorization": "Bearer readiness-test-token"}
    )
    assert response.status_code == 200 and response.json() == {"ready": True}
    from models.db_models import AuditEvent

    with sessions() as db:
        assert db.query(AuditEvent).count() == 0


@pytest.mark.parametrize(
    "token,header,expected",
    [
        ("readiness-test-token", "", 401),
        ("readiness-test-token", "Bearer incorrect", 401),
        ("", "Bearer readiness-test-token", 503),
    ],
)
def test_readiness_auth_fails_before_database_query(
    ready_api, monkeypatch, token, header, expected
):
    client, _ = ready_api
    db = Mock()
    backend.app.dependency_overrides[get_db] = lambda: db
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", token)
    response = client.get("/health/ready", headers={"Authorization": header})
    assert response.status_code == expected
    db.execute.assert_not_called()


def test_readiness_database_failure_is_not_a_healthy_response(ready_api):
    client, _ = ready_api
    db = Mock()
    db.execute.side_effect = OperationalError(
        "secret query", {}, Exception("secret driver")
    )
    backend.app.dependency_overrides[get_db] = lambda: db
    response = client.get(
        "/health/ready", headers={"Authorization": "Bearer readiness-test-token"}
    )
    assert response.status_code == 503
    assert "secret" not in response.text
    assert response.json() != {"ready": True}


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, {"ready": True}, True),
        (200, {"ready": False}, False),
        (200, {"ready": 1}, False),
        (200, [], False),
        (401, {"detail": "unauthorized"}, False),
        (503, {"detail": "database unavailable"}, False),
        (302, {}, False),
    ],
)
def test_probe_is_bounded_authenticated_and_preserves_pending_delivery(
    tmp_path, monkeypatch, status, body, expected
):
    client = DurableAuditClient("http://backend", tmp_path / "spool.jsonl", 10)
    client.emit("PENDING", event_key="pending", occurred_at="2026-10-25T00:00:00Z")
    client.last_outcome = "retry"
    get = Mock(return_value=Mock(status_code=status, json=lambda: body))
    post = Mock(side_effect=AssertionError("Readiness must not POST an audit event"))
    monkeypatch.setattr("audit_client.requests.get", get)
    monkeypatch.setattr("audit_client.requests.post", post)
    monkeypatch.setattr(
        "audit_client.backend_headers", lambda: {"Authorization": "Bearer test"}
    )
    assert client.check_backend() is expected
    assert client.backend_probe_outcome == ("ok" if expected else "retry")
    assert client.last_outcome == "retry" and client.spool_size() == 1
    get.assert_called_once_with(
        "http://backend/health/ready",
        headers={"Authorization": "Bearer test"},
        timeout=2.0,
        allow_redirects=False,
    )
    post.assert_not_called()


def test_probe_recovers_after_connection_failure_and_invalid_json(
    tmp_path, monkeypatch
):
    client = DurableAuditClient("http://backend", tmp_path / "spool.jsonl", 1)
    bad = Mock(status_code=200)
    bad.json.side_effect = ValueError("invalid JSON")
    get = Mock(
        side_effect=[
            requests.ConnectionError(),
            bad,
            Mock(status_code=200, json=lambda: {"ready": True}),
        ]
    )
    monkeypatch.setattr("audit_client.requests.get", get)
    assert not client.check_backend()
    assert not client.check_backend()
    assert client.check_backend()
    assert client.last_outcome is None and client.spool_size() == 0
    assert get.call_args.kwargs["timeout"] == 1


class TestReadinessStatus(ServiceTestCase):
    def test_idle_service_becomes_ready_without_delivery(self):
        self.audit.last_outcome = None
        self.audit.backend_probe_outcome = "ok"
        self.service._update_status()
        assert self.status.snapshot()["components"]["backend"]["state"] == "ok"
        assert self.audit.events == []

    def test_probe_never_masks_a_rejected_or_retrying_delivery(self):
        self.audit.backend_probe_outcome = "ok"
        for outcome, state in (("retry", "unavailable"), ("rejected", "degraded")):
            self.audit.last_outcome = outcome
            self.service._update_status()
            assert self.status.snapshot()["components"]["backend"]["state"] == state

    def test_new_probe_failure_overrides_old_delivery_success(self):
        self.audit.last_outcome = "ok"
        self.audit.backend_probe_outcome = "retry"
        self.service._update_status()
        assert self.status.snapshot()["components"]["backend"]["state"] == "unavailable"


def test_control_thread_probes_at_startup_and_on_interval_without_audit_work(
    tmp_path, monkeypatch
):
    clock = [0]
    ticks = [-1]
    calls = []
    thread_ids = []

    def tick():
        ticks[0] += 1
        clock[0] = (0, 1, 16)[ticks[0]]

    watcher = SimpleNamespace(
        reconcile=lambda: None,
        tick=tick,
        container_ids=[],
        tracked_count=0,
        pending_count=0,
    )
    audit = SimpleNamespace(flush_spool=lambda: 0)
    config = dataclasses.replace(
        MonitorConfig(), state_dir=tmp_path, poll_interval_seconds=0.001
    )
    board = StatusBoard(tmp_path / "status.json")
    worker = ControlWorker(config, watcher, audit, board)

    def probe():
        calls.append(clock[0])
        thread_ids.append(threading.get_ident())
        if len(calls) == 2:
            worker.request_stop()

    audit.check_backend = probe
    monkeypatch.setattr(
        "control_worker.time",
        SimpleNamespace(
            monotonic=lambda: clock[0],
            time=lambda: 1,
        ),
    )
    monkeypatch.setattr(
        "control_worker.IncidentPipeline",
        lambda _: SimpleNamespace(
            tick=lambda: None,
            executor=None,
        ),
    )
    monkeypatch.setattr("control_worker.flush_deployments", lambda _: None)
    monkeypatch.setattr(
        "control_worker.action_health",
        lambda: {
            "outcome_not_recorded": 0,
            "command_failed": 0,
            "active": 0,
        },
    )
    worker.start()
    worker.thread.join(timeout=2)
    if worker.thread.is_alive():
        worker.stop()
        pytest.fail("Control test did not finish")
    assert calls == [0, 16]
    assert all(value != threading.get_ident() for value in thread_ids)
