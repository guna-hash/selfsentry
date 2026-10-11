"""Additional reliability and endpoint security checks with isolated side effects."""

import importlib.util
import sys
import json
from pathlib import Path
from unittest.mock import patch, Mock
from types import SimpleNamespace

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
from audit_client import AuditClient
from tests.test_behavior_pipeline import setup, event, START, CID, outbox
from tests.test_backend_monitor import client  # noqa: F401 - pytest fixture
from tests.test_auto_isolate import AutoIsolateTestCase, FULL_ID
import auto_isolate


def test_audit_disk_failure_is_not_silently_accepted(tmp_path):
    audit = AuditClient("http://fake", tmp_path / "spool.jsonl")
    with patch("audit_client.requests.post", side_effect=requests.ConnectionError("offline")):
        with patch.object(audit, "_append_line", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                audit.emit("TEST")


def test_durable_sink_failure_leaves_falco_checkpoint_unchanged(tmp_path):
    from tests.test_monitor_service import FakeWatcher, FakeAudit, falco_line
    from monitor_service import MonitorService
    from falco_ingest import FalcoTailer
    import queue

    pipe, _, _ = setup(tmp_path)
    path = tmp_path / "falco.log"
    path.write_text(falco_line() + "\n")
    tailer = FalcoTailer(path, tmp_path / "checkpoint.json", start_from="beginning")
    svc = MonitorService(
        pipe.config, tailer, FakeWatcher(), FakeAudit(), pipe.status, pipe, queue.Queue()
    )
    with patch.object(pipe, "accept", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            svc.run_once()
    assert tailer.offset == 0
    svc.run_once()
    assert tailer.offset > 0


def test_evidence_outside_correlation_window_never_claims_agreement(tmp_path):
    from tests.test_incident_pipeline import payload
    from automation_policy import eligible

    pipe, _, _ = setup(tmp_path, correlation_seconds=1)
    item = payload()
    item["anomaly_features"]["timestamp"] = "2026-10-09T10:10:00+00:00"
    assert not eligible(item, pipe.config)[0]


def test_full_and_short_ids_use_same_registered_baseline(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    pipe.discover("a" * 64)
    pipe.handle_baseline_event(event(cid="a" * 64))
    pipe.handle_alert(event(cid="a" * 12, key="alert", security=True))
    clock[0] += 80
    pipe.tick()
    assert len(pipe.lifecycle) == 1
    assert outbox(pipe)[0]["container_id"] == CID


def test_main_app_refuses_unauthorized_writes(monkeypatch):
    from fastapi.testclient import TestClient

    path = Path(__file__).resolve().parents[1] / "backend-api" / "main.py"
    spec = importlib.util.spec_from_file_location("security_test_main", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app) as http:
        monkeypatch.delenv("SELFSENTRY_API_TOKEN", raising=False)
        assert http.post("/containers/test/isolate").status_code == 503
        monkeypatch.setenv("SELFSENTRY_API_TOKEN", "test-credential")
        assert http.post("/rules/1/approve").status_code == 401
        # Invalid request only reaches argument validation once authenticated.
        assert (
            http.post(
                "/containers/test/isolate", headers={"Authorization": "Bearer test-credential"}
            ).status_code
            == 422
        )
        assert http.get("/").status_code == 200


class TestIncompleteContainment(AutoIsolateTestCase):
    def test_pause_failure_is_not_reported_as_isolated(self):
        import docker

        with patch.object(self.container, "pause", side_effect=docker.errors.APIError("denied")):
            with self.assertRaises(auto_isolate.IsolationError):
                auto_isolate.isolate_container(FULL_ID, "test")
        assert self.record()["state"] == "isolation_failed"
        assert not auto_isolate.is_isolated(self.record())

    def test_network_failure_is_recorded_and_original_attachments_preserved(self):
        import docker

        fake = Mock()
        fake.disconnect.side_effect = docker.errors.APIError("denied")
        with patch.object(self.client.networks, "get", return_value=fake):
            with self.assertRaises(auto_isolate.IsolationError):
                auto_isolate.isolate_container(FULL_ID, "test")
        assert self.record()["state"] == "isolation_failed"
        assert set(self.record()["networks"]) == {"bridge", "appnet"}

    def test_host_network_is_refused_before_any_change(self):
        self.container.attrs["HostConfig"] = {"NetworkMode": "host"}
        with self.assertRaises(auto_isolate.IsolationError):
            auto_isolate.isolate_container(FULL_ID, "test")
        assert self.container.status == "running"
        assert self.record() is None


def test_real_pipeline_to_http_backend_replay(client, tmp_path):
    from tests.test_incident_pipeline import payload
    from incident_pipeline import IncidentPipeline

    http, session = client
    pipe, clock, _ = setup(tmp_path, auto_confirm_enabled=False)
    item = payload()
    item["defer_ai"] = True
    with pipe.db:
        pipe._enqueue(item, item["event_key"])

    # TestClient is a real HTTP/ORM adapter; preserve requests semantics in the coordinator.
    class Adapter:
        def post(self, url, **kwargs):
            kwargs.pop("timeout", None)
            return http.post(url.replace(pipe.config.backend_url, ""), **kwargs)

    delivery = IncidentPipeline(
        pipe,
        http=Adapter(),
        summarize=Mock(side_effect=RuntimeError("no key")),
        clock=lambda: clock[0],
        async_explanations=False,
    )
    delivery.tick()
    delivery.tick()
    saved = http.get("/incidents/").json()
    assert len(saved) == 1
    assert saved[0]["monitor_workflow"]["confirmation"]["status"] == "unconfirmed"
    assert saved[0]["monitor_workflow"]["response"]["status"] == "not_attempted"
    assert pipe.db.execute("SELECT stage FROM outbox").fetchone()[0] == "done"


@pytest.mark.parametrize(
    "raw",
    [
        "null",
        "[]",
        "123",
        '{"rule":3,"time":"x","priority":"Warning","output":"x"}',
        '{"rule":"x","time":"x","priority":"Warning","output":"x","output_fields":[1]}',
    ],
)
def test_malformed_shapes_are_rejected_consistently(raw):
    from falco_integration import parse_falco_alert, FalcoParseError

    with pytest.raises(FalcoParseError):
        parse_falco_alert(raw)


def test_gate_http_credentials_load_from_repository_dotenv(tmp_path, monkeypatch):
    import backend_auth

    path = tmp_path / ".env"
    path.write_text("SELFSENTRY_API_TOKEN=test-credential\n")
    monkeypatch.setattr(backend_auth, "_ENV_PATH", path)
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "temporary")
    monkeypatch.delenv("SELFSENTRY_API_TOKEN")
    assert backend_auth.backend_headers() == {"Authorization": "Bearer test-credential"}
