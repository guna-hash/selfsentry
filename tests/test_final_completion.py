"""Regression checks for the completion features; Docker/Falco remain mocked."""

import dataclasses
import json
import os
from pathlib import Path
import queue
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "correlation-engine",
    "monitor-service",
    "rule-synthesis-engine",
    "backend-api",
    "deployment-gate",
    "ops",
):
    sys.path.insert(0, str(ROOT / folder))
os.environ.setdefault("DATABASE_URL", "sqlite://")

from risk_explanation import explain_incident, explain_deployment  # noqa: E402
from rule_template_generator import generate_rule  # noqa: E402
from rule_backtester import backtest_rule, BacktestError  # noqa: E402
from monitor_config import MonitorConfig  # noqa: E402
from automation_policy import eligible  # noqa: E402
from audit_client import DurableAuditClient  # noqa: E402
from tests.test_behavior_pipeline import setup, event, START, CID  # noqa: E402
from tests.test_incident_pipeline import payload  # noqa: E402
from tests.test_monitor_service import FakeAudit, FakeWatcher  # noqa: E402
from control_worker import ControlWorker  # noqa: E402
from monitor_service import MonitorService  # noqa: E402
from falco_ingest import FalcoTailer  # noqa: E402
from container_health import monitoring_health  # noqa: E402
import selfsentry_cli as cli  # noqa: E402


@pytest.mark.parametrize(
    "score,severity", [(10, "low"), (45, "medium"), (75, "high"), (95, "critical")]
)
def test_every_severity_has_deterministic_actionable_guidance(score, severity):
    explanation = explain_incident(
        {
            "container_id": CID,
            "risk_score": score,
            "confidence": "high",
            "ai_summary": {"severity": "critical"},
        }
    )
    assert explanation["severity"] == severity
    assert CID in explanation["explanation"]
    assert "effective score" in explanation["risk_rationale"]
    assert 1 <= len(explanation["suggested_fixes"]) <= 3


def test_sensitive_path_guidance_uses_recorded_evidence():
    result = explain_incident(
        {
            "container_id": CID,
            "risk_score": 80,
            "confidence": "medium",
            "falco_alert": {"rule": "Sensitive file", "output": "path=/etc/shadow"},
        }
    )
    assert "/etc/shadow" in result["explanation"]
    assert any("rotate" in fix for fix in result["suggested_fixes"])


def test_blocked_scan_failure_is_explained_without_llm():
    result = explain_deployment(
        {"container_name": "web", "image_name": "alpine", "decision": "blocked"}
    )
    assert result["title"] == "Blocked Deployment"
    assert any("Trivy" in fix for fix in result["suggested_fixes"])


@pytest.mark.parametrize("action", ["spawned_process", "file_write"])
def test_supported_templates_backtest_real_literals_and_reject_false_positives(action):
    pattern = {
        "action": action,
        "proc_name": "cat",
        "parent_proc": "sh",
        "file_path": "/etc/shadow",
    }
    rule = generate_rule(pattern, 5)
    kind = "Baseline Process Spawn" if action == "spawned_process" else "Baseline File Write"
    comparison = "proc.pname" if action == "spawned_process" else "fd.name"
    other = "sh" if action == "spawned_process" else "/etc/shadow"
    benign = [{"rule": kind, "output_fields": {"proc.name": "nginx", comparison: other}}]
    good = backtest_rule(rule, benign)
    assert good["events_tested"] == good["true_negatives"] == 1
    assert good["true_positives"] is None  # benign data cannot establish TPs
    bad = backtest_rule(
        rule, benign + [{"rule": kind, "output_fields": {"proc.name": "cat", comparison: other}}]
    )
    assert bad["verdict"] == "flag_for_revision"
    assert bad["false_positives"] == 1


def test_backtest_fails_closed_for_empty_unusable_or_changed_condition():
    rule = generate_rule({"proc_name": "cat", "parent_proc": "sh"}, 1)
    assert backtest_rule(rule, [])["verdict"] != "pass"
    assert backtest_rule(rule, [{"rule": "Baseline Process Spawn"}])["events_tested"] == 0
    with pytest.raises(BacktestError):
        backtest_rule(rule.replace('proc.pname="sh"', 'proc.pname="sh" or container'), [])


@pytest.mark.parametrize("value", ['bad" or container', "cat\npriority: DEBUG", "<NA>"])
def test_literal_injection_is_refused(value):
    from rule_template_generator import RuleGenerationError

    with pytest.raises(RuleGenerationError):
        generate_rule({"proc_name": value, "parent_proc": "sh"}, 1)


def anomaly_payload():
    item = payload()
    item["falco_alert"] = None
    item["risk_score"] = 40
    item["confidence"] = "medium"
    item["monitor_evidence"].update(
        anomaly_assessment={"qualifies": True},
        synthesis_evidence={
            "rule": "Baseline Process Spawn",
            "container_id": CID,
            "timestamp": item["anomaly_features"]["timestamp"],
            "output_fields": {"proc.name": "cat", "proc.pname": "sh"},
        },
    )
    return item


def test_anomaly_only_can_propose_but_never_auto_isolate():
    item = anomaly_payload()
    config = dataclasses.replace(MonitorConfig(), auto_isolation_enabled=True)
    assert eligible(item, config, now=START + 5)[0]
    assert not eligible(item, config, action="isolate", now=START + 5)[0]


@pytest.mark.parametrize("change", ["witness", "owner", "late", "model", "threshold", "disabled"])
def test_anomaly_proposal_requires_ready_model_and_literal_window_witness(change):
    item = anomaly_payload()
    config = MonitorConfig()
    if change == "witness":
        item["monitor_evidence"].pop("synthesis_evidence")
    elif change == "owner":
        item["monitor_evidence"]["synthesis_evidence"]["container_id"] = "b" * 12
    elif change == "late":
        item["monitor_evidence"]["synthesis_evidence"]["timestamp"] = "2000-01-01T00:00:00Z"
    elif change == "model":
        item["monitor_evidence"]["baseline_state"] = "LEARNING"
    elif change == "threshold":
        item["anomaly_features"]["anomaly_score"] = 0.9
    else:
        config = dataclasses.replace(config, auto_confirm_anomaly_enabled=False)
    assert not eligible(item, config, now=START + 5)[0]


def test_audit_emit_never_performs_http_and_survives_restart(tmp_path):
    path = tmp_path / "audit_spool.jsonl"
    audit = DurableAuditClient("http://localhost:8000", path)
    with patch("audit_client.requests.post", side_effect=AssertionError("HTTP in ingestion")):
        audit.emit(event_type="LOW_RISK", event_key="one")
        audit.emit(event_type="LOW_RISK", event_key="one")
    restarted = DurableAuditClient("http://localhost:8000", path)
    assert restarted.spool_size() == 1
    with patch.object(restarted, "_post", return_value="retry"):
        restarted.flush_spool()
    assert restarted.spool_size() == 1
    with patch.object(restarted, "_post", return_value="ok"):
        restarted.flush_spool()
    assert restarted.spool_size() == 0


def test_blocked_backend_worker_does_not_stop_other_container_windows(tmp_path, monkeypatch):
    pipe, clock, _ = setup(tmp_path, poll_interval_seconds=0.01)
    audit = FakeAudit()
    watcher = FakeWatcher()
    watcher.container_ids = ["a" * 64, "b" * 64]
    entered, release = threading.Event(), threading.Event()

    class SlowBackend:
        executor = None

        def __init__(self, _):
            pass

        def tick(self):
            entered.set()
            release.wait(3)

    monkeypatch.setattr("control_worker.IncidentPipeline", SlowBackend)
    monkeypatch.setattr("control_worker.flush_deployments", lambda _: None)
    worker = ControlWorker(pipe.config, watcher, audit, pipe.status)
    log = tmp_path / "falco.jsonl"
    log.write_text("")
    service = MonitorService(
        pipe.config,
        FalcoTailer(log, tmp_path / "checkpoint", start_from="beginning"),
        worker,
        audit,
        pipe.status,
        pipe,
        queue.Queue(),
        control_worker=worker,
    )
    worker.start()
    try:
        assert entered.wait(1)
        for cid in (CID, "b" * 12):
            e = event(cid=cid, key=cid, security=True)
            with log.open("a") as handle:
                handle.write(e["raw_line"] + "\n")
        assert service.run_once() == 2
        clock[0] += 80
        service.run_once()
        rows = pipe.db.execute("SELECT container FROM windows").fetchall()
        assert {row[0] for row in rows} == {CID, "b" * 12}
        assert pipe.db.execute("SELECT count(*) FROM outbox").fetchone()[0] == 2
    finally:
        release.set()
        worker.stop()
        pipe.db.close()


def test_container_health_never_claims_paused_or_stale_data_as_active():
    from datetime import datetime, timezone

    container = SimpleNamespace(id="a" * 64, short_id=CID, status="running")
    status = {
        "running": True,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "components": {"falco_ingest": {"state": "ok"}},
        "monitored_container_ids": [container.id],
        "baselines": {CID: {"last_event_at": time.time(), "state": "MODEL_READY"}},
    }
    assert monitoring_health(container, status)["active"]
    container.status = "paused"
    assert not monitoring_health(container, status)["active"]
    container.status = "running"
    status["updated_at"] = "2000-01-01T00:00:00+00:00"
    assert not monitoring_health(container, status)["active"]


def test_pid_identity_prevents_stale_pid_signals(monkeypatch):
    # Use a realistic proc record; this execution host virtualizes process IDs.
    record = "123 (python worker) S " + " ".join(["0"] * 18 + ["12345", "0"])
    monkeypatch.setattr(Path, "read_text", lambda *_: record)
    assert cli.identity(123) == "12345"
    assert cli.alive({"pid": 123, "start_time": "12345"})
    assert not cli.alive({"pid": 123, "start_time": "not-this-process"})
    assert not cli.alive({})


def test_start_does_not_launch_anything_when_prerequisites_fail(tmp_path, monkeypatch):
    path = tmp_path / "processes.json"
    monkeypatch.setattr(
        cli, "check_prerequisites", Mock(side_effect=cli.StartupError("Docker unavailable"))
    )
    spawn = Mock()
    monkeypatch.setattr(cli.subprocess, "Popen", spawn)
    with pytest.raises(cli.StartupError, match="Docker unavailable"):
        cli.start(path)
    spawn.assert_not_called()
    assert not path.exists()


def test_cli_missing_environment_fails_clearly(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    with pytest.raises(cli.StartupError, match="Missing .env"):
        cli.check_prerequisites()


def test_falco_configuration_overrides_are_checked(tmp_path):
    path = tmp_path / "falco.yaml"
    path.write_text("rule_matching: first\njson_output: true\n")
    (tmp_path / "config.d").mkdir()
    (tmp_path / "config.d" / "override.yaml").write_text("rule_matching: all\n")
    assert cli.falco_settings(path)["rule_matching"] == "all"


@pytest.fixture
def final_api():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    import database
    from routes import incidents, deployments, rules, containers, monitor

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    database.Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)

    def get_db():
        with session() as db:
            yield db

    app = FastAPI()
    for route in (incidents, deployments, rules, containers, monitor):
        app.include_router(route.router)
    app.dependency_overrides[database.get_db] = get_db
    with TestClient(app) as client:
        yield client, session
    engine.dispose()


def test_explanations_are_stored_for_low_risk_and_cannot_be_overwritten_by_ai(final_api):
    from models.db_models import Incident

    http, session = final_api
    saved = http.post(
        "/incidents/", json={"container_id": CID, "risk_score": 5, "event_key": "low"}
    ).json()
    original = saved["risk_explanation"]
    http.post(
        f"/monitor/incidents/{saved['id']}/workflow",
        json={
            "explanation": {
                "status": "ready",
                "result": {
                    "plain_summary": "Advisory",
                    "risk_explanation": {"severity": "critical"},
                },
            }
        },
    )
    assert http.get(f"/incidents/{saved['id']}").json()["risk_explanation"] == original
    with session() as db:
        assert db.get(Incident, saved["id"]).ai_summary["risk_explanation"] == original


def test_deployment_replay_preserves_one_blocked_record_and_one_audit(final_api):
    from models.db_models import Deployment, AuditEvent

    http, session = final_api
    body = {
        "container_name": "web",
        "image_name": "nginx",
        "decision": "blocked",
        "event_key": "gate-1",
    }
    first = http.post("/deployments/", json=body).json()
    assert http.post("/deployments/", json=body).json() == first
    with session() as db:
        assert db.query(Deployment).count() == db.query(AuditEvent).count() == 1
    assert http.get("/deployments/").json()[0]["risk_explanation"]["suggested_fixes"]


def benign_corpus(path, process="nginx"):
    path.write_text(
        json.dumps(
            {
                "rule": "Baseline Process Spawn",
                "priority": "Notice",
                "time": "2026-10-15T00:00:00Z",
                "output": "benign",
                "output_fields": {"container.id": CID, "proc.name": process, "proc.pname": "sh"},
            }
        )
        + "\n"
    )


def test_backend_backtest_recomputed_and_revalidated_at_human_approval(
    final_api, tmp_path, monkeypatch
):
    from models.db_models import ConfirmedIncident, GeneratedRule, Incident, AuditEvent
    from routes import rules

    http, session = final_api
    corpus = tmp_path / "benign.jsonl"
    benign_corpus(corpus)
    monkeypatch.setenv("MONITOR_BENIGN_LOG_PATH", str(corpus))
    with session() as db:
        db.add(Incident(id=1, container_id=CID, risk_score=90))
        db.flush()
        db.add(ConfirmedIncident(id=1, incident_id=1, confirmed_by="alice"))
        db.commit()
    candidate = {
        "confirmed_incident_id": 1,
        "backtested_fp_rate": 0.04,
        "rule_yaml": generate_rule({"proc_name": "cat", "parent_proc": "sh"}, 1),
    }
    response = http.post("/rules/", json=candidate)
    assert response.status_code == 201, response.text
    history = http.get("/rules/history").json()[0]
    assert history["backtested_fp_rate"] == 0  # submitted rate was not trusted
    assert history["backtest"]["events_tested"] == 1
    assert history["backtest"]["benign_sha256"]
    benign_corpus(corpus, process="cat")  # corpus now exposes a false positive
    with patch.object(rules, "deploy_rule") as deploy:
        denied = http.post(
            f"/rules/{response.json()['id']}/approve", params={"reviewed_by": "alice"}
        )
    assert denied.status_code == 422
    deploy.assert_not_called()
    with session() as db:
        assert db.query(GeneratedRule).one().status == "pending_review"
        assert (
            db.query(AuditEvent).filter_by(event_type="RULE_BACKTEST_BLOCKED_DEPLOYMENT").count()
            == 1
        )
    # A client cannot bypass this by posting a fabricated zero rate.
    with session() as db:
        db.query(GeneratedRule).delete()
        db.commit()
    assert http.post("/rules/", json={**candidate, "backtested_fp_rate": 0}).status_code == 422


def test_native_refire_is_linked_without_claiming_true_positive(final_api):
    from models.db_models import ConfirmedIncident, GeneratedRule, Incident
    import yaml

    http, session = final_api
    rule = generate_rule({"proc_name": "cat", "parent_proc": "sh"}, 1)
    name = yaml.safe_load(rule)[0]["rule"]
    with session() as db:
        db.add(Incident(id=1, container_id=CID, risk_score=90))
        db.flush()
        db.add(ConfirmedIncident(id=1, incident_id=1, confirmed_by="alice"))
        db.flush()
        db.add(GeneratedRule(confirmed_incident_id=1, status="deployed", rule_yaml=rule))
        db.commit()
    body = {
        "container_id": CID,
        "risk_score": 50,
        "event_key": "refire",
        "falco_alert": {
            "rule": name,
            "timestamp": "2026-10-15T01:00:00Z",
            "output": "observed native match",
        },
    }
    http.post("/incidents/", json=body)
    http.post("/incidents/", json=body)
    history = http.get("/rules/history").json()[0]
    assert history["incident_id"] == 1
    assert len(history["native_refires"]) == 1
    assert history["native_refires"][0]["detail"]["evidence"][0]["rule"] == name


def test_failed_frontend_start_rolls_back_managed_processes_only(tmp_path, monkeypatch):
    path = tmp_path / "processes.json"
    (tmp_path / "state/logs").mkdir(parents=True)
    cfg = dataclasses.replace(MonitorConfig(), state_dir=tmp_path / "monitor")
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "check_prerequisites", lambda: cfg)
    monkeypatch.setattr(cli, "free_port", lambda _: None)
    monkeypatch.setattr(cli, "run", lambda _: "")
    monkeypatch.setattr(
        cli,
        "urlopen",
        Mock(return_value=SimpleNamespace(__enter__=lambda _: SimpleNamespace(status=200))),
    )
    # Context manager magic methods belong to the class, so use Mock for the response.
    response = Mock()
    response.__enter__ = Mock(return_value=SimpleNamespace(status=200))
    response.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(cli, "urlopen", lambda *a, **k: response)
    children = []
    dead = set()

    def spawn(*args, **kwargs):
        pid = 101 + len(children)
        child = SimpleNamespace(pid=pid, poll=lambda: 1 if pid == 103 else None)
        children.append(child)
        return child

    monkeypatch.setattr(cli.subprocess, "Popen", spawn)
    monkeypatch.setattr(cli, "identity", lambda pid: None if pid in dead else "start")
    monkeypatch.setattr("monitor_status.read_status", lambda _: {"pid": 102, "running": True})
    monkeypatch.setattr(cli.os, "killpg", lambda pid, _: dead.add(pid))
    with pytest.raises(cli.StartupError, match="frontend exited"):
        cli.start(path)
    assert dead == {101, 102, 103}
    assert not path.exists()


def test_resume_audits_success_and_failure_and_protection_is_enforced(
    final_api, tmp_path, monkeypatch
):
    from models.db_models import AuditEvent
    import auto_isolate
    from tests.test_auto_isolate import FakeContainer, FakeClient

    http, session = final_api
    monkeypatch.setenv("SELFSENTRY_STATE_DIR", str(tmp_path))
    live = FakeContainer()
    docker = FakeClient(live)
    monkeypatch.setattr(auto_isolate.docker, "from_env", lambda **_: docker)
    monkeypatch.setenv("MONITOR_PROTECTED_CONTAINERS", "/web")
    assert (
        http.post(
            "/containers/web/isolate", params={"isolated_by": "alice", "reason": "test"}
        ).status_code
        == 409
    )
    assert live.status == "running"
    monkeypatch.setenv("MONITOR_PROTECTED_CONTAINERS", "")
    auto_isolate.isolate_container("web", "test")
    docker.fail_connect = {"appnet"}
    assert http.post("/containers/web/resume", params={"resumed_by": "alice"}).status_code == 409
    assert live.status == "paused"
    docker.fail_connect.clear()
    assert http.post("/containers/web/resume", params={"resumed_by": "alice"}).status_code == 200
    with session() as db:
        kinds = {a.event_type for a in db.query(AuditEvent).all()}
        assert {
            "CONTAINER_RESUME_REQUESTED",
            "CONTAINER_RESUME_FAILED",
            "CONTAINER_RESUMED",
        } <= kinds


def test_gate_decision_journal_survives_lost_backend_response(tmp_path, monkeypatch):
    import deployment_outbox as outbox

    monkeypatch.setenv("SELFSENTRY_STATE_DIR", str(tmp_path))
    item = {"container_name": "web", "image_name": "nginx", "decision": "blocked"}
    outbox.enqueue(item)
    original_key = item["event_key"]
    with patch.object(
        outbox.requests, "post", side_effect=__import__("requests").ConnectionError()
    ):
        outbox.flush("http://localhost:8000")
    db = outbox.connect()
    assert db.execute("SELECT count(*) FROM decisions").fetchone()[0] == 1
    db.close()
    with patch.object(
        outbox.requests, "post", return_value=SimpleNamespace(status_code=201)
    ) as post:
        outbox.flush("http://localhost:8000")
    assert post.call_args.kwargs["json"]["event_key"] == original_key
    db = outbox.connect()
    assert db.execute("SELECT count(*) FROM decisions").fetchone()[0] == 0
    db.close()


def test_slow_model_training_does_not_block_another_container(tmp_path):
    from behavior_pipeline import BehaviorPipeline
    from tests.test_behavior_pipeline import seed_baseline
    from monitor_status import StatusBoard

    entered, release = threading.Event(), threading.Event()

    class SlowModel:
        def fit(self, _):
            entered.set()
            release.wait(3)

        def score_event(self, _):
            return SimpleNamespace(container_id=CID, anomaly_score=0.5)

    config = dataclasses.replace(
        MonitorConfig(), state_dir=tmp_path / "state", baseline_dir=tmp_path / "baselines"
    )
    clock = [START + 1]
    pipe = BehaviorPipeline(
        config,
        StatusBoard(tmp_path / "status.json"),
        FakeAudit(),
        clock=lambda: clock[0],
        model_factory=lambda _: SlowModel(),
        async_training=True,
    )
    try:
        seed_baseline(pipe)
        pipe.discover(CID)
        assert entered.wait(1)
        assert pipe.lifecycle[CID]["state"] == "MODEL_TRAINING"
        pipe.handle_alert(event(cid="b" * 12, key="other", security=True))
        clock[0] += 80
        pipe.tick()
        assert pipe.db.execute("SELECT count(*) FROM outbox").fetchone()[0] == 1
    finally:
        release.set()
        pipe.training_pool.shutdown(wait=True)
        pipe.close()


def test_startup_docker_probe_supports_sdk_without_context_manager(tmp_path, monkeypatch):
    import docker
    import sqlalchemy

    (tmp_path / ".env").write_text("")
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "test-only")
    monkeypatch.setenv("DATABASE_URL", "postgresql://test@localhost/test")
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    engine = Mock()
    engine.connect.return_value = connection
    monkeypatch.setattr(sqlalchemy, "create_engine", lambda *a, **k: engine)
    # DockerClient supports close(), but does not implement __enter__/__exit__.
    client = SimpleNamespace(ping=Mock(), close=Mock())
    monkeypatch.setattr(docker, "from_env", lambda **_: client)
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    with pytest.raises(cli.StartupError, match="Missing prerequisite: docker"):
        cli.check_prerequisites()
    client.ping.assert_called_once()
    client.close.assert_called_once()


def test_port_probe_still_rejects_a_real_listener():
    import socket

    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen()
        with pytest.raises(cli.StartupError, match="already in use"):
            cli.free_port(server.getsockname()[1])


def test_port_probe_accepts_recently_closed_backend_connection():
    import socket

    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen()
        with socket.socket() as client:
            client.connect(("127.0.0.1", port))
            connection, _ = server.accept()
            with connection:
                connection.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b""
    cli.free_port(port)


def test_live_backtest_guard_helper_against_real_routes(final_api, tmp_path, monkeypatch):
    from importlib.util import module_from_spec, spec_from_file_location
    from urllib.parse import urlsplit
    from models.db_models import ConfirmedIncident, GeneratedRule, Incident
    import requests

    http, session = final_api
    with session() as db:
        db.add(Incident(id=203, container_id=CID, risk_score=80))
        db.flush()
        db.add(ConfirmedIncident(id=203, incident_id=203, confirmed_by="test-reviewer"))
        db.flush()
        db.add(
            GeneratedRule(
                id=19,
                confirmed_incident_id=203,
                status="rejected",
                rule_yaml=generate_rule({"proc_name": "cat", "parent_proc": "sh"}, 203),
            )
        )
        db.commit()
    corpus = tmp_path / "benign.jsonl"
    benign_corpus(corpus)
    # The helper must load configuration from .env, not rely on an exported shell value.
    monkeypatch.setenv("MONITOR_BENIGN_LOG_PATH", "temporary-test-placeholder")
    monkeypatch.delenv("MONITOR_BENIGN_LOG_PATH")
    (tmp_path / ".env").write_text(f"MONITOR_BENIGN_LOG_PATH={corpus}\n")
    (tmp_path / "monitor-service").mkdir()
    (tmp_path / "monitor-service/monitor_config.py").touch()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(requests, "get", lambda url, **kw: http.get(urlsplit(url).path))
    monkeypatch.setattr(
        requests, "post", lambda url, **kw: http.post(urlsplit(url).path, json=kw["json"])
    )
    spec = spec_from_file_location(
        "completion_guard_helper", ROOT / "scripts/verify_completion_backtest_guard.py"
    )
    helper = module_from_spec(spec)
    spec.loader.exec_module(helper)
    assert helper.main() == 0
    saved = json.loads(
        (tmp_path / "state/evaluation/completion-live/backtest-guard.json").read_text()
    )
    assert saved["passed"] and saved["http_status"] == 422
    with session() as db:
        assert db.query(GeneratedRule).count() == 1
