"""Option B, isolation safeguards and restart/outage recovery with fake side effects."""

import dataclasses
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
import requests  # noqa: E402
import pytest  # noqa: E402
from automation_policy import eligible  # noqa: E402
from incident_pipeline import IncidentPipeline  # noqa: E402
from tests.test_behavior_pipeline import setup, START, CID  # noqa: E402


def payload(score=100):
    from datetime import datetime, timezone

    def ts(n):
        return datetime.fromtimestamp(START + n, timezone.utc).isoformat()

    return {
        "event_key": "window-one",
        "container_id": CID,
        "risk_score": score,
        "confidence": "high",
        "falco_alert": {
            "container_id": CID,
            "timestamp": ts(1),
            "priority": "Warning",
            "rule": "Shell",
        },
        "anomaly_features": {"container_id": CID, "timestamp": ts(2), "anomaly_score": 0.99},
        "monitor_evidence": {
            "baseline_state": "MODEL_READY",
            "anomaly_status": "used",
            "window_start": ts(0),
            "window_end": ts(60),
        },
    }


@pytest.mark.parametrize("score,expected", [(89, False), (90, True), (91, True)])
def test_confirmation_boundary(tmp_path, score, expected):
    pipe, _, _ = setup(tmp_path)
    assert eligible(payload(score), pipe.config)[0] is expected


@pytest.mark.parametrize(
    "change", ["missing_anomaly", "wrong_container", "old", "baseline", "disabled", "nan"]
)
def test_no_unsafe_agreement(tmp_path, change):
    pipe, clock, _ = setup(tmp_path)
    item = payload()
    cfg = pipe.config
    if change == "missing_anomaly":
        item["anomaly_features"] = None
    elif change == "wrong_container":
        item["anomaly_features"]["container_id"] = "b" * 12
    elif change == "old":
        clock[0] += 1000
    elif change == "baseline":
        item["falco_alert"]["rule"] = "Baseline Process Spawn"
    elif change == "disabled":
        cfg = dataclasses.replace(cfg, auto_confirm_enabled=False)
    else:
        item["anomaly_features"]["anomaly_score"] = float("nan")
    assert not eligible(item, cfg, now=clock[0])[0]


class Http:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.confirmed_by = "selfsentry-auto"

    def post(self, url, **kwargs):
        self.calls.append(url)
        if self.fail:
            raise requests.ConnectionError("offline")
        if url.endswith("/incidents/"):
            result = {"id": 1}
        elif url.endswith("/confirm"):
            result = {"confirmed_by": self.confirmed_by, "status": "confirmed"}
        else:
            result = kwargs["json"]
        response = Mock()
        response.json.return_value = result
        return response


def coordinator(tmp_path, **cfg):
    pipe, clock, audit = setup(tmp_path, **cfg)
    with pipe.db:
        pipe._enqueue(payload(), "window-one")
    http = Http()
    isolate = Mock()
    docker = Mock(
        return_value=SimpleNamespace(
            containers=SimpleNamespace(
                get=lambda cid: SimpleNamespace(id="a" * 64, name="web", status="running")
            )
        )
    )
    synth = Mock(return_value={"rule_id": 7, "status": "pending_review"})
    summarize = Mock(side_effect=RuntimeError("no key"))
    delivery = IncidentPipeline(
        pipe,
        http=http,
        isolate=isolate,
        docker_factory=docker,
        synthesize=synth,
        summarize=summarize,
        clock=lambda: clock[0],
        async_explanations=False,
    )
    return pipe, clock, audit, delivery, http, isolate, synth


def test_success_and_replay_do_not_repeat_isolation(tmp_path):
    pipe, _, audit, delivery, http, isolate, _ = coordinator(tmp_path, auto_isolation_enabled=True)
    delivery.tick()
    delivery.tick()
    isolate.assert_called_once()
    flow = json.loads(pipe.db.execute("SELECT body FROM actions").fetchone()[0])["workflow"]
    assert flow["response"]["status"] == "isolated"
    assert flow["explanation"]["status"] == "unavailable"
    assert any(x["event_type"] == "ISOLATION_ATTEMPTED" for x in audit.items)


def test_backend_outage_is_durable_and_recovers(tmp_path):
    pipe, clock, _, delivery, http, isolate, _ = coordinator(tmp_path)
    http.fail = True
    delivery.tick()
    assert pipe.db.execute("SELECT stage FROM outbox").fetchone()[0] == "pending"
    http.fail = False
    clock[0] += 10
    delivery.tick()
    assert pipe.db.execute("SELECT stage FROM outbox").fetchone()[0] == "done"
    isolate.assert_not_called()


@pytest.mark.parametrize("protected", ["web", "a" * 64, CID])
def test_protected_containers_are_never_isolated(tmp_path, protected):
    pipe, _, _, delivery, _, isolate, _ = coordinator(
        tmp_path, auto_isolation_enabled=True, protected_containers=(protected,)
    )
    delivery.tick()
    isolate.assert_not_called()
    assert "protected" in pipe.db.execute("SELECT body FROM actions").fetchone()[0]


def test_failed_isolation_is_not_automatically_retried(tmp_path):
    pipe, _, _, delivery, _, isolate, _ = coordinator(tmp_path, auto_isolation_enabled=True)
    isolate.side_effect = RuntimeError("daemon down")
    delivery.tick()
    delivery.tick()
    isolate.assert_called_once()
    assert "isolation_failed" in pipe.db.execute("SELECT body FROM actions").fetchone()[0]


def test_interrupted_attempt_requires_review(tmp_path):
    pipe, _, _, delivery, _, isolate, _ = coordinator(tmp_path, auto_isolation_enabled=True)
    body = {"id": 1, "payload": payload(), "workflow": {}}
    delivery._save("window-one", body, "isolation_attempted")
    delivery.tick()
    isolate.assert_not_called()
    assert "unknown_after_restart" in pipe.db.execute("SELECT body FROM actions").fetchone()[0]


def test_human_confirmation_does_not_trigger_automatic_candidate(tmp_path):
    _, _, _, delivery, http, _, synth = coordinator(tmp_path, benign_log_path="/validated/corpus")
    http.confirmed_by = "alice"
    delivery.tick()
    synth.assert_not_called()


def test_auto_candidate_requires_human_review(tmp_path):
    pipe, _, _, delivery, _, _, synth = coordinator(tmp_path, benign_log_path="/validated/corpus")
    delivery.tick()
    synth.assert_called_once()
    assert "pending_review" in pipe.db.execute("SELECT body FROM actions").fetchone()[0]


def test_slow_ai_does_not_block_processing(tmp_path):
    import threading

    pipe, clock, _, delivery, _, _, _ = coordinator(tmp_path)
    from concurrent.futures import ThreadPoolExecutor

    delivery.executor = ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    started = threading.Event()

    def slow(_):
        started.set()
        release.wait(2)
        return {"plain_summary": "recorded evidence"}

    delivery.summarize = slow
    try:
        delivery.tick()
        assert started.wait(1)
        assert pipe.db.execute("SELECT stage FROM outbox").fetchone()[0] == "advisory"
        pipe.handle_alert({"container_id": CID, "timestamp": "invalid", "event_key": "bad"})
        assert pipe.db.execute("SELECT count(*) FROM rejected_events").fetchone()[0] == 1
    finally:
        release.set()
        delivery.executor.shutdown(wait=True)
    clock[0] += 2
    delivery.tick()
    assert pipe.db.execute("SELECT stage FROM outbox").fetchone()[0] == "done"
