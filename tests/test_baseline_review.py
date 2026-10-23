"""Late alert exposure and explicit, evidence-checked recovery of existing data."""

import json
import sqlite3
from unittest.mock import patch

import pytest

from tests.test_behavior_pipeline import setup, seed_baseline, event, outbox, CID, START
from behavior_pipeline import BehaviorPipeline
from baseline_review import BaselineReviewError, review_baseline


@pytest.fixture
def ready(tmp_path):
    pipe, clock, audit = setup(tmp_path)
    seed_baseline(pipe)
    pipe.discover(CID)
    yield pipe, clock, audit
    pipe.close()


def late(pipe, offset=1, key="late"):
    item = event(second=offset, key=key, security=True)
    bucket = int((START + offset) // pipe.config.window_seconds) * pipe.config.window_seconds
    with pipe.db:
        pipe.db.execute("INSERT OR IGNORE INTO windows VALUES (?,?)", (CID, bucket))
    pipe.handle_alert(item)


def legacy_hold(pipe):
    pipe.models.pop(CID, None)
    pipe.lifecycle[CID]["requires_review"] = True
    pipe._transition(CID, "MODEL_UNAVAILABLE", "late security alert; review baseline")


def review(pipe, keys=None):
    return review_baseline(
        pipe,
        CID,
        "guna",
        "Reviewed non-training late-alert evidence",
        ["late"] if keys is None else keys,
    )


@pytest.mark.parametrize(
    "offset,affected", [(-1860, False), (-1800, True), (-660, True), (-600, False), (1, False)]
)
def test_late_alert_revokes_only_overlapping_training_window(ready, offset, affected):
    pipe, _, audit = ready
    path = pipe.config.baseline_dir / f"{CID}.json"
    before = path.read_bytes()
    late(pipe, offset)
    assert pipe.lifecycle[CID]["state"] == ("MODEL_UNAVAILABLE" if affected else "MODEL_READY")
    assert (CID not in pipe.models) == affected
    assert path.read_bytes() == before
    assert any(p["monitor_evidence"]["anomaly_status"] == "late" for p in outbox(pipe))
    assert audit.items[-1]["detail"]["training_overlap"] is affected


def test_late_alert_does_not_clear_an_existing_review_hold(ready):
    pipe, _, _ = ready
    legacy_hold(pipe)
    late(pipe)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models


@pytest.mark.parametrize("broken", ["missing", "malformed", "invalid-window"])
def test_uncertain_training_exposure_still_fails_closed(ready, broken):
    pipe, _, audit = ready
    path = pipe.config.baseline_dir / f"{CID}.json"
    if broken == "missing":
        path.unlink()
    elif broken == "malformed":
        path.write_text("broken json")
    else:
        raw = json.loads(path.read_text())
        raw["feature_vectors"][0]["window_end"] = raw["feature_vectors"][0]["window_start"]
        path.write_text(json.dumps(raw))
    late(pipe)
    assert pipe.lifecycle[CID]["state"] == "MODEL_UNAVAILABLE"
    assert pipe.lifecycle[CID]["requires_review"]
    assert audit.items[-1]["detail"]["training_overlap"] is None
    assert any(p["monitor_evidence"]["anomaly_status"] == "late" for p in outbox(pipe))


def test_recovery_keeps_samples_backs_up_and_survives_restart(ready):
    pipe, clock, audit = ready
    late(pipe)
    legacy_hold(pipe)
    before = (pipe.config.baseline_dir / f"{CID}.json").read_bytes()
    report = review(pipe)
    assert pipe.lifecycle[CID]["state"] == "MODEL_READY"
    assert not pipe.lifecycle[CID]["requires_review"]
    assert CID in pipe.models
    assert report["journal_alerts_checked"] == 1
    assert report["evidence_events"][0]["training_overlap"] is False
    assert any(a["event_type"] == "BASELINE_REVIEWED" for a in audit.items)
    from pathlib import Path

    backup = Path(report["backup_directory"])
    assert (backup / "baseline.json").read_bytes() == before
    assert (pipe.config.baseline_dir / f"{CID}.json").read_bytes() == before
    with sqlite3.connect(backup / "pipeline.sqlite") as db:
        saved = json.loads(
            db.execute("SELECT body FROM lifecycle WHERE container=?", (CID,)).fetchone()[0]
        )
        assert saved["requires_review"] is True
    restarted = BehaviorPipeline(pipe.config, pipe.status, pipe.audit, clock=lambda: clock[0])
    try:
        restarted.discover(CID)
        assert restarted.lifecycle[CID]["state"] == "MODEL_READY"
        assert restarted.store.load(CID).sample_count == 20
    finally:
        restarted.close()


@pytest.mark.parametrize("keys", [[], ["missing"], ["late", "missing"]])
def test_review_refuses_missing_evidence_and_preserves_hold(ready, keys):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    with pytest.raises(BaselineReviewError):
        review(pipe, keys)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models


def test_review_checks_all_alerts_not_only_requested_witnesses(ready):
    pipe, _, _ = ready
    late(pipe)
    late(pipe, -1799, "contaminating")
    with pytest.raises(BaselineReviewError, match="overlaps training"):
        review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]


def test_review_does_not_clear_an_unrelated_failure(ready):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    pipe.lifecycle[CID]["reason"] = "model failed readiness validation"
    with pytest.raises(BaselineReviewError, match="Only an existing late-alert"):
        review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]


@pytest.mark.parametrize(
    "actor,reason", [("", "reason"), ("selfsentry-auto", "reason"), ("guna", "")]
)
def test_review_requires_explicit_human_reason(ready, actor, reason):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    with pytest.raises(BaselineReviewError):
        review_baseline(pipe, CID, actor, reason, ["late"])
    assert pipe.lifecycle[CID]["requires_review"]


def test_failed_model_probe_keeps_hold_and_samples(ready):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    with patch.object(pipe, "_fit_model", side_effect=ValueError("bad model")):
        with pytest.raises(ValueError, match="bad model"):
            review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models
    assert pipe.store.load(CID).sample_count == 20


def test_changed_baseline_during_fit_is_not_accepted(ready):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    path = pipe.config.baseline_dir / f"{CID}.json"
    fit = pipe._fit_model

    def changed(cid, data):
        model = fit(cid, data)
        path.write_text(path.read_text() + "\n")
        return model

    with patch.object(pipe, "_fit_model", side_effect=changed):
        with pytest.raises(BaselineReviewError, match="changed during review"):
            review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models


def test_review_cli_excludes_a_running_monitor(ready, monkeypatch):
    import monitor_service

    pipe, _, _ = ready
    monkeypatch.setattr(monitor_service, "load_config", lambda: pipe.config)
    monkeypatch.setattr(monitor_service, "setup_logging", lambda _: None)
    lock = monitor_service.acquire_lock(pipe.config.state_dir)
    assert lock is not None
    try:
        assert (
            monitor_service.main(
                [
                    "--review-baseline",
                    CID,
                    "--reviewed-by",
                    "guna",
                    "--reason",
                    "review",
                    "--evidence-key",
                    "late",
                ]
            )
            == 3
        )
    finally:
        lock.close()


def test_review_cli_checks_evidence_without_resetting(ready, monkeypatch, capsys):
    import monitor_service
    from tests.test_behavior_pipeline import Audit

    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    monkeypatch.setattr(monitor_service, "load_config", lambda: pipe.config)
    monkeypatch.setattr(monitor_service, "setup_logging", lambda _: None)
    audit = Audit()
    monkeypatch.setattr(monitor_service, "DurableAuditClient", lambda *a, **kw: audit)
    assert (
        monitor_service.main(
            [
                "--review-baseline",
                CID,
                "--reviewed-by",
                "guna",
                "--reason",
                "reviewed journal timestamps",
                "--evidence-key",
                "late",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "reviewed"
    assert report["samples"] == 20
    assert any(item["event_type"] == "BASELINE_REVIEWED" for item in audit.items)
    assert pipe.store.load(CID).sample_count == 20


def test_review_cli_requires_human_identity_reason_and_evidence():
    import monitor_service

    with pytest.raises(SystemExit) as exc:
        monitor_service.main(["--review-baseline", CID])
    assert exc.value.code == 2


def test_review_cli_durably_queues_audit_without_network(ready, monkeypatch, capsys):
    import monitor_service
    from audit_client import DurableAuditClient

    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    monkeypatch.setattr(monitor_service, "load_config", lambda: pipe.config)
    monkeypatch.setattr(monitor_service, "setup_logging", lambda _: None)
    with patch("requests.post", side_effect=AssertionError("review must only queue audit")):
        assert monitor_service.main([
            "--review-baseline", CID, "--reviewed-by", "guna",
            "--reason", "reviewed journal timestamps", "--evidence-key", "late",
        ]) == 0
    report = json.loads(capsys.readouterr().out)
    # Reconstruct the production client: review evidence survives command exit.
    client = DurableAuditClient(
        pipe.config.backend_url, pipe.config.state_dir / "audit_spool.jsonl"
    )
    with sqlite3.connect(client._journal) as db:
        payloads = [json.loads(row[0]) for row in db.execute("SELECT body FROM audit_outbox")]
    reviews = [item for item in payloads if item["event_type"] == "BASELINE_REVIEWED"]
    assert len(reviews) == 1
    assert reviews[0]["detail"]["review_id"] == report["review_id"]
    assert any(item["event_type"] == "BASELINE_STATE_CHANGED" for item in payloads)
    assert (pipe.config.state_dir / "monitor.lock").exists()
    lock = monitor_service.acquire_lock(pipe.config.state_dir)
    assert lock is not None
    lock.close()


@pytest.mark.parametrize("fault", ["bad-time", "wrong-bucket", "wrong-container"])
def test_unverifiable_journal_never_clears_review_hold(ready, fault):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    body, bucket = pipe.db.execute("SELECT body,bucket FROM events WHERE key='late'").fetchone()
    event_body = json.loads(body)
    if fault == "bad-time":
        event_body["timestamp"] = "unparseable"
    elif fault == "wrong-bucket":
        bucket += 60
    else:
        event_body["container_id"] = "b" * 12
    with pipe.db:
        pipe.db.execute(
            "UPDATE events SET body=?,bucket=? WHERE key='late'", (json.dumps(event_body), bucket)
        )
    with pytest.raises(ValueError):
        review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models


@pytest.mark.parametrize("fault", ["insufficient", "no-variation", "short-duration"])
def test_invalid_training_evidence_cannot_be_restored(ready, fault):
    from datetime import timedelta

    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    path = pipe.config.baseline_dir / f"{CID}.json"
    baseline = json.loads(path.read_text())
    if fault == "insufficient":
        baseline["feature_vectors"].pop()
    elif fault == "no-variation":
        for vector in baseline["feature_vectors"]:
            vector["total_event_count"] = 1
    else:
        from baseline_review import utc_timestamp

        first = utc_timestamp(baseline["feature_vectors"][0]["window_start"])
        for index, vector in enumerate(baseline["feature_vectors"]):
            start = first + timedelta(seconds=index)
            vector.update(
                window_start=start.isoformat(),
                window_end=(start + timedelta(seconds=60)).isoformat(),
            )
    path.write_text(json.dumps(baseline))
    with pytest.raises(BaselineReviewError):
        review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models


def test_audit_failure_does_not_silently_restore_a_model(ready):
    pipe, _, _ = ready
    late(pipe)
    legacy_hold(pipe)
    with patch.object(pipe, "_audit", side_effect=OSError("audit storage unavailable")):
        with pytest.raises(OSError):
            review(pipe)
    assert pipe.lifecycle[CID]["requires_review"]
    assert CID not in pipe.models
