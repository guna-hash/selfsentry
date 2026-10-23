"""Audit regressions using temporary state and fake remote services."""

import dataclasses
import json
import sqlite3
import sys
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / name) for name in ("behavioral-engine", "rule-synthesis-engine")]
from baseline_collector import (  # noqa: E402
    BaselineParseError, parse_baseline_event, read_baseline_events_from_file,
)
from feature_extractor import extract_features  # noqa: E402
from confirmation_manager import ConfirmationError, confirm_incident  # noqa: E402
from rule_deduplicator import guard  # noqa: E402
from tests.rule_guard_support import inventory  # noqa: E402
from tests.test_behavior_pipeline import setup, seed_baseline, CID  # noqa: E402


def baseline(**updates):
    row = {"rule": "Baseline Sensitive Syscall", "time": "2026-10-10T01:00:00Z",
           "output_fields": {"container.id": CID, "evt.type": "umount2"}}
    row.update(updates)
    return json.dumps(row)


@pytest.mark.parametrize("line", [
    "[]", '{"rule": []}', baseline(time=17), baseline(time="invalid"),
    baseline(time="2026-10-10T01:00:00"), baseline(output_fields=[1]),
    baseline(rule="Baseline Network Outbound",
             output_fields={"container.id": CID, "fd.rport": "bad"}),
])
def test_malformed_baseline_uses_declared_error(line):
    with pytest.raises(BaselineParseError):
        parse_baseline_event(line)


def test_batch_reader_skips_malformed_fields_and_keeps_later_event(tmp_path):
    path = tmp_path / "falco.jsonl"
    path.write_text(baseline(time="invalid") + "\n" + baseline() + "\n")
    events = read_baseline_events_from_file(path)
    assert len(events) == 1
    vector = extract_features(events, CID, events[0].timestamp, events[0].timestamp)
    assert vector.sensitive_syscall_count == 1


def test_confirmation_does_not_claim_success_for_invalid_json(monkeypatch):
    response = Mock(status_code=200)
    response.json.side_effect = ValueError("not JSON")
    monkeypatch.setattr("confirmation_manager.requests.post", lambda *a, **k: response)
    with pytest.raises(ConfirmationError, match="outcome is unknown"):
        confirm_incident(1, "operator")


@pytest.mark.parametrize("fail_inside", [False, True])
def test_inventory_guard_closes_sqlite_after_use(tmp_path, monkeypatch, fail_inside):
    config, _ = inventory(tmp_path)
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    try:
        with guard(config) as registry:
            connection = registry.db
            if fail_inside:
                raise RuntimeError("caller failed")
    except RuntimeError:
        assert fail_inside
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_training_capacity_defers_then_resumes_without_queued_datasets(tmp_path):
    pipe, _, _ = setup(tmp_path)
    seed_baseline(pipe)
    vectors = pipe.store.load(CID).feature_vectors
    for cid in ("b" * 12, "c" * 12):
        for vector in vectors:
            pipe.store.append(dataclasses.replace(vector, container_id=cid))
    futures = [Future(), Future(), Future()]
    pipe.training_pool = Mock()
    pipe.training_pool.submit.side_effect = futures
    try:
        for cid in (CID, "b" * 12, "c" * 12):
            pipe.discover(cid)
        assert pipe.training_pool.submit.call_count == 2
        assert len(pipe.training_jobs) == 2
        assert pipe.lifecycle["c" * 12]["state"] == "BASELINE_READY"
        assert "capacity" in pipe.lifecycle["c" * 12]["reason"]
        futures[0].set_result(SimpleNamespace())
        pipe.tick()
        assert pipe.training_pool.submit.call_count == 3
        assert len(pipe.training_jobs) == 2
        assert pipe.lifecycle["c" * 12]["state"] == "MODEL_TRAINING"
    finally:
        pipe.close()


@pytest.mark.parametrize("state", [None, True, "false", 0])
def test_evaluation_rejects_unknown_or_enabled_isolation(state):
    sys.path.insert(0, str(ROOT / "evaluation"))
    from safety import require_isolation_disabled
    with pytest.raises(RuntimeError, match="isolation disabled"):
        require_isolation_disabled({"healthy": True, "configuration": {
            "auto_isolation_enabled": state,
        }})
    require_isolation_disabled({"healthy": True, "configuration": {
        "auto_isolation_enabled": False,
    }})


def test_fingerprint_hashes_configured_baseline(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "evaluation"))
    import fingerprint
    custom = tmp_path / "custom"
    custom.mkdir()
    path = custom / f"{CID}.json"
    path.write_text('{}')
    monkeypatch.setattr(fingerprint, "_run", lambda _: "unused")
    monkeypatch.setattr(fingerprint, "_git_dirty", lambda _: False)
    result = fingerprint.collect_fingerprint(
        tmp_path, CID, {"MONITOR_BASELINE_DIR": "custom"}, "image"
    )
    assert result["fingerprint_components"]["baseline_sha256"] == fingerprint.sha256_file(path)


def test_source_export_preserves_launchers_lock_and_inventory(tmp_path, monkeypatch):
    import tarfile
    sys.path.insert(0, str(ROOT / "evaluation"))
    import export_final_review
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    files = ["monitor-service/monitor_service.py", "bin/selfsentry", "requirements.lock",
             "docs/repository-audit/file_inventory.csv"]
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("example")
    export_final_review.main()
    with tarfile.open(tmp_path / "Downloads/selfsentry-final-review.tar.gz") as archive:
        assert set(files).issubset(archive.getnames())
