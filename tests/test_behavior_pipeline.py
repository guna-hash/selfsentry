"""Windowed M2 integration uses real storage, models and scoring; no Docker daemon."""

import dataclasses
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
from behavior_pipeline import BehaviorPipeline  # noqa: E402
from monitor_config import MonitorConfig, load_config, ConfigError  # noqa: E402
from monitor_status import StatusBoard  # noqa: E402
from event_classifier import classify_line  # noqa: E402
from feature_extractor import FeatureVector  # noqa: E402
import pytest  # noqa: E402

CID = "a" * 12
START = 1791532800  # aligned fixed windows


class Audit:
    def __init__(self):
        self.items = []

    def emit(self, **data):
        self.items.append(data)


def setup(tmp_path, **kwargs):
    cfg = dataclasses.replace(
        MonitorConfig(), state_dir=tmp_path / "state", baseline_dir=tmp_path / "baselines", **kwargs
    )
    cfg.validate()
    clock = [START + 1]
    audit = Audit()
    pipe = BehaviorPipeline(
        cfg, StatusBoard(tmp_path / "status.json"), audit, clock=lambda: clock[0]
    )
    return pipe, clock, audit


def event(cid=CID, second=1, key="one", security=False, proc="nginx"):
    stamp = datetime.fromtimestamp(START + second, timezone.utc).isoformat()
    raw = json.dumps(
        {
            "rule": "Shell" if security else "Baseline Process Spawn",
            "time": stamp,
            "priority": "Warning",
            "output": "process=sh parent=nginx",
            "output_fields": {"container.id": cid, "proc.name": proc, "proc.pname": "nginx"},
        }
    )
    return classify_line(raw, key).event


def outbox(pipe):
    return [json.loads(row[0]) for row in pipe.db.execute("SELECT body FROM outbox")]


def test_learning_falco_alert_persists_without_fabricated_anomaly(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    pipe.handle_baseline_event(event())
    pipe.handle_alert(event(key="alert", security=True))
    clock[0] += 80
    pipe.tick()
    payload = outbox(pipe)[0]
    assert payload["anomaly_features"] is None
    assert payload["monitor_evidence"]["anomaly_status"] == "learning"
    assert not payload["monitor_evidence"]["cross_layer_agreement"]
    assert payload["risk_score"] == 50
    assert pipe.store.load(CID, allow_missing=True).sample_count == 0


def test_window_closes_when_quiet_and_replay_does_not_duplicate(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    clock[0] = START
    pipe.discover(CID)
    pipe.handle_baseline_event(event())
    pipe.handle_baseline_event(event())
    clock[0] += 80
    pipe.tick()
    assert pipe.store.load(CID).sample_count == 1
    pipe.db.close()
    restarted = BehaviorPipeline(pipe.config, pipe.status, pipe.audit, clock=lambda: clock[0])
    restarted.handle_baseline_event(event())
    restarted.tick()
    assert restarted.store.load(CID).sample_count == 1


def test_unrecognized_journal_baseline_is_retained_without_learning(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    try:
        pipe.handle_baseline_event(event())
        invalid = event(security=True)
        pipe.db.execute(
            "UPDATE events SET body=? WHERE container=?", (json.dumps(invalid), CID)
        )
        pipe.db.commit()
        clock[0] += 80
        pipe.tick()
        assert pipe.status.snapshot()["counters"]["window_errors"] == 1
        assert "not a recognized baseline" in pipe.status.snapshot()["components"]["behavior"][
            "detail"
        ]
        assert pipe.store.load(CID, allow_missing=True).sample_count == 0
        assert pipe.db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert pipe.db.execute("SELECT count(*) FROM windows").fetchone()[0] == 0
    finally:
        pipe.db.close()


def test_replacement_and_unrelated_container_cannot_share_baselines(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    pipe.handle_baseline_event(event())
    pipe.discover("b" * 64)
    clock[0] += 80
    pipe.tick()
    assert pipe.store.load("b" * 12, allow_missing=True).sample_count == 0
    assert pipe.lifecycle["b" * 12]["state"] == "LEARNING"


def seed_baseline(pipe, count=20, wrong_owner=False, identical=False):
    for n in range(count):
        start = datetime.fromtimestamp(START - 1800 + n * 60, timezone.utc)
        pipe.store.append(
            FeatureVector(
                CID,
                start,
                start + timedelta(seconds=60),
                total_event_count=1 if identical else n + 1,
                distinct_process_count=1,
            )
        )
    if wrong_owner:
        path = pipe.config.baseline_dir / f"{CID}.json"
        body = json.loads(path.read_text())
        body["feature_vectors"][0]["container_id"] = "b" * 12
        path.write_text(json.dumps(body))


def test_valid_existing_baseline_trains_real_model(tmp_path):
    pipe, _, _ = setup(tmp_path)
    seed_baseline(pipe)
    pipe.discover(CID)
    assert pipe.lifecycle[CID]["state"] == "MODEL_READY"
    assert CID in pipe.models


@pytest.mark.parametrize("owner,identical", [(True, False), (False, True)])
def test_invalid_or_degenerate_baseline_is_unavailable(tmp_path, owner, identical):
    pipe, _, _ = setup(tmp_path)
    seed_baseline(pipe, wrong_owner=owner, identical=identical)
    pipe.discover(CID)
    assert pipe.lifecycle[CID]["state"] == "MODEL_UNAVAILABLE"
    assert CID not in pipe.models


def test_insufficient_samples_cannot_train(tmp_path):
    pipe, _, _ = setup(tmp_path)
    seed_baseline(pipe, count=19)
    pipe.discover(CID)
    assert pipe.lifecycle[CID]["state"] == "LEARNING"


def test_late_alert_is_retained_and_invalidates_model(tmp_path):
    pipe, clock, audit = setup(tmp_path)
    clock[0] = START
    pipe.discover(CID)
    pipe.handle_baseline_event(event())
    clock[0] += 80
    pipe.tick()
    pipe.handle_alert(event(key="late", security=True))
    assert outbox(pipe)[0]["monitor_evidence"]["anomaly_status"] == "late"
    assert pipe.lifecycle[CID]["state"] == "MODEL_UNAVAILABLE"
    assert any(x["event_type"] == "LATE_EVENT" for x in audit.items)


@pytest.mark.parametrize(
    "values",
    [
        {"MONITOR_POLL_INTERVAL": "nan"},
        {"MONITOR_LEARNING_SECONDS": "inf"},
        {"MONITOR_MIN_SAMPLES": "19"},
        {"AUTO_CONFIRM_ENABLED": "maybe"},
        {"AUTO_ISOLATION_THRESHOLD": "101"},
    ],
)
def test_bad_configuration_fails_startup(values):
    with pytest.raises(ConfigError):
        load_config(values)


def test_out_of_order_events_inside_open_window_are_grouped(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    pipe.handle_alert(event(second=2, key="later", security=True))
    pipe.handle_alert(event(second=1, key="earlier", security=True))
    clock[0] += 80
    pipe.tick()
    assert len(outbox(pipe)) == 1
    assert len(outbox(pipe)[0]["monitor_evidence"]["falco_alerts"]) == 2


def test_new_container_automatically_trains_after_twenty_valid_windows(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    clock[0] = START
    pipe.discover(CID)
    for window in range(20):
        clock[0] = START + window * 60 + 10
        for n in range(1 + window % 3):
            pipe.handle_baseline_event(event(second=window * 60 + n + 1, key=f"{window}-{n}"))
        clock[0] = START + window * 60 + 71
        pipe.tick()
    assert pipe.lifecycle[CID]["state"] == "MODEL_READY"
    assert pipe.store.load(CID).sample_count == 20


def test_bad_model_output_marks_failed_without_losing_falco(tmp_path):
    from unittest.mock import Mock

    pipe, clock, _ = setup(tmp_path)
    seed_baseline(pipe)
    pipe.discover(CID)
    pipe.models[CID] = Mock()
    pipe.models[CID].score_event.side_effect = RuntimeError("bad model")
    pipe.handle_baseline_event(event())
    pipe.handle_alert(event(key="alert", security=True))
    clock[0] += 80
    pipe.tick()
    assert outbox(pipe)[0]["monitor_evidence"]["anomaly_status"] == "failed"
    assert outbox(pipe)[0]["anomaly_features"] is None


def test_review_required_baseline_stays_unavailable_after_restart(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    seed_baseline(pipe)
    pipe.discover(CID)
    with pipe.db:
        pipe.db.execute("INSERT INTO windows VALUES (?, ?)", (CID, START - 1800))
    pipe.handle_alert(event(second=-1799, key="late", security=True))
    pipe.db.close()
    restarted = BehaviorPipeline(pipe.config, pipe.status, pipe.audit, clock=lambda: clock[0])
    restarted.discover(CID)
    assert restarted.lifecycle[CID]["state"] == "MODEL_UNAVAILABLE"
    assert CID not in restarted.models
    restarted.reset_baseline(CID, "clean workload for recapture")
    assert restarted.lifecycle[CID]["state"] == "LEARNING"
    assert restarted.store.load(CID, allow_missing=True).sample_count == 0


@pytest.mark.parametrize("invalid_score", [float("nan"), 2.0])
def test_invalid_model_probe_never_activates_anomaly_scoring(tmp_path, invalid_score):
    from unittest.mock import Mock

    pipe, _, _ = setup(tmp_path)
    seed_baseline(pipe)
    model = Mock()
    model.score_event.return_value.container_id = CID
    model.score_event.return_value.anomaly_score = invalid_score
    pipe.model_factory = lambda cid: model
    pipe.discover(CID)
    assert pipe.lifecycle[CID]["state"] == "MODEL_UNAVAILABLE"
    assert CID not in pipe.models


def shell_event(second=1, key="shell", proc="sh"):
    item = event(second=second, key=key, security=True, proc=proc)
    raw = json.loads(item["raw_line"])
    raw["rule"] = "Terminal shell in container"
    return classify_line(json.dumps(raw), key).event


@pytest.mark.parametrize("with_baseline", [False, True])
@pytest.mark.parametrize("parent", ["nginx", None])
def test_default_shell_counts_once_and_never_trains_security_window(
    tmp_path, with_baseline, parent,
):
    from unittest.mock import Mock
    from types import SimpleNamespace

    pipe, clock, _ = setup(tmp_path)
    pipe.discover(CID)
    model = Mock()
    model.score_event.return_value = SimpleNamespace(
        anomaly_score=0.1, raw_decision_function=0.1, is_anomaly=False,
    )
    pipe.models[CID] = model
    item = shell_event()
    fields = json.loads(item["raw_line"])
    fields["output_fields"]["proc.pname"] = parent
    pipe.handle_alert(classify_line(json.dumps(fields), "shell").event)
    if with_baseline:
        pipe.handle_baseline_event(event(key="baseline", proc="sh"))
    clock[0] += 80
    pipe.tick()
    vector = model.score_event.call_args.args[0]
    assert vector.shell_spawned_count == 1
    assert vector.total_event_count == 1
    assert outbox(pipe)[0]["falco_alert"]["rule"] == "Terminal shell in container"
    assert pipe.store.load(CID, allow_missing=True).sample_count == 0


@pytest.mark.parametrize("proc", ["<NA>", "nginx", None])
def test_default_shell_missing_or_non_shell_process_does_not_invent_features(tmp_path, proc):
    pipe, clock, _ = setup(tmp_path)
    pipe.handle_alert(shell_event(proc=proc))
    clock[0] += 80
    pipe.tick()
    payload = outbox(pipe)[0]
    assert payload["falco_alert"]["rule"] == "Terminal shell in container"
    assert payload["anomaly_features"] is None
    assert pipe.store.load(CID, allow_missing=True).sample_count == 0


def test_observed_timeline_survives_outbox_restart_in_chronological_order(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    pipe.handle_alert(shell_event(second=2, key="later"))
    pipe.handle_alert(shell_event(second=1, key="earlier"))
    clock[0] += 80
    pipe.tick()
    pipe.db.close()
    restarted = BehaviorPipeline(pipe.config, pipe.status, pipe.audit, clock=lambda: clock[0])
    timeline = outbox(restarted)[0]["monitor_evidence"]["observed_timeline"]
    assert [entry["event_key"] for entry in timeline] == ["earlier", "later"]
    assert [entry["step"] for entry in timeline] == [1, 2]
    assert all(entry["source"] == "falco" for entry in timeline)


def test_candidate_algorithm_is_recorded_in_model_lifecycle_and_assessment(tmp_path):
    pipe, clock, _ = setup(tmp_path, anomaly_algorithm="one_class_svm")
    seed_baseline(pipe)
    pipe.discover(CID)
    assert pipe.models[CID].algorithm == "one_class_svm"
    assert pipe.lifecycle[CID]["model_algorithm"] == "one_class_svm"
    pipe.handle_baseline_event(event())
    pipe.handle_alert(shell_event())
    clock[0] += 80
    pipe.tick()
    assessment = outbox(pipe)[0]["monitor_evidence"]["anomaly_assessment"]
    assert assessment["model_algorithm"] == "one_class_svm"


def test_discovery_partial_bucket_excluded_across_restart(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    clock[0] = START + 51
    pipe.handle_baseline_event(event(second=51, key="partial"))
    assert pipe.lifecycle[CID]["learn_after"] == START + 51
    pipe.db.close()

    pipe = BehaviorPipeline(pipe.config, pipe.status, pipe.audit,
                            clock=lambda: clock[0])
    try:
        clock[0] = START + 131
        pipe.tick()
        assert pipe.store.load(CID, allow_missing=True).sample_count == 0
        assert pipe.db.execute(
            "SELECT count(*) FROM windows WHERE container=?", (CID,)
        ).fetchone()[0] == 1

        pipe.handle_baseline_event(event(second=121, key="full"))
        clock[0] = START + 191
        pipe.tick()
        dataset = pipe.store.load(CID)
        assert dataset.sample_count == 1
        assert dataset.feature_vectors[0].window_start.timestamp() == START + 120
    finally:
        pipe.db.close()


def test_discovery_partial_bucket_still_delivers_security_alert(tmp_path):
    pipe, clock, _ = setup(tmp_path)
    try:
        clock[0] = START + 51
        pipe.handle_baseline_event(event(second=51, key="partial-baseline"))
        pipe.handle_alert(event(second=52, key="partial-alert", security=True))
        clock[0] = START + 131
        pipe.tick()
        assert pipe.store.load(CID, allow_missing=True).sample_count == 0
        payloads = outbox(pipe)
        assert len(payloads) == 1
        assert payloads[0]["monitor_evidence"]["falco_alerts"]
    finally:
        pipe.db.close()
