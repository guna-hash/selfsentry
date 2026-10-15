import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation"))
spec = importlib.util.spec_from_file_location(
    "academic_capture", ROOT / "evaluation/capture_academic_case.py"
)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


@pytest.mark.parametrize("flag", capture.ACTION_FLAGS)
def test_study_refuses_any_enabled_or_unspecified_automatic_action(flag):
    env = {key: "false" for key in capture.ACTION_FLAGS}
    env["MONITOR_ANOMALY_ALGORITHM"] = "isolation_forest"
    capture.validate_env(env)
    env[flag] = "true"
    with pytest.raises(RuntimeError):
        capture.validate_env(env)
    del env[flag]
    with pytest.raises(RuntimeError):
        capture.validate_env(env)


def test_experimental_model_is_not_silently_used_for_main_study():
    env = {key: "false" for key in capture.ACTION_FLAGS}
    env["MONITOR_ANOMALY_ALGORITHM"] = "one_class_svm"
    with pytest.raises(RuntimeError):
        capture.validate_env(env)


@pytest.mark.parametrize(
    "state,algorithm,healthy",
    [
        ("LEARNING", "isolation_forest", True),
        ("MODEL_READY", "one_class_svm", True),
        ("MODEL_READY", "isolation_forest", False),
    ],
)
def test_capture_requires_ready_default_model_and_healthy_monitor(state, algorithm, healthy):
    with pytest.raises(RuntimeError):
        capture.validate_status(
            {
                "running": True,
                "healthy": healthy,
                "baselines": {"abc": {"state": state, "model_algorithm": algorithm}},
            },
            "abc",
        )


def test_capture_keeps_only_new_target_records_and_preserves_native_fields(tmp_path):
    log = tmp_path / "alerts.json"
    raw = {
        "rule": "NativeGeneratedRule",
        "time": "2026-10-15T10:00:00Z",
        "output_fields": {"container.id": "abc", "proc.name": "ss-study-true"},
    }
    log.write_text("old\n")
    info = log.stat()
    with log.open("a") as f:
        f.write(json.dumps(raw) + "\n")
        f.write(json.dumps({**raw, "output_fields": {"container.id": "other"}}) + "\n")
    assert capture.read_segment(log, info.st_ino, info.st_size, "abcdef") == [raw]


def test_rotation_cannot_be_silently_counted_as_a_clean_capture(tmp_path):
    log = tmp_path / "alerts.json"
    log.write_text("test\n")
    info = log.stat()
    log.rename(tmp_path / "old.json")
    log.write_text("")
    with pytest.raises(RuntimeError, match="rotated/truncated"):
        capture.read_segment(log, info.st_ino, info.st_size, "abc")


def test_failed_setup_preserves_invalid_report_without_study_trigger(tmp_path, monkeypatch):
    out = tmp_path / "failed-capture"
    monkeypatch.setattr(sys, "argv", ["capture", "--case", "binary", "--out", str(out)])

    def failed_inspect(*args, **kwargs):
        raise capture.subprocess.CalledProcessError(1, "docker inspect")

    def unexpected_trigger(*args, **kwargs):
        pytest.fail("Study workload must not run after failed setup")

    monkeypatch.setattr(capture.subprocess, "check_output", failed_inspect)
    monkeypatch.setattr(capture.subprocess, "run", unexpected_trigger)
    assert capture.main() == 1
    saved = json.loads((out / "capture.json").read_text())
    assert saved["valid"] is False
    assert saved["errors"]
