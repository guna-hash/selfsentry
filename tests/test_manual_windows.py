"""Legacy diagnostic window regressions; synthetic file/clock, no live collector."""

import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "behavioral-engine"))
import collect_baseline as capture  # noqa: E402
import validate_live as validation  # noqa: E402
from baseline_builder import BaselineStore  # noqa: E402
from feature_extractor import FeatureVector  # noqa: E402

CID = "a" * 12
START = 1791532800


def vector(start):
    return FeatureVector(CID, datetime.fromtimestamp(start, timezone.utc),
                         datetime.fromtimestamp(start + 10, timezone.utc))


@pytest.mark.parametrize("module", [capture, validation])
@pytest.mark.parametrize("partial", [False, True])
def test_future_event_survives_closure_and_partial_record_is_retried(
    module, partial, tmp_path, monkeypatch,
):
    counter = [0]
    line = json.dumps({"rule": "Baseline Process Spawn",
                       "time": datetime.fromtimestamp(START + 11, timezone.utc).isoformat(),
                       "output_fields": {"container.id": CID, "proc.name": "worker"}}) + "\n"

    class Stream(io.StringIO):
        def readline(self):
            counter[0] += 1
            if counter[0] == 1:
                self.write(line[:10] if partial else line)
                self.seek(0)
            elif counter[0] == 2 and partial:
                self.seek(0, 2)
                self.write(line[10:])
                self.seek(0)
            return super().readline()

    fake_time = SimpleNamespace(monotonic=lambda: counter[0], sleep=lambda _: None)
    fake_datetime = SimpleNamespace(
        now=lambda _: datetime.fromtimestamp(START + counter[0] * 10, timezone.utc)
    )
    monkeypatch.setattr(module, "time", fake_time)
    monkeypatch.setattr(module, "datetime", fake_datetime)
    monkeypatch.setattr(module, "open", lambda *_: Stream(), raising=False)
    path = tmp_path / "baselines"
    if module is validation:
        BaselineStore(path).append(vector(START - 10))
        model = Mock()
        model.score_event.return_value = SimpleNamespace(is_anomaly=False, anomaly_score=0.1)
        monkeypatch.setattr(module, "AnomalyModel", lambda **_: model)
        validation.run_validation(CID, "fake", 0.05, 10, str(path))
        # First partial line is held; event timestamp 11 belongs to the second window.
        counts = [call.args[0].total_event_count for call in model.score_event.call_args_list]
        assert counts == [0, 1, 0]
    else:
        capture.run_capture(CID, "fake", 0.05, 10, str(path))
        counts = [v.total_event_count for v in BaselineStore(path).load(CID).feature_vectors]
        assert counts == [0, 1, 0]


def test_validation_refuses_a_baseline_with_different_window_length(tmp_path):
    BaselineStore(tmp_path).append(vector(START))
    with pytest.raises(ValueError, match="match every stored baseline window"):
        validation.run_validation(CID, "unopened", 1, 60, str(tmp_path))


@pytest.mark.parametrize("module", [capture, validation])
@pytest.mark.parametrize("duration,window", [(0, 10), (1, float("nan")), (float("inf"), 60)])
def test_invalid_timing_refused_before_file_or_model_work(module, duration, window, tmp_path):
    run = module.run_capture if module is capture else module.run_validation
    with pytest.raises(ValueError, match="finite and positive"):
        run(CID, "unopened", duration, window, str(tmp_path))
