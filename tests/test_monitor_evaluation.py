"""Evaluation math uses synthetic fixtures, never reported as live measurements."""
from evaluation.measure_results import aggregate
import pytest


def full_stats(rows):
    result = aggregate(rows)
    assert len(result["groups"]) == 1
    return next(iter(result["groups"].values()))["variants"]["full"]


def test_empty_measurements_stay_unknown():
    result = aggregate([])
    assert result["groups"] == {}
    assert result["total_records"] == 0
    stats = full_stats([{"variant": "full", "label": "benign", "detected": False}])
    assert stats["detection_rate"]["rate"] is None
    assert stats["detection_rate"]["n"] == 0
    assert stats["isolation_ms"]["n"] == 0
    assert stats["isolation_ms"]["median"] is None


def test_rates_and_latency_are_computed_from_recorded_trials():
    result = full_stats([
        {"variant": "full", "label": "attack", "detected": True,
         "detection_start": "2026-10-10T00:00:00Z",
         "detection_end": "2026-10-10T00:00:01Z"},
        {"variant": "full", "label": "attack", "detected": False},
        {"variant": "full", "label": "benign", "detected": False},
    ])
    assert result["detection_rate"]["n"] == 2
    assert result["detection_rate"]["successes"] == 1
    assert result["detection_rate"]["rate"] == 0.5
    assert result["false_positive_rate"]["n"] == 1
    assert result["false_positive_rate"]["rate"] == 0
    assert result["incident_visibility_ms"]["n"] == 1
    assert result["incident_visibility_ms"]["median"] == 1000


def test_invalid_measurement_is_refused():
    with pytest.raises(ValueError):
        aggregate([{"variant": "full", "label": "attack", "detected": True,
                    "isolation_start": "2026-10-10T00:00:02Z",
                    "isolation_end": "2026-10-10T00:00:01Z"}])


def test_different_configurations_are_not_pooled():
    rows = [{"variant": "full", "label": "attack", "detected": False,
             "config_fingerprint": fingerprint} for fingerprint in ("a", "b")]
    result = aggregate(rows)
    assert set(result["groups"]) == {"a", "b"}
    assert result["pooled_across_configurations"] is False
    for group in result["groups"].values():
        assert group["variants"]["full"]["detection_rate"]["n"] == 1
