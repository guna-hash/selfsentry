"""Regression fixture for repeated baseline patterns and forest boundary saturation."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "behavioral-engine"), str(ROOT / "monitor-service")]
from anomaly_model import AnomalyModel
from baseline_builder import BaselineDataset
from feature_extractor import FEATURE_NAMES, FeatureVector
from monitor_config import load_config, ConfigError

# Counts only: no production container identity, timestamps or baseline JSON in Git.
PATTERNS = [
    ((2, 0, 0, 2, 18, 0, 2, 14), 6),
    ((5, 0, 0, 3, 24, 1, 5, 14), 6),
    ((4, 0, 0, 3, 21, 1, 4, 14), 3),
    ((4, 0, 0, 3, 19, 1, 4, 12), 2),
    ((5, 0, 0, 3, 22, 1, 5, 12), 1),
    ((4, 0, 0, 3, 20, 1, 4, 13), 1),
    ((2, 0, 0, 2, 17, 0, 2, 13), 1),
]


def vector(values, minute=0):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return FeatureVector("regression", start, start + timedelta(minutes=1),
                         **dict(zip(FEATURE_NAMES, values)))


def dataset():
    rows = [values for values, count in PATTERNS for _ in range(count)]
    return BaselineDataset("regression", [vector(values, i) for i, values in enumerate(rows)])


def test_default_forest_preserves_historical_saturation_instead_of_rewriting_results():
    model = AnomalyModel("regression")
    model.fit(dataset())
    single = model.score_event(vector((7, 0, 0, 3, 26, 1, 7, 16)))
    burst = model.score_event(vector((7, 0, 0, 7, 122, 5, 8, 72)))
    assert single.anomaly_score == pytest.approx(0.1430080728562448)
    assert burst.anomaly_score == pytest.approx(single.anomaly_score)
    assert model.algorithm == "isolation_forest"


@pytest.mark.parametrize("counts", [
    (7, 0, 0, 3, 26, 1, 7, 16),
    (7, 0, 0, 7, 122, 5, 8, 72),
    (3, 0, 0, 3, 20, 1, 3, 14),
])
def test_candidate_detects_novel_vectors_without_threshold_changes(counts):
    model = AnomalyModel("regression", algorithm="one_class_svm")
    model.fit(dataset())
    result = model.score_event(vector(counts))
    assert result.is_anomaly and 0.8 <= result.anomaly_score <= 1


def test_candidate_baseline_replay_is_not_a_claim_of_independent_false_positive_rate():
    model = AnomalyModel("regression", algorithm="one_class_svm")
    baseline = dataset()
    model.fit(baseline)
    assert not any(model.score_event(v).anomaly_score >= 0.8 for v in baseline.feature_vectors)


def test_unknown_algorithm_fails_model_and_monitor_configuration():
    with pytest.raises(ValueError):
        AnomalyModel("regression", algorithm="unknown")
    with pytest.raises(ConfigError):
        load_config({"MONITOR_ANOMALY_ALGORITHM": "unknown"})


def test_model_choice_is_explicit_and_keeps_isolation_off_by_default():
    assert load_config({}).anomaly_algorithm == "isolation_forest"
    config = load_config({"MONITOR_ANOMALY_ALGORITHM": "one_class_svm"})
    assert config.anomaly_algorithm == "one_class_svm"
    assert not config.auto_isolation_enabled


def test_comparison_reads_renamed_baseline_without_rewriting_it(tmp_path):
    import json

    sys.path.insert(0, str(ROOT / "evaluation"))
    from compare_anomaly_models import compare

    path = tmp_path / "uploaded-baseline.json"
    content = json.dumps({"container_id": "regression",
                          "feature_vectors": [v.to_dict() for v in dataset().feature_vectors]})
    path.write_text(content)
    cases = tmp_path / "incidents.json"
    cases.write_text(json.dumps([
        {"id": i, "container_id": "regression", "monitor_evidence": {
            "anomaly_assessment": {"features": dict(zip(FEATURE_NAMES, counts))}}}
        for i, counts in [(1, (7, 0, 0, 3, 26, 1, 7, 16)),
                          (2, (7, 0, 0, 7, 122, 5, 8, 72))]
    ]))
    report = compare(path, cases)
    assert path.read_text() == content
    assert report["distinct_feature_vectors"] == 7
    assert report["forest_leaf_overlap"][0]["same_leaf_trees"] == 100
    assert report["algorithms"]["one_class_svm"]["leave_one_out_flags"] == 2
    assert report["algorithms"]["isolation_forest"]["leave_one_out_flags"] == 5
