"""Synthetic fixtures verify evaluator accounting; these are not detection measurements."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
from evaluate_holdout import evaluate  # noqa: E402
from feature_extractor import FEATURE_NAMES  # noqa: E402


def window(index):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index)
    return {'container_id': 'a' * 64, 'window_start': start.isoformat(),
            'window_end': (start + timedelta(minutes=1)).isoformat(),
            **{key: index % 3 for key in FEATURE_NAMES}}


def baseline():
    return json.dumps({'container_id': 'a' * 64,
                       'feature_vectors': [window(i) for i in range(20)]}).encode()


def corpus(*rows):
    return '\n'.join(json.dumps(row) for row in rows).encode()


def test_denominators_include_missing_and_unscored_windows():
    data = corpus({'label': 'benign', 'feature_vector': window(20)},
                  {'label': 'attack', 'feature_vector': window(21)},
                  {'label': 'attack'})
    result = evaluate(baseline(), data, 5)
    assert result['unscored'] == {'benign': 0, 'attack': 1, 'unknown': 2}
    assert result['scored_windows'] == sum(result['confusion'].values()) == 2
    assert result['benign_scored_denominator'] == result['attack_scored_denominator'] == 1
    assert result['valid_complete_run'] is False


def test_overlap_and_duplicate_validation_are_retained_as_invalid_trials():
    rows = [{'label': 'benign', 'feature_vector': window(0)},
            {'label': 'attack', 'feature_vector': window(20)},
            {'label': 'attack', 'feature_vector': window(20)}]
    result = evaluate(baseline(), corpus(*rows), 3)
    assert result['separation_errors'] == 2
    assert result['unscored'] == {'benign': 1, 'attack': 1, 'unknown': 0}
    assert result['valid_complete_run'] is False


def test_clean_holdout_has_fixed_default_model_and_hashed_inputs():
    data = corpus({'label': 'benign', 'feature_vector': window(20)},
                  {'label': 'attack', 'feature_vector': window(21)})
    result = evaluate(baseline(), data, 2)
    assert result['valid_complete_run'] is True
    assert result['algorithm'] == 'isolation_forest' and result['threshold'] == 0.5
    assert len(result['baseline_sha256']) == len(result['validation_sha256']) == 64


def test_invalid_training_and_underdeclared_trials_cannot_produce_metrics():
    with pytest.raises(ValueError):
        evaluate(baseline(), corpus({}, {}), 1)
    raw = json.loads(baseline())
    raw['feature_vectors'][0] = raw['feature_vectors'][1]
    with pytest.raises(ValueError, match='overlap'):
        evaluate(json.dumps(raw).encode(), b'{}', 1)
