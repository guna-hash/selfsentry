"""Offline held-out window evaluation of the unchanged default Isolation Forest.

Consumes private baseline JSON and labeled validation JSONL; never collects attacks,
changes baselines, tunes thresholds or claims a representative corpus by itself.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'behavioral-engine'))
from anomaly_model import AnomalyModel  # noqa: E402
from baseline_builder import BaselineDataset, BaselineNotReadyError  # noqa: E402
from feature_extractor import FeatureVector, FEATURE_NAMES  # noqa: E402


def vector(raw, cid):
    if not isinstance(raw, dict) or raw.get('container_id') != cid:
        raise ValueError('window ownership invalid')
    start, end = (datetime.fromisoformat(raw[key].replace('Z', '+00:00'))
                  for key in ('window_start', 'window_end'))
    if start.utcoffset() is None or end.utcoffset() is None or start >= end:
        raise ValueError('window timestamps invalid')
    features = {name: raw[name] for name in FEATURE_NAMES}
    if any(type(v) is not int or v < 0 for v in features.values()):
        raise ValueError('window features must be nonnegative integers')
    return FeatureVector(cid, start, end, **features)


def evaluate(baseline_bytes, validation_bytes, expected_windows):
    raw = json.loads(baseline_bytes)
    cid = raw['container_id']
    training = [vector(item, cid) for item in raw['feature_vectors']]
    if not training or len({tuple(v.to_array()) for v in training}) < 2:
        raise ValueError('Training requires nonempty varied baseline data')
    ordered = sorted(training, key=lambda v: v.window_start)
    if any(a.window_end > b.window_start for a, b in zip(ordered, ordered[1:])):
        raise ValueError('Training windows overlap or repeat')
    lines = validation_bytes.decode('utf-8').splitlines()
    if type(expected_windows) is not int or expected_windows <= 0 or expected_windows < len(lines):
        raise ValueError('Declare an expected window count covering all validation rows')
    model = AnomalyModel(cid)  # No SVM or evaluation-time threshold tuning.
    started = time.perf_counter()
    model.fit(BaselineDataset(cid, training))
    fit_seconds = time.perf_counter() - started
    counts = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0}
    predictions: list[dict[str, Any]] = []
    seen: list[FeatureVector] = []
    separation_errors = 0
    unscored = {'benign': 0, 'attack': 0, 'unknown': expected_windows - len(lines)}
    for index, line in enumerate(lines, 1):
        label, stamp = 'unknown', time.perf_counter()
        try:
            item = json.loads(line)
            label = item.get('label')
            if label not in ('benign', 'attack'):
                label = 'unknown'
                raise ValueError('missing/invalid ground-truth label')
            fv = vector(item['feature_vector'], cid)
            if any(fv.window_start < old.window_end and old.window_start < fv.window_end
                   for old in training + seen):
                separation_errors += 1
                raise ValueError('training/validation or validation/validation overlap')
            seen.append(fv)
            if fv.window_start < max(v.window_end for v in training):
                separation_errors += 1
                raise ValueError('validation must follow frozen training')
            result = model.score_event(fv)
            if not all(math.isfinite(v) for v in (result.anomaly_score,
                                                  result.raw_decision_function)):
                raise ValueError('nonfinite model output')
            key = ('tp' if result.is_anomaly else 'fn') if label == 'attack' else (
                'fp' if result.is_anomaly else 'tn')
            counts[key] += 1
            predictions.append({'line': index, 'label': label, 'scored': True,
                                'is_anomaly': result.is_anomaly, 'score': result.anomaly_score,
                                'raw_decision_function': result.raw_decision_function,
                                'seconds': time.perf_counter() - stamp})
        except (ValueError, KeyError, TypeError, AttributeError):
            unscored[label] += 1
            predictions.append({'line': index, 'label': label, 'scored': False,
                                'reason': 'invalid/missing/overlapping window; '
                                          'inspect private input'})
    benign, attacks = counts['fp'] + counts['tn'], counts['tp'] + counts['fn']
    return {'algorithm': 'isolation_forest', 'threshold': 0.5,
            'score_meaning': 'ranking score; not calibrated confidence',
            'baseline_sha256': hashlib.sha256(baseline_bytes).hexdigest(),
            'validation_sha256': hashlib.sha256(validation_bytes).hexdigest(),
            'training_samples': len(training), 'expected_windows': expected_windows,
            'scored_windows': sum(counts.values()), 'unscored': unscored,
            'separation_errors': separation_errors,
            'valid_complete_run': not any(unscored.values()) and benign > 0 and attacks > 0,
            'confusion': counts, 'benign_scored_denominator': benign,
            'attack_scored_denominator': attacks,
            'false_positive_rate_scored': counts['fp'] / benign if benign else None,
            'recall_scored': counts['tp'] / attacks if attacks else None,
            'fit_seconds': fit_seconds, 'predictions': predictions,
            'scope': 'offline supplied windows; representativeness/native capture not established'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--validation', type=Path, required=True)
    parser.add_argument('--expected-windows', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Reserve private output first so invalid input is also retained as a failed run.
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    report: dict[str, Any] = {'created_at': datetime.now(timezone.utc).isoformat(),
                              'python': sys.version, 'sklearn': version('scikit-learn')}
    code = 1
    try:
        report.update(evaluate(args.baseline.read_bytes(), args.validation.read_bytes(),
                               args.expected_windows))
        code = 0 if report['valid_complete_run'] else 1
    except (OSError, ValueError, KeyError, TypeError, BaselineNotReadyError):
        report.update(valid_complete_run=False, error='Invalid input; inspect private corpus')
    finally:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(report, indent=2, allow_nan=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
    return code


if __name__ == '__main__':
    raise SystemExit(main())
