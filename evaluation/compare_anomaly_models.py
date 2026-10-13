"""Offline model comparison; never modifies baselines or live automation settings.

Leave-one-out results are correlated diagnostics on a small dataset, not a measured
production false-positive rate. LOO fits 19 rows here for analysis only; it does not
bypass the monitor's 20-sample readiness requirement.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
import sklearn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "behavioral-engine"))
from anomaly_model import AnomalyModel  # noqa: E402
from baseline_builder import BaselineDataset  # noqa: E402
from feature_extractor import FEATURE_NAMES, FeatureVector  # noqa: E402

ALGORITHMS = ("isolation_forest", "one_class_svm")


def fit_diagnostic(algorithm, x):
    model = AnomalyModel("offline-diagnostic", algorithm=algorithm)
    # Standalone classifier diagnostic, deliberately not a deployable ready model.
    model._model.fit(x)
    train = model._model.decision_function(x)
    model._train_score_mean = float(np.mean(train))
    model._train_score_std = max(float(np.std(train)), 1e-6)
    return model


def scores(model, x):
    return [model._normalize_score(float(v)) for v in model._model.decision_function(x)]


def compare(baseline_path, incidents_path=None):
    raw = json.loads(baseline_path.read_text())
    cid = raw["container_id"]
    dataset = BaselineDataset(cid, [
        FeatureVector(
            container_id=row["container_id"],
            window_start=datetime.fromisoformat(row["window_start"]),
            window_end=datetime.fromisoformat(row["window_end"]),
            **{name: row[name] for name in FEATURE_NAMES},
        )
        for row in raw["feature_vectors"]
    ])
    if any(row.container_id != cid for row in dataset.feature_vectors):
        raise ValueError("baseline vector ownership differs from file ownership")
    if dataset.sample_count < 20:
        raise ValueError("comparison requires at least 20 baseline samples")
    x = np.array(dataset.to_array(), dtype=float)
    if not np.isfinite(x).all() or (x < 0).any():
        raise ValueError("baseline counts must be finite and nonnegative")
    incidents = json.loads(incidents_path.read_text()) if incidents_path else []
    cases = []
    for incident in incidents:
        if incident.get("container_id") not in (cid,):
            continue
        assessment = (incident.get("monitor_evidence") or {}).get("anomaly_assessment") or {}
        vector = assessment.get("features")
        if not vector:
            continue
        values = [vector[name] for name in FEATURE_NAMES]
        if not np.isfinite(values).all() or min(values) < 0:
            raise ValueError("incident counts must be finite and nonnegative")
        cases.append({"id": incident["id"], "features": values,
                      "recorded_score": assessment.get("anomaly_score")})
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
        "container_id": cid, "samples": len(x),
        "distinct_feature_vectors": len(np.unique(x, axis=0)),
        "sklearn_version": sklearn.__version__, "qualification_threshold": 0.8,
        "warning": "Training replay/LOO diagnostics; no independent benign validation or live run",
        "algorithms": {},
    }
    for algorithm in ALGORITHMS:
        model = fit_diagnostic(algorithm, x)
        replay = scores(model, x)
        loo = []
        for i in range(len(x)):
            leave_one = fit_diagnostic(algorithm, np.delete(x, i, axis=0))
            loo.append(scores(leave_one, x[i:i + 1])[0])
        result = {
            "training_replay_flags": sum(v >= 0.8 for v in replay),
            "training_replay_scores": replay,
            "leave_one_out_flags": sum(v >= 0.8 for v in loo),
            "leave_one_out_scores": loo,
            "cases": [],
        }
        for case in cases:
            y = np.array([case["features"]], dtype=float)
            score = scores(model, y)[0]
            result["cases"].append({**case, "score": score, "qualifies": score >= 0.8,
                                    "raw_decision_function": float(
                                        model._model.decision_function(y)[0])})
        report["algorithms"][algorithm] = result
    if len(cases) >= 2:
        # Explain saturation without assuming large count differences imply a bug.
        forest = fit_diagnostic("isolation_forest", x)._model
        y = np.array([c["features"] for c in cases], dtype=float)
        leaves = np.array([
            tree.apply(y[:, forest.estimators_features_[i]])
            for i, tree in enumerate(forest.estimators_)
        ])
        report["forest_leaf_overlap"] = [
            {"ids": [cases[i]["id"], cases[j]["id"]],
             "same_leaf_trees": int(np.sum(leaves[:, i] == leaves[:, j])),
             "trees": len(forest.estimators_)}
            for i in range(len(cases)) for j in range(i + 1, len(cases))
        ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--incidents-json", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "state/model-review/comparison.json")
    args = parser.parse_args()
    result = compare(args.baseline, args.incidents_json)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Samples={result['samples']}; distinct vectors={result['distinct_feature_vectors']}")
    for name, item in result["algorithms"].items():
        print(name, "training replay flags:", item["training_replay_flags"],
              "LOO flags:", item["leave_one_out_flags"])
        for case in item["cases"]:
            print("incident", case["id"], "score", round(case["score"], 6))
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
