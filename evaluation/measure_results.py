"""Aggregate recorded evaluation trials; missing measurements stay null.

Usage: python3 evaluation/measure_results.py trials.jsonl --output results.json

Timestamp contract
------------------
* Schema 2 trials record ``trial_started_at`` always and ``incident_visible_at``
  only when a persisted incident was actually observed. The interval between them
  is *incident visibility* latency (includes window alignment and lateness), not
  raw Falco latency.
* Legacy trials (no ``schema_version``) used ``detection_start`` as the trial
  start and ``detection_end`` only for detected trials. They are read as the same
  incident-visibility interval.
* An undetected trial has no latency. It stays in every denominator and is
  counted as ``n_incomplete`` for timings; a latency is never invented for it.
* Any other timing X uses ``X_start``/``X_end``. Start without end is incomplete;
  end without start is an error.

Grouping: results are grouped by ``config_fingerprint`` (legacy rows by a key
derived from rule hashes and baseline sample count). Groups are never pooled.
Trials with ``valid: false`` need ``exclusion_reason`` and are listed, not hidden.
No containers, network calls, attacks or response actions are performed here.
"""

import argparse
import json
import math
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SCHEMA_VERSION = 2
VARIANTS = ("falco_only", "hybrid", "full", "response")
TIMINGS = (
    "falco_detection",
    "ml_qualification",
    "correlation",
    "incident_creation",
    "incident_visibility",
    "isolation",
    "learning",
    "model_readiness",
)


def _stamp(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("measurement timestamps must include timezone")
    return stamp.timestamp()


def wilson_interval(successes, total, z=1.96):
    if not total:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _rate(successes, total):
    return {
        "n": total,
        "successes": successes,
        "rate": successes / total if total else None,
        "wilson_95": wilson_interval(successes, total),
    }


def _interval_fields(row, name):
    if name == "incident_visibility":
        if row.get("schema_version") == SCHEMA_VERSION:
            return row.get("trial_started_at"), row.get("incident_visible_at")
        return row.get("detection_start"), row.get("detection_end")
    return row.get(f"{name}_start"), row.get(f"{name}_end")


def _timing_stats(rows, name):
    durations, incomplete, not_measured = [], 0, 0
    for row in rows:
        if name == "incident_visibility" and row.get("visibility_measured") is False:
            not_measured += 1
            continue
        start, end = _interval_fields(row, name)
        if start is None and end is None:
            continue
        if start is None:
            raise ValueError(f"{name} has an end timestamp but no start")
        if name == "incident_visibility":
            if end is None and row["detected"]:
                raise ValueError("detected trial is missing its incident-visible timestamp")
            if end is not None and not row["detected"]:
                raise ValueError("undetected trial must not carry an incident-visible timestamp")
        if end is None:
            incomplete += 1
            continue
        duration = 1000 * (_stamp(end) - _stamp(start))
        if not math.isfinite(duration) or duration < 0:
            raise ValueError("invalid measurement interval")
        durations.append(duration)
    ordered = sorted(durations)
    return {
        "n": len(ordered),
        "n_incomplete": incomplete,
        "n_not_measured": not_measured,
        "median": statistics.median(ordered) if ordered else None,
        "p95": ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else None,
        "max": ordered[-1] if ordered else None,
    }


def _auto_confirmed(row):
    if "auto_confirmed" in row:
        return row["auto_confirmed"]
    if not row["detected"]:
        return None
    return "auto_confirmation_accuracy" in row  # legacy: field written only on auto-confirm


def group_key(row):
    if row.get("config_fingerprint"):
        return row["config_fingerprint"]
    rules = json.dumps(row.get("rule_file_sha256", {}), sort_keys=True)
    return f"legacy:rules={hash_short(rules)}:baseline_samples={row.get('baseline_samples')}"


def hash_short(text):
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()[:10]


def _validate(row):
    if row.get("variant") not in VARIANTS:
        raise ValueError("unknown evaluation variant")
    if row.get("label") not in ("attack", "benign") or type(row.get("detected")) is not bool:
        raise ValueError("each trial requires label attack/benign and boolean detected")
    if "valid" in row and type(row["valid"]) is not bool:
        raise ValueError("valid must be boolean when present")
    if row.get("valid") is False and not row.get("exclusion_reason"):
        raise ValueError("an excluded trial needs an exclusion_reason")


def _variant_stats(rows):
    attacks = [r for r in rows if r["label"] == "attack"]
    benign = [r for r in rows if r["label"] == "benign"]
    stats = {
        "trials": len(rows),
        "attack_trials": len(attacks),
        "benign_trials": len(benign),
        "detection_rate": _rate(sum(r["detected"] for r in attacks), len(attacks)),
        "false_positive_rate": _rate(sum(r["detected"] for r in benign), len(benign)),
    }
    scenarios = defaultdict(list)
    for row in rows:
        if "scenario" in row:
            scenarios[row["scenario"]].append(row)
    stats["scenarios"] = {
        name: {
            "label": group[0]["label"],
            "trials": len(group),
            "detected": sum(r["detected"] for r in group),
        }
        for name, group in sorted(scenarios.items())
    }
    # Latency describes detecting attacks. Benign rows that raised incidents are false
    # positives, so their time-to-incident is reported separately and never mixed in.
    for name in TIMINGS:
        stats[f"{name}_ms"] = _timing_stats(attacks, name)
    stats["benign_incident_visibility_ms"] = _timing_stats(benign, "incident_visibility")
    confirmed = [(r, _auto_confirmed(r)) for r in rows if r["detected"]]
    confirmed = [(r, c) for r, c in confirmed if c is not None]
    auto = [r for r, c in confirmed if c]
    detected_attacks = [(r, c) for r, c in confirmed if r["label"] == "attack"]
    stats["confirmation_precision"] = _rate(sum(r["label"] == "attack" for r in auto), len(auto))
    stats["attack_confirmation_coverage"] = _rate(
        sum(1 for _, c in detected_attacks if c), len(detected_attacks)
    )
    for name in ("candidate_validity", "benign_rule_rejection", "failure_recovery"):
        values = [r[name] for r in rows if name in r]
        if any(type(v) is not bool for v in values):
            raise ValueError(f"{name} must be boolean when measured")
        stats[name] = _rate(sum(values), len(values))
    duplicates = [r["duplicate_incident_count"] for r in rows if "duplicate_incident_count" in r]
    if any(type(n) is not int or n < 0 for n in duplicates):
        raise ValueError("duplicate incident counts must be nonnegative integers")
    stats["duplicate_incident_rate"] = (
        sum(n > 0 for n in duplicates) / len(duplicates) if duplicates else None
    )
    return stats


def aggregate(records):
    for row in records:
        _validate(row)
    excluded = [
        {"trial_id": r.get("trial_id"), "reason": r["exclusion_reason"]}
        for r in records
        if r.get("valid") is False
    ]
    included = [r for r in records if r.get("valid") is not False]
    grouped = defaultdict(list)
    for row in included:
        grouped[group_key(row)].append(row)
    groups = {}
    for key, rows in sorted(grouped.items()):
        groups[key] = {
            "variants": {
                variant: _variant_stats([r for r in rows if r["variant"] == variant])
                for variant in VARIANTS
                if any(r["variant"] == variant for r in rows)
            }
        }
    return {
        "measurement_source": "recorded controlled trials",
        "latency_meaning": "incident_visibility_ms is trial start to persisted incident "
        "visible via API; it is not raw Falco detection latency",
        "pooled_across_configurations": False,
        "total_records": len(records),
        "excluded_trials": excluded,
        "groups": groups,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trials", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = [json.loads(line) for line in args.trials.read_text().splitlines() if line.strip()]
    results = aggregate(records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        f"{len(records)} recorded trials, {len(results['groups'])} configuration group(s), "
        f"{len(results['excluded_trials'])} excluded; summary in {args.output}"
    )


if __name__ == "__main__":
    main()
