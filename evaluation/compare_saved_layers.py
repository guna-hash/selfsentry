"""Retrospective layer observation and deterministic ML replay; no live side effects."""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

root = Path.cwd()
sys.path.insert(0, str(root / "behavioral-engine"))
from anomaly_model import AnomalyModel  # noqa: E402
from baseline_builder import BaselineStore  # noqa: E402
from baseline_collector import parse_baseline_event  # noqa: E402
from feature_extractor import extract_features  # noqa: E402

trials = [
    json.loads(line)
    for line in (root / "state/evaluation/full-20261011-only.jsonl").read_text().splitlines()
    if line.strip()
]
entries = [
    json.loads(line)
    for line in (root / "state/evaluation/schedules/full-20261011.jsonl").read_text().splitlines()
    if line.strip()
]
incidents = json.loads(
    (root / "state/evaluation/evidence/full-20261011-incidents.json").read_text()
)
by_id = {row["id"]: row for row in incidents}
by_index = {row["index"]: row for row in entries}
if len(trials) != 200 or len({row["trial_id"] for row in trials}) != 200:
    raise SystemExit("Expected 200 unique trials.")
if len({row["config_fingerprint"] for row in trials}) != 1:
    raise SystemExit("Mixed configurations; compare separately.")
if any(row.get("valid") is False for row in trials):
    raise SystemExit("Invalid trials require separate accounting.")
cid = trials[0]["container_id"]
settings = trials[0]["fingerprint_components"].get("monitor_settings", {})
folder = Path(settings.get("MONITOR_BASELINE_DIR") or root / "behavioral-engine/baselines")
baseline = folder / f"{cid}.json"
expected = {row["fingerprint_components"]["baseline_sha256"] for row in trials}
actual = hashlib.sha256(baseline.read_bytes()).hexdigest()
if expected != {actual}:
    raise SystemExit("Baseline differs from the evaluated baseline; replay stopped.")
threshold = float(settings.get("MONITOR_ANOMALY_THRESHOLD") or 0.8)
model = AnomalyModel(cid)
model.fit(BaselineStore(folder).load(cid))
events = defaultdict(list)
for line in (root / "state/evaluation/full-20261011-telemetry.jsonl").read_text().splitlines():
    if line.strip():
        row = json.loads(line)
        events[int(row["bucket"])].append(row)
results = []
mismatches = []
checks = 0
for trial in trials:
    entry = by_index[trial["schedule_index"]]
    bucket = int(entry["boundary_epoch"])
    start = datetime.fromtimestamp(bucket, timezone.utc)
    end = datetime.fromtimestamp(bucket + trial["window_seconds"], timezone.utc)
    stored = events.get(bucket, [])
    alerts = [row["event"] for row in stored if row["kind"] == "alert"]
    raw = [
        parse_baseline_event(row["event"]["raw_line"])
        for row in stored
        if row["kind"] == "baseline"
    ]
    raw = [event for event in raw if event is not None]
    if any(event.container_id != cid for event in raw):
        raise SystemExit("Telemetry contains another container; replay stopped.")
    unique = {
        (
            r.timestamp,
            r.event_type,
            r.proc_name,
            r.parent_proc_name,
            r.dest_ip,
            r.dest_port,
            r.file_path,
            r.syscall_name,
        ): r
        for r in raw
    }
    score = None
    qualified = False
    if unique:
        vector = extract_features(list(unique.values()), cid, start, end)
        result = model.score_event(vector)
        score = float(result.anomaly_score)
        qualified = bool(result.is_anomaly and score >= threshold)
    for incident_id in trial["incident_ids"]:
        assessment = (by_id[incident_id].get("monitor_evidence") or {}).get("anomaly_assessment")
        if assessment:
            checks += 1
            if (
                score is None
                or abs(score - assessment["anomaly_score"]) > 1e-8
                or qualified != assessment["qualifies"]
            ):
                mismatches.append(
                    {
                        "trial_id": trial["trial_id"],
                        "saved_score": assessment["anomaly_score"],
                        "replay_score": score,
                    }
                )
    results.append(
        {
            "trial_id": trial["trial_id"],
            "scenario": trial["scenario"],
            "label": trial["label"],
            "falco_alert": bool(alerts),
            "ml_qualified": qualified,
            "ml_score": score,
            "ml_scored": score is not None,
            "union_detected": bool(alerts) or qualified,
            "full_detected": trial["detected"],
            "auto_confirmed": trial.get("auto_confirmed") is True,
        }
    )
if mismatches:
    print(json.dumps({"assessment_mismatches": mismatches, "checked": checks}, indent=2))
    raise SystemExit("Replay does not match saved assessments; no validated comparison written.")
summary = {
    "comparison_type": (
        "retrospective observations/replay from the same full-pipeline run; "
        "not independent live variant runs"
    ),
    "raw_falco_receipt_latency": "not measured",
    "ml_processing_latency": "not measured",
    "baseline_sha256": actual,
    "threshold": threshold,
    "saved_assessments_verified": checks,
    "trials": len(results),
    "scenarios": {},
}
for scenario in sorted({row["scenario"] for row in results}):
    rows = [row for row in results if row["scenario"] == scenario]
    summary["scenarios"][scenario] = {
        "label": rows[0]["label"],
        "n": len(rows),
        **{
            key: sum(row[key] for row in rows)
            for key in (
                "falco_alert",
                "ml_qualified",
                "ml_scored",
                "union_detected",
                "full_detected",
                "auto_confirmed",
            )
        },
    }
summary["totals"] = {}
for label in ("attack", "benign"):
    rows = [row for row in results if row["label"] == label]
    summary["totals"][label] = {
        "n": len(rows),
        **{
            key: sum(row[key] for row in rows)
            for key in (
                "falco_alert",
                "ml_qualified",
                "ml_scored",
                "union_detected",
                "full_detected",
                "auto_confirmed",
            )
        },
    }
summary["union_vs_full_mismatches"] = sum(
    row["union_detected"] != row["full_detected"] for row in results
)
output = root / "state/evaluation/saved-layer-comparison.json"
output.write_text(json.dumps({"summary": summary, "trials": results}, indent=2) + "\n")
print(json.dumps(summary, indent=2))
print("Saved:", output)
