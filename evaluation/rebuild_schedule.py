"""Rebuild one saved schedule into a derived dataset; original evidence is untouched."""

import argparse
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from run_schedule import build_record


def rebuild(root, run_id, source, destination, timezone, seed):
    ZoneInfo(timezone)
    schedule = root / f"state/evaluation/schedules/{run_id}.jsonl"
    evidence = root / f"state/evaluation/evidence/{run_id}-incidents.json"
    entries = [json.loads(line) for line in schedule.read_text().splitlines() if line.strip()]
    incidents = json.loads(evidence.read_text())
    rows = [json.loads(line) for line in source.read_text().splitlines() if line.strip()]
    originals = {row["trial_id"]: row for row in rows}
    replacements = {}
    for entry in entries:
        trial_id = f"{run_id}-{entry['index']:04d}"
        prior = originals.get(trial_id)
        if not prior:
            raise ValueError(f"Original trial missing: {trial_id}; no output written")
        cfg = {
            "target": prior["container_id"],
            "run_id": run_id,
            "window": prior["window_seconds"],
            "lateness": prior["lateness_seconds"],
            "seed": prior.get("schedule_seed", seed),
            "incident_timezone": timezone,
        }
        record = build_record(entry, incidents, cfg)
        record["reprocessing"] = {
            "schedule": str(schedule),
            "incident_evidence": str(evidence),
            "reason": "explicit source timezone for naive database timestamp",
            "original_valid": prior.get("valid"),
            "original_exclusion_reason": prior.get("exclusion_reason"),
        }
        replacements[trial_id] = record
    if destination.resolve() == source.resolve() or destination.exists():
        raise ValueError("Output must be a new file, separate from original evidence")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        "".join(json.dumps(replacements.get(row["trial_id"], row)) + "\n" for row in rows)
    )
    print(f"Rebuilt {len(replacements)} trials into {destination}; originals preserved")
    for record in replacements.values():
        print(
            record["trial_id"],
            record["scenario"],
            "detected=",
            record["detected"],
            "valid=",
            record.get("valid", True),
            record.get("exclusion_reason", ""),
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--incident-timezone", required=True)
    parser.add_argument("--source", type=Path, default=Path("state/evaluation/trials.jsonl"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261011)
    args = parser.parse_args()
    rebuild(
        Path(__file__).resolve().parents[1],
        args.run_id,
        args.source,
        args.output,
        args.incident_timezone,
        args.seed,
    )
