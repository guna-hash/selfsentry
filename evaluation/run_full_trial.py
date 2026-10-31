"""Collect one controlled full-pipeline trial; never enables isolation or approves rules.

Timestamp contract (schema 2): trial_started_at is always recorded; incident_visible_at
is recorded only if a persisted incident was observed. Undetected trials carry no
latency. Configuration is fingerprinted before and after; a change during the trial
marks it invalid (kept as evidence, excluded from aggregation).
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import requests
from safety import backend_json, require_isolation_disabled
from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fingerprint import collect_fingerprint  # noqa: E402
from clock_guard import (  # noqa: E402
    AlertTail,
    ClockGuardError,
    DEFAULT_ALERTS_PATH,
    judge_events,
    require_recent_preflight,
)

SCHEMA_VERSION = 2


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_json(base, endpoint):
    return backend_json(base, endpoint)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["binary-execution", "benign-admin", "quiet"])
    parser.add_argument("--container", default="selfsentry-test")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = dotenv_values(root / ".env")
    base = config.get("SELFSENTRY_BACKEND_URL") or "http://127.0.0.1:8000"
    window = int(config.get("MONITOR_WINDOW_SECONDS") or 60)
    lateness = float(config.get("MONITOR_LATENESS_SECONDS") or 10)
    info = json.loads(subprocess.check_output(["docker", "inspect", args.container]))[0]
    target = info["Id"][:12]
    if not info["State"]["Running"] or info["State"]["Paused"]:
        raise SystemExit("Target must be running and unpaused.")
    status = get_json(base, "/monitor/status")
    require_isolation_disabled(status)
    baseline = status.get("baselines", {}).get(target, {})
    if not status.get("healthy") or baseline.get("state") != "MODEL_READY":
        raise SystemExit("A healthy monitor and a ready target model are required.")
    fingerprint_before = collect_fingerprint(root, target, config, info["Image"])
    try:
        preflight = require_recent_preflight(root / "state/evaluation/clock_check.json", target)
    except ClockGuardError as exc:
        raise SystemExit(f"Clock preflight required: {exc}")
    alert_tail = AlertTail(config.get("FALCO_LOG_PATH") or DEFAULT_ALERTS_PATH)
    try:
        alert_tail.mark()
    except ClockGuardError as exc:
        raise SystemExit(str(exc))
    print(
        "Keep automatic isolation OFF; run no other target workload during this trial.", flush=True
    )
    # Start near the beginning of a new fixed window to avoid overlapping trial evidence.
    boundary = (int(time.time()) // window + 1) * window
    delay = max(0, boundary + 2 - time.time())
    print(f"Waiting {delay:.1f}s for a fresh {window}s window...", flush=True)
    time.sleep(delay)
    require_isolation_disabled(get_json(base, "/monitor/status"))
    trial_id = uuid.uuid4().hex
    started_epoch = time.time()
    started = utc_now()
    start_mono = time.monotonic()
    if args.scenario == "binary-execution":
        command = [
            "/bin/sh",
            "-c",
            "set -eu; d=$(mktemp -d /tmp/selfsentry-eval.XXXXXX); "
            'trap \'rm -rf "$d"\' EXIT; cp /bin/true "$d/validation-true"; '
            'chmod 700 "$d/validation-true"; "$d/validation-true"',
        ]
    elif args.scenario == "benign-admin":
        command = [
            "/bin/sh",
            "-c",
            "id >/dev/null; ls /usr/share/nginx/html >/dev/null; " "uname -s >/dev/null",
        ]
    else:
        command = None
    folder = root / "state/evaluation/evidence"
    folder.mkdir(parents=True, exist_ok=True)
    if command:
        outcome = subprocess.run(
            ["docker", "exec", args.container, *command], capture_output=True, text=True
        )
        if outcome.returncode:
            (folder / f"{trial_id}-invalid.json").write_text(
                json.dumps(
                    {
                        "scenario": args.scenario,
                        "started": started,
                        "returncode": outcome.returncode,
                        "stderr": outcome.stderr,
                    },
                    indent=2,
                )
            )
            raise SystemExit(
                "Action failed; saved invalid-run evidence, no labeled trial appended."
            )
    first_seen = None
    observed_seconds = None
    rows = []
    poll_errors = []
    deadline = start_mono + window + lateness + 30
    while time.monotonic() < deadline:
        try:
            all_rows = get_json(base, "/incidents/")
        except requests.RequestException as exc:
            poll_errors.append({"at": utc_now(), "type": type(exc).__name__})
            time.sleep(0.5)
            continue
        rows = [
            row
            for row in all_rows
            if row.get("container_id") == target
            and (row.get("monitor_evidence") or {}).get("window_start")
            == datetime.fromtimestamp(boundary, timezone.utc).isoformat()
        ]
        if rows and first_seen is None:
            first_seen = utc_now()
            observed_seconds = time.monotonic() - start_mono
        time.sleep(0.5)
    try:
        final_status = get_json(base, "/monitor/status")
    except requests.RequestException as exc:
        final_status = {"error": type(exc).__name__}
    finished_epoch = time.time()
    fingerprint_after = collect_fingerprint(root, target, config, info["Image"])
    try:
        clock = judge_events(
            alert_tail.new_events(target),
            started_epoch,
            finished_epoch,
            expect_events=command is not None,
        )
    except ClockGuardError as exc:
        clock = {"valid": False, "status": f"falco_output_unreadable: {exc}"}
    exclusions = []
    record = {
        "schema_version": SCHEMA_VERSION,
        "trial_id": trial_id,
        "variant": "full",
        "scenario": args.scenario,
        "label": "attack" if args.scenario == "binary-execution" else "benign",
        "detected": bool(rows),
        "container_id": target,
        "detection_definition": "at least one persisted incident in the target trial window",
        "trial_started_at": started,
        "trial_finished": utc_now(),
        "window_seconds": window,
        "lateness_seconds": lateness,
        "baseline_samples": baseline.get("samples"),
        "poll_interval_seconds": 0.5,
        "incident_ids": [row["id"] for row in rows],
        "duplicate_incident_count": max(0, len(rows) - 1),
        "controlled_simulation": args.scenario == "binary-execution",
        "poll_errors": poll_errors,
        "clock_check": {
            **clock,
            "preflight_checked_at": preflight.get("checked_at"),
            "preflight_status": preflight.get("status"),
        },
        "config_fingerprint": fingerprint_before["config_fingerprint"],
        "fingerprint_components": fingerprint_before["fingerprint_components"],
        "software_context": fingerprint_before["software_context"],
        "rule_file_sha256": fingerprint_before["fingerprint_components"]["rule_file_sha256"],
    }
    if fingerprint_after["config_fingerprint"] != fingerprint_before["config_fingerprint"]:
        exclusions.append("configuration changed during trial")
        record["config_fingerprint_after"] = fingerprint_after["config_fingerprint"]
    if not clock["valid"]:
        exclusions.append(f"invalid clock: {clock['status']}")
    if exclusions:
        record["valid"] = False
        record["exclusion_reason"] = "; ".join(exclusions)
    if rows:
        record["auto_confirmed"] = any(
            (row.get("confirmation") or {}).get("confirmed_by") == "selfsentry-auto" for row in rows
        )
        if record["auto_confirmed"]:
            record["auto_confirmation_accuracy"] = record["label"] == "attack"
    if first_seen:
        record["incident_visible_at"] = first_seen
        record["incident_visibility_seconds_monotonic"] = observed_seconds
    (folder / f"{trial_id}.json").write_text(
        json.dumps(
            {
                "trial": record,
                "incidents": rows,
                "status_before": status,
                "status_after": final_status,
            },
            indent=2,
        )
    )
    destination = root / "state/evaluation/trials.jsonl"
    with destination.open("a") as stream:
        stream.write(json.dumps(record) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(record, indent=2))
    print("Saved:", destination)


if __name__ == "__main__":
    main()
