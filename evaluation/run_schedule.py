"""Scheduled evaluation runner: one workload per fixed window, collected once at the end.

Windows run back to back in a seeded shuffled order, so attack and benign windows are
interleaved and a run is reproducible and resumable (--skip). Per window it records the
workload, a configuration fingerprint and a Falco clock verdict; incidents are fetched once
after the last window and mapped to windows by the monitor's window_start.

Latency here is trial start -> incident created_at (incident_creation_ms). Incident
visibility is not polled in this mode and is recorded as not measured. Never enables
isolation, never approves rules. Do not approve rules or restart Falco during a run.
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clock_guard import (  # noqa: E402
    AlertTail,
    ClockGuardError,
    DEFAULT_ALERTS_PATH,
    judge_events,
    require_recent_preflight,
)
from fingerprint import collect_fingerprint  # noqa: E402
from scenarios import DEFAULT_PLAN, SCENARIOS  # noqa: E402

SCHEMA_VERSION = 2


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def parse_plan(text):
    plan = []
    for part in text.split(","):
        name, _, count = part.strip().partition("=")
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario in plan: {name!r}")
        if not count.isdigit() or int(count) < 1:
            raise ValueError(f"plan count for {name} must be a positive integer")
        plan.append((name, int(count)))
    return plan


def build_schedule(plan, seed):
    items = [name for name, count in plan for _ in range(count)]
    random.Random(seed).shuffle(items)
    return items


def created_at_epoch(value, naive_timezone=None):
    """Interpret naive database timestamps only with an explicit source timezone."""
    stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    assumed = stamp.tzinfo is None
    if assumed:
        if not naive_timezone:
            raise ValueError("naive incident created_at requires --incident-timezone")
        stamp = stamp.replace(tzinfo=ZoneInfo(naive_timezone))
    return stamp.timestamp(), assumed


def build_record(entry, incidents, cfg):
    """Pure: turn one schedule-log entry plus fetched incidents into a trial record."""
    scenario = SCENARIOS[entry["scenario"]]
    window_iso = iso(entry["boundary_epoch"])
    rows = [
        r
        for r in incidents
        if r.get("container_id") == cfg["target"]
        and (r.get("monitor_evidence") or {}).get("window_start") == window_iso
    ]
    started = entry.get("workload_started_epoch", entry["boundary_epoch"])
    record = {
        "schema_version": SCHEMA_VERSION,
        "trial_id": f"{cfg['run_id']}-{entry['index']:04d}",
        "variant": "full",
        "scenario": entry["scenario"],
        "label": scenario["label"],
        "detected": bool(rows),
        "container_id": cfg["target"],
        "detection_definition": "at least one persisted incident in the target trial window",
        "trial_started_at": iso(started),
        "trial_finished": iso(entry["boundary_epoch"] + cfg["window"]),
        "window_seconds": cfg["window"],
        "lateness_seconds": cfg["lateness"],
        "baseline_samples": entry.get("baseline_samples"),
        "incident_ids": [r["id"] for r in rows],
        "duplicate_incident_count": max(0, len(rows) - 1),
        "controlled_simulation": scenario["label"] == "attack",
        "visibility_measured": False,
        "schedule_run_id": cfg["run_id"],
        "schedule_index": entry["index"],
        "schedule_seed": cfg["seed"],
        "category": scenario["category"],
    }
    for key in ("config_fingerprint", "fingerprint_components", "software_context", "clock_check"):
        if key in entry:
            record[key] = entry[key]
    if "fingerprint_components" in entry:
        record["rule_file_sha256"] = entry["fingerprint_components"]["rule_file_sha256"]
    reasons = list(entry.get("invalid_reasons", []))
    if rows:
        record["auto_confirmed"] = any(
            (r.get("confirmation") or {}).get("confirmed_by") == "selfsentry-auto" for r in rows
        )
        if record["auto_confirmed"]:
            record["auto_confirmation_accuracy"] = record["label"] == "attack"
        created = []
        for r in rows:
            try:
                created.append(created_at_epoch(r["created_at"], cfg.get("incident_timezone")))
            except (KeyError, ValueError):
                reasons.append(
                    "incident created_at missing, unparseable, or source timezone unspecified"
                )
        if created:
            epoch = min(c[0] for c in created)
            record["incident_created_at"] = iso(epoch)
            record["incident_created_at_was_naive"] = any(c[1] for c in created)
            record["incident_timestamp_timezone"] = cfg.get("incident_timezone")
            record["incident_timestamp_semantics"] = (
                "database row timestamp; not verified commit completion"
            )
            upper = started + cfg["window"] + cfg["lateness"] + 120
            if not (started - 2 <= epoch <= upper):
                reasons.append(
                    "incident created_at outside plausible range (timezone or clock mismatch)"
                )
            else:
                record["incident_creation_end"] = iso(epoch)
    if "workload_started_epoch" in entry:
        record["incident_creation_start"] = iso(started)
    if reasons:
        record["valid"] = False
        record["exclusion_reason"] = "; ".join(dict.fromkeys(reasons))
        record.pop("incident_creation_end", None)
    return record


def http_get(base, endpoint):
    import requests

    response = requests.get(base + endpoint, timeout=10)
    response.raise_for_status()
    return response.json()


def run_windows(args, root, config, target, info, log_path):
    window = int(config.get("MONITOR_WINDOW_SECONDS") or 60)
    base = config.get("SELFSENTRY_BACKEND_URL") or "http://127.0.0.1:8000"
    plan = parse_plan(args.plan)
    schedule = build_schedule(plan, args.seed)
    stop = (args.skip + args.limit) if args.limit else None
    chosen = schedule[args.skip:stop]
    require_recent_preflight(root / "state/evaluation/clock_check.json", target)
    tail = AlertTail(config.get("FALCO_LOG_PATH") or DEFAULT_ALERTS_PATH)
    tail.mark()
    boundary = (int(time.time()) // window + 2) * window
    print(
        f"{len(chosen)} windows (of {len(schedule)} planned), "
        f"about {len(chosen) * window / 60:.0f} min. "
        "Keep automatic isolation OFF; no other target workload; do not approve rules.",
        flush=True,
    )
    with log_path.open("a") as log:
        for offset, name in enumerate(chosen):
            index = args.skip + offset
            scenario = SCENARIOS[name]
            time.sleep(max(0, boundary + 2 - time.time()))
            entry = {"index": index, "scenario": name, "boundary_epoch": boundary}
            reasons = []
            try:
                status = http_get(base, "/monitor/status")
                baseline = status.get("baselines", {}).get(target, {})
                entry["baseline_samples"] = baseline.get("samples")
                if not status.get("healthy") or baseline.get("state") != "MODEL_READY":
                    reasons.append("monitor unhealthy or model not ready at window start")
            except Exception as exc:  # noqa: BLE001 - record any outage as evidence
                reasons.append(f"monitor status unavailable: {type(exc).__name__}")
            fp = collect_fingerprint(root, target, config, info["Image"])
            entry.update(
                config_fingerprint=fp["config_fingerprint"],
                fingerprint_components=fp["fingerprint_components"],
                software_context=fp["software_context"],
            )
            if reasons:
                entry["invalid_reasons"] = reasons + ["workload skipped"]
            else:
                try:
                    tail.mark()
                except ClockGuardError as exc:
                    entry["invalid_reasons"] = [
                        f"falco output unreadable: {exc}",
                        "workload skipped",
                    ]
                else:
                    entry["workload_started_epoch"] = time.time()
                    if scenario["command"]:
                        cmd = (
                            ["docker", "exec"]
                            + (["-t"] if scenario["tty"] else [])
                            + [args.container, "/bin/sh", "-c", scenario["command"]]
                        )
                        outcome = subprocess.run(cmd, capture_output=True, text=True)
                        entry["workload_returncode"] = outcome.returncode
                        if outcome.returncode:
                            entry["workload_stderr"] = outcome.stderr[-500:]
                            entry["invalid_reasons"] = ["workload command failed"]
                    time.sleep(max(0, boundary + window - time.time()))
                    try:
                        entry["clock_check"] = judge_events(
                            tail.new_events(target),
                            entry["workload_started_epoch"],
                            boundary + window + 1,
                            expect_events=scenario["command"] is not None,
                        )
                    except ClockGuardError as exc:
                        entry["clock_check"] = {"valid": False, "status": f"unreadable: {exc}"}
                    if not entry["clock_check"]["valid"]:
                        entry.setdefault("invalid_reasons", []).append(
                            f"invalid clock: {entry['clock_check']['status']}"
                        )
                    after = collect_fingerprint(root, target, config, info["Image"])
                    if after["config_fingerprint"] != fp["config_fingerprint"]:
                        entry.setdefault("invalid_reasons", []).append(
                            "configuration changed during window"
                        )
            log.write(json.dumps(entry) + "\n")
            log.flush()
            os.fsync(log.fileno())
            result = (
                'INVALID: ' + '; '.join(entry['invalid_reasons'])
                if entry.get('invalid_reasons') else 'ok'
            )
            print(
                f"[{index + 1}/{len(schedule)}] {name:30s} {result}",
                flush=True,
            )
            boundary += window
    return base


def finalize(args, root, config, target, log_path):
    base = config.get("SELFSENTRY_BACKEND_URL") or "http://127.0.0.1:8000"
    window = int(config.get("MONITOR_WINDOW_SECONDS") or 60)
    lateness = float(config.get("MONITOR_LATENESS_SECONDS") or 10)
    entries = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    if not entries:
        raise SystemExit("No schedule entries to finalize.")
    wait = max(entries[-1]["boundary_epoch"] + window + lateness + 90 - time.time(), 0)
    print(f"Waiting {wait:.0f}s for the last incidents to persist...", flush=True)
    time.sleep(wait)
    incidents = None
    for _ in range(12):
        try:
            incidents = http_get(base, "/incidents/")
            break
        except Exception as exc:  # noqa: BLE001
            print(f"incident fetch failed ({type(exc).__name__}); retrying", flush=True)
            time.sleep(10)
    if incidents is None:
        raise SystemExit(
            "Incidents unreachable; schedule log kept. "
            f"Re-run with --finalize-only --run-id {args.run_id}"
        )
    destination = root / "state/evaluation/trials.jsonl"
    existing = set()
    if destination.exists():
        existing = {
            json.loads(line).get("trial_id")
            for line in destination.read_text().splitlines()
            if line.strip()
        }
    cfg = {
        "target": target,
        "run_id": args.run_id,
        "window": window,
        "lateness": lateness,
        "seed": args.seed,
        "incident_timezone": args.incident_timezone,
    }
    evidence = root / f"state/evaluation/evidence/{args.run_id}-incidents.json"
    written = 0
    with destination.open("a") as stream:
        for entry in entries:
            record = build_record(entry, incidents, cfg)
            if record["trial_id"] in existing:
                continue
            stream.write(json.dumps(record) + "\n")
            written += 1
        stream.flush()
        os.fsync(stream.fileno())
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(incidents, indent=2))
    print(f"{written} trial records appended to {destination}; incident evidence in {evidence}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="selfsentry-test")
    parser.add_argument("--plan", default=DEFAULT_PLAN)
    parser.add_argument("--seed", type=int, default=20261011)
    parser.add_argument(
        "--skip", type=int, default=0, help="windows already completed in this schedule"
    )
    parser.add_argument("--limit", type=int, default=None, help="run at most this many windows")
    parser.add_argument("--run-id", default=None, help="reuse to continue a run; default is new")
    parser.add_argument("--finalize-only", action="store_true")
    parser.add_argument("--incident-timezone", help="Source timezone for naive database timestamps")
    args = parser.parse_args()
    if args.incident_timezone:
        ZoneInfo(args.incident_timezone)
    from dotenv import dotenv_values

    root = Path(__file__).resolve().parents[1]
    config = dotenv_values(root / ".env")
    info = json.loads(subprocess.check_output(["docker", "inspect", args.container]))[0]
    target = info["Id"][:12]
    if not info["State"]["Running"] or info["State"]["Paused"]:
        raise SystemExit("Target must be running and unpaused.")
    args.run_id = args.run_id or uuid.uuid4().hex[:8]
    log_path = root / f"state/evaluation/schedules/{args.run_id}.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"run id: {args.run_id}  seed: {args.seed}", flush=True)
    if not args.finalize_only:
        try:
            run_windows(args, root, config, target, info, log_path)
        except ClockGuardError as exc:
            raise SystemExit(f"Clock preflight required: {exc}")
    finalize(args, root, config, target, log_path)


if __name__ == "__main__":
    main()
