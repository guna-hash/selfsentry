"""Separate, observation-only live benign validation; never retrains the model."""

from contextlib import closing

import argparse
import hashlib
import json
import random
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "monitor-service")]
from clock_guard import AlertTail, judge_events, run_preflight  # noqa: E402
from monitor_config import load_config  # noqa: E402
from scenarios import SCENARIOS  # noqa: E402


def scenario_command(name: str) -> str:
    command = SCENARIOS[name]["command"]
    if not isinstance(command, str):
        raise ValueError(f"Scenario {name} requires a string command")
    return command


COMMANDS = {
    name: "set -eu; " + scenario_command(name)
    for name in ("benign-admin", "benign-config-read", "benign-ls-from-shell")
}
COMMANDS["benign-standard-http"] = (
    "curl --fail --silent --show-error --max-time 10 http://127.0.0.1/ >/dev/null"
)
FLAGS = ("AUTO_ISOLATION_ENABLED", "AUTO_CONFIRM_ENABLED", "MONITOR_RULE_CANDIDATES_ENABLED")


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get(base, endpoint):
    response = requests.get(base + endpoint, timeout=10)
    response.raise_for_status()
    return response.json()


def check_status(status, cid):
    model = status.get("baselines", {}).get(cid, {})
    if not status.get("running") or not status.get("healthy"):
        raise RuntimeError("Monitor is not running and healthy")
    if model.get("state") != "MODEL_READY" or model.get("model_algorithm") != "one_class_svm":
        raise RuntimeError("Target must have a ready one_class_svm model")


def checked_environment(pid):
    env = dict(
        part.split("=", 1)
        for part in Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0")
        if "=" in part
    )
    if env.get("MONITOR_ANOMALY_ALGORITHM") != "one_class_svm":
        raise RuntimeError("Running monitor must explicitly select one_class_svm")
    for key in FLAGS:
        if env.get(key, "").lower() != "false":
            raise RuntimeError(f"Running monitor must explicitly set {key}=false")
    return env


def pipeline_evidence(path, cid, bucket):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        kinds = Counter(
            row[0]
            for row in db.execute(
                "SELECT kind FROM events WHERE container=? AND bucket=?", (cid, bucket)
            )
        )
        closed = bool(
            db.execute(
                "SELECT 1 FROM windows WHERE container=? AND bucket=?", (cid, bucket)
            ).fetchone()
        )
        stages = []
        delivered_ids = []
        for body, stage, incident_id in db.execute("SELECT body, stage, incident_id FROM outbox"):
            data = json.loads(body)
            evidence = data.get("monitor_evidence") or {}
            if data.get("container_id", "").startswith(cid) and evidence.get(
                "window_start"
            ) == stamp(bucket):
                stages.append(stage)
                if stage == "done" and incident_id is not None:
                    delivered_ids.append(incident_id)
    reasons = []
    if not closed:
        reasons.append("window_not_closed")
    if not kinds.get("baseline"):
        reasons.append("no_accepted_baseline_events")
    if any(stage != "done" for stage in stages):
        reasons.append("incident_delivery_not_done")
    return {
        "event_counts": dict(kinds),
        "window_closed": closed,
        "outbox_stages": stages,
        "delivered_incident_ids": delivered_ids,
    }, reasons


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="selfsentry-test")
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    parser.add_argument("--per-scenario", type=int, default=6)
    parser.add_argument("--seed", type=int, default=20261013)
    args = parser.parse_args()
    if not 1 <= args.per_scenario <= 20:
        parser.error("--per-scenario must be 1..20")
    base = args.backend.rstrip("/")
    info = json.loads(subprocess.check_output(["docker", "inspect", args.container]))[0]
    if not info["State"]["Running"] or info["State"]["Paused"]:
        raise RuntimeError("Target must be running and unpaused")
    cid = info["Id"][:12]
    status = get(base, "/monitor/status")
    check_status(status, cid)
    pid = status["pid"]
    env = checked_environment(pid)
    config = load_config({
        **{key: value for key, value in dotenv_values(ROOT / ".env").items()
           if value is not None}, **env,
    })
    if config.window_seconds < 35:
        raise RuntimeError("This batch requires monitor windows of at least 35 seconds")
    baseline = config.baseline_dir / f"{cid}.json"
    sources = [
        baseline,
        ROOT / "behavioral-engine/anomaly_model.py",
        ROOT / "behavioral-engine/feature_extractor.py",
        ROOT / "monitor-service/monitor_config.py",
        ROOT / "falco-rules/baseline-capture-rules.yaml",
        ROOT / "falco-rules/auto-generated-rules.yaml",
        Path(__file__).resolve(),
    ]
    sources.extend(p for p in (ROOT / ".env", Path("/etc/falco/falco_rules.yaml")) if p.exists())
    hashes = {
        str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p): digest(p) for p in sources
    }
    started = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "state/evaluation" / f"svm-benign-{started}"
    out.mkdir(parents=True, exist_ok=False)
    manifest = {
        "started_at": stamp(time.time()),
        "container_id": info["Id"],
        "image_id": info["Image"],
        "monitor_pid": pid,
        "algorithm": "one_class_svm",
        "automatic_actions": {key: env[key] for key in FLAGS},
        "seed": args.seed,
        "commands": COMMANDS,
        "hashes": hashes,
        "window_seconds": config.window_seconds,
        "lateness_seconds": config.lateness_seconds,
        "scope": "24 lab benign windows by default; separate from original benchmark",
    }
    save(out / "manifest.json", manifest)
    preflight = run_preflight(args.container, config.falco_log_path,
                              out / "clock_check.json", backend=base)
    if not preflight["passed"]:
        raise RuntimeError(f"Clock preflight failed; evidence: {out}")
    schedule = list(COMMANDS) * args.per_scenario
    random.Random(args.seed).shuffle(schedule)
    window = config.window_seconds
    boundary = (int(time.time()) // window + 2) * window
    rows = []
    print(f"Evidence: {out}\nRunning {len(schedule)} windows. Leave services running.", flush=True)
    for index, scenario in enumerate(schedule, 1):
        time.sleep(max(0, boundary + 2 - time.time()))
        current = get(base, "/monitor/status")
        check_status(current, cid)
        if current["pid"] != pid or checked_environment(pid) != env:
            raise RuntimeError(
                "Monitor restarted or environment changed; partial evidence retained"
            )
        if any(
            digest(p) != hashes[str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)]
            for p in sources
        ):
            raise RuntimeError(
                "Baseline, model, rules or runner changed; partial evidence retained"
            )
        tail = AlertTail(config.falco_log_path)
        tail.mark()
        row = {
            "trial": index,
            "scenario": scenario,
            "window_start": stamp(boundary),
            "bucket": boundary,
            "invalid_reasons": [],
        }
        before = time.time()
        try:
            result = subprocess.run(
                ["docker", "exec", args.container, "/bin/sh", "-c", COMMANDS[scenario]],
                capture_output=True,
                text=True,
                timeout=min(30, window - 3),
            )
            row["returncode"] = result.returncode
            if result.returncode:
                row["invalid_reasons"].append("workload_failed")
                row["stderr"] = result.stderr[-500:]
        except subprocess.TimeoutExpired:
            row["invalid_reasons"].append("workload_timeout")
        time.sleep(max(0, boundary + window + 1 - time.time()))
        row["clock"] = judge_events(tail.new_events(cid), before, boundary + window + 1, True)
        if not row["clock"]["valid"]:
            row["invalid_reasons"].append("missing_or_stale_falco_events")
        rows.append(row)
        with (out / "schedule.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(
            f"{index}/{len(schedule)} {scenario}: captured; awaiting final validation", flush=True
        )
        boundary += window
    print("Waiting for final window processing and incident delivery...", flush=True)
    time.sleep(config.lateness_seconds + 90)
    current = get(base, "/monitor/status")
    check_status(current, cid)
    unchanged = (
        current["pid"] == pid
        and checked_environment(pid) == env
        and all(
            digest(p) == hashes[str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)]
            for p in sources
        )
    )
    incidents = get(base, "/incidents/")
    selected = []
    for row in rows:
        pipeline, reasons = pipeline_evidence(
            config.state_dir / "pipeline.sqlite", cid, row["bucket"]
        )
        row["pipeline"] = pipeline
        row["invalid_reasons"].extend(reasons)
        if not unchanged:
            row["invalid_reasons"].append("configuration_changed")
        matches = [
            i
            for i in incidents
            if i.get("container_id", "").startswith(cid)
            and (i.get("monitor_evidence") or {}).get("window_start") == row["window_start"]
        ]
        selected.extend(matches)
        row["incident_ids"] = [i["id"] for i in matches]
        if not set(pipeline["delivered_incident_ids"]).issubset(row["incident_ids"]):
            row["invalid_reasons"].append("delivered_incident_missing_from_api")
        if any(
            (i.get("monitor_evidence") or {}).get("anomaly_assessment", {}).get("model_algorithm")
            not in (None, "one_class_svm")
            for i in matches
        ):
            row["invalid_reasons"].append("unexpected_model_algorithm")
        row["incident_detected"] = bool(matches)
        row["valid"] = not row["invalid_reasons"]
    summary = {
        "algorithm": "one_class_svm",
        "total_windows": len(rows),
        "valid_windows": sum(r["valid"] for r in rows),
        "invalid_windows": sum(not r["valid"] for r in rows),
        "valid_windows_with_incidents": sum(r["valid"] and r["incident_detected"] for r in rows),
        "by_scenario": {},
        "limitations": (
            "Small repeated lab workloads; not production FPR. "
            "No retraining or threshold tuning."
        ),
    }
    for name in COMMANDS:
        group = [r for r in rows if r["scenario"] == name]
        summary["by_scenario"][name] = {
            "valid": sum(r["valid"] for r in group),
            "invalid": sum(not r["valid"] for r in group),
            "valid_with_incidents": sum(r["valid"] and r["incident_detected"] for r in group),
        }
    (out / "trials.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    save(out / "incidents.json", selected)
    save(out / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    print(f"Saved: {out / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
