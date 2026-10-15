"""Capture one controlled study window; never confirm, approve, deploy or retrain."""

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "monitor-service"))
from monitor_config import load_config  # noqa: E402
from clock_guard import judge_events, parse_falco_time, run_preflight  # noqa: E402
from run_svm_benign import pipeline_evidence  # noqa: E402

CASES = {
    "binary": (
        False,
        "set -eu; d=$(mktemp -d /tmp/ss-academic.XXXXXX); "
        'trap \'rm -rf "$d"\' EXIT; cp /bin/true "$d/ss-study-true"; '
        'chmod 700 "$d/ss-study-true"; "$d/ss-study-true"; :',
    ),
    "sensitive": (False, "cat /etc/shadow >/dev/null; :"),
    "terminal": (True, "echo SelfSentry-academic-terminal; :"),
    "admin": (
        False,
        "set -eu; id >/dev/null; ls /usr/share/nginx/html >/dev/null; uname -s >/dev/null",
    ),
    "config": (
        False,
        "set -eu; cat /etc/nginx/nginx.conf >/dev/null; "
        "grep -c worker /etc/nginx/nginx.conf >/dev/null",
    ),
    "http": (False, "curl --fail --silent --show-error --max-time 10 http://127.0.0.1/ >/dev/null"),
}
ACTION_FLAGS = ("AUTO_ISOLATION_ENABLED", "AUTO_CONFIRM_ENABLED", "MONITOR_RULE_CANDIDATES_ENABLED")


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get(base, route):
    response = requests.get(base + route, timeout=10)
    response.raise_for_status()
    return response.json()


def validate_status(status, cid):
    model = status.get("baselines", {}).get(cid, {})
    if not status.get("running") or not status.get("healthy"):
        raise RuntimeError("Monitor must be running and healthy")
    if model.get("state") != "MODEL_READY" or model.get("model_algorithm") != "isolation_forest":
        raise RuntimeError("Study requires a model-ready target using default Isolation Forest")


def validate_env(env):
    if env.get("MONITOR_ANOMALY_ALGORITHM") != "isolation_forest":
        raise RuntimeError("Explicitly select isolation_forest on the running monitor")
    if any(env.get(key, "").lower() != "false" for key in ACTION_FLAGS):
        raise RuntimeError("All three automatic-action flags must explicitly be false")


def read_segment(path, inode, offset, cid):
    info = path.stat()
    if info.st_ino != inode or info.st_size < offset:
        raise RuntimeError("Falco log rotated/truncated during capture; retain invalid report")
    with path.open("rb") as stream:
        stream.seek(offset)
        lines = stream.read().decode(errors="replace").splitlines()
    result = []
    for line in lines:
        try:
            raw = json.loads(line)
            found = (raw.get("output_fields") or {}).get("container.id", "")
            if found and (cid.startswith(found) or found.startswith(cid)):
                result.append(raw)
        except (ValueError, AttributeError, TypeError):
            continue
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--out", type=Path, required=True, help="New directory; never overwritten")
    parser.add_argument("--container", default="selfsentry-test")
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {"case": args.case, "valid": False, "errors": [], "started_at": iso(time.time())}
    try:
        base = args.backend.rstrip("/")
        inspect = json.loads(subprocess.check_output(["docker", "inspect", args.container]))[0]
        cid = inspect["Id"][:12]
        if not inspect["State"]["Running"] or inspect["State"]["Paused"]:
            raise RuntimeError("Target must be running and unpaused")
        status = get(base, "/monitor/status")
        validate_status(status, cid)
        pid = status["pid"]
        env = dict(
            part.split("=", 1)
            for part in Path(f"/proc/{pid}/environ").read_bytes().decode().split("\0")
            if "=" in part
        )
        validate_env(env)
        config = load_config({**dotenv_values(ROOT / ".env"), **env})
        if config.window_seconds != 60:
            raise RuntimeError("This study protocol specifies 60-second windows")
        baseline = config.baseline_dir / f"{cid}.json"
        baseline_hash = sha(baseline)
        report.update(
            container_id=inspect["Id"],
            image_id=inspect["Image"],
            monitor_pid=pid,
            baseline_sha256=baseline_hash,
            settings={key: env[key] for key in (*ACTION_FLAGS, "MONITOR_ANOMALY_ALGORITHM")},
            source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            source_status=subprocess.check_output(["git", "status", "--short"], text=True).strip(),
            generated_rules_sha256=sha(ROOT / "falco-rules/auto-generated-rules.yaml"),
        )
        preflight = run_preflight(args.container, config.falco_log_path, args.out / "clock.json")
        if not preflight["passed"]:
            raise RuntimeError("Clock preflight failed; no study trigger executed")
        boundary = (int(time.time()) // 60 + 2) * 60
        print(f"Waiting for {iso(boundary)}; evidence: {args.out}", flush=True)
        time.sleep(max(0, boundary + 2 - time.time()))
        log = Path(config.falco_log_path)
        info = log.stat()
        before = time.time()
        tty, command = CASES[args.case]
        report.update(window_start=iso(boundary), window_end=iso(boundary + 60), command=command)
        proc = subprocess.run(
            ["docker", "exec", *(["-t"] if tty else []), args.container, "/bin/sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=20,
        )
        report.update(returncode=proc.returncode, stderr=proc.stderr[-500:])
        if proc.returncode:
            raise RuntimeError("Workload failed; do not count this trial")
        time.sleep(max(0, boundary + 61 - time.time()))
        alerts = read_segment(log, info.st_ino, info.st_size, cid)
        (args.out / "falco.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
        clock = judge_events(
            [parse_falco_time(a["time"]) for a in alerts], before, boundary + 61, True
        )
        report["clock"] = clock
        if not clock["valid"]:
            raise RuntimeError("Missing or stale Falco timestamps; stop the study and diagnose")
        report["falco_rules"] = sorted({a["rule"] for a in alerts})
        # Give the durable outbox time to deliver; the report still requires human linkage review.
        time.sleep(config.lateness_seconds + 30)
        incidents = get(base, "/incidents/")
        matches = [
            item
            for item in incidents
            if item.get("container_id", "").startswith(cid)
            and (item.get("monitor_evidence") or {}).get("window_start") == iso(boundary)
        ]
        (args.out / "incidents.json").write_text(json.dumps(matches, indent=2) + "\n")
        report["incident_ids"] = [item["id"] for item in matches]
        pipeline, reasons = pipeline_evidence(config.state_dir / "pipeline.sqlite", cid, boundary)
        report["pipeline"] = pipeline
        if reasons:
            raise RuntimeError("Pipeline evidence incomplete: " + ", ".join(reasons))
        if not set(pipeline["delivered_incident_ids"]).issubset(report["incident_ids"]):
            raise RuntimeError("Delivered incident missing from API snapshot")
        ending = get(base, "/monitor/status")
        validate_status(ending, cid)
        if ending["pid"] != pid or sha(baseline) != baseline_hash:
            raise RuntimeError("Monitor restarted or baseline changed during trial")
        report["valid"] = True
        report["interpretation"] = (
            "Capture valid; loop/coverage success still requires reviewed evidence"
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        sqlite3.Error,
        requests.RequestException,
        subprocess.SubprocessError,
    ) as exc:
        report["errors"].append(str(exc))
    (args.out / "capture.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
