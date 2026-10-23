"""Measure a bounded disposable workload without changing application settings."""

import argparse
from typing import Any
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

import requests
from dotenv import load_dotenv

API = "http://127.0.0.1:8000"
LABEL = "selfsentry.workload-check"
QUEUES = ("audit_spool_size", "incident_outbox_size", "docker_event_queue_depth",
          "control_event_queue_depth")


class CheckFailed(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def status(session=None):
    getter = session.get if session else requests.get
    response = getter(API + "/monitor/status", timeout=3)
    response.raise_for_status()
    return response.json()


def parse_stat(raw, page_size):
    fields = raw.rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        return None
    return {"ppid": int(fields[1]), "ticks": int(fields[11]) + int(fields[12]),
            "start": fields[19], "rss_bytes": int(fields[21]) * page_size}


def processes():
    result = {}
    for folder in Path("/proc").iterdir():
        if not folder.name.isdigit():
            continue
        try:
            entry = parse_stat((folder / "stat").read_text(), os.sysconf("SC_PAGE_SIZE"))
            if entry:
                result[int(folder.name)] = entry
        except (OSError, ValueError, IndexError):
            continue  # Processes may exit during the snapshot.
    return result


def tree_members(root_pid, snapshot):
    selected = {root_pid}
    while True:
        added = {pid for pid, entry in snapshot.items()
                 if entry["ppid"] in selected and pid not in selected}
        if not added:
            return selected
        selected.update(added)


def tree_metrics(roots, current, previous, elapsed, ticks_per_second):
    result = {}
    for role, record in roots.items():
        root = current.get(record["pid"])
        require(root is not None and root["start"] == str(record["start_time"]),
                "Managed process identity changed: " + role)
        members = tree_members(record["pid"], current)
        ticks = 0
        for pid in members:
            old = previous.get(pid)
            entry = current[pid]
            if old and old["start"] == entry["start"]:
                ticks += max(0, entry["ticks"] - old["ticks"])
        result[role] = {
            "process_count": len(members),
            "rss_mib": round(sum(current[pid]["rss_bytes"] for pid in members) / 2**20, 3),
            "cpu_percent_one_core": (
                round(100 * ticks / ticks_per_second / elapsed, 3) if elapsed > 0 else None
            ),
        }
    return result


def distribution(values):
    ordered = sorted(value for value in values if value is not None)
    if not ordered:
        return None
    return {"median": ordered[(len(ordered) - 1) // 2],
            "p95": ordered[math.ceil(len(ordered) * 0.95) - 1], "maximum": ordered[-1]}


def generator_script(count=200, pause=0.2):
    require(type(count) is int and 1 <= count <= 3000, "Invalid generator count")
    require(type(pause) in (int, float) and math.isfinite(pause) and 0.001 <= pause <= 1,
            "Invalid generator pause")
    return (
        "set -eu\ni=0\n"
        f"while [ \"$i\" -lt {count} ]; do\n"
        "  /bin/true\n  i=$((i + 1))\n"
        "  printf 'SELFSENTRY_WORKLOAD_STEP %s\\n' \"$i\"\n"
        f"  /bin/sleep {pause:.3f}\ndone\n"
        f"printf 'SELFSENTRY_WORKLOAD_DONE {count}\\n'\n"
    )


def progress_output(raw, count=200, require_done=False):
    lines = raw.splitlines()
    completed = []
    done = False
    for line in lines:
        step = re.fullmatch(r"SELFSENTRY_WORKLOAD_STEP ([1-9][0-9]*)", line)
        if step:
            require(not done, "Generator emitted a step after completion")
            completed.append(int(step.group(1)))
        else:
            require(line == f"SELFSENTRY_WORKLOAD_DONE {count}" and not done,
                    "Unexpected generator output")
            done = True
    require(completed == list(range(1, len(completed) + 1)) and len(completed) <= count,
            "Generator progress is missing, duplicated or out of order")
    require(not done or len(completed) == count, "Generator completed before all steps")
    require(not require_done or done, "Generator completion marker is missing")
    return [{"index": ordinal - 1, "reported_ordinal": ordinal} for ordinal in completed]


def execute_generator(container_id, report, count=200):
    deadline = execution_deadline(count)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["docker", "exec", container_id, "/bin/sh", "-c", generator_script(count)],
            capture_output=True, text=True, timeout=deadline,
        )
        report["workload_seconds"] = round(time.monotonic() - started, 3)
        report["generator_returncode"] = completed.returncode
        report["execs"] = progress_output(completed.stdout, count=count)
        require(completed.returncode == 0, "Container process generator failed")
        progress_output(completed.stdout, count=count, require_done=True)
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if raw and not raw.endswith("\n"):
            raw = raw[:raw.rfind("\n") + 1]
            report["truncated_progress_line"] = True
        report["execs"] = progress_output(raw, count=count)
        report["workload_seconds"] = round(time.monotonic() - started, 3)
        raise CheckFailed(f"Container generator exceeded its {deadline}-second deadline") from None


def docker(args, timeout=15, missing_ok=False):
    completed = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if completed.returncode and missing_ok and (
        "No such container" in completed.stderr or "No such object" in completed.stderr
    ):
        return None
    require(completed.returncode == 0, "Docker " + args[0] + " failed")
    return completed.stdout.strip()


def owned_container(spec, name, token):
    require(spec.get("Name") == "/" + name
            and (spec.get("Config", {}).get("Labels") or {}).get(LABEL) == token
            and re.fullmatch(r"[0-9a-f]{64}", spec.get("Id", "")) is not None,
            "Container ownership could not be verified; refusing removal")
    return spec["Id"]


def cleanup(name, token):
    raw = docker(["container", "inspect", name], missing_ok=True)
    if raw is None:
        return "already absent"
    full_id = owned_container(json.loads(raw)[0], name, token)
    docker(["rm", "--force", full_id], timeout=60)
    require(docker(["container", "inspect", full_id], missing_ok=True) is None,
            "Probe removal was not confirmed")
    return "removed"


def summarize(samples, reads):
    phases: dict[str, Any] = {}
    for phase in sorted({item["phase"] for item in samples}):
        selected = [item for item in samples if item["phase"] == phase]
        phases[phase] = {"samples": len(selected), "process_trees": {}}
        for role in ("backend", "monitor", "frontend"):
            metrics = [item["process_trees"][role] for item in selected
                       if role in item.get("process_trees", {})]
            phases[phase]["process_trees"][role] = {
                "rss_mib": distribution([item["rss_mib"] for item in metrics]),
                "cpu_percent_one_core": distribution(
                    [item["cpu_percent_one_core"] for item in metrics]),
            }
        phases[phase]["queue_maxima"] = {
            key: max((item.get("status", {}).get(key, 0) for item in selected
                      if type(item.get("status", {}).get(key)) is int), default=None)
            for key in QUEUES
        }
    return {"phases": phases, "http_reads": len(reads),
            "http_errors": sum("error" in item for item in reads),
            "http_latency_ms": distribution([item["latency_ms"] for item in reads]),
            "sampling_errors": sum("error" in item for item in samples),
            "unhealthy_samples": sum(item.get("status", {}).get("healthy") is not True
                                     for item in samples)}


def execution_deadline(count):
    require(type(count) is int and 200 <= count <= 3000, "Executions must be 200 through 3000")
    return math.ceil(count * 0.25 + 25)


def journal_storage(directory):
    """Logical SQLite/WAL file sizes only, not whole-host or PostgreSQL storage."""
    result = {}
    for name in ("pipeline.sqlite", "pipeline.sqlite-wal", "pipeline.sqlite-shm"):
        try:
            result[name] = (directory / name).stat().st_size
        except FileNotFoundError:
            # WAL/SHM files can legitimately disappear at a checkpoint.
            result[name] = 0 if name != "pipeline.sqlite" else None
        except OSError:
            result[name] = None
    return result


def run(root, executions=200):
    deadline_seconds = execution_deadline(executions)
    os.umask(0o077)
    manifest = json.loads(Path(__file__).with_name("source-hashes.json").read_text())
    for name, expected in manifest.items():
        path = root / name
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "Source differs from the reviewed version: " + name)
    load_dotenv(root / ".env")
    sys.path.insert(0, str(root / "monitor-service"))
    from monitor_config import load_config
    journal_directory = load_config().state_dir
    roots = json.loads((root / "state/run/processes.json").read_text())
    require(set(roots) == {"backend", "monitor", "frontend"},
            "All three services must be managed before measurement")
    for record in roots.values():
        require(type(record.get("pid")) is int and record["pid"] > 1
                and str(record.get("start_time", "")).isdigit(), "Invalid managed PID record")
    before = status()
    require(before.get("healthy") is True and before.get("pid") == roots["monitor"]["pid"],
            "Healthy managed monitor required")
    require(before.get("configuration", {}).get("auto_isolation_enabled") is False,
            "Automatic isolation must be disabled")
    require(before.get("audit_spool_size") == 0 and before.get("incident_outbox_size") == 0,
            "Existing delivery backlog needs review before measurement")
    initial_processes = processes()
    tree_metrics(roots, initial_processes, {}, 0, os.sysconf("SC_CLK_TCK"))
    image = docker(["image", "inspect", "--format", "{{.Id}}", "alpine:3.20"])
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None, "Invalid local image ID")
    sys.path.insert(0, str(root / "deployment-gate"))
    from deployment_gate import run_gate
    from backend_auth import backend_headers

    token = uuid.uuid4().hex
    name = "selfsentry-workload-" + token[:12]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    folder = root / "state/evaluation" / ("workload-check-" + stamp)
    folder.mkdir(parents=True, mode=0o700)
    report: dict[str, Any] = {
        "passed": False, "runner_version": 3, "image_id": image, "container_name": name,
        "errors": [], "cleanup_errors": [], "before": before, "execs": [],
        "workload": {"process_executions": executions, "nominal_executions_per_second": 5,
                     "pacing_sleep_executions": executions, "generator_shells": 1,
                     "docker_exec_calls": 1,
                     "execution_deadline_seconds": deadline_seconds, "http_readers": 4,
                     "reader_pause_seconds": 0.5, "baseline_seconds": 10,
                     "cooldown_seconds": 15},
        "measurement_limits": ["One paced workload on one probe, not representative fleet traffic",
                               "RSS observations do not prove absence of memory leaks",
                               "No native drop-counter or model-timing instrumentation"],
        "journal_storage_before": journal_storage(journal_directory)}
    samples: list[dict[str, Any]] = []
    reads: list[dict[str, Any]] = []
    state = {"phase": "baseline"}
    stop_sampler, stop_readers = threading.Event(), threading.Event()
    sampler_failed = threading.Event()
    sampler = None
    readers = []
    attempted_creation = False

    def sample():
        previous: dict[int, Any] = {}
        previous_at = time.monotonic()
        previous_phase = None
        with requests.Session() as session:
            while not stop_sampler.is_set():
                item: dict[str, Any] = {
                    "phase": state["phase"], "at": datetime.now(timezone.utc).isoformat(),
                    "journal_storage": journal_storage(journal_directory)}
                try:
                    current, now = processes(), time.monotonic()
                    elapsed = now - previous_at if item["phase"] == previous_phase else 0
                    item["process_trees"] = tree_metrics(
                        roots, current, previous, elapsed, os.sysconf("SC_CLK_TCK"))
                    previous, previous_at, previous_phase = current, now, item["phase"]
                    value = status(session)
                    item["status"] = {
                        key: value.get(key) for key in (
                            *QUEUES, "healthy", "pid", "models_ready", "containers",
                            "heartbeat_fresh", "control_progress_fresh", "counters",
                            "health_reason", "degraded_components", "components",
                            "deployment_actions", "deployment_outbox", "updated_at")
                    }
                    require(value.get("pid") == before["pid"], "Monitor PID changed")
                    require(value.get("configuration", {}).get("auto_isolation_enabled") is False,
                            "Automatic isolation setting changed")
                except Exception as exc:
                    item["error"] = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
                    sampler_failed.set()
                samples.append(item)
                stop_sampler.wait(1)

    def reader(number):
        deadline = time.monotonic() + deadline_seconds + 5
        with requests.Session() as session:
            while not stop_readers.is_set() and time.monotonic() < deadline:
                started = time.monotonic()
                item = {"reader": number}
                try:
                    value = status(session)
                    require(value.get("healthy") is True, "Unhealthy HTTP read response")
                    require(value.get("pid") == before["pid"], "Monitor PID changed")
                except Exception as exc:
                    item["error"] = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
                item["latency_ms"] = round((time.monotonic() - started) * 1000, 3)
                reads.append(item)
                stop_readers.wait(0.5)

    try:
        print("Sampling 10 seconds of baseline...", flush=True)
        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        time.sleep(10)
        require(not sampler_failed.is_set(), "Baseline resource sampling failed")
        state["phase"] = "gate"
        print("Scanning and starting one disposable Alpine probe through the gate...", flush=True)
        attempted_creation = True
        gate = run_gate([
            "--name", name, "--label", LABEL + "=" + token,
            "--user", "65534:65534", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--network", "none",
            "--pids-limit", "32", "--memory", "64m", "--cpus", "0.25",
            "--entrypoint", "/bin/sleep", image, str(deadline_seconds + 180),
        ], backend_url=API)
        report["gate"] = gate
        require(gate["decision"] == "allowed", "Gate did not allow the probe; no override used")
        spec = json.loads(docker(["container", "inspect", name]))[0]
        container_id = owned_container(spec, name, token)
        report["container_id"] = container_id
        require(spec["State"]["Running"] is True and spec["Image"] == image,
                "Probe is not running with the expected image")
        for _ in range(15):
            response = requests.get(API + "/deployments/registration/" + container_id[:12],
                                    headers=backend_headers(), timeout=3)
            response.raise_for_status()
            if response.json().get("registered") is True:
                break
            time.sleep(1)
        else:
            raise CheckFailed("Probe registration was not confirmed")
        require(not sampler_failed.is_set(), "Sampling failed during gate startup")
        state["phase"] = "gate_settle"
        consecutive = 0
        for _ in range(20):
            settled = status()
            if (settled.get("healthy") is True
                    and settled.get("containers", {}).get("pending_registration") == 0
                    and settled.get("audit_spool_size") == 0
                    and settled.get("incident_outbox_size") == 0):
                consecutive += 1
            else:
                consecutive = 0
            if consecutive == 3:
                break
            time.sleep(1)
        else:
            raise CheckFailed("Gate setup did not settle to healthy empty queues")
        report["workload_before"] = status()
        state["phase"] = "workload"
        for number in range(4):
            thread = threading.Thread(target=reader, args=(number,), daemon=True)
            readers.append(thread)
            thread.start()
        print(f"Running one paced container loop: {executions} /bin/true + "
              f"{executions} sleep commands...",
              flush=True)
        execute_generator(container_id, report, executions)
        stop_readers.set()
        for thread in readers:
            thread.join(timeout=5)
        require(not any(thread.is_alive() for thread in readers), "HTTP readers did not finish")
        report["workload_after"] = status()
    except Exception as exc:
        report["errors"].append(str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__)
    finally:
        stop_readers.set()
        for thread in readers:
            thread.join(timeout=5)
        state["phase"] = "cleanup"
        if attempted_creation:
            try:
                report["cleanup"] = cleanup(name, token)
            except Exception as exc:
                report["cleanup_errors"].append(
                    str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__)
        if sampler:
            state["phase"] = "cooldown"
            print("Sampling cooldown after cleanup...", flush=True)
            time.sleep(15)
        try:
            after = status()
            report["after"] = after
            require(after.get("healthy") is True and after.get("pid") == before["pid"],
                    "Post-workload monitor health/PID changed")
            require(after.get("audit_spool_size") == 0
                    and after.get("incident_outbox_size") == 0,
                    "Delivery queues did not drain by the end of cooldown")
            require(after.get("containers", {}).get("pending_registration") == 0,
                    "Pending registration remains after cooldown")
            preserved = {}
            for cid, baseline in before.get("baselines", {}).items():
                if baseline.get("state") != "MODEL_READY":
                    continue
                keys = ("state", "samples", "requires_review", "model_algorithm")
                previous = {key: baseline.get(key) for key in keys}
                current = {key: after.get("baselines", {}).get(cid, {}).get(key)
                           for key in keys}
                preserved[cid] = previous == current
            report["existing_ready_model_status_preserved"] = preserved
            require(all(preserved.values()), "An existing ready-model status changed")
            deltas = {key: after.get("counters", {}).get(key, 0)
                      - report.get("workload_before", before).get("counters", {}).get(key, 0)
                      for key in ("falco_lines_processed", "baseline_events_seen",
                                  "unusable_events")}
            report["counter_deltas_through_cooldown"] = deltas
            require(deltas["falco_lines_processed"] > 0 and deltas["baseline_events_seen"] > 0,
                    "The run did not demonstrate Falco baseline ingestion")
        except Exception as exc:
            message = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
            report["errors"].append(message)
        stop_sampler.set()
        if sampler:
            sampler.join(timeout=5)
            if sampler.is_alive():
                report["errors"].append("Sampler did not finish before report deadline")
        report["journal_storage_after"] = journal_storage(journal_directory)
        report["summary"] = summarize(samples, reads)
        if report["summary"]["sampling_errors"]:
            report["errors"].append("Some resource/status samples failed")
        setup_phases = {"gate", "gate_settle"}
        unhealthy = [item for item in samples
                     if item.get("status", {}).get("healthy") is not True]
        setup_unhealthy = [item for item in unhealthy if item["phase"] in setup_phases]
        if any(item["phase"] not in setup_phases for item in unhealthy):
            report["errors"].append("Some samples outside gate setup were unhealthy")
        if report["summary"]["http_errors"]:
            report["errors"].append("Some concurrent HTTP reads failed")
        if {item["reader"] for item in reads} != {0, 1, 2, 3}:
            report["errors"].append("Not all four HTTP readers produced observations")
        if not any(item["phase"] == "workload" for item in samples):
            report["errors"].append("No resource samples cover the workload")
        report["steady_workload_passed"] = (not report["errors"] and not report["cleanup_errors"]
                                            and len(report["execs"]) == executions)
        report["setup_continuously_healthy"] = not setup_unhealthy
        report["all_sampled_phases_healthy"] = bool(samples) and not unhealthy
        report["setup_health_issues"] = [{"at": item.get("at"), "phase": item["phase"],
                                          "status": item.get("status"), "error": item.get("error")}
                                         for item in setup_unhealthy]
        if setup_unhealthy:
            report["errors"].append("Gate setup had unhealthy samples; inspect recorded reasons")
        report["passed"] = (report["steady_workload_passed"]
                            and report["all_sampled_phases_healthy"])
        report["samples"], report["http_reads"] = samples, reads
        (folder / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        brief = {key: report.get(key) for key in (
            "passed", "steady_workload_passed", "setup_continuously_healthy",
            "all_sampled_phases_healthy",
            "workload_seconds", "counter_deltas_through_cooldown",
            "existing_ready_model_status_preserved", "cleanup", "errors", "cleanup_errors")}
        brief["completed_true_executions"] = len(report["execs"])
        brief["setup_health_issues"] = [
            {"at": item["at"], "phase": item["phase"],
             "health_reason": (item["status"] or {}).get("health_reason"),
             "degraded_components": (item["status"] or {}).get("degraded_components"),
             "deployment_actions": (item["status"] or {}).get("deployment_actions")}
            for item in report["setup_health_issues"][:5]
        ]
        summary = report["summary"]
        brief["http_reads"] = summary["http_reads"]
        brief["http_errors"] = summary["http_errors"]
        brief["http_latency_ms"] = summary["http_latency_ms"]
        brief["workload_queue_maxima"] = summary["phases"].get("workload", {}).get(
            "queue_maxima")
        observations: dict[str, Any] = {}
        brief["resource_observations"] = observations
        for role in ("backend", "monitor", "frontend"):
            item = {}
            for phase in ("baseline", "workload", "cooldown"):
                metric = summary["phases"].get(phase, {}).get("process_trees", {}).get(role, {})
                item[phase] = {"peak_rss_mib": (metric.get("rss_mib") or {}).get("maximum"),
                               "cpu_p95_one_core": (metric.get("cpu_percent_one_core")
                                                    or {}).get("p95")}
            observations[role] = item
        print(json.dumps(brief, indent=2))
        print("Evidence:", folder / "results.json")
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "selfsentry")
    parser.add_argument("--executions", type=int, default=200,
                        help="200 to 3000; 3000 gives approximately ten minutes at five per second")
    args = parser.parse_args()
    return run(args.repo.expanduser().resolve(), args.executions)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise CheckFailed("Interrupted; attempting owned probe cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("Stopped:", str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__,
              file=sys.stderr)
        raise SystemExit(2)
