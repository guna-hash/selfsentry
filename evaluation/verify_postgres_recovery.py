"""Controlled VM PostgreSQL outage/recovery; isolation must remain disabled.

Temporarily stops only postgresql@16-main. Keeps backend/Falco/monitor running.
Creates one disposable container; verifies a durable queued incident and exactly
one recovered row. Always attempts DB restart and container cleanup in finally.
With --restart-stack, also gracefully stops the managed applications after failed
delivery is durable, restores PostgreSQL, then starts the applications to test replay.
Falco, Docker and existing workloads stay running. This is not a crash/SIGKILL test.
Run sudo -v first. No baseline, secrets or original trial files are modified.
"""

from contextlib import closing
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
import requests
from safety import backend_json, require_isolation_disabled
from dotenv import dotenv_values

UNIT = "postgresql@16-main"
BASE = "http://127.0.0.1:8000"
STUDY_FLAGS = {
    "MONITOR_ANOMALY_ALGORITHM": "isolation_forest",
    "AUTO_ISOLATION_ENABLED": "false",
    "AUTO_CONFIRM_ENABLED": "false",
    "MONITOR_RULE_CANDIDATES_ENABLED": "false",
}


def command(*args):
    return subprocess.check_output(args, text=True, timeout=45).strip()


def active():
    return subprocess.run(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0


def get(path):
    return backend_json(BASE, path)


def queued(database, cid):
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro",
                                 uri=True, timeout=5)) as db:
        rows = list(db.execute("SELECT key,body,stage,incident_id,attempts FROM outbox"))
    return [
        {
            "key": key,
            "stage": stage,
            "incident_id": incident,
            "attempts": attempts,
            "body": json.loads(raw),
        }
        for key, raw, stage, incident, attempts in rows
        if str(json.loads(raw).get("container_id", "")).startswith(cid)
    ]


def restart_setup(root, before):
    """Refuse the live restart mode before any fault unless its scope is controlled."""
    sys.path[:0] = [str(root / "ops"), str(root / "monitor-service")]
    from selfsentry_cli import alive, load_records
    from monitor_config import load_config

    records = load_records(root / "state/run/processes.json")
    if set(records) != {"backend", "monitor", "frontend"} or not all(
        alive(record) for record in records.values()
    ):
        raise RuntimeError("All three services must be managed and running")
    if records["monitor"]["pid"] != before.get("pid"):
        raise RuntimeError("API monitor PID does not match the managed monitor")
    if before.get("incident_outbox_size") != 0:
        raise RuntimeError("Existing pending incidents: defer this controlled outage")
    runtime = dict(
        part.split("=", 1)
        for part in Path(f"/proc/{before['pid']}/environ").read_text().split("\0")
        if "=" in part
    )
    if any(runtime.get(key) != value for key, value in STUDY_FLAGS.items()):
        raise RuntimeError("Running monitor must explicitly use the frozen manual-study flags")
    # The restart uses this same environment, without exposing its credential values.
    env = {key: value for key, value in dotenv_values(root / ".env").items()
           if value is not None}
    env.update(runtime)
    config = load_config(env)
    if config.backend_url not in ("http://127.0.0.1:8000", "http://localhost:8000"):
        raise RuntimeError("Restart acceptance requires the managed local backend")
    return config, env


def stack_action(root, folder, action, env):
    """Use the existing PID-identity-aware lifecycle manager; preserve its output."""
    with (folder / f"stack-{action}-{uuid.uuid4().hex[:8]}.log").open("x") as log:
        subprocess.run(
            [sys.executable, str(root / "ops/selfsentry_cli.py"), action],
            cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
            timeout=150, check=True,
        )


def assert_retained(item, rows):
    row = next((row for row in rows if row["key"] == item["key"]), None)
    if not row or row["stage"] != "pending" or row["body"] != item["body"]:
        raise RuntimeError("Pending payload was not retained unchanged across application stop")
    return row


def restart_checks(before, after, item, matches):
    timeline = (item["body"].get("monitor_evidence") or {}).get("observed_timeline")
    return {
        "monitor_restarted_healthy": after.get("healthy") is True
        and after.get("running") is True and after.get("pid") != before.get("pid"),
        "original_nonempty_timeline_preserved": bool(timeline) and len(matches) == 1
        and (matches[0].get("monitor_evidence") or {}).get("observed_timeline") == timeline,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restart-stack", action="store_true",
                        help="Also test graceful managed application restart with pending work")
    args = parser.parse_args(argv)
    root = Path.cwd()
    if not (root / "monitor-service/monitor_service.py").is_file():
        raise SystemExit("Run from ~/selfsentry.")
    command("sudo", "-n", "true")
    if not active():
        raise SystemExit(UNIT + " must already be active; no service changed.")
    before = get("/monitor/status")
    require_isolation_disabled(before)
    if (
        not before.get("healthy")
        or before.get("components", {}).get("database", {}).get("state") != "ok"
    ):
        raise SystemExit("Healthy monitor and working database required; no service changed.")
    values = dotenv_values(root / ".env")
    state = Path(values.get("MONITOR_STATE_DIR") or "state/monitor").expanduser()
    launch_env = None
    if args.restart_stack:
        config, launch_env = restart_setup(root, before)
        state = config.state_dir
    database = state / "pipeline.sqlite"
    if not database.is_file():
        raise SystemExit("Monitor journal not found; no service changed.")
    name = "selfsentry-db-recovery-" + uuid.uuid4().hex[:8]
    folder = root / "state/evaluation/acceptance" / name
    folder.mkdir(parents=True)
    evidence = {
        "test": "queued_graceful_stack_restart" if args.restart_stack
        else "postgresql_outage_recovery",
        "unit": UNIT,
        "status_before": before,
        "container_name": name,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    created = stopped = stack_stopped = passed = False
    rules = root / "falco-rules/auto-generated-rules.yaml"
    rules_hash = hashlib.sha256(rules.read_bytes()).hexdigest() if args.restart_stack else None
    clock_offset = time.time() - time.monotonic()

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Termination requested; attempting recovery")

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        cid = command(
            "docker",
            "run",
            "-d",
            "--pull=never",
            "--name",
            name,
            "--network",
            "none",
            "--user",
            "1000:1000",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--entrypoint",
            "/bin/sleep",
            "nginx:1.25",
            "600",
        )[:12]
        created = True
        evidence["container_id"] = cid
        if args.restart_stack:
            assert launch_env is not None  # Established by restart_setup above.
            # A live freshness pass is required before introducing the database fault.
            sys.path.insert(0, str(root / "evaluation"))
            from clock_guard import run_preflight

            clock = run_preflight(name, config.falco_log_path, folder / "clock-before.json",
                                  wait_seconds=30)
            evidence["clock_before"] = clock
            evidence["source_commit"] = command("git", "rev-parse", "HEAD")
            evidence["source_status"] = command("git", "status", "--short")
            evidence["manual_study_settings"] = STUDY_FLAGS
            evidence["generated_rules_sha256_before"] = rules_hash
            if not clock["passed"]:
                raise RuntimeError("Invalid clock preflight; no outage introduced")
            evidence["falco_pid_before"] = command(
                "systemctl", "show", launch_env.get("FALCO_SERVICE", "falco-modern-bpf"),
                "-p", "MainPID", "--value",
            )
            if not evidence["falco_pid_before"].isdigit() or int(evidence["falco_pid_before"]) <= 0:
                raise RuntimeError("Falco process identity unavailable; no outage introduced")
        # Mark restoration required before the stop call (including partial failures).
        stopped = True
        command("sudo", "-n", "systemctl", "stop", UNIT)
        if active():
            raise RuntimeError("Database did not stop; no outage validated")
        evidence["database_stopped_at"] = datetime.now(timezone.utc).isoformat()
        command(
            "docker",
            "exec",
            "-t",
            name,
            "/bin/sh",
            "-c",
            'echo "SelfSentry database recovery validation"; /bin/true',
        )
        print(
            "Database temporarily stopped; waiting for the durable incident (up to 150 seconds)...",
            flush=True,
        )
        deadline = time.monotonic() + 150
        item = None
        while time.monotonic() < deadline:
            for candidate in queued(database, cid):
                alerts = (candidate["body"].get("monitor_evidence") or {}).get("falco_alerts")
                if candidate["stage"] == "pending" and candidate["attempts"] >= 1 and alerts:
                    item = candidate
                    break
            if item:
                break
            time.sleep(1)
        if item is None:
            raise RuntimeError("No failed-delivery incident observed in the durable outbox")
        evidence["queued_during_outage"] = item
        if args.restart_stack:
            print("Pending work verified. Stopping managed applications, preserving outbox...",
                  flush=True)
            stack_stopped = True  # Recovery required even if stop only partially completes.
            stack_action(root, folder, "stop", launch_env)
            evidence["queued_after_stop"] = assert_retained(item, queued(database, cid))
        print("Queued incident verified. Restoring PostgreSQL...", flush=True)
        command("sudo", "-n", "systemctl", "start", UNIT)
        if not active():
            raise RuntimeError("Database restart did not reach active state")
        stopped = False
        evidence["database_restored_at"] = datetime.now(timezone.utc).isoformat()
        if args.restart_stack:
            stack_action(root, folder, "start", launch_env)
            stack_stopped = False
        deadline = time.monotonic() + 120
        matches = []
        while time.monotonic() < deadline:
            try:
                matches = [r for r in get("/incidents/") if r.get("event_key") == item["key"]]
                if matches and (matches[0].get("monitor_workflow") or {}).get("response"):
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
        if not matches:
            raise RuntimeError("Incident did not become visible after recovery")
        # A second observation checks retry delivery did not add another row.
        time.sleep(5)
        matches = [r for r in get("/incidents/") if r.get("event_key") == item["key"]]
        after = get("/monitor/status")
        target_rows = queued(database, cid)
        stage = next((r["stage"] for r in target_rows if r["key"] == item["key"]), None)
        evidence.update(
            incidents_after_recovery=matches, status_after=after, target_outbox_after=target_rows
        )
        checks = {
            "database_running": active(),
            "database_api_recovered": after.get("components", {}).get("database", {}).get("state")
            == "ok",
            "monitor_kept_running": after.get("pid") == before.get("pid")
            and after.get("healthy") is True,
            "exactly_one_incident_for_queued_key": len(matches) == 1,
            "delivery_left_pending_state": stage in ("done", "advisory"),
            "response_not_attempted": len(matches) == 1
            and (matches[0].get("monitor_workflow") or {}).get("response", {}).get("status")
            == "not_attempted",
        }
        if args.restart_stack:
            assert launch_env is not None
            del checks["monitor_kept_running"]
            checks.update(restart_checks(before, after, item, matches))
            evidence["generated_rules_sha256_after"] = hashlib.sha256(
                rules.read_bytes()
            ).hexdigest()
            checks["generated_rules_unchanged"] = (
                evidence["generated_rules_sha256_after"] == rules_hash
            )
            clock = run_preflight(name, config.falco_log_path, folder / "clock-after.json",
                                  wait_seconds=30)
            evidence["clock_after"] = clock
            checks["clock_after_passed"] = clock["passed"]
            evidence["falco_pid_after"] = command(
                "systemctl", "show", launch_env.get("FALCO_SERVICE", "falco-modern-bpf"),
                "-p", "MainPID", "--value",
            )
            checks["falco_process_unchanged"] = (
                evidence["falco_pid_after"] == evidence["falco_pid_before"]
            )
            evidence["clock_offset_change_seconds"] = time.time() - time.monotonic() - clock_offset
            checks["no_large_clock_discontinuity"] = abs(
                evidence["clock_offset_change_seconds"]
            ) <= 2
        passed = all(checks.values())
        evidence["checks"] = checks
        print(
            json.dumps(
                {"incident_ids": [r["id"] for r in matches], "checks": checks, "passed": passed},
                indent=2,
            ),
            flush=True,
        )
    except (Exception, KeyboardInterrupt) as exc:
        evidence["failure"] = f"{type(exc).__name__}: {exc}"
        print("Check did not complete:", evidence["failure"], flush=True)
    finally:
        if stopped:
            try:
                command("sudo", "-n", "systemctl", "start", UNIT)
            except Exception as exc:
                evidence["restart_error"] = f"{type(exc).__name__}: {exc}"
                print("Restart PostgreSQL now: sudo systemctl start " + UNIT, flush=True)
        evidence["database_active_at_cleanup"] = active()
        if stack_stopped and evidence["database_active_at_cleanup"]:
            try:
                stack_action(root, folder, "start", launch_env)
            except Exception as exc:
                evidence["stack_recovery_error"] = f"{type(exc).__name__}: {exc}"
                print("Recover managed applications: ./bin/selfsentry restart", flush=True)
        if args.restart_stack:
            try:
                stack_action(root, folder, "status", launch_env)
                evidence["managed_stack_running_at_cleanup"] = True
            except Exception:
                evidence["managed_stack_running_at_cleanup"] = False
                passed = False
        if created:
            try:
                if args.restart_stack:
                    # Retain fixture runtime state/logs before removing our own container.
                    (folder / "fixture-before-removal.json").write_text(
                        command("docker", "inspect", name) + "\n"
                    )
                    with (folder / "fixture.log").open("x") as log:
                        subprocess.run(["docker", "logs", name], stdout=log,
                                       stderr=subprocess.STDOUT, timeout=30, check=True)
                command("docker", "rm", "-f", name)
                evidence["container_removed"] = True
            except Exception as exc:
                evidence["cleanup_error"] = f"{type(exc).__name__}: {exc}"
                print("Remove test container: docker rm -f " + name, flush=True)
                passed = False
        passed = passed and evidence["database_active_at_cleanup"]
        evidence["passed"] = passed
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        p = folder / "evidence.json"
        p.write_text(json.dumps(evidence, indent=2) + "\n")
        print("Evidence:", p, flush=True)
        signal.signal(signal.SIGTERM, previous_term)
    if not passed:
        raise SystemExit("PostgreSQL recovery not verified; preserve and share this output.")
    print("PostgreSQL outage recovery verified; database active, disposable container removed.")


if __name__ == "__main__":
    main()
