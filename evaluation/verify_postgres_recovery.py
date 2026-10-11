"""Controlled VM PostgreSQL outage/recovery; isolation must remain disabled.

Temporarily stops only postgresql@16-main. Keeps backend/Falco/monitor running.
Creates one disposable container; verifies a durable queued incident and exactly
one recovered row. Always attempts DB restart and container cleanup in finally.
Run sudo -v first. No baseline, secrets or original trial files are modified.
"""

from pathlib import Path
from datetime import datetime, timezone
import json
import sqlite3
import subprocess
import time
import uuid
import requests
from dotenv import dotenv_values

UNIT = "postgresql@16-main"
BASE = "http://127.0.0.1:8000"


def command(*args):
    return subprocess.check_output(args, text=True, timeout=45).strip()


def active():
    return subprocess.run(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0


def get(path):
    r = requests.get(BASE + path, timeout=10)
    r.raise_for_status()
    return r.json()


def queued(database, cid):
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5) as db:
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


def main():
    root = Path.cwd()
    if not (root / "monitor-service/monitor_service.py").is_file():
        raise SystemExit("Run from ~/selfsentry.")
    command("sudo", "-n", "true")
    if not active():
        raise SystemExit(UNIT + " must already be active; no service changed.")
    before = get("/monitor/status")
    if (
        not before.get("healthy")
        or before.get("components", {}).get("database", {}).get("state") != "ok"
    ):
        raise SystemExit("Healthy monitor and working database required; no service changed.")
    values = dotenv_values(root / ".env")
    state = Path(values.get("MONITOR_STATE_DIR") or "state/monitor").expanduser()
    database = state / "pipeline.sqlite"
    if not database.is_file():
        raise SystemExit("Monitor journal not found; no service changed.")
    name = "selfsentry-db-recovery-" + uuid.uuid4().hex[:8]
    folder = root / "state/evaluation/acceptance" / name
    folder.mkdir(parents=True)
    evidence = {
        "test": "postgresql_outage_recovery",
        "unit": UNIT,
        "status_before": before,
        "container_name": name,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    created = stopped = passed = False
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
        print("Queued incident verified. Restoring PostgreSQL...", flush=True)
        command("sudo", "-n", "systemctl", "start", UNIT)
        if not active():
            raise RuntimeError("Database restart did not reach active state")
        stopped = False
        evidence["database_restored_at"] = datetime.now(timezone.utc).isoformat()
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
        passed = all(checks.values())
        evidence["checks"] = checks
        print(
            json.dumps(
                {"incident_ids": [r["id"] for r in matches], "checks": checks, "passed": passed},
                indent=2,
            ),
            flush=True,
        )
    except Exception as exc:
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
        if created:
            try:
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
    if not passed:
        raise SystemExit("PostgreSQL recovery not verified; preserve and share this output.")
    print("PostgreSQL outage recovery verified; database active, disposable container removed.")


if __name__ == "__main__":
    main()
