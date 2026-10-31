"""Live no-baseline smoke check on one disposable container; run from ~/selfsentry.

Keep the monitor's automatic isolation disabled. Does not modify configuration or
existing baseline files. Creates an isolated disposable container and removes it
in finally, including on failures. Saves observed evidence without inventing results.
"""

from pathlib import Path
from datetime import datetime, timezone
import json
import subprocess
import time
import uuid
from safety import backend_json, require_isolation_disabled


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=30).strip()


def main():
    root = Path.cwd()
    if not (root / "monitor-service/monitor_service.py").is_file():
        raise SystemExit("Run from ~/selfsentry.")
    base = "http://127.0.0.1:8000"

    def get(path):
        return backend_json(base, path)

    before = get("/monitor/status")
    require_isolation_disabled(before)
    if before.get("healthy") is not True:
        raise SystemExit("Healthy monitor required; no container created.")
    name = "selfsentry-no-baseline-" + uuid.uuid4().hex[:8]
    evidence = {
        "test": "no_baseline_fallback",
        "status_before": before,
        "container_name": name,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    folder = root / "state/evaluation/acceptance" / name
    folder.mkdir(parents=True)
    created = False
    passed = False
    try:
        cid = docker(
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
            "300",
        )
        created = True
        cid = cid[:12]
        evidence["container_id"] = cid
        if cid in before.get("baselines", {}):
            raise RuntimeError("Unexpected pre-existing lifecycle for new container")
        evidence["command_output"] = docker(
            "exec",
            "-t",
            name,
            "/bin/sh",
            "-c",
            'echo "SelfSentry no-baseline validation"; /bin/true',
        )
        print("Waiting for a Falco incident from", cid, "(up to 150 seconds)...", flush=True)
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            rows = [
                r
                for r in get("/incidents/")
                if str(r.get("container_id", "")).startswith(cid) and r.get("monitor_evidence")
            ]
            if rows:
                row = max(rows, key=lambda r: r["id"])
                e = row["monitor_evidence"]
                # Observe a security alert, not just startup baseline telemetry.
                if e.get("falco_alerts"):
                    evidence["incident"] = row
                    w = row.get("monitor_workflow") or {}
                    checks = {
                        "falco_security_alert_retained": bool(e.get("falco_alerts")),
                        "model_not_ready": e.get("baseline_state")
                        in ("NO_BASELINE", "LEARNING", "MODEL_UNAVAILABLE"),
                        "ml_explicitly_unavailable": e.get("anomaly_status")
                        in ("learning", "unavailable"),
                        "no_cross_layer_agreement": e.get("cross_layer_agreement") is False,
                        "not_auto_confirmed": not row.get("confirmation")
                        and (w.get("confirmation") or {}).get("status") != "confirmed",
                        "response_not_attempted": (w.get("response") or {}).get("status")
                        == "not_attempted",
                    }
                    evidence["checks"] = checks
                    # Incident may be visible before its workflow is synchronized.
                    if not checks["response_not_attempted"]:
                        time.sleep(1)
                        continue
                    passed = all(checks.values())
                    print(
                        json.dumps(
                            {"incident_id": row["id"], "checks": checks, "passed": passed}, indent=2
                        ),
                        flush=True,
                    )
                    break
            time.sleep(1)
        else:
            evidence["failure"] = "No security incident observed within 150 seconds"
        evidence["status_after"] = get("/monitor/status")
    except Exception as exc:
        evidence["failure"] = f"{type(exc).__name__}: {exc}"
    finally:
        if created:
            try:
                docker("rm", "-f", name)
                evidence["container_removed"] = True
            except Exception as exc:
                evidence["container_removed"] = False
                evidence["cleanup_error"] = f"{type(exc).__name__}: {exc}"
                passed = False
                print("Cleanup failed. Run: docker rm -f " + name, flush=True)
        evidence["passed"] = passed
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        p = folder / "evidence.json"
        p.write_text(json.dumps(evidence, indent=2) + "\n")
        print("Evidence:", p, flush=True)
    if not passed:
        raise SystemExit("No-baseline check did not pass; preserve evidence and share the output.")
    print("No-baseline fallback verified; disposable container removed.")


if __name__ == "__main__":
    main()
