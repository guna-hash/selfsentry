"""Real Docker protection check using the installed response workflow.

Synthetic qualifying evidence and a local fake backend are deliberately used.
This is a Docker/workflow integration check, not another live detection trial.
Isolation is enabled only in the isolated harness configuration. The actual
monitor configuration, incidents and baseline are never modified. A defensive
callback records unexpected isolation attempts without touching Docker.
"""

from pathlib import Path
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import dataclasses
import json
import sqlite3
import sys
import tempfile
import uuid
from typing import Any


def main():
    root = Path.cwd()
    if not (root / "monitor-service/incident_pipeline.py").is_file():
        raise SystemExit("Run from ~/selfsentry.")
    sys.path.insert(0, str(root / "monitor-service"))
    import docker
    from incident_pipeline import IncidentPipeline
    from automation_policy import eligible
    from monitor_config import MonitorConfig
    from monitor_status import StatusBoard
    import requests
    from safety import require_isolation_disabled

    r = requests.get("http://127.0.0.1:8000/monitor/status", timeout=10)
    r.raise_for_status()
    status_before = r.json()
    require_isolation_disabled(status_before)
    if not status_before.get("healthy"):
        raise SystemExit("Healthy running monitor required.")
    name = "selfsentry-protected-" + uuid.uuid4().hex[:8]
    folder = root / "state/evaluation/acceptance" / name
    folder.mkdir(parents=True)
    evidence = {
        "test": "protected_container_docker_workflow_integration",
        "evidence_type": "synthetic policy fixture; real Docker identity/state; fake backend",
        "status_before": status_before,
        "results": [],
        "container_name": name,
    }
    client = docker.from_env()
    container = None
    passed = False
    callbacks = []

    def forbid_isolation(*args):
        callbacks.append(args)
        raise AssertionError("Protected-container check attempted isolation")

    class Http:
        def post(self, url, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None, json=lambda: kwargs.get("json", {})
            )

    class Audit:
        def __init__(self):
            self.rows = []

        def emit(self, **kwargs):
            self.rows.append(kwargs)

    try:
        client.images.get("nginx:1.25")  # No image download.
        container = client.containers.run(
            "nginx:1.25",
            "300",
            entrypoint="/bin/sleep",
            name=name,
            detach=True,
            network_mode="none",
            user="1000:1000",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
        )
        container.reload()
        full_id, cid = container.id, container.id[:12]
        original_networks = container.attrs["NetworkSettings"]["Networks"]
        evidence["container_id"] = full_id
        for kind, protected in (("name", name), ("short_id", cid), ("full_id", full_id)):
            now = datetime.now(timezone.utc)
            ts = now.isoformat()
            payload = {
                "container_id": cid,
                "risk_score": 100,
                "confidence": "high",
                "falco_alert": {
                    "container_id": cid,
                    "timestamp": ts,
                    "priority": "CRITICAL",
                    "rule": "Synthetic validation fixture",
                },
                "anomaly_features": {"container_id": cid, "timestamp": ts, "anomaly_score": 0.99},
                "monitor_evidence": {
                    "baseline_state": "MODEL_READY",
                    "anomaly_status": "used",
                    "window_start": (now - timedelta(seconds=1)).isoformat(),
                    "window_end": (now + timedelta(seconds=1)).isoformat(),
                },
            }
            with tempfile.TemporaryDirectory() as d:
                local = Path(d)
                config = dataclasses.replace(
                    MonitorConfig(),
                    state_dir=local,
                    auto_isolation_enabled=True,
                    protected_containers=(protected,),
                    rule_candidates_enabled=False,
                )
                allowed, reason = eligible(payload, config, action="isolate", now=now.timestamp())
                if not allowed:
                    raise RuntimeError(
                        "Fixture does not reach response protection branch: " + reason
                    )
                db = sqlite3.connect(local / "actions.sqlite")
                audit = Audit()
                behavior = SimpleNamespace(
                    config=config, db=db, status=StatusBoard(local / "status.json"), audit=audit
                )
                pipeline = IncidentPipeline(
                    behavior,
                    http=Http(),
                    isolate=forbid_isolation,
                    docker_factory=docker.from_env,
                    summarize=lambda _: {"plain_summary": "fixture"},
                    clock=lambda: now.timestamp(),
                    async_explanations=False,
                )
                body: dict[str, Any] = {
                    "id": 0,
                    "payload": payload,
                    "workflow": {
                        "confirmation": {"status": "confirmed", "confirmed_by": "selfsentry-auto"}
                    },
                }
                pipeline._process(kind, body, "isolate")
                db.close()
            container.reload()
            checks = {
                "eligible_fixture": allowed,
                "workflow_protected": body["workflow"]["response"].get("status") == "protected",
                "full_id_matched": body["workflow"]["response"].get("container_id") == full_id,
                "no_isolation_callback": not callbacks,
                "still_running_unpaused": container.status == "running"
                and not container.attrs["State"]["Paused"],
                "network_state_unchanged": container.attrs["NetworkSettings"]["Networks"]
                == original_networks,
            }
            result = {"protection": kind, "checks": checks, "passed": all(checks.values())}
            evidence["results"].append(result)
            print(json.dumps(result, indent=2), flush=True)
        passed = all(item["passed"] for item in evidence["results"])
    except Exception as exc:
        evidence["failure"] = f"{type(exc).__name__}: {exc}"
        print("Protection check failed:", evidence["failure"])
    finally:
        if container is not None:
            try:
                container.remove(force=True)
                evidence["container_removed"] = True
            except Exception as exc:
                evidence["cleanup_error"] = f"{type(exc).__name__}: {exc}"
                passed = False
                print("Remove test container: docker rm -f " + name)
        client.close()
        evidence["passed"] = passed
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        p = folder / "evidence.json"
        p.write_text(json.dumps(evidence, indent=2) + "\n")
        print("Evidence:", p)
    if not passed:
        raise SystemExit("Protected-container check did not pass; share the output.")
    print("Protection verified by name, short ID and full ID; disposable container removed.")


if __name__ == "__main__":
    main()
