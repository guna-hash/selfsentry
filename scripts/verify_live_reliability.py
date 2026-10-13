"""Disposable Docker acceptance probes; saves pass/fail evidence, never edits TODO."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

import docker
import requests

ROOT = Path(__file__).resolve().parents[1]
for folder in ("policy-checker", "monitor-service", "response-engine"):
    sys.path.insert(0, str(ROOT / folder))
from deploy_policy_validator import check_deployment_config  # noqa: E402
from event_classifier import classify_line  # noqa: E402
from auto_isolate import isolate_container, resume_container  # noqa: E402
from monitor_config import load_config  # noqa: E402


def inspect_state(container):
    container.reload()
    attrs = container.attrs
    return {
        "id": container.id, "status": container.status,
        "user": attrs["Config"]["User"],
        "privileged": attrs["HostConfig"]["Privileged"],
        "read_only": attrs["HostConfig"]["ReadonlyRootfs"],
        "cap_add": attrs["HostConfig"].get("CapAdd"),
        "networks": sorted(attrs["NetworkSettings"]["Networks"]),
    }


def probe(args, evidence):
    client = docker.from_env()
    owned = []
    network = None
    try:
        # Require an existing image: no implicit downloads during a timed demo.
        image = client.images.get(args.image)
        evidence["image_id"] = image.id
        prefix = "selfsentry-check-" + uuid.uuid4().hex[:10]
        if args.mode == "policy":
            for label, privileged in (("privileged", True), ("clean", False)):
                # Created but never started; inspect is real without privileged execution.
                container = client.containers.create(
                    image.id, ["sleep", "300"], name=f"{prefix}-{label}",
                    user="65534:65534", read_only=True, cap_drop=["ALL"],
                    privileged=privileged, network_mode="none",
                )
                owned.append(container)
                state = inspect_state(container)
                result = check_deployment_config(container.attrs).summary()
                evidence[label] = {"inspect": state, "policy": result}
                if privileged:
                    assert result["should_block_deployment"]
                    assert "POLICY-PRIVILEGED" in result["violation_rule_ids"]
                else:
                    assert result["compliant"] and not result["should_block_deployment"]
        elif args.mode == "isolation":
            network = client.networks.create(prefix, driver="bridge", internal=True)
            container = client.containers.run(
                image.id, ["sleep", "300"], name=prefix, detach=True,
                user="65534:65534", read_only=True, cap_drop=["ALL"], network=network.name,
            )
            owned.append(container)
            evidence["before"] = inspect_state(container)
            isolate_container(container.id, "disposable reliability probe")
            evidence["isolated"] = inspect_state(container)
            assert evidence["isolated"]["status"] == "paused"
            assert evidence["isolated"]["networks"] == []
            resume_container(container.id, "reliability-probe")
            evidence["resumed"] = inspect_state(container)
            assert evidence["resumed"]["status"] == "running"
            assert evidence["resumed"]["networks"] == evidence["before"]["networks"]
            evidence["scope"] = "direct response function; not automatic policy eligibility"
        else:
            cfg = load_config()
            log = Path(args.log or cfg.falco_log_path)
            with log.open() as stream:
                stream.seek(0, 2)
                container = client.containers.run(
                    image.id, ["sleep", "300"], name=prefix, detach=True,
                    user="65534:65534", read_only=True, cap_drop=["ALL"], network_mode="none",
                )
                owned.append(container)
                evidence["container"] = inspect_state(container)
                since = datetime.now(timezone.utc)
                subprocess.run(
                    ["docker", "exec", "-t", container.id, "sh", "-c",
                     "echo SelfSentry-shell-probe"], check=True, timeout=30,
                )
                deadline = time.monotonic() + args.timeout
                while time.monotonic() < deadline:
                    for line in stream:
                        try:
                            classified = classify_line(line)
                        except ValueError:
                            continue
                        if classified and classified.event["container_id"] in (
                            container.id, container.id[:12],
                        ):
                            if classified.event["rule"] == "Terminal shell in container":
                                evidence["parsed_alert"] = classified.event
                    response = requests.get(
                        args.backend.rstrip("/") + "/incidents/", timeout=10
                    )
                    response.raise_for_status()
                    for incident in response.json():
                        if incident["container_id"] not in (container.id, container.id[:12]):
                            continue
                        alerts = (incident.get("monitor_evidence") or {}).get("falco_alerts", [])
                        for alert in alerts:
                            stamp = datetime.fromisoformat(
                                alert["timestamp"].replace("Z", "+00:00")
                            )
                            if alert["rule"] == "Terminal shell in container" and stamp >= since:
                                evidence["incident"] = incident
                    if "parsed_alert" in evidence and "incident" in evidence:
                        evidence["dashboard_check"] = "pending operator visual confirmation"
                        return
                    time.sleep(1)
                raise RuntimeError("Default shell alert did not reach parser and incident in time")
    finally:
        errors = []
        for container in owned:
            try:
                container.reload()
                if container.status == "paused":
                    container.unpause()
                container.remove(force=True)
            except Exception as exc:
                errors.append(str(exc))
        if network:
            try:
                network.remove()
            except Exception as exc:
                errors.append(str(exc))
        client.close()
        evidence["cleanup_errors"] = errors
        if errors:
            raise RuntimeError("Disposable resource cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("policy", "shell", "isolation"))
    parser.add_argument("--image", default="alpine:3.20", help="Already-local image with sh/sleep")
    parser.add_argument("--log", help="Readable Falco JSON log; defaults to monitor config")
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "state/evaluation" / f"reliability-{args.mode}-{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    evidence = {"mode": args.mode, "started_at": stamp, "passed": False}
    try:
        probe(args, evidence)
        evidence["passed"] = True
    except Exception as exc:
        evidence["error"] = str(exc)
    finally:
        out.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"{'PASS' if evidence['passed'] else 'FAIL'}: {out}")
    if not evidence["passed"]:
        print(evidence.get("error", "probe failed"), file=sys.stderr)
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
