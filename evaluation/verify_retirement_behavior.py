"""Approved rule-5 before/unloaded/restored observations on one owned disposable probe.

Requires the separately configured protected socket and enabled retirement endpoint.
Never configures services, retries uncertain writes, overrides a blocked gate, or isolates
an existing workload. An absent match is scoped to the witnessed observation window.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from typing import Any

import requests
import yaml
from dotenv import load_dotenv

from clock_guard import clock_snapshot, parse_falco_time, require_same_clock
from measure_workload import docker, require, status

API = "http://127.0.0.1:8000"
LABEL = "selfsentry.retirement-probe"
RULE_NAME = "Auto_Generated_validation_true_from_sh_37"
RULE_HASH = "47216c322ce212dc121f1efd4170df764331f215a3ae2b41de4c02ae8138f25c"


def matching_events(data, identifier, start, end):
    """Strict log parsing: incomplete, stale or wrong-identity evidence cannot prove absence."""
    require(data.endswith(b"\n"), "Observation ends with an incomplete Falco record")
    events = []
    for raw in data.splitlines():
        event = json.loads(raw)
        fields = event.get("output_fields") or {}
        cid = fields.get("container.id", "")
        if not isinstance(cid, str) or not re.fullmatch(r"[a-f0-9]{12,64}", cid):
            continue
        if not identifier.startswith(cid):
            continue
        timestamp = parse_falco_time(event["time"])
        require(start - 2 <= timestamp <= end + 2, "Invalid Falco event clock; trial invalid")
        events.append({"time": event["time"], "rule": event.get("rule"),
                       "process": fields.get("proc.name"), "parent": fields.get("proc.pname")})
    return events


def judge_observation(events, expected_present):
    witness = any(e["rule"] == "Baseline Process Spawn" and
                  e["process"] == "validation-true" and e["parent"] == "sh" for e in events)
    matched = any(e["rule"] == RULE_NAME for e in events)
    require(witness, "No matching baseline witness: absence cannot be interpreted")
    require(matched is expected_present, "Native rule presence differs from expected phase")
    return {"baseline_witness": witness, "native_match": matched,
            "expected_native_match": expected_present, "passed": True}


def owned(spec, name, token):
    require(spec.get("Name") == "/" + name and
            (spec.get("Config", {}).get("Labels") or {}).get(LABEL) == token and
            re.fullmatch(r"[a-f0-9]{64}", spec.get("Id", "")),
            "Disposable probe ownership differs; refusing action")
    return spec["Id"]


def observe(log, identifier, expected_present, seconds):
    # A held file plus inode/truncation checks prevent a rotation from looking like silence.
    log = Path(log)
    with log.open("rb") as stream:
        info = os.fstat(stream.fileno())
        offset = stream.seek(0, 2)
        before = clock_snapshot()
        command = ('set -e; cp /bin/true /tmp/validation-true; chmod 700 /tmp/validation-true; '
                   'set +e; /tmp/validation-true; result=$?; '
                   'printf "SELFSENTRY_PROBE_EXIT %s\\n" "$result"; /bin/true')
        trigger = subprocess.run(["docker", "exec", identifier, "/bin/sh", "-c", command],
                                 capture_output=True, text=True, timeout=10)
        require(trigger.returncode == 0, "Probe launcher did not complete")
        require(re.fullmatch(r"SELFSENTRY_PROBE_EXIT [0-9]+\n", trigger.stdout) is not None,
                "Probe did not report its process exit status")
        time.sleep(seconds)
        after = clock_snapshot()
        require_same_clock(before, after)
        current = log.stat()
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
                and current.st_size >= offset, "Falco log rotated/truncated; trial invalid")
        data = stream.read(4 * 1024 * 1024 + 1)
        require(len(data) <= 4 * 1024 * 1024, "Observation exceeds log budget; trial invalid")
    events = matching_events(data, identifier, before["realtime"], after["realtime"])
    return {**judge_observation(events, expected_present), "events": events,
            "host_clock_before": before, "host_clock_after": after,
            "probe_exit": trigger.stdout.strip(), "probe_stderr": trigger.stderr[:1000],
            "observation_seconds": seconds}


def run(root, approved, reviewer, expected_file, seconds=20):
    require(approved is True and reviewer.strip() and reviewer.strip() != "selfsentry-auto",
            "Explicit rule-5 retirement/restore approval and human reviewer required")
    require(type(seconds) is int and 15 <= seconds <= 60,
            "Observation must be 15 through 60 seconds")
    require(re.fullmatch(r"[a-f0-9]{64}", expected_file) is not None, "Reviewed file SHA required")
    os.umask(0o077)
    load_dotenv(root / ".env")
    sys.path[:0] = [str(root / "monitor-service"), str(root / "rule-synthesis-engine"),
                    str(root / "deployment-gate")]
    from backend_auth import backend_headers
    from deployment_gate import run_gate
    from monitor_config import load_config
    from native_retirement import ReloadClient, prepare
    import rule_deployer

    before = status()
    require(before.get("healthy") is True, "Healthy monitor required")
    for configuration in (before.get("configuration", {}), before.get("backend_configuration", {})):
        require(configuration.get("auto_isolation_enabled") is False and
                configuration.get("auto_confirm_enabled") is False and
                configuration.get("rule_candidates_enabled") is False,
                "Isolation, automatic confirmation and rule candidates must be disabled")
    session = requests.Session()
    session.headers.update(backend_headers())
    response = session.get(API + "/rules/history", timeout=15)
    response.raise_for_status()
    rule = next(r for r in response.json() if r["id"] == 5)
    require(rule["status"] == "deployed" and hashlib.sha256(
        rule["rule_yaml"].encode()).hexdigest() == RULE_HASH, "Reviewed rule 5 differs")
    require(yaml.safe_load(rule["rule_yaml"])[0]["rule"] == RULE_NAME, "Native name differs")
    target = Path(rule_deployer.AUTO_GENERATED_RULES_PATH)
    plan = prepare(rule["rule_yaml"], target, rule_deployer.FALCO_CONFIG_PATH)
    require(plan["original_sha256"] == expected_file, "Reviewed generated file differs")
    response = session.get(API + "/rules/5/native-retirement-plan", timeout=15)
    response.raise_for_status()
    gate_plan = response.json()
    require(gate_plan.get("enabled") is True and (gate_plan.get("receipt") is None or
            gate_plan["receipt"]["phase"] == "rolled_back"), "Native endpoint/receipt not ready")
    client = ReloadClient(os.environ.get("FALCO_RELOAD_SOCKET", "/run/falco/control.sock"))
    require(client.status()["ready"] is True, "Protected listener must be ready")
    image = docker(["image", "inspect", "--format", "{{.Id}}", "alpine:3.20"])
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image) is not None,
            "Local immutable image required")
    token = uuid.uuid4().hex
    name = "selfsentry-retirement-probe-" + token[:12]
    folder = root / "state/evaluation" / ("retirement-behavior-" + datetime.now(
        timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    folder.mkdir(parents=True, mode=0o700)
    report: dict[str, Any] = {
        "passed": False, "rule_id": 5, "probe_name": name,
        "image_id": image, "ownership_token": token,
        "original_file_sha256": expected_file, "requests": [], "phases": {},
        "errors": [], "scope": "One harmless literal-process witness, not detection quality"}
    output = folder / "results.json"

    def save():
        output.write_text(json.dumps(report, indent=2) + "\n")

    def action(name, file_hash):
        entry: dict[str, Any] = {"action": name, "phase": "intent_recorded"}
        report["requests"].append(entry)
        save()
        body = {"reviewed_by": reviewer, "reason": "Approved rule-5 before/unloaded/restored test",
                "expected_file_sha256": file_hash, "expected_rule_sha256": RULE_HASH,
                "confirm_native_unload": True, "action": name}
        result = session.post(API + "/rules/5/retire-native", json=body, timeout=90)
        entry.update(http_status=result.status_code, response=result.json(),
                     phase="response_received")
        save()
        result.raise_for_status()
        return entry["response"]

    attempted, retired, restored = False, None, None
    rollback_confirmed = False
    try:
        save()
        attempted = True
        report["gate"] = run_gate([
            "--name", name, "--label", LABEL + "=" + token,
            "--user", "65534:65534", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--network", "none",
            "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=4m,mode=1777",
            "--pids-limit", "32", "--memory", "64m", "--cpus", "0.25",
            "--entrypoint", "/bin/sleep", image, "600"], backend_url=API)
        require(report["gate"]["decision"] == "allowed", "Gate refused probe; no override used")
        identifier = owned(json.loads(docker(["container", "inspect", name]))[0], name, token)
        report["container_id"] = identifier
        for _ in range(30):
            current = status()
            if current.get("healthy") and identifier in current.get("monitored_container_ids", []):
                break
            time.sleep(1)
        else:
            raise RuntimeError("Probe was not discovered by the healthy monitor")
        log = load_config().falco_log_path
        report["phases"]["before"] = observe(log, identifier, True, seconds)
        save()
        retired = action("retire", expected_file)
        require(retired.get("phase") == "applied" and retired.get("status") == "retired",
                "Retirement outcome uncertain; inspect evidence, do not retry")
        try:
            report["phases"]["unloaded"] = observe(log, identifier, False, seconds)
            save()
        finally:
            # Recovery is authorized, but only a known applied retirement reaches this block.
            restored = action("rollback", plan["candidate_sha256"])
            require(restored.get("phase") == "rolled_back" and restored.get("status") == "deployed"
                    and restored.get("operation_id") == retired["operation_id"],
                    "Restore outcome unresolved; no repeated request")
            rollback_confirmed = True
        report["phases"]["restored"] = observe(log, identifier, True, seconds)
        require(hashlib.sha256(target.read_bytes()).hexdigest() == expected_file,
                "Restored generated file differs from original")
    except Exception as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        if attempted:
            try:
                raw = docker(["container", "inspect", name], missing_ok=True)
                if raw is not None:
                    identifier = owned(json.loads(raw)[0], name, token)
                    docker(["rm", "--force", identifier], timeout=30)
                    require(docker(["container", "inspect", identifier], missing_ok=True) is None,
                            "Probe cleanup was not confirmed")
                report["cleanup"] = "removed_or_confirmed_absent"
            except Exception as exc:
                report["errors"].append("Cleanup: " + type(exc).__name__)
        try:
            current = status()
            report["monitor_healthy_after"] = current.get("healthy") is True
            require(report["monitor_healthy_after"] and current.get("pid") == before.get("pid"),
                    "Monitor health/PID changed")
        except Exception as exc:
            report["errors"].append("Monitor check: " + type(exc).__name__)
        report["passed"] = not report["errors"] and set(report["phases"]) == {
            "before", "unloaded", "restored"} and rollback_confirmed
        report["native_recovery_required"] = bool(report["requests"]) and not rollback_confirmed
        save()
        print(json.dumps(report, indent=2))
        print("Evidence:", output)
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "selfsentry")
    parser.add_argument("--approve-rule-5-retire-and-restore", action="store_true")
    parser.add_argument("--reviewed-by", required=True)
    parser.add_argument("--expected-file-sha256", required=True)
    args = parser.parse_args()
    return run(args.repo.expanduser().resolve(), args.approve_rule_5_retire_and_restore,
               args.reviewed_by, args.expected_file_sha256)


if __name__ == "__main__":
    raise SystemExit(main())
