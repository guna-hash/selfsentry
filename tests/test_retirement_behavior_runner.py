"""Guard the native acceptance runner against false absence and uncertain-action retries."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
import verify_retirement_behavior as runner  # noqa: E402


def event(rule="Baseline Process Spawn", process="validation-true", parent="sh"):
    return {"rule": rule, "process": process, "parent": parent}


def test_absence_requires_the_exact_executed_baseline_witness():
    assert runner.judge_observation([event()], False)["passed"]
    for evidence in ([], [event(process="true")], [event(parent="other")]):
        with pytest.raises(RuntimeError, match="baseline witness"):
            runner.judge_observation(evidence, False)
    with pytest.raises(RuntimeError, match="differs"):
        runner.judge_observation([event(), event(runner.RULE_NAME)], False)
    assert runner.judge_observation([event(), event(runner.RULE_NAME)], True)["passed"]


def raw_event(cid, timestamp=100):
    return json.dumps({"time": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                       "rule": "Baseline Process Spawn", "output_fields": {
                           "container.id": cid, "proc.name": "validation-true", "proc.pname": "sh",
                       }}).encode() + b"\n"


def test_log_identity_clock_and_incomplete_data_cannot_fabricate_absence():
    identifier = "a" * 64
    assert len(runner.matching_events(raw_event(identifier[:12]), identifier, 99, 101)) == 1
    assert runner.matching_events(raw_event("b" * 12), identifier, 99, 101) == []
    assert runner.matching_events(raw_event("a"), identifier, 99, 101) == []
    with pytest.raises(RuntimeError, match="clock"):
        runner.matching_events(raw_event(identifier, 50), identifier, 99, 101)
    with pytest.raises(RuntimeError, match="incomplete"):
        runner.matching_events(raw_event(identifier).rstrip(), identifier, 99, 101)


@pytest.mark.parametrize("approved,reviewer", [(False, "guna"), (True, ""),
                                               (True, "selfsentry-auto")])
def test_approval_is_checked_before_any_service_or_container_action(tmp_path, approved, reviewer):
    with pytest.raises(RuntimeError, match="approval"):
        runner.run(tmp_path, approved, reviewer, "a" * 64)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", [None, "unloaded_probe", "retire_lost_ack", "restore_lost_ack"])
def test_three_phases_restore_after_observation_failure_and_never_retry_uncertain_posts(
        tmp_path, monkeypatch, failure):
    original = b"original rule file"
    target = tmp_path / "rules.yaml"
    target.write_bytes(original)
    original_hash = hashlib.sha256(original).hexdigest()
    candidate_hash = hashlib.sha256(b"candidate").hexdigest()
    rule_yaml = f"- rule: {runner.RULE_NAME}\n"
    monkeypatch.setattr(runner, "RULE_HASH", hashlib.sha256(rule_yaml.encode()).hexdigest())
    identifier = "a" * 64
    current = {"healthy": True, "pid": 77, "monitored_container_ids": [identifier],
               "configuration": {"auto_isolation_enabled": False, "auto_confirm_enabled": False,
                                 "rule_candidates_enabled": False}}
    current["backend_configuration"] = current["configuration"]
    monkeypatch.setattr(runner, "status", lambda: current)
    posts, phases, ownership = [], [], {}

    def gate(argv, **kwargs):
        ownership["name"] = argv[argv.index("--name") + 1]
        ownership["token"] = argv[argv.index("--label") + 1].split("=", 1)[1]
        return {"decision": "allowed"}

    def docker(argv, **kwargs):
        if argv[0] == "image":
            return "sha256:" + "f" * 64
        if argv[0] == "rm":
            ownership["removed"] = True
            return ""
        if ownership.get("removed"):
            return None
        return json.dumps([{"Name": "/" + ownership["name"], "Id": identifier,
                            "Config": {"Labels": {runner.LABEL: ownership["token"]}}}])

    monkeypatch.setattr(runner, "docker", docker)

    class Response:
        status_code = 200

        def __init__(self, value):
            self.value = value

        def json(self):
            return self.value

        def raise_for_status(self):
            pass

    class Session:
        headers = {}

        def get(self, url, **kwargs):
            if url.endswith("history"):
                return Response([{"id": 5, "status": "deployed", "rule_yaml": rule_yaml}])
            return Response({"enabled": True, "receipt": {"phase": "rolled_back"}})

        def post(self, url, json, **kwargs):
            action = json["action"]
            posts.append(action)
            if failure == action.replace("rollback", "restore") + "_lost_ack":
                raise requests.Timeout("lost acknowledgment")
            target.write_bytes(b"candidate" if action == "retire" else original)
            return Response({"status": "retired" if action == "retire" else "deployed",
                             "phase": "applied" if action == "retire" else "rolled_back",
                             "operation_id": "operation"})

    monkeypatch.setattr(runner.requests, "Session", Session)
    modules = {
        "backend_auth": SimpleNamespace(backend_headers=lambda: {}),
        "deployment_gate": SimpleNamespace(run_gate=gate),
        "monitor_config": SimpleNamespace(load_config=lambda: SimpleNamespace(
            falco_log_path=tmp_path / "alerts.json")),
        "rule_deployer": SimpleNamespace(AUTO_GENERATED_RULES_PATH=target,
                                         FALCO_CONFIG_PATH=tmp_path / "falco.yaml"),
        "native_retirement": SimpleNamespace(
            prepare=lambda *a: {"original_sha256": original_hash,
                                "candidate_sha256": candidate_hash},
            ReloadClient=lambda *a: SimpleNamespace(status=lambda: {"ready": True})),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    def observe(log, cid, expected, seconds):
        phases.append(expected)
        if failure == "unloaded_probe" and expected is False:
            raise RuntimeError("missing witness")
        return {"passed": True}

    monkeypatch.setattr(runner, "observe", observe)
    code = runner.run(tmp_path, True, "guna", original_hash)
    report = json.loads(next((tmp_path / "state/evaluation").glob("*/results.json")).read_text())
    assert ownership["removed"] is True
    assert code == (0 if failure is None else 1)
    if failure == "retire_lost_ack":
        assert posts == ["retire"] and report["native_recovery_required"] is True
    else:
        assert posts == ["retire", "rollback"]
        assert report["native_recovery_required"] is (failure == "restore_lost_ack")
    if failure in (None, "unloaded_probe"):
        assert target.read_bytes() == original
    if failure is None:
        assert phases == [True, False, True]


@pytest.mark.parametrize("mode", ["present", "absent", "rotation", "no_witness", "stale"])
def test_observer_reads_actual_file_and_refuses_invalid_negative_evidence(
        tmp_path, monkeypatch, mode):
    log = tmp_path / "alerts.json"
    log.write_bytes(b"")
    identifier = "a" * 64
    clocks = iter([{"boot_id": "boot", "monotonic": 100, "realtime": 100},
                   {"boot_id": "boot", "monotonic": 101, "realtime": 101}])
    monkeypatch.setattr(runner, "clock_snapshot", lambda: next(clocks))
    monkeypatch.setattr(runner.time, "sleep", lambda *a: None)

    def trigger(argv, **kwargs):
        assert argv[:4] == ["docker", "exec", identifier, "/bin/sh"]
        data = raw_event(identifier, timestamp=50 if mode == "stale" else 100)
        if mode == "present":
            data += data.replace(b"Baseline Process Spawn", runner.RULE_NAME.encode())
        if mode == "no_witness":
            data = data.replace(b"validation-true", b"something_else")
        if mode == "rotation":
            log.rename(log.with_suffix(".old"))
        log.write_bytes(data)
        return runner.subprocess.CompletedProcess(argv, 0, "SELFSENTRY_PROBE_EXIT 0\n", "")

    monkeypatch.setattr(runner.subprocess, "run", trigger)
    if mode in ("rotation", "no_witness", "stale"):
        with pytest.raises(RuntimeError):
            runner.observe(log, identifier, False, 20)
    else:
        assert runner.observe(str(log), identifier, mode == "present", 20)["passed"] is True
