"""Tests for deployment-gate/deployment_gate.py.

Docker is faked, the Trivy scan is mocked, the backend POST is mocked. The policy checker
is the real one, so these tests exercise the real allow/block rules.
"""

import json
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "deployment-gate"))
sys.path.insert(0, str(_ROOT / "image-scanner"))

import deployment_gate  # noqa: E402
import trivy_wrapper  # noqa: E402

CONTAINER_ID = "abc123def456" + "0" * 52

COMPLIANT_SPEC = {
    "Id": CONTAINER_ID,
    "Image": "sha256:" + "b" * 64,
    "Name": "/web",
    "Config": {"User": "1000:1000", "Image": "alpine:3.20"},
    "HostConfig": {"Privileged": False, "CapAdd": None, "ReadonlyRootfs": True},
}
ROOT_SPEC = {
    "Id": CONTAINER_ID,
    "Image": "sha256:" + "b" * 64,
    "Name": "/web",
    "Config": {"User": "", "Image": "alpine:3.20"},
    "HostConfig": {"Privileged": False, "CapAdd": None, "ReadonlyRootfs": True},
}


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeDocker:
    def __init__(self, spec, create_fails=False, start_fails=False):
        self.spec = spec
        self.create_fails = create_fails
        self.start_fails = start_fails
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        command = args[0]
        if command == "create":
            if self.create_fails:
                return completed(returncode=1, stderr="No such image")
            return completed(CONTAINER_ID + "\n")
        if command == "inspect":
            return completed(json.dumps([self.spec]))
        if command == "start":
            if self.start_fails:
                return completed(returncode=1, stderr="cannot start")
            return completed(CONTAINER_ID)
        return completed()

    @property
    def commands(self):
        return [call[0] for call in self.calls]


def clean_scan():
    return trivy_wrapper.ScanResult(image="alpine:3.20")


def critical_scan():
    scan = trivy_wrapper.ScanResult(image="alpine:3.20")
    scan.vulnerabilities.append(
        trivy_wrapper.Vulnerability(
            id="CVE-2026-0001",
            pkg_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
            severity="CRITICAL",
        )
    )
    return scan


class GateTestCase(unittest.TestCase):
    def setUp(self):
        temporary_state = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_state.cleanup)
        env = patch.dict(os.environ, {"SELFSENTRY_STATE_DIR": temporary_state.name})
        env.start()
        self.addCleanup(env.stop)
        self.docker = None
        self.scan = patch.object(deployment_gate, "scan_image", return_value=clean_scan())
        self.scan_mock = self.scan.start()
        self.addCleanup(self.scan.stop)
        self.post = patch.object(deployment_gate.requests, "post")
        self.post_mock = self.post.start()
        self.addCleanup(self.post.stop)
        self.post_mock.return_value = MagicMock(status_code=201, text="")
        self.post_mock.return_value.json.side_effect = lambda: {
            "id": 1, "decision": self.post_mock.call_args.kwargs["json"]["decision"],
        }

    def use_docker(self, spec, **kwargs):
        self.docker = FakeDocker(spec, **kwargs)
        patcher = patch.object(deployment_gate, "_docker", self.docker)
        patcher.start()
        self.addCleanup(patcher.stop)

    def payload(self):
        return self.post_mock.call_args.kwargs["json"]

    def rule_ids(self):
        return [v["rule_id"] for v in self.payload()["policy_violations"]]


class TestGateDecisions(GateTestCase):
    def test_missing_image_id_blocks_without_scanning_a_mutable_tag(self):
        spec = dict(COMPLIANT_SPEC)
        spec.pop("Image")
        self.use_docker(spec)
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "blocked")
        self.scan_mock.assert_not_called()
        self.assertNotIn("start", self.docker.commands)
        self.assertIn("GATE-SCAN-FAILED", self.rule_ids())

    def test_scans_the_created_image_id_even_when_the_tag_points_elsewhere(self):
        image_id = "sha256:" + "a" * 64
        self.use_docker(dict(COMPLIANT_SPEC, Image=image_id))
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.scan_mock.assert_called_once_with(image_id)
        self.assertEqual(result["record"]["image_name"], "alpine:3.20")

    def test_compliant_deployment_is_started_and_recorded_as_allowed(self):
        self.use_docker(COMPLIANT_SPEC)
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(self.docker.commands, ["create", "inspect", "start"])
        self.assertEqual(self.payload()["decision"], "allowed")
        self.assertEqual(self.payload()["image_name"], "alpine:3.20")
        self.assertTrue(result["recorded"])

    def test_root_user_is_blocked_and_the_container_removed(self):
        self.use_docker(ROOT_SPEC)
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "blocked")
        self.assertEqual(self.docker.commands, ["create", "inspect", "rm"])
        self.assertIn("POLICY-ROOT-USER", self.rule_ids())

    def test_critical_image_scan_blocks_an_otherwise_compliant_container(self):
        self.use_docker(COMPLIANT_SPEC)
        self.scan_mock.return_value = critical_scan()
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("POLICY-IMAGE-SCAN-BLOCKING", self.rule_ids())
        self.assertEqual(self.payload()["scan_findings"][0]["id"], "CVE-2026-0001")
        self.assertEqual(self.payload()["scan_summary"]["critical"], 1)

    def test_override_starts_a_blocked_deployment_and_records_the_reason(self):
        self.use_docker(ROOT_SPEC)
        result = deployment_gate.run_gate(["alpine:3.20"], override_reason="ticket 42")
        self.assertEqual(result["decision"], "overridden")
        self.assertEqual(self.docker.commands, ["create", "inspect", "start"])
        self.assertEqual(self.payload()["override_reason"], "ticket 42")

    def test_scan_failure_fails_closed(self):
        self.use_docker(COMPLIANT_SPEC)
        self.scan_mock.side_effect = trivy_wrapper.TrivyScanError("db download failed")
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("GATE-SCAN-FAILED", self.rule_ids())
        self.assertEqual(self.payload()["scan_summary"], {})
        self.assertNotIn("start", self.docker.commands)

    def test_scan_failure_can_be_overridden_by_an_admin(self):
        self.use_docker(COMPLIANT_SPEC)
        self.scan_mock.side_effect = trivy_wrapper.TrivyNotInstalledError("no trivy")
        result = deployment_gate.run_gate(["alpine:3.20"], override_reason="offline lab")
        self.assertEqual(result["decision"], "overridden")
        self.assertIn("start", self.docker.commands)

    def test_backend_down_still_enforces_and_does_not_raise(self):
        self.use_docker(ROOT_SPEC)
        self.post_mock.side_effect = requests.ConnectionError("down")
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "blocked")
        self.assertFalse(result["recorded"])
        self.assertIn("rm", self.docker.commands)

    def test_backend_rejection_is_reported_as_not_recorded(self):
        self.use_docker(COMPLIANT_SPEC)
        self.post_mock.return_value = MagicMock(status_code=500, text="boom")
        result = deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(result["decision"], "allowed")
        self.assertFalse(result["recorded"])


class TestGateDockerFailures(GateTestCase):
    def test_create_failure_raises_and_nothing_else_runs(self):
        self.use_docker(COMPLIANT_SPEC, create_fails=True)
        with self.assertRaises(deployment_gate.DockerCommandError):
            deployment_gate.run_gate(["nope:latest"])
        self.assertEqual(self.docker.commands, ["create"])
        self.post_mock.assert_not_called()

    def test_start_failure_removes_the_container_and_raises(self):
        self.use_docker(COMPLIANT_SPEC, start_fails=True)
        with self.assertRaises(deployment_gate.DockerCommandError):
            deployment_gate.run_gate(["alpine:3.20"])
        self.assertEqual(self.docker.commands[-1], "rm")


class TestActionDurability(GateTestCase):
    def journal(self):
        from contextlib import closing
        import deployment_outbox
        with closing(deployment_outbox.connect()) as db:
            return db.execute(
                "SELECT container_id,action,outcome FROM deployment_actions"
            ).fetchall()

    def test_intent_committed_before_start_and_completed_afterward(self):
        fake = FakeDocker(COMPLIANT_SPEC)

        def docker(*args):
            if args[0] == "start":
                self.assertEqual(self.journal(), [(CONTAINER_ID, "start", "outcome_not_recorded")])
            return fake(*args)

        with patch.object(deployment_gate, "_docker", side_effect=docker):
            deployment_gate.run_gate(["alpine"])
        self.assertEqual(self.journal(), [(CONTAINER_ID, "start", "command_succeeded")])

    def test_journal_failure_refuses_start_and_removal(self):
        import sqlite3
        for spec in (COMPLIANT_SPEC, ROOT_SPEC):
            with self.subTest(spec=spec), patch.object(
                deployment_gate, "_docker", side_effect=FakeDocker(spec)
            ) as docker, patch.object(
                deployment_gate, "begin_action", side_effect=sqlite3.OperationalError("disk full")
            ):
                with self.assertRaises(sqlite3.OperationalError):
                    deployment_gate.run_gate(["alpine"])
                self.assertEqual([c.args[0] for c in docker.call_args_list], ["create", "inspect"])
        self.post_mock.assert_not_called()

    def test_post_action_persistence_failure_retains_uncertainty_without_delivery(self):
        import sqlite3
        import deployment_outbox
        fake = FakeDocker(COMPLIANT_SPEC)
        with patch.object(deployment_gate, "_docker", side_effect=fake), patch.object(
            deployment_gate, "finish_action", side_effect=sqlite3.OperationalError("disk full")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual(fake.commands, ["create", "inspect", "start"])
        self.assertEqual(self.journal(), [(CONTAINER_ID, "start", "outcome_not_recorded")])
        self.post_mock.assert_not_called()
        deployment_outbox.flush("http://unused")
        self.post_mock.assert_not_called()  # Reopening/flushing never executes or delivers intent.

    def test_failed_removal_is_not_reported_as_completed_block(self):
        fake = FakeDocker(ROOT_SPEC)

        def docker(*args):
            return completed(returncode=1, stderr="denied") if args[0] == "rm" else fake(*args)

        with patch.object(deployment_gate, "_docker", side_effect=docker):
            with self.assertRaises(deployment_gate.DockerCommandError):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual(self.journal(), [(CONTAINER_ID, "remove", "command_failed")])
        self.post_mock.assert_not_called()

    def test_failed_start_and_cleanup_have_separate_outcomes(self):
        with patch.object(deployment_gate, "_docker",
                          side_effect=FakeDocker(COMPLIANT_SPEC, start_fails=True)):
            with self.assertRaises(deployment_gate.DockerCommandError):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual(self.journal(), [
            (CONTAINER_ID, "start", "command_failed"),
            (CONTAINER_ID, "remove", "command_succeeded"),
        ])
        self.post_mock.assert_not_called()


class TestGateTimeouts(GateTestCase):
    def test_each_command_passes_its_deadline(self):
        for command, deadline in (("create", 300), ("inspect", 30), ("start", 60), ("rm", 60)):
            with self.subTest(command=command), patch.object(
                deployment_gate.subprocess, "run", return_value=completed()
            ) as run:
                deployment_gate._docker(command, "argument")
                self.assertEqual(run.call_args.kwargs["timeout"], deadline)

    def test_start_timeout_keeps_uncertainty_without_removal_or_delivery(self):
        import deployment_outbox
        from contextlib import closing
        fake = FakeDocker(COMPLIANT_SPEC)

        def docker(*args):
            if args[0] == "start":
                fake.calls.append(args)
                raise deployment_gate.DockerCommandTimeout("daemon outcome unknown")
            return fake(*args)

        with patch.object(deployment_gate, "_docker", side_effect=docker):
            with self.assertRaises(deployment_gate.DockerCommandTimeout):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual(fake.commands, ["create", "inspect", "start"])
        with closing(deployment_outbox.connect()) as db:
            self.assertEqual(db.execute("SELECT outcome FROM deployment_actions").fetchall(),
                             [("outcome_not_recorded",)])
            self.assertEqual(db.execute("SELECT count(*) FROM decisions").fetchone(), (0,))
        self.post_mock.assert_not_called()

    def test_removal_timeout_keeps_uncertainty_without_delivery(self):
        import deployment_outbox
        fake = FakeDocker(ROOT_SPEC)

        def docker(*args):
            if args[0] == "rm":
                fake.calls.append(args)
                raise deployment_gate.DockerCommandTimeout("daemon outcome unknown")
            return fake(*args)

        with patch.object(deployment_gate, "_docker", side_effect=docker):
            with self.assertRaises(deployment_gate.DockerCommandTimeout):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual(fake.commands, ["create", "inspect", "rm"])
        self.assertEqual(deployment_outbox.action_health(),
                         {"outcome_not_recorded": 1, "command_failed": 0})
        self.post_mock.assert_not_called()

    def test_create_timeout_returns_error_without_unknown_container_cleanup(self):
        with patch.object(
            deployment_gate, "_docker",
            side_effect=deployment_gate.DockerCommandTimeout("create unknown")
        ) as run:
            self.assertEqual(deployment_gate.main(["alpine"]), 2)
        self.assertEqual([c.args[0] for c in run.call_args_list], ["create"])
        self.post_mock.assert_not_called()

    def test_timeout_message_omits_sensitive_command_arguments(self):
        secret = "PASSWORD=sensitive-example"
        with patch.object(deployment_gate.subprocess, "run", side_effect=subprocess.TimeoutExpired(
            ["docker", "create", "--env", secret], 300, output=secret, stderr=secret
        )):
            with self.assertRaises(deployment_gate.DockerCommandTimeout) as raised:
                deployment_gate._docker("create", "--env", secret)
        self.assertNotIn(secret, str(raised.exception))

    def test_deadline_terminates_real_sleeping_cli_process(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as state:
            pid_file = Path(state) / "child.pid"
            program = ("import os,time,pathlib; "
                       f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                       "time.sleep(30)")

            def run_child(*args, **kwargs):
                return real_run([sys.executable, "-c", program], **kwargs)

            with patch.dict(deployment_gate.DOCKER_TIMEOUT_SECONDS, {"inspect": 0.5}), patch.object(
                deployment_gate.subprocess, "run", side_effect=run_child
            ):
                with self.assertRaises(deployment_gate.DockerCommandTimeout):
                    deployment_gate._docker("inspect", "fake-id")
            self.assertTrue(pid_file.exists(), "child must run before testing its termination")
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)


class TestCreationDurability(GateTestCase):
    def creations(self):
        from contextlib import closing
        import deployment_outbox
        with closing(deployment_outbox.connect()) as db:
            return db.execute(
                "SELECT container_id,outcome FROM creation_attempts ORDER BY rowid"
            ).fetchall()

    def test_creation_intent_precedes_command_and_full_id_precedes_inspection(self):
        fake = FakeDocker(COMPLIANT_SPEC)

        def docker(*args):
            if args[0] == "create":
                self.assertEqual(self.creations(), [(None, "outcome_not_recorded")])
            if args[0] == "inspect":
                self.assertEqual(self.creations(), [(CONTAINER_ID, "command_succeeded")])
            return fake(*args)

        with patch.object(deployment_gate, "_docker", side_effect=docker):
            deployment_gate.run_gate(["alpine"])
        self.assertEqual(self.creations(), [(CONTAINER_ID, "command_succeeded")])

    def test_intent_failure_prevents_even_docker_create(self):
        import sqlite3
        with patch.object(deployment_gate, "begin_creation",
                          side_effect=sqlite3.OperationalError("disk full")), patch.object(
            deployment_gate, "_docker"
        ) as docker:
            self.assertEqual(deployment_gate.main(["alpine"]), 2)
        docker.assert_not_called()
        self.post_mock.assert_not_called()

    def test_outcome_failure_keeps_intent_and_does_not_inspect_start_or_remove(self):
        import sqlite3
        import deployment_outbox
        fake = FakeDocker(COMPLIANT_SPEC)
        with patch.object(deployment_gate, "_docker", side_effect=fake), patch.object(
            deployment_gate, "finish_creation", side_effect=sqlite3.OperationalError("disk full")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual(fake.commands, ["create"])
        self.assertEqual(self.creations(), [(None, "outcome_not_recorded")])
        self.assertEqual(deployment_outbox.action_health()["outcome_not_recorded"], 1)
        deployment_outbox.flush("http://unused")
        self.post_mock.assert_not_called()

    def test_create_timeout_retains_unknown_attempt_without_replay(self):
        import deployment_outbox
        with patch.object(deployment_gate, "_docker",
                          side_effect=deployment_gate.DockerCommandTimeout("unknown")) as docker:
            with self.assertRaises(deployment_gate.DockerCommandTimeout):
                deployment_gate.run_gate(["alpine"])
        self.assertEqual([c.args[0] for c in docker.call_args_list], ["create"])
        self.assertEqual(self.creations(), [(None, "outcome_not_recorded")])
        deployment_outbox.flush("http://unused")
        self.assertEqual(self.creations(), [(None, "outcome_not_recorded")])
        self.post_mock.assert_not_called()

    def test_bad_create_identity_retains_uncertainty_without_guessing_cleanup_target(self):
        invalid = ("", "web", CONTAINER_ID[:12], "g" * 64,
                   CONTAINER_ID + "\n" + "a" * 64)
        for output in invalid:
            with self.subTest(output=output), patch.object(
                deployment_gate, "_docker", return_value=completed(output)
            ) as docker:
                self.assertEqual(deployment_gate.main(["alpine"]), 2)
            self.assertEqual([c.args[0] for c in docker.call_args_list], ["create"])
        self.assertEqual(self.creations(), [(None, "outcome_not_recorded")] * len(invalid))
        self.post_mock.assert_not_called()

    def test_nonzero_create_has_failed_outcome_without_policy_delivery(self):
        self.use_docker(COMPLIANT_SPEC, create_fails=True)
        with self.assertRaises(deployment_gate.DockerCommandError):
            deployment_gate.run_gate(["alpine"])
        self.assertEqual(self.creations(), [(None, "command_failed")])
        self.assertEqual(self.docker.commands, ["create"])
        self.post_mock.assert_not_called()


class TestMainExitCodes(GateTestCase):
    def test_allowed_exits_zero(self):
        self.use_docker(COMPLIANT_SPEC)
        self.assertEqual(deployment_gate.main(["alpine:3.20"]), 0)

    def test_blocked_exits_one(self):
        self.use_docker(ROOT_SPEC)
        self.assertEqual(deployment_gate.main(["alpine:3.20"]), 1)

    def test_docker_failure_exits_two(self):
        self.use_docker(COMPLIANT_SPEC, create_fails=True)
        self.assertEqual(deployment_gate.main(["nope:latest"]), 2)


class TestParseArgs(unittest.TestCase):
    def test_own_options_are_split_from_docker_arguments(self):
        options, docker_args = deployment_gate.parse_args(
            ["--override-reason", "ticket 42", "--", "-p", "80:80", "nginx"]
        )
        self.assertEqual(options.override_reason, "ticket 42")
        self.assertEqual(docker_args, ["-p", "80:80", "nginx"])

    def test_without_own_options_everything_goes_to_docker(self):
        options, docker_args = deployment_gate.parse_args(["--rm", "alpine", "--", "echo"])
        self.assertIsNone(options.override_reason)
        self.assertEqual(docker_args, ["--rm", "alpine", "--", "echo"])

    def test_leading_separator_is_dropped(self):
        options, docker_args = deployment_gate.parse_args(["--", "--name", "web", "alpine"])
        self.assertIsNone(options.override_reason)
        self.assertEqual(docker_args, ["--name", "web", "alpine"])

    def test_no_docker_arguments_is_an_error(self):
        with self.assertRaises(SystemExit):
            deployment_gate.parse_args([])

    def test_own_option_without_separator_is_an_error(self):
        with self.assertRaises(SystemExit):
            deployment_gate.parse_args(["--override-reason", "x", "alpine"])


if __name__ == "__main__":
    unittest.main()
