"""Tests for deployment-gate/deployment_gate.py.

Docker is faked, the Trivy scan is mocked, the backend POST is mocked. The policy checker
is the real one, so these tests exercise the real allow/block rules.
"""

import json
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

CONTAINER_ID = "abc123def4560000"

COMPLIANT_SPEC = {
    "Id": CONTAINER_ID,
    "Name": "/web",
    "Config": {"User": "1000:1000", "Image": "alpine:3.20"},
    "HostConfig": {"Privileged": False, "CapAdd": None, "ReadonlyRootfs": True},
}
ROOT_SPEC = {
    "Id": CONTAINER_ID,
    "Name": "/web",
    "Config": {"User": "", "Image": "alpine:3.20"},
    "HostConfig": {"Privileged": False, "CapAdd": None, "ReadonlyRootfs": True},
}


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


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
            id="CVE-2026-0001", pkg_name="openssl", installed_version="1.0",
            fixed_version="1.1", severity="CRITICAL",
        )
    )
    return scan


class GateTestCase(unittest.TestCase):
    def setUp(self):
        self.docker = None
        self.scan = patch.object(deployment_gate, "scan_image", return_value=clean_scan())
        self.scan_mock = self.scan.start()
        self.addCleanup(self.scan.stop)
        self.post = patch.object(deployment_gate.requests, "post")
        self.post_mock = self.post.start()
        self.addCleanup(self.post.stop)
        self.post_mock.return_value = MagicMock(status_code=201, text="")

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

    def test_no_docker_arguments_is_an_error(self):
        with self.assertRaises(SystemExit):
            deployment_gate.parse_args([])

    def test_own_option_without_separator_is_an_error(self):
        with self.assertRaises(SystemExit):
            deployment_gate.parse_args(["--override-reason", "x", "alpine"])


if __name__ == "__main__":
    unittest.main()
