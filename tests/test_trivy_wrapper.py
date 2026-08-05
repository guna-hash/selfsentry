"""
Tests for image-scanner/trivy_wrapper.py

These tests mock subprocess.run and shutil.which so they run in CI
without a real trivy binary installed. A manual validation step against
a real trivy install is documented in docs/phase1_image_scanner.md.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "image-scanner"))

import trivy_wrapper  # noqa: E402


SAMPLE_TRIVY_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "nginx:1.25",
    "Results": [
        {
            "Target": "nginx:1.25 (debian 12.4)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "libssl3",
                    "InstalledVersion": "3.0.11-1",
                    "FixedVersion": "3.0.12-1",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSL buffer overflow",
                },
                {
                    "VulnerabilityID": "CVE-2023-5678",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "FixedVersion": "",
                    "Severity": "HIGH",
                    "Title": "curl heap overflow",
                },
            ],
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Match": "AKIA****************",
                }
            ],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Resolution": "Add a USER instruction",
                }
            ],
        }
    ],
}


def _mock_completed_process(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["trivy"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestTrivyInstalledCheck(unittest.TestCase):
    def test_raises_when_trivy_missing(self):
        with patch("trivy_wrapper.shutil.which", return_value=None):
            with self.assertRaises(trivy_wrapper.TrivyNotInstalledError):
                trivy_wrapper._check_trivy_installed()

    def test_passes_when_trivy_present(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"):
            path = trivy_wrapper._check_trivy_installed()
        self.assertEqual(path, "/usr/local/bin/trivy")


class TestRunTrivyJson(unittest.TestCase):
    def test_successful_scan_returns_parsed_json(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"), patch(
            "trivy_wrapper.subprocess.run",
            return_value=_mock_completed_process(json.dumps(SAMPLE_TRIVY_JSON)),
        ):
            raw = trivy_wrapper._run_trivy_json("nginx:1.25")
        self.assertEqual(raw["ArtifactName"], "nginx:1.25")

    def test_nonzero_exit_raises_scan_error(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"), patch(
            "trivy_wrapper.subprocess.run",
            return_value=_mock_completed_process("", returncode=1, stderr="unknown image"),
        ):
            with self.assertRaises(trivy_wrapper.TrivyScanError):
                trivy_wrapper._run_trivy_json("nonexistent:latest")

    def test_timeout_raises_scan_error(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"), patch(
            "trivy_wrapper.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=1),
        ):
            with self.assertRaises(trivy_wrapper.TrivyScanError):
                trivy_wrapper._run_trivy_json("slow-image:latest", timeout_seconds=1)

    def test_invalid_json_raises_scan_error(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"), patch(
            "trivy_wrapper.subprocess.run",
            return_value=_mock_completed_process("not json"),
        ):
            with self.assertRaises(trivy_wrapper.TrivyScanError):
                trivy_wrapper._run_trivy_json("nginx:1.25")

    def test_missing_binary_raises_not_installed_error(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"), patch(
            "trivy_wrapper.subprocess.run", side_effect=FileNotFoundError()
        ):
            with self.assertRaises(trivy_wrapper.TrivyNotInstalledError):
                trivy_wrapper._run_trivy_json("nginx:1.25")


class TestParseScanResult(unittest.TestCase):
    def test_parses_vulnerabilities_secrets_misconfigs(self):
        result = trivy_wrapper._parse_scan_result("nginx:1.25", SAMPLE_TRIVY_JSON)

        self.assertEqual(result.image, "nginx:1.25")
        self.assertEqual(len(result.vulnerabilities), 2)
        self.assertEqual(len(result.secrets), 1)
        self.assertEqual(len(result.misconfigurations), 1)

        crit = [v for v in result.vulnerabilities if v.severity == "CRITICAL"]
        self.assertEqual(crit[0].id, "CVE-2023-1234")
        self.assertEqual(crit[0].fixed_version, "3.0.12-1")

    def test_empty_results_produce_empty_lists(self):
        result = trivy_wrapper._parse_scan_result("empty:latest", {"Results": []})
        self.assertEqual(result.vulnerabilities, [])
        self.assertEqual(result.secrets, [])
        self.assertEqual(result.misconfigurations, [])

    def test_missing_results_key_does_not_crash(self):
        result = trivy_wrapper._parse_scan_result("weird:latest", {})
        self.assertEqual(result.vulnerabilities, [])


class TestScanResultDerivedProperties(unittest.TestCase):
    def test_counts_and_blocking_flag(self):
        result = trivy_wrapper._parse_scan_result("nginx:1.25", SAMPLE_TRIVY_JSON)
        self.assertEqual(result.critical_count, 1)
        self.assertEqual(result.high_count, 1)
        self.assertTrue(result.has_blocking_findings)  # critical CVE + secret present

    def test_no_blocking_findings_when_clean(self):
        clean_json = {
            "Results": [
                {
                    "Target": "clean:latest",
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Misconfigurations": [],
                }
            ]
        }
        result = trivy_wrapper._parse_scan_result("clean:latest", clean_json)
        self.assertFalse(result.has_blocking_findings)

    def test_summary_shape(self):
        result = trivy_wrapper._parse_scan_result("nginx:1.25", SAMPLE_TRIVY_JSON)
        summary = result.summary()
        self.assertEqual(summary, {
            "image": "nginx:1.25",
            "critical": 1,
            "high": 1,
            "total_vulnerabilities": 2,
            "secrets_found": 1,
            "misconfigurations_found": 1,
        })


class TestScanImagePublicApi(unittest.TestCase):
    def test_rejects_empty_image_name(self):
        with self.assertRaises(ValueError):
            trivy_wrapper.scan_image("")

    def test_rejects_whitespace_image_name(self):
        with self.assertRaises(ValueError):
            trivy_wrapper.scan_image("   ")

    def test_full_flow_with_mocked_subprocess(self):
        with patch("trivy_wrapper.shutil.which", return_value="/usr/local/bin/trivy"), patch(
            "trivy_wrapper.subprocess.run",
            return_value=_mock_completed_process(json.dumps(SAMPLE_TRIVY_JSON)),
        ):
            result = trivy_wrapper.scan_image("nginx:1.25")

        self.assertIsInstance(result, trivy_wrapper.ScanResult)
        self.assertEqual(result.critical_count, 1)
        assert result.raw["ArtifactName"] == "nginx:1.25"


if __name__ == "__main__":
    unittest.main()
