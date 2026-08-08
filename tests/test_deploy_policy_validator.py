"""
Tests for policy-checker/deploy_policy_validator.py

These tests use plain dict fixtures shaped like real `docker inspect`
output, so they run anywhere with no Docker daemon required. A manual
validation step against a real `docker inspect` is documented in
docs/phase2_deployment_policy_checker.md.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy-checker"))

import deploy_policy_validator as dpv  # noqa: E402


def _base_container_spec(**overrides) -> dict:
    """A clean, fully-compliant docker-inspect-shaped fixture. Pass keyword
    overrides to replace top-level keys (e.g. Config={...}) in individual
    tests."""
    spec = {
        "Id": "abc123",
        "Name": "/clean-container",
        "Config": {
            "User": "1000",
            "Image": "myapp:1.0",
        },
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "ReadonlyRootfs": True,
        },
    }
    spec.update(overrides)
    return spec


def _violation_ids(result: dpv.PolicyResult) -> list[str]:
    return [v.rule_id for v in result.violations]


class TestRootUserCheck(unittest.TestCase):
    def test_flags_empty_user(self):
        spec = _base_container_spec(Config={"User": "", "Image": "x"})
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-ROOT-USER", _violation_ids(result))

    def test_flags_explicit_root_string(self):
        spec = _base_container_spec(Config={"User": "root", "Image": "x"})
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-ROOT-USER", _violation_ids(result))

    def test_flags_uid_zero(self):
        spec = _base_container_spec(Config={"User": "0", "Image": "x"})
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-ROOT-USER", _violation_ids(result))

    def test_flags_uid_zero_with_group(self):
        spec = _base_container_spec(Config={"User": "0:0", "Image": "x"})
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-ROOT-USER", _violation_ids(result))

    def test_passes_non_root_user(self):
        spec = _base_container_spec()  # User: "1000"
        result = dpv.check_deployment_config(spec)
        self.assertNotIn("POLICY-ROOT-USER", _violation_ids(result))

    def test_missing_config_key_treated_as_root(self):
        spec = _base_container_spec()
        del spec["Config"]
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-ROOT-USER", _violation_ids(result))


class TestPrivilegedCheck(unittest.TestCase):
    def test_flags_privileged_true(self):
        spec = _base_container_spec()
        spec["HostConfig"]["Privileged"] = True
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-PRIVILEGED", _violation_ids(result))
        violation = next(v for v in result.violations if v.rule_id == "POLICY-PRIVILEGED")
        self.assertEqual(violation.severity, dpv.PolicySeverity.CRITICAL)

    def test_passes_privileged_false(self):
        spec = _base_container_spec()
        result = dpv.check_deployment_config(spec)
        self.assertNotIn("POLICY-PRIVILEGED", _violation_ids(result))


class TestExcessCapabilitiesCheck(unittest.TestCase):
    def test_flags_cap_add_present(self):
        spec = _base_container_spec()
        spec["HostConfig"]["CapAdd"] = ["SYS_ADMIN", "NET_ADMIN"]
        result = dpv.check_deployment_config(spec)
        violation = next(v for v in result.violations if v.rule_id == "POLICY-EXCESS-CAPS")
        self.assertIn("SYS_ADMIN", violation.detail)
        self.assertIn("NET_ADMIN", violation.detail)

    def test_passes_when_cap_add_is_none(self):
        spec = _base_container_spec()  # CapAdd: None
        result = dpv.check_deployment_config(spec)
        self.assertNotIn("POLICY-EXCESS-CAPS", _violation_ids(result))

    def test_passes_when_cap_add_is_empty_list(self):
        spec = _base_container_spec()
        spec["HostConfig"]["CapAdd"] = []
        result = dpv.check_deployment_config(spec)
        self.assertNotIn("POLICY-EXCESS-CAPS", _violation_ids(result))


class TestWritableRootFsCheck(unittest.TestCase):
    def test_flags_writable_rootfs(self):
        spec = _base_container_spec()
        spec["HostConfig"]["ReadonlyRootfs"] = False
        result = dpv.check_deployment_config(spec)
        self.assertIn("POLICY-WRITABLE-ROOTFS", _violation_ids(result))

    def test_passes_readonly_rootfs(self):
        spec = _base_container_spec()  # ReadonlyRootfs: True
        result = dpv.check_deployment_config(spec)
        self.assertNotIn("POLICY-WRITABLE-ROOTFS", _violation_ids(result))


class TestImageScanIntegration(unittest.TestCase):
    def test_flags_when_image_scan_has_blocking_findings(self):
        spec = _base_container_spec()
        result = dpv.check_deployment_config(spec, image_scan_has_blocking_findings=True)
        self.assertIn("POLICY-IMAGE-SCAN-BLOCKING", _violation_ids(result))
        self.assertTrue(result.should_block_deployment)

    def test_includes_scan_summary_in_detail_when_provided(self):
        spec = _base_container_spec()
        result = dpv.check_deployment_config(
            spec,
            image_scan_has_blocking_findings=True,
            image_scan_summary={"critical": 3, "secrets_found": 1},
        )
        violation = next(v for v in result.violations if v.rule_id == "POLICY-IMAGE-SCAN-BLOCKING")
        self.assertIn("critical", violation.detail)

    def test_no_violation_when_image_scan_clean(self):
        spec = _base_container_spec()
        result = dpv.check_deployment_config(spec, image_scan_has_blocking_findings=False)
        self.assertNotIn("POLICY-IMAGE-SCAN-BLOCKING", _violation_ids(result))


class TestPolicyResultDerivedProperties(unittest.TestCase):
    def test_clean_container_is_compliant(self):
        spec = _base_container_spec()
        result = dpv.check_deployment_config(spec)
        self.assertTrue(result.is_compliant)
        self.assertFalse(result.should_block_deployment)
        self.assertEqual(result.violations, [])

    def test_dirty_container_blocks_deployment(self):
        spec = _base_container_spec(Config={"User": "root", "Image": "x"})
        spec["HostConfig"]["Privileged"] = True
        result = dpv.check_deployment_config(spec)
        self.assertFalse(result.is_compliant)
        self.assertTrue(result.should_block_deployment)
        self.assertGreaterEqual(len(result.blocking_violations), 2)

    def test_medium_only_violation_does_not_block(self):
        # Only the read-only rootfs check fails (MEDIUM severity). Per the
        # project guide's "read-only where possible" wording, this is a soft
        # warning, not a hard gate, so it must NOT block deployment alone.
        spec = _base_container_spec()
        spec["HostConfig"]["ReadonlyRootfs"] = False
        result = dpv.check_deployment_config(spec)
        self.assertFalse(result.is_compliant)
        self.assertFalse(result.should_block_deployment)

    def test_summary_shape(self):
        spec = _base_container_spec()
        result = dpv.check_deployment_config(spec)
        summary = result.summary()
        self.assertEqual(summary, {
            "container": "clean-container",
            "compliant": True,
            "total_violations": 0,
            "blocking_violations": 0,
            "should_block_deployment": False,
            "violation_rule_ids": [],
        })


class TestContainerNameExtraction(unittest.TestCase):
    def test_strips_leading_slash_from_name(self):
        spec = _base_container_spec()  # Name: "/clean-container"
        result = dpv.check_deployment_config(spec)
        self.assertEqual(result.container_name, "clean-container")

    def test_falls_back_to_id_when_name_missing(self):
        spec = _base_container_spec()
        del spec["Name"]
        result = dpv.check_deployment_config(spec)
        self.assertEqual(result.container_name, "abc123")


class TestInputValidation(unittest.TestCase):
    def test_rejects_non_dict_input(self):
        with self.assertRaises(ValueError):
            dpv.check_deployment_config("not-a-dict")

    def test_rejects_none_input(self):
        with self.assertRaises(ValueError):
            dpv.check_deployment_config(None)

    def test_handles_minimal_spec_without_crashing(self):
        # Missing Config AND HostConfig entirely -- should not crash, and
        # should treat the unverifiable user as root (HIGH -> blocking).
        result = dpv.check_deployment_config({"Id": "xyz"})
        self.assertTrue(result.should_block_deployment)


if __name__ == "__main__":
    unittest.main()
