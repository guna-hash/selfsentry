"""Tests for rule-synthesis-engine/rule_deployer.py.

All file paths are redirected to a temp directory and the Falco reload is mocked,
so these tests never touch the real Falco install or the live rules file.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rule-synthesis-engine"))

import rule_deployer  # noqa: E402

VALID_RULE = (
    "- rule: Auto_Generated_Test\n"
    "  desc: test\n"
    "  condition: spawned_process\n"
    "  output: test\n"
    "  priority: WARNING\n"
)


class DeployerTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.rules_path = root / "auto-generated-rules.yaml"
        self.rules_path.write_text("# header\n")
        self.falco_yaml = root / "falco.yaml"
        self.config_dir = root / "config.d"
        self.config_dir.mkdir()
        self.set_mode("all")

        self.reload_mock = MagicMock()
        for name, value in (
            ("AUTO_GENERATED_RULES_PATH", str(self.rules_path)),
            ("FALCO_CONFIG_PATH", str(self.falco_yaml)),
            ("FALCO_CONFIG_DIR", str(self.config_dir)),
            ("_reload_falco", self.reload_mock),
        ):
            patcher = patch.object(rule_deployer, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def set_mode(self, mode):
        self.falco_yaml.write_text(f"rule_matching: {mode}\n")


class TestRuleMatchingGuard(DeployerTestCase):
    def test_mode_all_is_accepted(self):
        rule_deployer._require_rule_matching_all()

    def test_mode_first_is_refused(self):
        self.set_mode("first")
        with self.assertRaises(rule_deployer.RuleDeploymentError):
            rule_deployer._require_rule_matching_all()

    def test_missing_key_defaults_to_first_and_is_refused(self):
        self.falco_yaml.write_text("engine:\n  kind: modern_ebpf\n")
        with self.assertRaises(rule_deployer.RuleDeploymentError):
            rule_deployer._require_rule_matching_all()

    def test_config_d_can_override_to_all(self):
        self.set_mode("first")
        (self.config_dir / "zz-selfsentry.yaml").write_text("rule_matching: all\n")
        rule_deployer._require_rule_matching_all()

    def test_config_d_can_override_to_first(self):
        (self.config_dir / "zz-override.yaml").write_text("rule_matching: first\n")
        with self.assertRaises(rule_deployer.RuleDeploymentError):
            rule_deployer._require_rule_matching_all()


class TestDeployRule(DeployerTestCase):
    def test_refused_deploy_leaves_rules_file_and_falco_untouched(self):
        self.set_mode("first")
        with self.assertRaises(rule_deployer.RuleDeploymentError):
            rule_deployer.deploy_rule("r1", VALID_RULE)
        self.assertEqual(self.rules_path.read_text(), "# header\n")
        self.reload_mock.assert_not_called()

    def test_successful_deploy_appends_rule_and_reloads(self):
        self.assertTrue(rule_deployer.deploy_rule("r1", VALID_RULE))
        self.assertIn("Auto_Generated_Test", self.rules_path.read_text())
        self.reload_mock.assert_called_once()

    def test_invalid_yaml_is_rolled_back_and_not_reloaded(self):
        with self.assertRaises(rule_deployer.RuleDeploymentError):
            rule_deployer.deploy_rule("r1", "- rule: [unclosed")
        self.assertEqual(self.rules_path.read_text(), "# header\n")
        self.reload_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
