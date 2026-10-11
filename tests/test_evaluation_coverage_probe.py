"""Tests for evaluation/coverage_probe.py (pure classification) and AlertTail.new_alerts."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

import clock_guard  # noqa: E402
import coverage_probe as cp  # noqa: E402


class Judge(unittest.TestCase):
    def test_expected_rule_fired(self):
        out = cp.judge_probe([{"rule": "Baseline Process Spawn"},
                              {"rule": "Read sensitive file untrusted"}],
                             ["Read sensitive file untrusted"])
        self.assertEqual(out["status"], "fires")
        self.assertEqual(out["fired_rules"], ["Read sensitive file untrusted"])

    def test_baseline_only_is_not_fired(self):
        out = cp.judge_probe([{"rule": "Baseline File Write"}], ["Execution from /dev/shm"])
        self.assertEqual(out["status"], "not_fired")
        self.assertFalse(out["expected_rule_fired"])

    def test_other_rule_only_is_not_counted_as_supported(self):
        out = cp.judge_probe([{"rule": "Terminal shell in container"}], ["Execution from /dev/shm"])
        self.assertEqual(out["status"], "other_rule_only")
        self.assertFalse(out["expected_rule_fired"])

    def test_every_scenario_names_expected_rules(self):
        for scenario in cp.SCENARIOS:
            self.assertTrue(scenario["expected"])
            self.assertIn(scenario["category"],
                          {"shell", "unexpected-process", "sensitive-file", "networking"})


class TailAlerts(unittest.TestCase):
    def test_new_alerts_carry_rule_and_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.json"
            path.write_text("")
            tail = clock_guard.AlertTail(path)
            tail.mark()
            path.write_text(json.dumps({"time": "2026-10-11T12:00:00.5Z", "rule": "R", "priority": "Warning",
                                        "output_fields": {"container.id": "abc123456789"}}) + "\n")
            alerts = tail.new_alerts("abc123456789")
            self.assertEqual([(a["rule"], a["priority"]) for a in alerts], [("R", "Warning")])


if __name__ == "__main__":
    unittest.main()
