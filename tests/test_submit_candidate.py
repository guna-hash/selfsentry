"""Tests for rule-synthesis-engine/submit_candidate.py.

The backend, confirmation, pattern extraction and backtesting are mocked; the Jinja2
rule generation is real. No network, Falco or Postgres is touched.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rule-synthesis-engine"))

import submit_candidate  # noqa: E402

PATTERN = {"proc_name": "whoami", "parent_proc": "sh", "action": "spawned_process"}
PASS_RESULT = {
    "false_positive_rate": 0.02, "matched_events": 2, "events_tested": 100, "verdict": "pass",
}
FLAGGED_RESULT = {
    "false_positive_rate": 0.4, "matched_events": 40, "events_tested": 100,
    "verdict": "flag_for_revision",
}


class SubmitCandidateTestCase(unittest.TestCase):
    def setUp(self):
        self.confirm = self.start_patch("confirm_incident")
        self.confirm.return_value = {"status": "confirmed", "confirmed_incident_id": 3}
        self.start_patch("extract_pattern").return_value = PATTERN
        self.backtest = self.start_patch("backtest_rule")
        self.backtest.return_value = PASS_RESULT
        self.requests = self.start_patch("requests")
        self.requests.get.return_value.json.return_value = {"id": 28, "container_id": "c1"}
        self.requests.post.return_value.status_code = 201
        self.requests.post.return_value.json.return_value = {"id": 7, "status": "pending_review"}

    def start_patch(self, name):
        patcher = patch.object(submit_candidate, name)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def run_submit(self, **kwargs):
        return submit_candidate.submit_candidate(
            28, "guna", events=[{"rule": "Baseline Process Spawn"}], **kwargs
        )


class TestSubmitCandidate(SubmitCandidateTestCase):
    def test_passing_candidate_is_queued_for_review(self):
        result = self.run_submit()
        self.assertEqual(result["rule_id"], 7)
        self.assertEqual(result["status"], "pending_review")
        payload = self.requests.post.call_args.kwargs["json"]
        self.assertEqual(payload["confirmed_incident_id"], 3)
        self.assertEqual(payload["backtested_fp_rate"], 0.02)
        self.assertIn("whoami", payload["rule_yaml"])

    def test_flagged_candidate_is_refused_and_not_posted(self):
        self.backtest.return_value = FLAGGED_RESULT
        with self.assertRaises(submit_candidate.SubmissionError):
            self.run_submit()
        self.requests.post.assert_not_called()

    def test_flagged_candidate_can_be_queued_with_explicit_override(self):
        self.backtest.return_value = FLAGGED_RESULT
        result = self.run_submit(allow_flagged=True)
        self.assertEqual(result["status"], "pending_review")

    def test_zero_events_tested_is_refused(self):
        self.backtest.return_value = {**PASS_RESULT, "events_tested": 0}
        with self.assertRaises(submit_candidate.SubmissionError):
            self.run_submit()
        self.requests.post.assert_not_called()

    def test_missing_confirmed_incident_id_is_refused(self):
        self.confirm.return_value = {"status": "confirmed"}
        with self.assertRaises(submit_candidate.SubmissionError):
            self.run_submit()
        self.requests.get.assert_not_called()

    def test_backend_rejection_is_reported(self):
        self.requests.post.return_value = MagicMock(status_code=409, text="duplicate")
        with self.assertRaises(submit_candidate.SubmissionError):
            self.run_submit()


if __name__ == "__main__":
    unittest.main()
