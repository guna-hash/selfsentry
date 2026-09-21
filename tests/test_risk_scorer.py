"""
Tests for correlation-engine/risk_scorer.py

Fully synthetic shape #1 (Falco alert) and shape #2 (anomaly event) dicts -
no live Falco/model required. Verifies matching, scoring, and confidence
tiering against the REAL backend-compatible output shape (container_id,
risk_score, confidence, falco_alert, anomaly_features - no incident_id,
no dual_layer_agreement, no status - see docs/interfaces.md).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "correlation-engine"))

from risk_scorer import compute_risk_score  # noqa: E402


def falco(container_id="c1", timestamp="2026-08-16T10:00:00Z", priority="WARNING"):
    return {"container_id": container_id, "timestamp": timestamp, "priority": priority,
            "rule": "test rule", "output": "test output"}


def anomaly(container_id="c1", timestamp="2026-08-16T10:00:00Z", score=0.5):
    return {"container_id": container_id, "timestamp": timestamp, "anomaly_score": score}


class TestOutputShape(unittest.TestCase):
    def test_output_has_exactly_the_real_backend_fields(self):
        result = compute_risk_score([falco()], [])
        self.assertEqual(
            set(result[0].keys()),
            {"container_id", "risk_score", "confidence", "falco_alert", "anomaly_features"},
        )

    def test_no_incident_id_dual_layer_or_status_fields(self):
        result = compute_risk_score([falco()], [anomaly()])
        for forbidden in ("incident_id", "dual_layer_agreement", "status"):
            self.assertNotIn(forbidden, result[0])


class TestMatching(unittest.TestCase):
    def test_matches_same_container_within_window(self):
        result = compute_risk_score(
            [falco(timestamp="2026-08-16T10:00:00Z")],
            [anomaly(timestamp="2026-08-16T10:00:30Z")],  # 30s apart, within 60s window
        )
        self.assertEqual(len(result), 1)
        self.assertIsNotNone(result[0]["anomaly_features"])
        self.assertEqual(result[0]["confidence"], "high")

    def test_does_not_match_outside_window(self):
        result = compute_risk_score(
            [falco(timestamp="2026-08-16T10:00:00Z")],
            [anomaly(timestamp="2026-08-16T10:05:00Z")],  # 5 min apart, outside 60s window
        )
        self.assertEqual(len(result), 2)  # two separate, unmatched incidents

    def test_does_not_match_different_containers(self):
        result = compute_risk_score([falco(container_id="c1")], [anomaly(container_id="c2")])
        self.assertEqual(len(result), 2)
        self.assertIsNone(result[0]["anomaly_features"])
        self.assertIsNone(result[1]["falco_alert"])

    def test_each_anomaly_event_claimed_at_most_once(self):
        # Two Falco alerts, same container, both within window of ONE anomaly event -
        # only the first should claim it; the second falls back to Falco-only.
        result = compute_risk_score(
            [falco(timestamp="2026-08-16T10:00:00Z"), falco(timestamp="2026-08-16T10:00:05Z")],
            [anomaly(timestamp="2026-08-16T10:00:02Z")],
        )
        matched_count = sum(1 for inc in result if inc["anomaly_features"] is not None)
        self.assertEqual(matched_count, 1)


class TestScoring(unittest.TestCase):
    def test_dual_layer_scores_higher_than_falco_only(self):
        dual = compute_risk_score([falco(priority="WARNING")], [anomaly(score=0.9)])
        falco_only = compute_risk_score([falco(priority="WARNING", container_id="c9")], [])
        self.assertGreater(dual[0]["risk_score"], falco_only[0]["risk_score"])

    def test_falco_only_scores_higher_than_anomaly_only_for_same_strength(self):
        falco_only = compute_risk_score([falco(priority="WARNING")], [])
        anomaly_only = compute_risk_score([], [anomaly(score=0.4, container_id="c9")])
        self.assertGreater(falco_only[0]["risk_score"], anomaly_only[0]["risk_score"])

    def test_score_capped_at_100(self):
        result = compute_risk_score([falco(priority="EMERGENCY")], [anomaly(score=1.0)])
        self.assertLessEqual(result[0]["risk_score"], 100)

    def test_unknown_falco_priority_uses_default_score(self):
        result = compute_risk_score([falco(priority="TOTALLY_MADE_UP")], [])
        self.assertEqual(result[0]["risk_score"], 30)  # DEFAULT_FALCO_SCORE


class TestConfidenceTiering(unittest.TestCase):
    def test_dual_layer_is_high(self):
        result = compute_risk_score([falco(priority="NOTICE")], [anomaly(score=0.1)])
        self.assertEqual(result[0]["confidence"], "high")

    def test_strong_falco_alone_is_medium(self):
        result = compute_risk_score([falco(priority="CRITICAL")], [])
        self.assertEqual(result[0]["confidence"], "medium")

    def test_weak_falco_alone_is_low(self):
        result = compute_risk_score([falco(priority="NOTICE")], [])
        self.assertEqual(result[0]["confidence"], "low")

    def test_strong_anomaly_alone_is_medium(self):
        result = compute_risk_score([], [anomaly(score=0.85)])
        self.assertEqual(result[0]["confidence"], "medium")

    def test_weak_anomaly_alone_is_low(self):
        result = compute_risk_score([], [anomaly(score=0.3)])
        self.assertEqual(result[0]["confidence"], "low")


class TestNeverDropsUnmatchedEvents(unittest.TestCase):
    def test_unmatched_anomaly_becomes_its_own_incident(self):
        # This is the "catch novel attacks with no matching rule" guarantee.
        result = compute_risk_score([], [anomaly(score=0.95)])
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0]["falco_alert"])
        self.assertIsNotNone(result[0]["anomaly_features"])


if __name__ == "__main__":
    unittest.main()
