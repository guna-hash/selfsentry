"""
Tests for correlation-engine/event_router.py

Pure unit tests against route_incident()'s decision logic - no live
backend, Docker, or Falco required. dispatch_incident()'s side-effecting
paths (logging, the auto_isolate stub) are tested separately with a
smaller set of smoke tests, since their job is "did the right branch
run", not "is the math right".
"""

import sys
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "correlation-engine"))

import event_router  # noqa: E402


class TestEffectiveScore(unittest.TestCase):
    def test_high_confidence_no_adjustment(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 90, "confidence": "high"}
        )
        self.assertEqual(decision.effective_score, 90)

    def test_medium_confidence_minus_ten(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 90, "confidence": "medium"}
        )
        self.assertEqual(decision.effective_score, 80)

    def test_low_confidence_minus_twenty(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 90, "confidence": "low"}
        )
        self.assertEqual(decision.effective_score, 70)

    def test_unknown_confidence_treated_as_low(self):
        # Defensive default - an unrecognized confidence string should
        # never silently grant full trust (see event_router.py docstring).
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 90, "confidence": "0.94"}
        )
        self.assertEqual(decision.effective_score, 70)

    def test_effective_score_never_negative(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 5, "confidence": "low"}
        )
        self.assertEqual(decision.effective_score, 0)

    def test_effective_score_never_exceeds_100(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 100, "confidence": "high"}
        )
        self.assertEqual(decision.effective_score, 100)


class TestRoutingTiers(unittest.TestCase):
    def test_below_40_logs_only(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 30, "confidence": "high"}
        )
        self.assertEqual(decision.actions, [event_router.ACTION_LOG])

    def test_40_to_69_gets_ai_analysis_noted(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 50, "confidence": "high"}
        )
        self.assertEqual(
            decision.actions,
            [event_router.ACTION_LOG, event_router.ACTION_AI_ANALYSIS_NOTED],
        )

    def test_70_to_89_gets_analyst_alert(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 75, "confidence": "high"}
        )
        self.assertEqual(
            decision.actions,
            [
                event_router.ACTION_LOG,
                event_router.ACTION_AI_ANALYSIS_NOTED,
                event_router.ACTION_ANALYST_ALERT,
            ],
        )
        self.assertTrue(decision.should_page_analyst)
        self.assertFalse(decision.should_isolate)

    def test_90_plus_gets_auto_isolate(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 95, "confidence": "high"}
        )
        self.assertIn(event_router.ACTION_AUTO_ISOLATE, decision.actions)
        self.assertTrue(decision.should_isolate)


class TestConfidenceGatesIsolation(unittest.TestCase):
    """
    The core "real-world" behavior requested: same raw risk_score=90
    must NOT reach auto-isolate unless confidence is high.
    """

    def test_risk_90_high_confidence_isolates(self):
        decision = event_router.route_incident(
            {"container_id": "c1", "risk_score": 90, "confidence": "high"}
        )
        self.assertTrue(decision.should_isolate)

    def test_risk_90_medium_confidence_does_not_isolate(self):
        decision = event_router.route_incident(
            {"container_id": "c2", "risk_score": 90, "confidence": "medium"}
        )
        self.assertFalse(decision.should_isolate)
        self.assertTrue(decision.should_page_analyst)  # still escalated to a human

    def test_risk_90_low_confidence_does_not_isolate(self):
        decision = event_router.route_incident(
            {"container_id": "c3", "risk_score": 90, "confidence": "low"}
        )
        self.assertFalse(decision.should_isolate)

    def test_perfect_score_low_confidence_still_cannot_isolate(self):
        # risk_score=100, confidence=low -> effective=80, still below the
        # 90 auto-isolate threshold. This is intentional: a single noisy
        # signal, however extreme, should never trigger isolation alone.
        decision = event_router.route_incident(
            {"container_id": "c4", "risk_score": 100, "confidence": "low"}
        )
        self.assertFalse(decision.should_isolate)
        self.assertTrue(decision.should_page_analyst)


class TestRouteIncidentsBatch(unittest.TestCase):
    def test_routes_a_list(self):
        incidents = [
            {"container_id": "c1", "risk_score": 20, "confidence": "high"},
            {"container_id": "c2", "risk_score": 95, "confidence": "high"},
        ]
        decisions = event_router.route_incidents(incidents)
        self.assertEqual(len(decisions), 2)
        self.assertFalse(decisions[0].should_isolate)
        self.assertTrue(decisions[1].should_isolate)


class TestDispatchIncident(unittest.TestCase):
    """
    Smoke tests for dispatch_incident() - confirms the right branches run
    and auto_isolate's NotImplementedError is caught safely rather than
    crashing the pipeline, since response-engine/auto_isolate.py is still
    a stub as of this writing.
    """

    def test_log_only_incident_dispatches_cleanly(self):
        incident = {"container_id": "c1", "risk_score": 20, "confidence": "high"}
        decision = event_router.route_incident(incident)
        results = event_router.dispatch_incident(incident, decision)
        self.assertEqual(results[event_router.ACTION_LOG], "done")

    def test_auto_isolate_success_reports_isolated(self):
        incident = {"container_id": "c1", "risk_score": 95, "confidence": "high"}
        decision = event_router.route_incident(incident)
        fake_module = MagicMock()
        with patch.object(
            event_router, "_load_auto_isolate_module", return_value=fake_module
        ):
            results = event_router.dispatch_incident(incident, decision)
        self.assertEqual(results[event_router.ACTION_AUTO_ISOLATE], "isolated")
        fake_module.isolate_container.assert_called_once()
        container_id, reason = fake_module.isolate_container.call_args.args
        self.assertEqual(container_id, "c1")
        self.assertIn("effective_score=", reason)

    def test_auto_isolate_failure_is_reported_not_raised(self):
        incident = {"container_id": "c1", "risk_score": 95, "confidence": "high"}
        decision = event_router.route_incident(incident)
        fake_module = MagicMock()
        fake_module.isolate_container.side_effect = RuntimeError("docker down")
        with patch.object(
            event_router, "_load_auto_isolate_module", return_value=fake_module
        ):
            results = event_router.dispatch_incident(incident, decision)
        self.assertEqual(
            results[event_router.ACTION_AUTO_ISOLATE],
            "isolation_failed: docker down",
        )

    def test_auto_isolate_missing_module_falls_back_to_stub(self):
        incident = {"container_id": "c1", "risk_score": 95, "confidence": "high"}
        decision = event_router.route_incident(incident)
        with patch.object(
            event_router, "_load_auto_isolate_module", return_value=None
        ):
            results = event_router.dispatch_incident(incident, decision)
        self.assertEqual(
            results[event_router.ACTION_AUTO_ISOLATE], "not_implemented_stub"
        )


if __name__ == "__main__":
    unittest.main()
