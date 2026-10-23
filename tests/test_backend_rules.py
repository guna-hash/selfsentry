"""Tests for backend-api/routes/rules.py.

Uses an in-memory SQLite database and mocks the Falco deployment, so no Postgres,
Falco, or sudo is touched.
"""

import os
import sys
import unittest
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from tests.rule_guard_support import inventory
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"  # keep the app's own engine away from Postgres
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import database  # noqa: E402
from models.db_models import ConfirmedIncident, GeneratedRule, Incident  # noqa: E402
from routes import rules as rules_module  # noqa: E402

RULE_YAML = (
    "- rule: Auto_Generated_Test_1\n"
    "  desc: test\n"
    "  condition: spawned_process\n"
    "  output: test\n"
    "  priority: WARNING\n"
)


class RulesApiTestCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.config, self.inventory_rules = inventory(temp.name)
        runtime = patch(
            "rule_deduplicator._runtime_arguments", return_value=["falco", "-c", str(self.config)]
        )
        runtime.start()
        self.addCleanup(runtime.stop)
        environment = patch.dict(
            os.environ,
            {
                "FALCO_CONFIG_PATH": str(self.config),
                "RULE_GUARD_STATE_DIR": str(Path(temp.name) / "guard"),
            },
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        self.addCleanup(self.engine.dispose)
        database.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False)

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app = FastAPI()
        app.include_router(rules_module.router)
        app.dependency_overrides[rules_module.get_db] = override_get_db
        self.client = TestClient(app)
        # Route tests use a verified corpus result; separate tests exercise real validation.
        verification = patch.object(
            rules_module,
            "_verified_backtest",
            return_value={
                "false_positive_rate": 0.02,
                "false_positives": 2,
                "true_negatives": 98,
                "events_tested": 100,
                "verdict": "pass",
                "benign_sha256": "test-corpus",
            },
        )
        verification.start()
        self.addCleanup(verification.stop)

        with self.Session() as db:
            db.add(Incident(id=1, container_id="c1", risk_score=90.0))
            db.commit()
            db.add(ConfirmedIncident(id=1, incident_id=1, confirmed_by="tester"))
            db.commit()

    def add_rule(self, status="pending_review"):
        with self.Session() as db:
            rule = GeneratedRule(
                confirmed_incident_id=1,
                rule_yaml=RULE_YAML,
                backtested_fp_rate=0.02,
                status=status,
            )
            db.add(rule)
            db.commit()
            return rule.id

    def rule_status(self, rule_id):
        with self.Session() as db:
            return db.get(GeneratedRule, rule_id).status

    def submit(self, **overrides):
        body = {"confirmed_incident_id": 1, "rule_yaml": RULE_YAML, "backtested_fp_rate": 0.02}
        body.update(overrides)
        return self.client.post("/rules/", json=body)

    def approve(self, rule_id):
        return self.client.post(f"/rules/{rule_id}/approve", params={"reviewed_by": "alice"})


class TestSubmitRule(RulesApiTestCase):
    def test_submit_creates_pending_rule_visible_in_queue(self):
        response = self.submit()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "pending_review")
        pending = self.client.get("/rules/pending").json()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["backtested_fp_rate"], 0.02)

    def test_unknown_confirmed_incident_is_404(self):
        self.assertEqual(self.submit(confirmed_incident_id=999).status_code, 404)

    def test_yaml_that_is_not_a_rule_list_is_422(self):
        self.assertEqual(self.submit(rule_yaml="just a string").status_code, 422)

    def test_malformed_yaml_is_422(self):
        self.assertEqual(self.submit(rule_yaml="- rule: [unclosed").status_code, 422)

    def test_duplicate_active_rule_for_same_incident_is_rejected(self):
        self.assertEqual(self.submit().status_code, 201)
        self.assertEqual(self.submit().json()["status"], "rejected_duplicate")

    def test_rejected_rule_can_be_resubmitted(self):
        rule_id = self.add_rule(status="rejected")
        self.assertEqual(self.rule_status(rule_id), "rejected")
        self.assertEqual(self.submit().status_code, 201)


class TestApproveRule(RulesApiTestCase):
    def test_rejection_cannot_interrupt_approval_during_native_deployment(self):
        rule_id = self.add_rule()
        entered, release = threading.Event(), threading.Event()

        def deployment(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release deployment")

        with patch.object(rules_module, "deploy_rule", side_effect=deployment), (
            ThreadPoolExecutor(max_workers=1)
        ) as pool:
            approval = pool.submit(self.approve, rule_id)
            try:
                self.assertTrue(entered.wait(5))
                rejection = self.client.post(
                    f"/rules/{rule_id}/reject",
                    params={"reviewed_by": "bob", "reason": "concurrent review"},
                )
                self.assertEqual(rejection.status_code, 409)
                self.assertIn("in progress", rejection.json()["detail"])
            finally:
                release.set()
            self.assertEqual(approval.result(timeout=5).status_code, 200)
        self.assertEqual(self.rule_status(rule_id), "deployed")

    def test_approve_deploys_and_marks_deployed(self):
        rule_id = self.add_rule()
        with patch.object(rules_module, "deploy_rule") as deploy:
            response = self.approve(rule_id)
        self.assertEqual(response.status_code, 200)
        deploy.assert_called_once_with(str(rule_id), RULE_YAML)
        self.assertEqual(self.rule_status(rule_id), "deployed")
        with self.Session() as db:
            self.assertEqual(db.get(GeneratedRule, rule_id).reviewed_by, "alice")

    def test_deployment_failure_keeps_approved_and_returns_502(self):
        rule_id = self.add_rule()
        error = rules_module.RuleDeploymentError("falco down")
        with patch.object(rules_module, "deploy_rule", side_effect=error):
            response = self.approve(rule_id)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(self.rule_status(rule_id), "approved")

    def test_retry_after_failed_deployment_succeeds(self):
        rule_id = self.add_rule()
        error = rules_module.RuleDeploymentError("falco down")
        with patch.object(rules_module, "deploy_rule", side_effect=[error, None]):
            self.assertEqual(self.approve(rule_id).status_code, 502)
            self.assertEqual(self.approve(rule_id).status_code, 200)
        self.assertEqual(self.rule_status(rule_id), "deployed")

    def test_already_deployed_rule_is_409_and_not_redeployed(self):
        rule_id = self.add_rule(status="deployed")
        with patch.object(rules_module, "deploy_rule") as deploy:
            self.assertEqual(self.approve(rule_id).status_code, 409)
        deploy.assert_not_called()

    def test_rejected_rule_cannot_be_approved(self):
        rule_id = self.add_rule(status="rejected")
        with patch.object(rules_module, "deploy_rule") as deploy:
            self.assertEqual(self.approve(rule_id).status_code, 409)
        deploy.assert_not_called()

    def test_missing_rule_is_404(self):
        self.assertEqual(self.approve(999).status_code, 404)


class TestRejectRule(RulesApiTestCase):
    def reject(self, rule_id):
        return self.client.post(
            f"/rules/{rule_id}/reject", params={"reviewed_by": "alice", "reason": "too broad"}
        )

    def test_reject_pending_rule_never_deploys(self):
        rule_id = self.add_rule()
        with patch.object(rules_module, "deploy_rule") as deploy:
            self.assertEqual(self.reject(rule_id).status_code, 200)
        deploy.assert_not_called()
        self.assertEqual(self.rule_status(rule_id), "rejected")

    def test_deployed_rule_cannot_be_rejected(self):
        rule_id = self.add_rule(status="deployed")
        self.assertEqual(self.reject(rule_id).status_code, 409)


class TestRetireRule(RulesApiTestCase):
    def test_native_refire_is_retained_even_after_database_retirement(self):
        from models.db_models import AuditEvent

        rule_id = self.add_rule(status="retired")
        with self.Session() as db:
            rules_module.record_native_refires(db, db.get(Incident, 1), {
                "falco_alert": {"rule": "Auto_Generated_Test_1", "container_id": "c1"},
            })
            db.commit()
            audit = db.query(AuditEvent).filter(AuditEvent.event_type == "RULE_NATIVE_REFIRE").one()
            self.assertEqual(audit.detail["rule_id"], rule_id)
            self.assertEqual(audit.detail["recorded_rule_status"], "retired")

    def test_retirement_is_audited_without_claiming_native_unloading(self):
        from models.db_models import AuditEvent

        rule_id = self.add_rule(status="deployed")
        with patch.object(rules_module, "deploy_rule") as deploy:
            response = self.client.post(
                f"/rules/{rule_id}/deprecate", params={"reviewed_by": "alice"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["native_rule_unloaded"])
        deploy.assert_not_called()
        with self.Session() as db:
            self.assertEqual(db.get(GeneratedRule, rule_id).status, "retired")
            audit = db.query(AuditEvent).filter(AuditEvent.event_type == "RULE_RETIRED").one()
            self.assertEqual(audit.detail["reviewed_by"], "alice")
            self.assertFalse(audit.detail["native_rule_unloaded"])

    def test_retirement_requires_an_explicit_human_reviewer(self):
        rule_id = self.add_rule(status="deployed")
        for actor in ("", " ", "selfsentry-auto"):
            response = self.client.post(
                f"/rules/{rule_id}/deprecate", params={"reviewed_by": actor}
            )
            self.assertEqual(response.status_code, 422)
        self.assertEqual(self.rule_status(rule_id), "deployed")

    def test_repeated_retirement_does_not_rewrite_the_first_reviewer(self):
        from models.db_models import AuditEvent

        rule_id = self.add_rule(status="deployed")
        for actor in ("alice", "bob"):
            response = self.client.post(
                f"/rules/{rule_id}/deprecate", params={"reviewed_by": actor}
            )
            self.assertEqual(response.status_code, 200)
        with self.Session() as db:
            self.assertEqual(db.get(GeneratedRule, rule_id).reviewed_by, "alice")
            self.assertEqual(
                db.query(AuditEvent).filter(AuditEvent.event_type == "RULE_RETIRED").count(), 1
            )


class TestReviewQueueListing(RulesApiTestCase):
    def test_approved_but_undeployed_rule_stays_in_queue_for_retry(self):
        rule_id = self.add_rule(status="approved")
        queue = self.client.get("/rules/pending").json()
        self.assertEqual([r["id"] for r in queue], [rule_id])

    def test_deployed_and_rejected_rules_are_not_in_queue(self):
        self.add_rule(status="deployed")
        self.add_rule(status="rejected")
        self.assertEqual(self.client.get("/rules/pending").json(), [])


if __name__ == "__main__":
    unittest.main()


class TestMonitorRuleSafety(RulesApiTestCase):
    def test_failed_backtest_is_not_deployable(self):
        self.assertEqual(self.submit(backtested_fp_rate=0.051).status_code, 422)

    def test_automatic_confirmation_is_not_human_rule_approval(self):
        rule_id = self.add_rule()
        with patch.object(rules_module, "deploy_rule") as deploy:
            response = self.client.post(
                f"/rules/{rule_id}/approve", params={"reviewed_by": "selfsentry-auto"}
            )
        self.assertEqual(response.status_code, 422)
        deploy.assert_not_called()

    def test_deployment_failure_is_audited(self):
        from models.db_models import AuditEvent

        rule_id = self.add_rule()
        with patch.object(
            rules_module, "deploy_rule", side_effect=rules_module.RuleDeploymentError("down")
        ):
            self.approve(rule_id)
        with self.Session() as db:
            events = db.query(AuditEvent).all()
            self.assertIn("RULE_DEPLOYMENT_FAILED", [e.event_type for e in events])


class TestCandidateRecovery(RulesApiTestCase):
    def test_deployed_candidate_is_found_after_a_lost_submission_response(self):
        rule_id = self.add_rule(status="deployed")
        response = self.client.get("/rules/for-confirmed/1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], rule_id)
        self.assertEqual(response.json()["status"], "deployed")


class TestZeroDuplicationGuard(RulesApiTestCase):
    def manual_rule(self):
        self.inventory_rules.write_text(self.inventory_rules.read_text() + RULE_YAML)

    def test_manual_duplicate_rejected_audited_and_excluded_from_queue(self):
        self.manual_rule()
        with patch.object(rules_module, "_verified_backtest") as backtest:
            result = self.submit().json()
        self.assertEqual(result["status"], "rejected_duplicate")
        self.assertIn("Auto_Generated_Test_1", result["rejection_reason"])
        backtest.assert_not_called()
        self.assertEqual(self.client.get("/rules/pending").json(), [])
        history = self.client.get("/rules/history").json()[0]
        self.assertEqual(history["rejection_reason"], result["rejection_reason"])
        self.assertEqual(history["lifecycle_events"][0]["event_type"], "RULE_DUPLICATE_REJECTED")
        with patch.object(rules_module, "deploy_rule") as deploy:
            self.assertEqual(self.approve(result["id"]).status_code, 409)
        deploy.assert_not_called()

    def test_preflight_records_rejection_without_running_backtest(self):
        self.manual_rule()
        result = self.client.post(
            "/rules/preflight",
            json={
                "confirmed_incident_id": 1,
                "rule_yaml": RULE_YAML,
                "backtested_fp_rate": 0,
            },
        )
        self.assertEqual(result.json()["status"], "rejected_duplicate")
        self.assertEqual(self.client.get("/rules/pending").json(), [])

    def test_manual_rule_added_after_submission_blocks_human_approval(self):
        result = self.submit().json()
        self.manual_rule()
        with patch.object(rules_module, "deploy_rule") as deploy:
            response = self.approve(result["id"])
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.rule_status(result["id"]), "rejected_duplicate")
        deploy.assert_not_called()

    def test_prior_deployment_remains_protected_after_retirement(self):
        self.add_rule(status="retired")
        result = self.submit(rule_yaml=RULE_YAML.replace("Test_1", "Renamed_2")).json()
        self.assertEqual(result["status"], "rejected_duplicate")

    def test_cross_incident_duplicate_cannot_be_queued(self):
        with self.Session() as db:
            db.add(ConfirmedIncident(id=2, incident_id=1, confirmed_by="tester"))
            db.commit()
        self.assertEqual(self.submit().json()["status"], "pending_review")
        self.assertEqual(
            self.submit(confirmed_incident_id=2).json()["status"], "rejected_duplicate"
        )
        self.assertEqual(len(self.client.get("/rules/pending").json()), 1)

    def test_unavailable_inventory_fails_closed_before_backtest(self):
        self.config.unlink()
        with patch.object(rules_module, "_verified_backtest") as backtest:
            result = self.submit()
        self.assertEqual(result.status_code, 503)
        backtest.assert_not_called()
        self.assertEqual(self.client.get("/rules/history").json(), [])

    def test_deployment_boundary_rejection_persists_terminal_reason(self):
        result = self.submit().json()
        with patch.object(
            rules_module,
            "deploy_rule",
            side_effect=rules_module.DuplicateRule(
                "Near-duplicate of existing rule: Admin", "Admin"
            ),
        ):
            response = self.approve(result["id"])
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.rule_status(result["id"]), "rejected_duplicate")
        self.assertIn("Admin", self.client.get("/rules/history").json()[0]["rejection_reason"])
