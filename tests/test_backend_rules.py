"""Tests for backend-api/routes/rules.py.

Uses an in-memory SQLite database and mocks the Falco deployment, so no Postgres,
Falco, or sudo is touched.
"""

import os
import sys
import unittest
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

        with self.Session() as db:
            db.add(Incident(id=1, container_id="c1", risk_score=90.0))
            db.commit()
            db.add(ConfirmedIncident(id=1, incident_id=1, confirmed_by="tester"))
            db.commit()

    def add_rule(self, status="pending_review"):
        with self.Session() as db:
            rule = GeneratedRule(
                confirmed_incident_id=1, rule_yaml=RULE_YAML,
                backtested_fp_rate=0.02, status=status,
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

    def test_duplicate_active_rule_for_same_incident_is_409(self):
        self.assertEqual(self.submit().status_code, 201)
        self.assertEqual(self.submit().status_code, 409)

    def test_rejected_rule_can_be_resubmitted(self):
        rule_id = self.add_rule(status="rejected")
        self.assertEqual(self.rule_status(rule_id), "rejected")
        self.assertEqual(self.submit().status_code, 201)


class TestApproveRule(RulesApiTestCase):
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
