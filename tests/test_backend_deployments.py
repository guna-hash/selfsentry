"""Tests for backend-api/routes/deployments.py (in-memory SQLite, no Docker)."""

import os
import sys
import unittest
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"  # keep the app's own engine away from Postgres
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import database  # noqa: E402
from models.db_models import ScanResult  # noqa: E402
from routes import deployments as deployments_module  # noqa: E402

CLEAN_SCAN = {
    "image": "alpine:3.20", "critical": 0, "high": 0, "total_vulnerabilities": 0,
    "secrets_found": 0, "misconfigurations_found": 0,
}


def payload(**overrides):
    body = {
        "container_name": "web",
        "container_id": "abc123def456",
        "image_name": "alpine:3.20",
        "decision": "allowed",
        "requested_by": "alice",
        "scan_summary": CLEAN_SCAN,
        "scan_findings": [],
        "policy_summary": {"should_block_deployment": False},
        "policy_violations": [],
    }
    body.update(overrides)
    return body


class DeploymentsApiTestCase(unittest.TestCase):
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
        app.include_router(deployments_module.router)
        app.dependency_overrides[deployments_module.get_db] = override_get_db
        self.client = TestClient(app)


class TestRecordDeployment(DeploymentsApiTestCase):
    def test_allowed_deployment_is_stored_with_its_scan(self):
        response = self.client.post("/deployments/", json=payload())
        self.assertEqual(response.status_code, 201)
        with self.Session() as db:
            self.assertEqual(db.query(ScanResult).count(), 1)
        item = self.client.get("/deployments/").json()[0]
        self.assertEqual(item["decision"], "allowed")
        self.assertEqual(item["scan"]["critical"], 0)
        self.assertEqual(item["requested_by"], "alice")

    def test_blocked_deployment_keeps_violations_and_findings(self):
        violation = {"rule_id": "POLICY-ROOT-USER", "title": "Container runs as root",
                     "severity": "HIGH", "detail": "d", "remediation": "r"}
        finding = {"id": "CVE-2026-0001", "package": "openssl", "severity": "CRITICAL"}
        body = payload(
            decision="blocked",
            scan_summary={**CLEAN_SCAN, "critical": 20},
            scan_findings=[finding],
            policy_violations=[violation],
        )
        self.assertEqual(self.client.post("/deployments/", json=body).status_code, 201)
        item = self.client.get("/deployments/").json()[0]
        self.assertEqual(item["decision"], "blocked")
        self.assertEqual(item["policy_violations"][0]["rule_id"], "POLICY-ROOT-USER")
        self.assertEqual(item["scan"]["critical"], 20)
        self.assertEqual(item["scan"]["top_findings"][0]["id"], "CVE-2026-0001")

    def test_failed_scan_is_stored_without_a_scan_row(self):
        body = payload(decision="blocked", scan_summary={})
        self.assertEqual(self.client.post("/deployments/", json=body).status_code, 201)
        with self.Session() as db:
            self.assertEqual(db.query(ScanResult).count(), 0)
        self.assertIsNone(self.client.get("/deployments/").json()[0]["scan"])

    def test_override_requires_a_reason(self):
        body = payload(decision="overridden")
        self.assertEqual(self.client.post("/deployments/", json=body).status_code, 422)
        body = payload(decision="overridden", override_reason="ticket 42")
        self.assertEqual(self.client.post("/deployments/", json=body).status_code, 201)

    def test_unknown_decision_is_rejected(self):
        body = payload(decision="maybe")
        self.assertEqual(self.client.post("/deployments/", json=body).status_code, 422)


class TestListDeployments(DeploymentsApiTestCase):
    def test_newest_first(self):
        for name in ("first", "second", "third"):
            self.client.post("/deployments/", json=payload(container_name=name))
        names = [d["container_name"] for d in self.client.get("/deployments/").json()]
        self.assertEqual(names, ["third", "second", "first"])


if __name__ == "__main__":
    unittest.main()
