"""Tests for backend-api/routes/deployments.py (in-memory SQLite, no Docker)."""

import os
import sys
import unittest
import tempfile
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
from models.db_models import AuditEvent, Deployment, ScanResult  # noqa: E402
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
    def test_journal_replay_conflict_retains_evidence_while_next_record_reaches_api(self):
        root = Path(__file__).resolve().parents[1]
        sys.path[:0] = [str(root / "deployment-gate"), str(root / "monitor-service")]
        import deployment_outbox as outbox

        original = payload(event_key="taken")
        self.assertEqual(self.client.post("/deployments/", json=original).status_code, 201)
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"SELFSENTRY_STATE_DIR": directory}):
                outbox.enqueue({**original, "container_id": "changed"})
                outbox.enqueue(payload(event_key="new", container_id="new"))

                def transport(url, **kwargs):
                    return self.client.post("/deployments/", json=kwargs["json"])

                with patch.object(outbox.requests, "post", side_effect=transport):
                    self.assertEqual(outbox.flush("http://test"), {"pending": 0, "rejected": 1})
                db = outbox.connect()
                try:
                    self.assertEqual(
                        db.execute("SELECT key FROM decisions").fetchall(), [("taken",)]
                    )
                finally:
                    db.close()
        with self.Session() as db:
            self.assertEqual(db.query(Deployment).count(), 2)
            self.assertEqual(db.query(AuditEvent).count(), 2)

    def test_findings_without_summary_are_not_silently_discarded(self):
        result = self.client.post("/deployments/", json=payload(
            scan_summary={}, scan_findings=[{"id": "finding"}]
        ))
        self.assertEqual(result.status_code, 422)

    def test_reused_key_cannot_acknowledge_another_container_or_report(self):
        original = payload(event_key="stable")
        first = self.client.post("/deployments/", json=original)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(self.client.post("/deployments/", json=original).json(), first.json())
        for change in ({"container_id": "other"}, {"decision": "blocked"},
                       {"scan_summary": {**CLEAN_SCAN, "high": 4}},
                       {"scan_summary": {**CLEAN_SCAN, "extra": "changed"}}):
            with self.subTest(change=change):
                response = self.client.post("/deployments/", json={**original, **change})
                self.assertEqual(response.status_code, 409)
        with self.Session() as db:
            self.assertEqual(db.query(Deployment).count(), 1)
            self.assertEqual(db.query(ScanResult).count(), 1)

    def test_legacy_record_without_fingerprint_requires_matching_stored_fields(self):
        original = payload(event_key="legacy")
        first = self.client.post("/deployments/", json=original).json()
        with self.Session() as db:
            audit = db.query(AuditEvent).filter_by(event_key="legacy").one()
            audit.detail = {k: v for k, v in audit.detail.items()
                            if k not in ("request_sha256", "request_fingerprint_version")}
            db.commit()
        self.assertEqual(self.client.post("/deployments/", json=original).json(), first)
        changed = {**original, "requested_by": "different"}
        self.assertEqual(self.client.post("/deployments/", json=changed).status_code, 409)

    def test_cross_operation_or_orphan_replay_is_a_conflict(self):
        with self.Session() as db:
            db.add(AuditEvent(event_key="cross", event_type="OTHER", source="monitor",
                              detail={"deployment_id": 1, "decision": "allowed"}))
            db.add(AuditEvent(event_key="orphan", event_type="DEPLOYMENT_ALLOWED", source="gate",
                              detail={"deployment_id": 999, "decision": "allowed"}))
            db.commit()
        for key in ("cross", "orphan"):
            with self.subTest(key=key):
                result = self.client.post("/deployments/", json=payload(event_key=key))
                self.assertEqual(result.status_code, 409)

    def test_invalid_scan_counts_do_not_become_clean_history(self):
        summaries = [{"unknown": 1}, {"critical": 0}]
        summaries += [{**CLEAN_SCAN, "critical": value} for value in
                      (None, True, -1, 1.5, "0", 2147483648)]
        for summary in summaries:
            with self.subTest(summary=summary):
                response = self.client.post("/deployments/", json=payload(scan_summary=summary))
                self.assertEqual(response.status_code, 422)
        with self.Session() as db:
            self.assertEqual(db.query(ScanResult).count(), 0)
            self.assertEqual(db.query(Deployment).count(), 0)

    def test_request_matches_persisted_string_and_finding_shapes(self):
        for field, value in (
            ("event_key", ""), ("container_name", ""), ("container_name", "x" * 257),
            ("container_id", "x" * 129), ("image_name", "x" * 257),
            ("override_reason", "x" * 513), ("requested_by", "x" * 129),
            ("scan_findings", ["not a finding"]), ("policy_violations", ["not a violation"]),
        ):
            with self.subTest(field=field):
                response = self.client.post("/deployments/", json=payload(**{field: value}))
                self.assertEqual(response.status_code, 422)

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


class TestExactRegistration(DeploymentsApiTestCase):
    def test_gate_registration_remains_visible_outside_history_limit(self):
        self.client.post('/deployments/', json=payload())
        for n in range(501):
            self.client.post('/deployments/', json=payload(container_id=f'new-{n}'))
        result = self.client.get('/deployments/registration/abc123def456').json()
        self.assertTrue(result['registered'])

    def test_name_or_blocked_decision_does_not_grant_registration(self):
        self.client.post('/deployments/', json=payload(decision='blocked'))
        result = self.client.get('/deployments/registration/abc123def456').json()
        self.assertFalse(result['registered'])
        self.assertFalse(self.client.get('/deployments/registration/web').json()['registered'])


if __name__ == "__main__":
    unittest.main()
