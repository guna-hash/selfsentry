"""Tests for backend-api/routes/audit.py (in-memory SQLite)."""

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
from models.db_models import AuditEvent  # noqa: E402
from routes import audit as audit_module  # noqa: E402


def payload(**overrides):
    body = {
        "event_type": "UNAPPROVED_CONTAINER_START",
        "severity": "warning",
        "event_key": "key-1",
        "container_id": "abc123def456",
        "container_name": "stray",
        "image_name": "nginx:latest",
        "detail": {"registration_status": "unregistered"},
        "occurred_at": "2026-10-09T10:00:00+00:00",
    }
    body.update(overrides)
    return body


class AuditApiTestCase(unittest.TestCase):
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
        app.include_router(audit_module.router)
        app.dependency_overrides[audit_module.get_db] = override_get_db
        self.client = TestClient(app)


class TestRecordAuditEvent(AuditApiTestCase):
    def test_event_is_stored_and_listed_with_an_explicit_utc_time(self):
        self.assertEqual(self.client.post("/audit/", json=payload()).status_code, 201)
        item = self.client.get("/audit/").json()[0]
        self.assertEqual(item["event_type"], "UNAPPROVED_CONTAINER_START")
        self.assertEqual(item["detail"]["registration_status"], "unregistered")
        self.assertEqual(item["occurred_at"], "2026-10-09T10:00:00Z")

    def test_repeating_an_event_key_does_not_create_a_second_row(self):
        self.client.post("/audit/", json=payload())
        response = self.client.post("/audit/", json=payload())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["duplicate"])
        with self.Session() as db:
            self.assertEqual(db.query(AuditEvent).count(), 1)

    def test_events_without_a_key_are_always_stored(self):
        self.client.post("/audit/", json=payload(event_key=None))
        self.client.post("/audit/", json=payload(event_key=None))
        with self.Session() as db:
            self.assertEqual(db.query(AuditEvent).count(), 2)

    def test_unknown_severity_is_rejected(self):
        self.assertEqual(
            self.client.post("/audit/", json=payload(severity="catastrophic")).status_code, 422
        )


class TestListAuditEvents(AuditApiTestCase):
    def test_newest_first_and_filterable(self):
        self.client.post("/audit/", json=payload(event_key="a", event_type="CONTAINER_STARTED"))
        self.client.post("/audit/", json=payload(event_key="b", event_type="CONTAINER_STOPPED"))
        types = [e["event_type"] for e in self.client.get("/audit/").json()]
        self.assertEqual(types, ["CONTAINER_STOPPED", "CONTAINER_STARTED"])
        only = self.client.get("/audit/", params={"event_type": "CONTAINER_STARTED"}).json()
        self.assertEqual([e["event_type"] for e in only], ["CONTAINER_STARTED"])

    def test_filter_by_container(self):
        self.client.post("/audit/", json=payload(event_key="a", container_id="aaa"))
        self.client.post("/audit/", json=payload(event_key="b", container_id="bbb"))
        items = self.client.get("/audit/", params={"container_id": "bbb"}).json()
        self.assertEqual([e["container_id"] for e in items], ["bbb"])


if __name__ == "__main__":
    unittest.main()
