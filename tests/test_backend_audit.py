"""Tests for backend-api/routes/audit.py (in-memory SQLite)."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"  # keep the app's own engine away from Postgres
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))

from fastapi import FastAPI  # noqa: E402
from fastapi import Response  # noqa: E402
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
    def test_schema_lengths_and_empty_keys_are_rejected_before_insert(self):
        for field, value in (
            ("event_type", ""), ("event_type", "x" * 65), ("source", "x" * 65),
            ("event_key", ""), ("event_key", "x" * 129),
            ("container_id", "x" * 129), ("container_name", "x" * 257),
            ("image_name", "x" * 257),
        ):
            with self.subTest(field=field, length=len(value)):
                response = self.client.post("/audit/", json=payload(**{field: value}))
                self.assertEqual(response.status_code, 422)
        with self.Session() as db:
            self.assertEqual(db.query(AuditEvent).count(), 0)

    def test_competing_insert_is_acknowledged_after_unique_constraint_conflict(self):
        # Both requests passed their initial lookup; the other commits first.
        with self.Session() as db:
            commit = db.commit

            def competing_commit():
                with self.Session() as other:
                    other.add(AuditEvent(event_key="raced", event_type="CONTAINER_STARTED"))
                    other.commit()
                commit()

            response = Response()
            with patch.object(db, "commit", side_effect=competing_commit):
                result = audit_module.record_audit_event(
                    audit_module.AuditEventIn(
                        event_key="raced", event_type="CONTAINER_STARTED"
                    ), response, db,
                )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(result["duplicate"])
            self.assertEqual(db.query(AuditEvent).count(), 1)
            self.assertEqual(result["id"], db.query(AuditEvent).one().id)

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
            self.client.post(
                "/audit/", json=payload(severity="catastrophic")
            ).status_code,
            422,
        )


class TestListAuditEvents(AuditApiTestCase):
    def test_newest_first_and_filterable(self):
        self.client.post(
            "/audit/", json=payload(event_key="a", event_type="CONTAINER_STARTED")
        )
        self.client.post(
            "/audit/", json=payload(event_key="b", event_type="CONTAINER_STOPPED")
        )
        types = [e["event_type"] for e in self.client.get("/audit/").json()]
        self.assertEqual(types, ["CONTAINER_STOPPED", "CONTAINER_STARTED"])
        only = self.client.get(
            "/audit/", params={"event_type": "CONTAINER_STARTED"}
        ).json()
        self.assertEqual([e["event_type"] for e in only], ["CONTAINER_STARTED"])

    def test_filter_by_container(self):
        self.client.post("/audit/", json=payload(event_key="a", container_id="aaa"))
        self.client.post("/audit/", json=payload(event_key="b", container_id="bbb"))
        items = self.client.get("/audit/", params={"container_id": "bbb"}).json()
        self.assertEqual([e["container_id"] for e in items], ["bbb"])

    def test_exact_id_search_reaches_events_outside_latest_page(self):
        for index in range(205):
            self.client.post("/audit/", json=payload(event_key=f"lookup-{index}"))
        self.assertNotIn(1, [item["id"] for item in self.client.get("/audit/").json()])
        found = self.client.get("/audit/", params={"event_id": 1}).json()
        self.assertEqual([item["id"] for item in found], [1])
        self.assertEqual(
            self.client.get("/audit/", params={"event_id": 9999}).json(), []
        )

    def test_cursor_pages_remain_stable_as_new_events_arrive(self):
        for index in range(5):
            self.client.post("/audit/", json=payload(event_key=f"page-{index}"))
        first = self.client.get("/audit/", params={"limit": 2}).json()
        self.assertEqual([item["id"] for item in first], [5, 4])
        self.client.post("/audit/", json=payload(event_key="arrived-later"))
        older = self.client.get("/audit/", params={"limit": 2, "before_id": 4}).json()
        self.assertEqual([item["id"] for item in older], [3, 2])

    def test_cursor_filters_combine_and_ids_are_validated(self):
        self.client.post(
            "/audit/", json=payload(event_key="a", event_type="CONTAINER_RESUMED")
        )
        self.client.post(
            "/audit/", json=payload(event_key="b", event_type="RULE_NATIVE_REFIRE")
        )
        self.client.post(
            "/audit/", json=payload(event_key="c", event_type="CONTAINER_RESUMED")
        )
        found = self.client.get(
            "/audit/",
            params={
                "event_type": "CONTAINER_RESUMED",
                "before_id": 3,
            },
        ).json()
        self.assertEqual([item["id"] for item in found], [1])
        for param in ("event_id", "before_id"):
            for value in (0, -1, "invalid"):
                self.assertEqual(
                    self.client.get("/audit/", params={param: value}).status_code, 422
                )


if __name__ == "__main__":
    unittest.main()


class TestAuditReplayIdentity(AuditApiTestCase):
    def test_changed_identity_fields_conflict_without_replacing_original(self):
        changes = {
            'event_type': 'PRIVATE_CHANGED', 'severity': 'critical', 'source': 'operator',
            'container_id': 'b' * 64, 'container_name': 'private-name',
            'image_name': 'private-image', 'detail': {'private': 'changed'},
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                original = payload(event_key='identity-' + field)
                created = self.client.post('/audit/', json=original)
                original_row = self.client.get('/audit/', params={
                    'event_id': created.json()['id']}).json()[0]
                response = self.client.post('/audit/', json={**original, field: value})
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json(), {
                    'detail': 'Audit event key identifies different data'})
                stored = self.client.get('/audit/', params={
                    'event_id': created.json()['id']}).json()[0]
                self.assertEqual(stored, original_row)

    def test_mapping_order_is_irrelevant_but_boolean_is_not_integer(self):
        first = payload(detail={'a': 1, 'b': {'x': 2, 'y': 3}})
        self.assertEqual(self.client.post('/audit/', json=first).status_code, 201)
        reordered = {**first, 'detail': {'b': {'y': 3, 'x': 2}, 'a': 1}}
        self.assertEqual(self.client.post('/audit/', json=reordered).status_code, 200)
        changed_type = {**first, 'detail': {'a': True, 'b': {'x': 2, 'y': 3}}}
        self.assertEqual(self.client.post('/audit/', json=changed_type).status_code, 409)

    def test_timestamp_is_first_write_metadata_and_does_not_change_on_replay(self):
        created = self.client.post('/audit/', json=payload())
        before = self.client.get('/audit/', params={'event_id': created.json()['id']}).json()[0]
        for stamp in (None, '2026-11-10T00:00:00Z', '2026-10-09T15:30:00+05:30'):
            with self.subTest(stamp=stamp):
                response = self.client.post('/audit/', json=payload(occurred_at=stamp))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['id'], before['id'])
        self.assertEqual(self.client.get('/audit/', params={
            'event_id': before['id']}).json()[0], before)

    def test_competing_changed_insert_conflicts_after_rollback(self):
        from fastapi import HTTPException
        with self.Session() as db:
            commit = db.commit

            def competing_commit():
                with self.Session() as other:
                    other.add(AuditEvent(event_key='raced-change', event_type='ORIGINAL'))
                    other.commit()
                commit()
            with patch.object(db, 'commit', side_effect=competing_commit):
                with self.assertRaises(HTTPException) as error:
                    audit_module.record_audit_event(audit_module.AuditEventIn(
                        event_key='raced-change', event_type='CHANGED'), Response(), db)
            self.assertEqual(error.exception.status_code, 409)
            self.assertEqual(db.query(AuditEvent).count(), 1)
            self.assertEqual(db.query(AuditEvent).one().event_type, 'ORIGINAL')

    def test_nonfinite_detail_is_refused_before_insert_or_duplicate_ack(self):
        for existing in (False, True):
            for value in ('NaN', 'Infinity', '-Infinity', '1e999'):
                with self.subTest(existing=existing, value=value):
                    key = 'finite-' + str(existing) + '-' + value
                    if existing:
                        self.client.post('/audit/', json=payload(event_key=key))
                    raw = ('{"event_type":"TEST","event_key":"' + key
                           + '","detail":{"nested":{"value":' + value + '}}}')
                    response = self.client.post('/audit/', content=raw, headers={
                        'Content-Type': 'application/json'})
                    self.assertEqual(response.status_code, 422)
                    self.assertEqual(response.json(), {
                        'detail': 'Audit detail must contain finite JSON values'})
        with self.Session() as db:
            self.assertEqual(db.query(AuditEvent).count(), 4)

    def test_nonfinite_historical_detail_cannot_be_acknowledged_as_matching(self):
        with self.Session() as db:
            db.add(AuditEvent(event_type='TEST', event_key='invalid-history',
                              detail={'bad': float('nan')}))
            db.commit()
        response = self.client.post('/audit/', json={
            'event_type': 'TEST', 'event_key': 'invalid-history', 'detail': {}})
        self.assertEqual(response.status_code, 409)
        with self.Session() as db:
            self.assertEqual(db.query(AuditEvent).count(), 1)


class TestWatcherRestartReplay(AuditApiTestCase):
    def check_restart(self, registration, policy="alert"):
        import dataclasses
        import tempfile

        from audit_client import DurableAuditClient
        from container_watcher import ContainerWatcher
        from monitor_config import MonitorConfig
        from tests.test_container_watcher import FakeInspector, FakeLookup, ID_A, docker_event

        lookup = FakeLookup()
        lookup.default = registration
        config = dataclasses.replace(
            MonitorConfig(), registration_grace_seconds=0, unapproved_start_policy=policy,
        )
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "audit_spool.jsonl"

            def post(_url, **kwargs):
                return self.client.post("/audit/", json=kwargs["json"])

            with patch("audit_client.requests.post", side_effect=post):
                first = DurableAuditClient("http://backend", spool)
                watcher = ContainerWatcher(config, first, lookup, FakeInspector())
                watcher.handle_docker_event(docker_event("start", ID_A))
                watcher.tick()
                self.assertEqual(first.flush_spool(), 1)
                for _ in range(2):
                    restarted = DurableAuditClient("http://backend", spool)
                    watcher = ContainerWatcher(config, restarted, lookup, FakeInspector())
                    watcher.reconcile()
                    watcher.tick()
                    self.assertEqual(restarted.flush_spool(), 1)
                    self.assertEqual(restarted.spool_size(), 0)
                with self.Session() as db:
                    rows = db.query(AuditEvent).order_by(AuditEvent.id).all()
                    self.assertEqual(len(rows), 2)
                    self.assertEqual(rows[0].detail["detection_method"], "docker_event")
                    self.assertEqual(rows[1].detail["detection_method"], "startup_reconcile")
                    self.assertNotEqual(rows[0].event_key, rows[1].event_key)

    def test_unapproved_start_reconciles_without_blocking_audit_delivery(self):
        self.check_restart(False)

    def test_registered_start_reconciles_without_blocking_audit_delivery(self):
        self.check_restart(True)

    def test_unknown_registration_reconciles_without_blocking_audit_delivery(self):
        self.check_restart(None)

    def test_ignored_unapproved_start_reconciles_without_blocking_audit_delivery(self):
        self.check_restart(False, policy="ignore")
