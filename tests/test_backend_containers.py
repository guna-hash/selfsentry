"""Tests for backend-api/routes/containers.py.

Docker is faked, the database is in-memory SQLite, and isolation records go to a temp dir.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ["DATABASE_URL"] = "sqlite://"  # keep the app's own engine away from Postgres
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))

import docker  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import database  # noqa: E402
from models.db_models import Incident  # noqa: E402
from routes import containers as containers_module  # noqa: E402

WEB_SHORT = "abc123def456"
WEB_ID = WEB_SHORT + "0" * 52


def make_container(name="web", status="running"):
    return SimpleNamespace(
        id=WEB_ID, short_id=WEB_SHORT, name=name, status=status,
        attrs={"Config": {"Image": "nginx:1.25"}},
    )


class ContainersApiTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        self.addCleanup(self.engine.dispose)
        database.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False)

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {"SELFSENTRY_STATE_DIR": tmp.name})
        env.start()
        self.addCleanup(env.stop)

        self.docker_client = MagicMock()
        self.docker_client.containers.list.return_value = [make_container()]
        factory = patch.object(containers_module, "_docker_client")
        self.docker_factory = factory.start()
        self.addCleanup(factory.stop)
        self.docker_factory.return_value = self.docker_client

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app = FastAPI()
        app.include_router(containers_module.router)
        app.dependency_overrides[containers_module.get_db] = override_get_db
        self.client = TestClient(app)

    def add_incident(self, incident_id, risk, container_id=WEB_SHORT):
        with self.Session() as db:
            db.add(Incident(id=incident_id, container_id=container_id, risk_score=risk))
            db.commit()


class TestListContainers(ContainersApiTestCase):
    def test_lists_container_with_latest_incident_risk(self):
        self.add_incident(1, 90.0)
        self.add_incident(2, 55.0)
        item = self.client.get("/containers/").json()[0]
        self.assertEqual(item["name"], "web")
        self.assertEqual(item["image"], "nginx:1.25")
        self.assertEqual(item["latest_risk_score"], 55.0)
        self.assertEqual(item["latest_incident_id"], 2)
        self.assertFalse(item["isolated"])

    def test_container_without_incidents_has_no_risk(self):
        item = self.client.get("/containers/").json()[0]
        self.assertIsNone(item["latest_risk_score"])
        self.assertIsNone(item["latest_incident_id"])

    def test_incident_matched_by_container_name_too(self):
        self.add_incident(1, 70.0, container_id="web")
        self.assertEqual(self.client.get("/containers/").json()[0]["latest_risk_score"], 70.0)

    def test_isolated_flag_and_reason_come_from_the_isolation_record(self):
        containers_module.auto_isolate._write_record(
            WEB_ID,
            {"state": "isolated", "reason": "high risk", "isolated_at": "2026-10-09T00:00:00+00:00",
             "networks": {}},
        )
        item = self.client.get("/containers/").json()[0]
        self.assertTrue(item["isolated"])
        self.assertEqual(item["isolation_reason"], "high risk")

    def test_resumed_record_does_not_count_as_isolated(self):
        containers_module.auto_isolate._write_record(
            WEB_ID, {"state": "resumed", "reason": "old", "networks": {}}
        )
        item = self.client.get("/containers/").json()[0]
        self.assertFalse(item["isolated"])
        self.assertIsNone(item["isolation_reason"])

    def test_docker_unavailable_returns_503(self):
        self.docker_factory.side_effect = docker.errors.DockerException("daemon down")
        self.assertEqual(self.client.get("/containers/").status_code, 503)


class TestResumeAndIsolateRoutes(ContainersApiTestCase):
    def resume(self):
        return self.client.post("/containers/web/resume", params={"resumed_by": "alice"})

    def isolate(self):
        return self.client.post(
            "/containers/web/isolate", params={"isolated_by": "alice", "reason": "suspicious"}
        )

    def test_resume_success(self):
        outcome = {"container_id": WEB_ID, "networks": ["bridge"], "resumed_by": "alice"}
        with patch.object(containers_module.auto_isolate, "resume_container",
                          return_value=outcome) as resume:
            response = self.resume()
        self.assertEqual(response.status_code, 200)
        resume.assert_called_once_with("web", "alice")

    def test_resume_unknown_container_is_404(self):
        error = containers_module.auto_isolate.ContainerNotFound("gone")
        with patch.object(containers_module.auto_isolate, "resume_container", side_effect=error):
            self.assertEqual(self.resume().status_code, 404)

    def test_resume_without_active_isolation_is_409(self):
        error = containers_module.auto_isolate.ResumeError("no record")
        with patch.object(containers_module.auto_isolate, "resume_container", side_effect=error):
            self.assertEqual(self.resume().status_code, 409)

    def test_resume_requires_resumed_by(self):
        self.assertEqual(self.client.post("/containers/web/resume").status_code, 422)

    def test_isolate_success_passes_who_and_why(self):
        with patch.object(containers_module.auto_isolate, "isolate_container") as isolate:
            self.assertEqual(self.isolate().status_code, 200)
        isolate.assert_called_once_with("web", "manual, by alice: suspicious")

    def test_isolate_unknown_container_is_404(self):
        error = containers_module.auto_isolate.ContainerNotFound("gone")
        with patch.object(containers_module.auto_isolate, "isolate_container", side_effect=error):
            self.assertEqual(self.isolate().status_code, 404)


if __name__ == "__main__":
    unittest.main()
