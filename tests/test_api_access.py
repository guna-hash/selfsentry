"""Exercise authorization and history bounds through the actual application."""

import importlib.util
import os
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend-api"))
os.environ.setdefault("DATABASE_URL", "sqlite://")
import database  # noqa: E402
from models.db_models import Incident  # noqa: E402

TOKEN = "access-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def api(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", TOKEN)
    spec = importlib.util.spec_from_file_location("access_test_main", ROOT / "backend-api/main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sessions = sessionmaker(bind=engine)

    def dependency():
        with sessions() as db:
            yield db

    module.app.dependency_overrides[database.get_db] = dependency
    try:
        with TestClient(module.app) as client:
            yield client, sessions, engine
    finally:
        engine.dispose()


@pytest.mark.parametrize("path", [
    "/incidents/", "/incidents/1", "/audit/", "/containers/", "/deployments/",
    "/rules/history", "/monitor/status", "/health/ready", "/openapi.json", "/docs",
])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_private_reads_require_credentials_before_database_or_route_work(api, path, method):
    client, _, engine = api

    def forbidden(*args):
        pytest.fail("Unauthenticated request reached the database")

    event.listen(engine, "before_cursor_execute", forbidden)
    try:
        response = client.request(method, path)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert client.request(
            method, path, headers={"Authorization": "Bearer wrong"}
        ).status_code == 401
    finally:
        event.remove(engine, "before_cursor_execute", forbidden)


def test_missing_configuration_fails_closed_but_public_probe_and_preflight_work(api, monkeypatch):
    client, _, _ = api
    monkeypatch.delenv("SELFSENTRY_API_TOKEN")
    assert client.get("/audit/", headers=HEADERS).status_code == 503
    assert client.get("/").json() == {"status": "SelfSentry backend running"}
    response = client.options("/incidents/", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_authenticated_reads_and_writes_still_reach_the_routes(api):
    client, _, _ = api
    assert client.get("/audit/", headers=HEADERS).json() == []
    assert client.get("/openapi.json", headers=HEADERS).status_code == 200
    assert client.get("/health/ready", headers=HEADERS).json() == {"ready": True}
    assert client.post("/incidents/", json={}).status_code == 401
    assert client.post("/incidents/", json={}, headers=HEADERS).status_code == 422
    assert client.get("/audit/", headers={**HEADERS, "Origin": "http://localhost:5173"}).headers[
        "access-control-allow-origin"] == "http://localhost:5173"


def test_history_is_bounded_and_cursor_stays_stable_when_new_records_arrive(api):
    client, sessions, _ = api
    with sessions() as db:
        db.add_all([Incident(container_id="test", risk_score=10) for _ in range(505)])
        db.commit()
    first = client.get("/incidents/", headers=HEADERS).json()
    assert len(first) == 200
    assert [row["id"] for row in first] == list(range(505, 305, -1))
    with sessions() as db:
        db.add(Incident(container_id="test", risk_score=90))
        db.commit()
    second = client.get("/incidents/?limit=500&before_id=306", headers=HEADERS).json()
    assert [row["id"] for row in second] == list(range(305, 0, -1))
    assert not {row["id"] for row in first} & {row["id"] for row in second}
    assert len(client.get("/incidents/?limit=500", headers=HEADERS).json()) == 500
    assert client.get("/incidents/?before_id=1", headers=HEADERS).json() == []
    assert client.get("/incidents/1", headers=HEADERS).json()["id"] == 1


@pytest.mark.parametrize("query", [
    "limit=0", "limit=501", "limit=-1", "before_id=0",
    "before_id=-1", "limit=oops", "before_id=oops",
])
def test_bad_history_bounds_are_rejected(api, query):
    client, _, _ = api
    assert client.get("/incidents/?" + query, headers=HEADERS).status_code == 422
