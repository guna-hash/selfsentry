"""Disposable engine/driver checks; silent local TCP is not a PostgreSQL server."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import sys
import threading
import time
from unittest.mock import Mock

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))
import database  # noqa: E402


def test_plain_postgres_selects_installed_driver_without_mutating_url_or_connecting():
    url = "postgresql://test:example-password@127.0.0.1/test?sslmode=require&application_name=audit"
    engine = database.create_database_engine(url)
    try:
        assert engine.dialect.driver == "psycopg2"
        assert engine.url.query["sslmode"] == "require"
        assert engine.url.query["application_name"] == "audit"
        assert "example-password" not in str(engine.url)
        assert url.startswith("postgresql://")
    finally:
        engine.dispose()


@pytest.mark.parametrize("query,expected", [("", 5), ("?connect_timeout=9&sslmode=require", 9)])
def test_connection_policy_preserves_explicit_positive_timeout(monkeypatch, query, expected):
    create = Mock()
    monkeypatch.setattr(database, "create_engine", create)
    database.create_database_engine("postgresql+psycopg2://test@127.0.0.1/test" + query)
    assert create.call_args.kwargs["connect_args"] == {"connect_timeout": expected}
    assert create.call_args.kwargs["pool_timeout"] == 5
    assert create.call_args.kwargs["pool_pre_ping"] is True


@pytest.mark.parametrize("query", ["0", "-1", "invalid", "1.5", "2&connect_timeout=3"])
def test_invalid_or_ambiguous_timeout_fails_before_engine_construction(monkeypatch, query):
    create = Mock()
    monkeypatch.setattr(database, "create_engine", create)
    with pytest.raises(ValueError, match="positive whole number"):
        database.create_database_engine("postgresql://test@127.0.0.1/test?connect_timeout=" + query)
    create.assert_not_called()


def test_sqlite_disposable_transaction_remains_usable():
    engine = database.create_database_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE example (value INTEGER)"))
            connection.execute(text("INSERT INTO example VALUES (7)"))
        with engine.connect() as connection:
            assert connection.execute(text("SELECT value FROM example")).scalar_one() == 7
    finally:
        engine.dispose()


@pytest.fixture
def silent_owned_tcp_peer():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1)
    port = listener.getsockname()[1]
    stop, accepted = threading.Event(), threading.Event()

    def serve():
        try:
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    accepted.set()
                    stop.wait(12)
                break
        finally:
            listener.close()

    server = threading.Thread(target=serve)
    server.start()
    try:
        yield port, accepted, stop
    finally:
        stop.set()
        server.join(3)
    assert not server.is_alive()


@pytest.mark.parametrize("query,expected", [("", 5), ("&connect_timeout=2", 2)])
def test_real_psycopg2_times_out_against_silent_owned_tcp_peer(
    silent_owned_tcp_peer, query, expected
):
    port, accepted, stop = silent_owned_tcp_peer
    engine = database.create_database_engine(
        f"postgresql://test@127.0.0.1:{port}/test?sslmode=disable{query}"
    )
    started = time.monotonic()
    try:
        # The owned listener is released even if a driver timeout regresses.
        with ThreadPoolExecutor(max_workers=1) as executor:
            attempt = executor.submit(engine.connect)
            try:
                with pytest.raises(OperationalError):
                    attempt.result(timeout=10)
            finally:
                stop.set()
        elapsed = time.monotonic() - started
        assert accepted.is_set(), "must actually reach the silent peer"
        assert expected - 0.5 <= elapsed < 10
        print(f"silent-peer connect_timeout={expected}: elapsed={elapsed:.2f}s")
    finally:
        engine.dispose()


@pytest.fixture
def actual_backend(monkeypatch):
    import importlib.util
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import QueuePool

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=QueuePool, pool_size=1, max_overflow=0, pool_timeout=0.1)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "test-operator-token")
    spec = importlib.util.spec_from_file_location(
        "audit_database_error_main", Path(__file__).resolve().parents[1] / "backend-api/main.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sessions = sessionmaker(bind=engine)

    def dependency():
        with sessions() as session:
            yield session

    module.app.dependency_overrides[database.get_db] = dependency
    try:
        with TestClient(module.app, raise_server_exceptions=False) as http:
            yield http, engine
    finally:
        engine.dispose()


def test_operational_error_is_safe_503_with_cors_and_no_secret_in_logs(actual_backend, caplog):
    from sqlalchemy import event

    http, engine = actual_backend
    private = "synthetic-private-driver-data"

    def unavailable(*args):
        raise OperationalError(private, {"sensitive": private}, RuntimeError(private))

    event.listen(engine, "before_cursor_execute", unavailable)
    try:
        response = http.get("/audit/", headers={"Origin": "http://localhost:5173"})
    finally:
        event.remove(engine, "before_cursor_execute", unavailable)
    assert response.status_code == 503
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers.get("retry-after") is None
    assert private not in response.text
    assert "write may" not in response.text
    assert private not in caplog.text
    assert "OperationalError" in caplog.text
    assert engine.pool.checkedout() == 0
    assert http.get("/audit/").status_code == 200


def test_real_pool_exhaustion_is_503_and_recovers_after_release(actual_backend):
    http, engine = actual_backend
    with engine.connect():
        response = http.get("/audit/")
        assert response.status_code == 503
    assert engine.pool.checkedout() == 0
    assert http.get("/audit/").status_code == 200


def test_before_insert_failure_returns_503_without_creating_a_record(actual_backend):
    from sqlalchemy import event

    http, engine = actual_backend

    def failed_insert(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("INSERT"):
            raise OperationalError("synthetic insert", {}, RuntimeError("synthetic outage"))

    event.listen(engine, "before_cursor_execute", failed_insert)
    try:
        response = http.post("/audit/", json={"event_type": "TEST", "event_key": "not-written"},
                             headers={"Authorization": "Bearer test-operator-token"})
    finally:
        event.remove(engine, "before_cursor_execute", failed_insert)
    assert response.status_code == 503
    assert engine.pool.checkedout() == 0
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 0


def test_lost_commit_acknowledgement_keeps_outcome_unknown_and_identical_retry_deduplicates(
    actual_backend, monkeypatch
):
    http, engine = actual_backend
    commit = engine.dialect.do_commit

    def commit_then_lose_response(connection):
        commit(connection)
        raise OperationalError("synthetic commit", {}, RuntimeError("synthetic lost response"))

    body = {"event_type": "TEST", "event_key": "possibly-written"}
    headers = {"Authorization": "Bearer test-operator-token"}
    with monkeypatch.context() as patch:
        patch.setattr(engine.dialect, "do_commit", commit_then_lose_response)
        response = http.post("/audit/", json=body, headers=headers)
    assert response.status_code == 503
    assert "may have completed" in response.json()["detail"]
    assert engine.pool.checkedout() == 0
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 1
    retry = http.post("/audit/", json=body, headers=headers)
    assert retry.status_code == 200
    assert retry.json()["duplicate"] is True
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 1


@pytest.mark.parametrize("kind", ["ProgrammingError", "IntegrityError"])
def test_unexpected_database_code_or_constraint_errors_are_not_reclassified(actual_backend, kind):
    from sqlalchemy import event, exc

    http, engine = actual_backend

    def failed(*args):
        raise getattr(exc, kind)("synthetic statement", {}, RuntimeError("synthetic fault"))

    event.listen(engine, "before_cursor_execute", failed)
    try:
        result = http.get("/audit/")
    finally:
        event.remove(engine, "before_cursor_execute", failed)
    assert result.status_code == 500
    assert engine.pool.checkedout() == 0


def test_authentication_still_precedes_database_mutation(actual_backend):
    from sqlalchemy import event

    http, engine = actual_backend
    attempted = []

    def failed(*args):
        attempted.append(True)
        raise OperationalError("synthetic statement", {}, RuntimeError("outage"))

    event.listen(engine, "before_cursor_execute", failed)
    try:
        result = http.post("/audit/", json={"event_type": "TEST"})
    finally:
        event.remove(engine, "before_cursor_execute", failed)
    assert result.status_code == 401
    assert attempted == []
