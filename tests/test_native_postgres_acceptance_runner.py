from datetime import datetime, timezone
from decimal import Decimal
import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

spec = importlib.util.spec_from_file_location(
    "check", Path(__file__).resolve().parents[1] / "evaluation/verify_postgres_acceptance.py",
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_restore_fingerprints_detect_changes_and_keep_duplicate_rows():
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE events(value TEXT, count INTEGER)"))
            connection.execute(text("INSERT INTO events VALUES ('a',1), ('b',2), ('a',1)"))
            original = check.fingerprints(connection, schema=None)
            connection.execute(text("DELETE FROM events"))
            connection.execute(text("INSERT INTO events VALUES ('b',2), ('a',1), ('a',1)"))
            assert check.fingerprints(connection, schema=None) == original
            connection.execute(text("UPDATE events SET count=3 WHERE value='b'"))
            changed = check.fingerprints(connection, schema=None)
            assert changed["events"]["rows"] == original["events"]["rows"] == 3
            assert changed != original
            connection.execute(text(
                "DELETE FROM events WHERE rowid=(SELECT min(rowid) FROM events)"
            ))
            assert check.fingerprints(connection, schema=None)["events"]["rows"] == 2
    finally:
        engine.dispose()


def test_revision_bookkeeping_is_separate_from_application_data():
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE containers(id INTEGER, image TEXT)"))
            connection.execute(text("INSERT INTO containers VALUES (1,'test')"))
            original = check.fingerprints(connection, schema=None)
            connection.execute(text("CREATE TABLE alembic_version(version_num TEXT)"))
            connection.execute(text("INSERT INTO alembic_version VALUES ('new-head')"))
            assert check.fingerprints(connection, schema=None) == original
    finally:
        engine.dispose()


@pytest.mark.parametrize("name", ["selfsentry_db", "postgres", "template1", "other_database"])
def test_write_target_requires_an_owned_acceptance_database(name):
    url = make_url("postgresql://test:example@localhost/selfsentry_db")
    with pytest.raises(check.CheckFailed):
        check.target_url(url, name, {name})


def test_even_a_valid_name_cannot_target_the_active_database():
    name = "ss_accept_012345abcdef_restore"
    url = make_url("postgresql://test:example@localhost/" + name)
    with pytest.raises(check.CheckFailed, match="active database"):
        check.target_url(url, name, {name})


def test_an_unconfirmed_creation_cannot_be_used_as_a_target():
    name = "ss_accept_012345abcdef_migrate"
    url = make_url("postgresql://test:example@localhost/selfsentry_db")
    with pytest.raises(check.CheckFailed, match="unowned"):
        check.target_url(url, name, set())
    assert check.target_url(url, name, {name}).database == name


def test_libpq_environment_cannot_redirect_restore_to_an_inherited_database(monkeypatch):
    monkeypatch.setenv("PGDATABASE", "selfsentry_db")
    monkeypatch.setenv("PGSERVICE", "unexpected")
    monkeypatch.setenv("PGOPTIONS", "-c search_path=wrong")
    url = make_url("postgresql://test:example@localhost:5432/selfsentry_db")
    env = check.pg_environment(url, "ss_accept_012345abcdef_restore")
    assert env["PGDATABASE"] == "ss_accept_012345abcdef_restore"
    assert env["PGUSER"] == "test" and env["PGPASSWORD"] == "example"
    assert "PGSERVICE" not in env and "PGOPTIONS" not in env
    assert env["PGCONNECT_TIMEOUT"] == "5"


def test_unreviewed_connection_options_stop_the_check():
    url = make_url("postgresql://test:example@localhost/selfsentry_db?service=unexpected")
    with pytest.raises(check.CheckFailed, match="Connection option"):
        check.pg_environment(url, "ss_accept_012345abcdef_restore")


def test_canonical_values_preserve_types_and_reject_nonfinite_data():
    values = [datetime(2026, 10, 23, tzinfo=timezone.utc), Decimal("1.25"), b"data"]
    encoded = json.dumps(values, default=check.json_value, allow_nan=False)
    assert '"datetime"' in encoded and '"decimal"' in encoded and '"bytes"' in encoded
    assert json.dumps({"flag": True}) != json.dumps({"flag": 1})
    with pytest.raises(ValueError):
        json.dumps({"value": float("nan")}, allow_nan=False)
