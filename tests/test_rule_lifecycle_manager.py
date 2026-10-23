"""Tests for the database connection handling in rule_lifecycle_manager.py."""

import sys
import sqlite3
from contextlib import contextmanager

import pytest
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rule-synthesis-engine"))

import rule_lifecycle_manager  # noqa: E402


class TestDatabaseConnection(unittest.TestCase):
    def test_missing_database_url_raises_clear_error(self):
        with patch.object(rule_lifecycle_manager, "DATABASE_URL", None):
            with self.assertRaises(RuntimeError):
                rule_lifecycle_manager._get_connection()

    def test_sqlalchemy_dialect_suffix_is_stripped_before_connecting(self):
        url = "postgresql+psycopg2://user:pw@localhost:5432/db"
        with patch.object(rule_lifecycle_manager, "DATABASE_URL", url), patch.object(
            rule_lifecycle_manager.psycopg2, "connect"
        ) as connect:
            rule_lifecycle_manager._get_connection()
        connect.assert_called_once_with("postgresql://user:pw@localhost:5432/db", connect_timeout=5)


# These adapter tests execute the counter SQL against the declared table shape
# without a rule_id uniqueness constraint. They do not emulate PostgreSQL locks.


class OutcomeConnection:
    def __init__(self, path):
        self.raw = sqlite3.connect(path)
        self.raw.execute("PRAGMA foreign_keys=ON")
        self.closed = False

    def __enter__(self):
        self.raw.__enter__()
        return self

    def __exit__(self, *args):
        return self.raw.__exit__(*args)

    def close(self):
        self.closed = True
        self.raw.close()

    @contextmanager
    def cursor(self):
        cursor = self.raw.cursor()

        class Cursor:
            def execute(self, sql, params):
                cursor.execute(sql.replace("%s", "?").replace("FOR UPDATE", "")
                               .replace("now()", "CURRENT_TIMESTAMP"), params)

            def fetchone(self):
                return cursor.fetchone()

            def fetchall(self):
                return cursor.fetchall()

        try:
            yield Cursor()
        finally:
            cursor.close()


@pytest.fixture
def outcome_db(tmp_path, monkeypatch):
    path = tmp_path / "outcomes.sqlite"
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE generated_rules (id INTEGER PRIMARY KEY);
            INSERT INTO generated_rules VALUES (1);
            CREATE TABLE rule_performance (
                id INTEGER PRIMARY KEY, rule_id INTEGER REFERENCES generated_rules(id),
                true_positives INTEGER, false_positives INTEGER, last_updated TIMESTAMP
            );
        """)
    connections = []

    def connect():
        connection = OutcomeConnection(path)
        connections.append(connection)
        return connection

    monkeypatch.setattr(rule_lifecycle_manager, "_get_connection", connect)
    yield path, connections
    for connection in connections:
        if not connection.closed:
            connection.close()


def outcome_rows(path):
    with sqlite3.connect(path) as db:
        return db.execute(
            "SELECT rule_id,true_positives,false_positives FROM rule_performance ORDER BY id"
        ).fetchall()


def test_outcomes_work_without_a_preexisting_unique_index_and_close_connections(outcome_db):
    path, connections = outcome_db
    rule_lifecycle_manager.record_rule_outcome(1, True)
    rule_lifecycle_manager.record_rule_outcome(1, False)
    assert outcome_rows(path) == [(1, 1, 1)]
    assert rule_lifecycle_manager.evaluate_rule_for_retirement(1) is True
    assert all(connection.closed for connection in connections)


def test_duplicate_historical_counters_fail_without_modifying_or_deleting_data(outcome_db):
    path, connections = outcome_db
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO rule_performance(rule_id,true_positives,false_positives) VALUES (1,?,?)",
            [(3, 1), (4, 2)],
        )
    before = outcome_rows(path)
    with pytest.raises(RuntimeError, match="Multiple performance rows"):
        rule_lifecycle_manager.record_rule_outcome(1, True)
    with pytest.raises(RuntimeError, match="Multiple performance rows"):
        rule_lifecycle_manager.evaluate_rule_for_retirement(1)
    assert outcome_rows(path) == before
    assert all(connection.closed for connection in connections)


def test_unknown_rule_does_not_create_an_orphan_outcome(outcome_db):
    path, connections = outcome_db
    with pytest.raises(LookupError, match="Rule 999 not found"):
        rule_lifecycle_manager.record_rule_outcome(999, True)
    assert outcome_rows(path) == []
    assert all(connection.closed for connection in connections)


def test_missing_or_zero_observations_do_not_recommend_retirement(outcome_db):
    path, connections = outcome_db
    assert rule_lifecycle_manager.evaluate_rule_for_retirement(1) is False
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO rule_performance(rule_id) VALUES (1)")
    assert rule_lifecycle_manager.evaluate_rule_for_retirement(1) is False
    rule_lifecycle_manager.record_rule_outcome(1, True)
    assert outcome_rows(path) == [(1, 1, 0)]
    assert rule_lifecycle_manager.evaluate_rule_for_retirement(1) is False
    assert all(connection.closed for connection in connections)


def test_failed_counter_write_rolls_back_and_closes_the_connection(outcome_db):
    path, connections = outcome_db
    rule_lifecycle_manager.record_rule_outcome(1, True)
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TRIGGER reject_update BEFORE UPDATE ON rule_performance
            BEGIN SELECT RAISE(ABORT, 'controlled write failure'); END;
        """)
    with pytest.raises(sqlite3.IntegrityError, match="controlled write failure"):
        rule_lifecycle_manager.record_rule_outcome(1, False)
    assert outcome_rows(path) == [(1, 1, 0)]
    assert all(connection.closed for connection in connections)


if __name__ == "__main__":
    unittest.main()
