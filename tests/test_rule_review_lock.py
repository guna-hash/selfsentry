"""Pinned PostgreSQL connection protocol; these mocks do not prove native locking."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend-api"))
from routes import rules  # noqa: E402


def postgres_session():
    db = MagicMock()
    engine = db.get_bind.return_value
    engine.dialect.name = "postgresql"
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.scalar.return_value = True
    return db, connection


def test_review_pins_one_connection_and_unlocks_only_after_review_commits():
    db, connection = postgres_session()
    with patch.object(rules, "Session") as session_factory:
        review = session_factory.return_value.__enter__.return_value
        with rules._review_session(db, 7) as guarded:
            assert guarded is review
            guarded.commit()
            assert connection.execute.call_count == 1  # Lock still held after approval commit.
        session_factory.assert_called_once_with(bind=connection)
    assert "pg_try_advisory_lock" in str(connection.execute.call_args_list[0].args[0])
    assert "pg_advisory_unlock" in str(connection.execute.call_args_list[-1].args[0])
    connection.invalidate.assert_not_called()


def test_competing_postgres_review_does_not_open_a_write_session():
    db, connection = postgres_session()
    connection.execute.return_value.scalar.return_value = False
    with patch.object(rules, "Session") as session_factory:
        with pytest.raises(HTTPException) as error:
            with rules._review_session(db, 7):
                pytest.fail("A competing review was allowed")
    assert error.value.status_code == 409
    session_factory.assert_not_called()


def test_review_failure_still_unlocks_the_pinned_connection():
    db, connection = postgres_session()
    with patch.object(rules, "Session"):
        with pytest.raises(RuntimeError, match="backtest failed"):
            with rules._review_session(db, 7):
                raise RuntimeError("backtest failed")
    assert "pg_advisory_unlock" in str(connection.execute.call_args.args[0])


@pytest.mark.parametrize("stage", ["acquire", "commit", "unlock"])
def test_ambiguous_database_failures_discard_the_connection(stage):
    db, connection = postgres_session()
    failure = SQLAlchemyError("connection failed")
    if stage == "acquire":
        connection.execute.side_effect = failure
    elif stage == "commit":
        connection.commit.side_effect = failure
    else:
        connection.execute.side_effect = [MagicMock(scalar=lambda: True), failure]
    with patch.object(rules, "Session"):
        if stage == "unlock":
            with rules._review_session(db, 7):
                pass
        else:
            with pytest.raises(SQLAlchemyError):
                with rules._review_session(db, 7):
                    pytest.fail("Failed lock acquisition must not allow review")
    connection.invalidate.assert_called_once()
