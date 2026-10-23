"""Migration behavior on disposable SQLite; PostgreSQL is not exercised here."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def migration_setup(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend-api"))
    # Other route tests already load this module with a disposable URL.
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    import database
    import models.db_models  # noqa: F401

    spec = importlib.util.spec_from_file_location("schema_check", ROOT / "scripts/verify_schema.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.sqlite'}")
    config = Config(str(ROOT / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        yield config, connection, database.Base.metadata, check.schema_differences
    engine.dispose()


def test_upgrade_matches_metadata_and_preserves_rows_on_repeat(migration_setup):
    config, connection, metadata, differences = migration_setup
    command.upgrade(config, "head")
    assert differences(connection, metadata) == []
    connection.execute(
        text("INSERT INTO containers(container_id,image_name) VALUES ('abc','test')")
    )
    connection.commit()
    command.upgrade(config, "head")
    assert connection.execute(text("SELECT count(*) FROM containers")).scalar_one() == 1


def test_existing_unversioned_database_is_not_automatically_adopted(migration_setup):
    config, connection, metadata, _ = migration_setup
    metadata.create_all(connection)
    connection.commit()
    with pytest.raises(RuntimeError, match="requires an empty database"):
        command.upgrade(config, "head")
    assert set(metadata.tables) <= set(inspect(connection).get_table_names())


def test_downgrade_requires_explicit_opt_in_and_roundtrip_works(migration_setup):
    config, connection, metadata, differences = migration_setup
    command.upgrade(config, "head")
    with pytest.raises(RuntimeError, match="explicit opt-in"):
        command.downgrade(config, "base")
    connection.rollback()
    assert set(metadata.tables) <= set(inspect(connection).get_table_names())
    config.cmd_opts = SimpleNamespace(x=["allow_destructive_downgrade=true"])
    command.downgrade(config, "base")
    assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
    command.upgrade(config, "head")
    assert differences(connection, metadata) == []


def test_schema_check_detects_missing_table_without_repairing_it(migration_setup):
    config, connection, metadata, differences = migration_setup
    command.upgrade(config, "head")
    connection.execute(text("DROP TABLE audit_events"))
    connection.commit()
    before = set(inspect(connection).get_table_names())
    result = differences(connection, metadata)
    assert any(item[0] == "add_table" and item[1].name == "audit_events" for item in result)
    assert set(inspect(connection).get_table_names()) == before


def test_rule_performance_is_unique_in_metadata_and_migrated_schema(migration_setup):
    config, connection, metadata, differences = migration_setup
    command.upgrade(config, "head")
    assert metadata.tables["rule_performance"].c.rule_id.unique is True
    constraints = inspect(connection).get_unique_constraints("rule_performance")
    assert any(item["column_names"] == ["rule_id"] for item in constraints)
    connection.execute(text("INSERT INTO rule_performance(rule_id) VALUES (123)"))
    connection.commit()
    with pytest.raises(IntegrityError):
        connection.execute(text("INSERT INTO rule_performance(rule_id) VALUES (123)"))
        connection.commit()
    connection.rollback()
    assert connection.execute(text("SELECT count(*) FROM rule_performance")).scalar_one() == 1
    assert differences(connection, metadata) == []


def test_unique_revision_preserves_counts_and_allows_null_rule_ids(migration_setup):
    config, connection, metadata, differences = migration_setup
    command.upgrade(config, "20261022_0001")
    connection.execute(text(
        "INSERT INTO rule_performance(rule_id,true_positives,false_positives) "
        "VALUES (123,7,2), (NULL,1,0), (NULL,2,0)"
    ))
    connection.commit()
    command.upgrade(config, "head")
    rows = connection.execute(text(
        "SELECT rule_id,true_positives,false_positives FROM rule_performance ORDER BY id"
    )).fetchall()
    assert rows == [(123, 7, 2), (None, 1, 0), (None, 2, 0)]
    assert differences(connection, metadata) == []


def test_unique_revision_refuses_duplicates_without_deleting_them(migration_setup):
    config, connection, _, _ = migration_setup
    command.upgrade(config, "20261022_0001")
    connection.execute(text("INSERT INTO rule_performance(rule_id) VALUES (123), (123)"))
    connection.commit()
    with pytest.raises(RuntimeError, match="Duplicate rule performance"):
        command.upgrade(config, "head")
    connection.rollback()
    assert connection.execute(text("SELECT count(*) FROM rule_performance")).scalar_one() == 2
    assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
        "20261022_0001"
    )


def test_unique_revision_downgrade_preserves_rows(migration_setup):
    config, connection, _, _ = migration_setup
    command.upgrade(config, "head")
    connection.execute(text("INSERT INTO rule_performance(rule_id) VALUES (123)"))
    connection.commit()
    command.downgrade(config, "20261022_0001")
    assert connection.execute(text("SELECT count(*) FROM rule_performance")).scalar_one() == 1
    assert inspect(connection).get_unique_constraints("rule_performance") == []
