"""Verify PostgreSQL backup/restore and migrations using disposable databases."""

import argparse
from typing import Any
from datetime import date, datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

import requests
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

IDENTITY = """SELECT json_build_object(
    'database_oid', (SELECT oid::text FROM pg_database WHERE datname=current_database()),
    'server_start_epoch', extract(epoch FROM pg_postmaster_start_time())::text,
    'port', current_setting('port'))"""


class CheckFailed(RuntimeError):
    pass


def json_value(value):
    if isinstance(value, (datetime, date)):
        return {"type": type(value).__name__, "value": value.isoformat()}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    if isinstance(value, (bytes, memoryview)):
        return {"type": "bytes", "value": bytes(value).hex()}
    raise TypeError(f"Unsupported database value type: {type(value).__name__}")


def fingerprints(connection, schema="public"):
    """Include duplicate rows while making row order irrelevant."""
    quote = connection.dialect.identifier_preparer.quote
    result = {}
    for table in sorted(inspect(connection).get_table_names(schema=schema)):
        if table == "alembic_version":
            continue
        qualified = f"{quote(schema)}.{quote(table)}" if schema else quote(table)
        rows = connection.execute(
            text(f"SELECT * FROM {qualified}"), execution_options={"stream_results": True}
        )
        hashes = []
        for row in rows.mappings():
            encoded = json.dumps(
                dict(row), sort_keys=True, separators=(",", ":"),
                default=json_value, allow_nan=False,
            ).encode()
            hashes.append(hashlib.sha256(encoded).digest())
        digest = hashlib.sha256(b"".join(sorted(hashes))).hexdigest()
        result[table] = {"rows": len(hashes), "sha256": digest}
    return result


def pg_environment(url, database):
    # Avoid inherited libpq options silently selecting a service or another database.
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update({
        "PGHOST": url.host, "PGPORT": str(url.port or 5432),
        "PGUSER": url.username, "PGPASSWORD": url.password or "",
        "PGDATABASE": database, "PGCONNECT_TIMEOUT": "5",
        "PGAPPNAME": "selfsentry-acceptance",
    })
    for name, value in url.query.items():
        option = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
                  "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY"}.get(name)
        if option:
            env[option] = str(value)
        elif name != "connect_timeout":
            raise CheckFailed(f"Connection option needs review before acceptance: {name}")
    return env


def target_url(source_url, name, owned):
    if name not in owned or not re.fullmatch(r"ss_accept_[a-f0-9]{12}_(restore|migrate)", name):
        raise CheckFailed("Refusing an unowned database target")
    if name == source_url.database:
        raise CheckFailed("Refusing the active database as a write target")
    return source_url.set(database=name)


def native_constraints(engine):
    """Exercise native uniqueness, foreign keys and rollback only in a fresh test DB."""
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            rule = connection.execute(text(
                "INSERT INTO generated_rules(rule_yaml) VALUES ('acceptance-only') RETURNING id"
            )).scalar_one()
            connection.execute(text(
                "INSERT INTO rule_performance(rule_id,true_positives,false_positives) "
                "VALUES (:rule,7,2)"
            ), {"rule": rule})
            for name, statement, params, code in (
                ("unique", "INSERT INTO rule_performance(rule_id) VALUES (:rule)",
                 {"rule": rule}, "23505"),
                ("foreign key", "INSERT INTO rule_performance(rule_id) VALUES (-1)",
                 {}, "23503"),
            ):
                try:
                    with connection.begin_nested():
                        connection.execute(text(statement), params)
                except IntegrityError as exc:
                    if getattr(exc.orig, "pgcode", None) != code:
                        raise CheckFailed(f"Unexpected PostgreSQL failure testing {name}") from None
                else:
                    raise CheckFailed(f"Native {name} constraint did not reject the row")
            counts = connection.execute(text(
                "SELECT true_positives,false_positives FROM rule_performance WHERE rule_id=:rule"
            ), {"rule": rule}).one()
            if tuple(counts) != (7, 2):
                raise CheckFailed("Savepoint failures changed retained counters")
        finally:
            transaction.rollback()
        if connection.execute(text("SELECT count(*) FROM rule_performance")).scalar_one() != 0:
            raise CheckFailed("Native transaction rollback left test rows")
        if connection.execute(text("SELECT count(*) FROM generated_rules")).scalar_one() != 0:
            raise CheckFailed("Native transaction rollback left parent rows")
    return {"unique_constraint": True, "foreign_key": True, "savepoints": True, "rollback": True}


def monitor_status():
    response = requests.get("http://127.0.0.1:8000/monitor/status", timeout=15)
    response.raise_for_status()
    return response.json()


def run_check(root):
    os.umask(0o077)
    sys.path[:0] = [str(root / "backend-api")]
    from database import Base, create_database_engine, engine
    import models.db_models  # noqa: F401

    source_url = engine.url
    if (
        engine.dialect.name != "postgresql"
        or source_url.host not in ("localhost", "127.0.0.1", "::1")
    ):
        raise CheckFailed("This runner requires the reviewed local PostgreSQL installation")
    if not source_url.username or not source_url.database:
        raise CheckFailed("Database role and database name must be explicit")
    tools: dict[str, str] = {}
    for name in ("sudo", "psql", "createdb", "dropdb", "pg_dump", "pg_restore"):
        found = shutil.which(name)
        if not found:
            raise CheckFailed(f"Required native tool is missing: {name}")
        tools[name] = found
    before = monitor_status()
    if (
        not before.get("healthy") or type(before.get("pid")) is not int
        or before["pid"] <= 0
    ):
        raise CheckFailed("A healthy monitor is required before starting")
    spec = importlib.util.spec_from_file_location("schema_check", root / "scripts/verify_schema.py")
    if spec is None or spec.loader is None:
        raise CheckFailed("Schema verifier cannot be imported")
    schema = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(schema)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    folder = root / "state/evaluation" / ("postgres-acceptance-" + stamp)
    folder.mkdir(parents=True, mode=0o700)
    backup = Path.home() / "selfsentry-db-backups" / stamp
    owned = set()
    disposable_engines = []
    report: dict[str, Any] = {"passed": False, "started_at": stamp, "checks": {}, "commands": [],
                              "source_database": source_url.database, "cleanup": {}, "errors": []}

    def command(argv, label, env=None, timeout=300, cwd=None):
        # Credentials travel only in child environment, never in argv or report output.
        report["commands"].append({"label": label, "argv": list(map(str, argv))})
        completed = subprocess.run(
            list(map(str, argv)), env=env, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        (folder / f"{label}.log").write_text(completed.stdout)
        if completed.returncode:
            raise CheckFailed(f"{label} failed; retained its log in {folder}")
        return completed.stdout.strip()

    admin = [tools["sudo"], "-n", "-u", "postgres"]
    port = str(source_url.port or 5432)
    admin_env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    admin_connection = ["--no-password", "--host=/var/run/postgresql", "--port=" + port]

    def create(name):
        # Creation success establishes ownership. Cleanup only targets confirmed creations.
        if not re.fullmatch(r"ss_accept_[a-f0-9]{12}_(restore|migrate)", name):
            raise CheckFailed("Invalid disposable database name")
        command([
            *admin, tools["createdb"], *admin_connection, "--template=template0",
            "--owner=" + str(source_url.username), name,
        ], "create-" + name, env=admin_env, timeout=60, cwd="/tmp")
        owned.add(name)

    def new_engine(name):
        target = target_url(source_url, name, owned)
        instance = create_database_engine(target)
        disposable_engines.append(instance)
        return instance

    def alembic(name, action):
        target = target_url(source_url, name, owned)
        env = dict(os.environ, DATABASE_URL=target.render_as_string(hide_password=False),
                   AUTO_ISOLATION_ENABLED="false")
        command([
            sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), action, "head",
        ], f"{action}-{name}-{len(report['commands'])}", env=env, cwd=root)

    try:
        print("Checking PostgreSQL versions and administrator connection...", flush=True)
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            source_identity = connection.execute(text(IDENTITY)).scalar_one()
            server_version = connection.execute(text("SHOW server_version_num")).scalar_one()
        report["server_version_num"] = server_version
        for name in ("pg_dump", "pg_restore"):
            version = command([tools[name], "--version"], name + "-version", timeout=15)
            match = re.search(r"PostgreSQL\) (\d+)", version)
            if not match or int(match.group(1)) != int(server_version) // 10000:
                raise CheckFailed("Client/server major versions differ; review before backup")
        identity = command([
            *admin, tools["psql"], *admin_connection, "--no-psqlrc", "--tuples-only",
            "--no-align", "--dbname=" + source_url.database, "--command=" + IDENTITY,
        ], "administrator-cluster-check", env=admin_env, timeout=20, cwd="/tmp")
        if json.loads(identity) != source_identity:
            raise CheckFailed("Administrator socket does not identify the source cluster")
        report["checks"]["same_local_cluster"] = True
        token = uuid.uuid4().hex[:12]
        restore_name, migration_name = f"ss_accept_{token}_restore", f"ss_accept_{token}_migrate"
        create(restore_name)
        create(migration_name)

        backup.mkdir(parents=True, mode=0o700)
        dump = backup / "selfsentry.dump"
        print("Backing up the active database using an exported read-only snapshot...", flush=True)
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(text("SET LOCAL statement_timeout = '60s'"))
                connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                snapshot = connection.execute(text("SELECT pg_export_snapshot()")).scalar_one()
                expected = fingerprints(connection)
                command([
                    tools["pg_dump"], "--no-password", "--format=custom",
                    "--snapshot=" + snapshot, "--lock-wait-timeout=10s",
                    "--file=" + str(dump),
                ], "pg-dump", env=pg_environment(source_url, source_url.database))
        report["source_snapshot"] = expected
        report["backup"] = {"path": str(dump), "bytes": dump.stat().st_size,
                            "sha256": hashlib.sha256(dump.read_bytes()).hexdigest()}
        command([tools["pg_restore"], "--list", dump], "archive-list", timeout=30)
        report["checks"]["backup_created"] = True

        print("Restoring a temporary database and comparing application rows...", flush=True)
        target_url(source_url, restore_name, owned)
        command([
            tools["pg_restore"], "--no-password", "--exit-on-error", "--no-owner",
            "--no-privileges", "--dbname=" + restore_name, dump,
        ], "pg-restore", env=pg_environment(source_url, restore_name))
        restored = new_engine(restore_name)
        with restored.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            actual = fingerprints(connection)
            differences = schema.schema_differences(connection, Base.metadata)
        if actual != expected or differences:
            raise CheckFailed("Restored schema or snapshot row fingerprints differ")
        report["checks"].update(restore_rows_match=True, restore_schema_matches=True)

        print("Testing schema adoption on the restored copy only...", flush=True)
        alembic(restore_name, "stamp")
        with restored.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            if fingerprints(connection) != expected:
                raise CheckFailed("Adoption changed application data in the restored copy")
            restored_revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
        report["checks"]["restored_copy_adoption_preserved_rows"] = True
        report["restored_revision"] = restored_revision

        print("Testing fresh migrations and native database constraints...", flush=True)
        alembic(migration_name, "upgrade")
        migrated = new_engine(migration_name)
        with migrated.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            if schema.schema_differences(connection, Base.metadata):
                raise CheckFailed("Fresh migration schema differs from the ORM")
        report["checks"]["fresh_migration_matches"] = True
        report["checks"].update(native_constraints(migrated))
        with migrated.begin() as connection:
            connection.execute(text(
                "INSERT INTO containers(container_id,image_name) VALUES (:cid,'acceptance:local')"
            ), {"cid": "acceptance-" + token})
        with migrated.connect() as connection:
            sentinel = fingerprints(connection)
        alembic(migration_name, "upgrade")
        with migrated.connect() as connection:
            if fingerprints(connection) != sentinel:
                raise CheckFailed("Repeating upgrade head changed the temporary database rows")
        report["checks"]["repeat_upgrade_preserves_rows"] = True
        report["checks"]["data_checks_passed"] = True
    except Exception as exc:
        report["errors"].append(str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__)
    finally:
        for instance in disposable_engines:
            instance.dispose()
        for name in sorted(owned):
            try:
                target_url(source_url, name, owned)
                command([
                    *admin, tools["dropdb"], *admin_connection, name,
                ], "drop-" + name, env=admin_env, timeout=60, cwd="/tmp")
                report["cleanup"][name] = "removed"
            except Exception as exc:
                report["cleanup"][name] = "needs review: " + type(exc).__name__
                report["errors"].append("Temporary database cleanup needs review: " + name)
        try:
            after = monitor_status()
            for _ in range(30):
                if after.get("healthy"):
                    break
                time.sleep(1)
                after = monitor_status()
            report["checks"]["monitor_healthy_after"] = after.get("healthy") is True
            report["checks"]["monitor_not_restarted"] = after.get("pid") == before.get("pid")
            if not all(
                report["checks"][name]
                for name in ("monitor_healthy_after", "monitor_not_restarted")
            ):
                report["errors"].append("Monitor health or PID changed; inspect the live status")
        except Exception as exc:
            report["errors"].append("Final monitor check unavailable: " + type(exc).__name__)
        engine.dispose()
        report["passed"] = (
            not report["errors"] and report["checks"].get("data_checks_passed") is True
        )
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = folder / "results.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        summary = {key: report[key] for key in ("passed", "checks", "cleanup", "errors")}
        print(json.dumps(summary, indent=2))
        print("Evidence:", path)
        if report.get("backup"):
            print("Database backup retained:", report["backup"]["path"])
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "selfsentry")
    args = parser.parse_args()
    root = args.repo.expanduser().resolve()
    if not (root / "scripts/verify_schema.py").is_file():
        raise CheckFailed("--repo must point to the integrated SelfSentry checkout")
    return run_check(root)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise CheckFailed("Interrupted; attempted cleanup of owned temporary databases")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except Exception as exc:
        message = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
        print("Stopped:", message, file=sys.stderr)
        raise SystemExit(2)
