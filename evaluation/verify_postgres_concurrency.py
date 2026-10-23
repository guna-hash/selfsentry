"""Native concurrency checks in one owned, freshly migrated PostgreSQL database."""

import argparse
from typing import Any
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import uuid

from sqlalchemy import text
from sqlalchemy.engine import make_url

from postgres_support import CheckFailed, IDENTITY, monitor_status, pg_environment, target_url


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def check_sources(root):
    manifest = json.loads(Path(__file__).with_name("source-hashes.json").read_text())
    for name, expected in manifest.items():
        path = root / name
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "Source differs from the reviewed version: " + name)


def worker_target(value, name):
    """A child must receive the parent's specific disposable target, never a default."""
    require(re.fullmatch(r"ss_accept_[a-f0-9]{12}_migrate", name) is not None,
            "Invalid disposable worker target")
    url = make_url(value)
    require(url.database == name and url.host in ("localhost", "127.0.0.1", "::1")
            and url.get_backend_name() == "postgresql", "Worker target does not match")
    return url


def audit_race(engine, mixed=False):
    from fastapi import HTTPException, Response
    from sqlalchemy.orm import Session
    from routes.audit import AuditEventIn, record_audit_event

    barrier = threading.Barrier(8, timeout=20)
    key = "acceptance-" + uuid.uuid4().hex

    class RacingSession(Session):
        rollbacks = 0

        def commit(self):
            # Every initial lookup must have finished before any INSERT commits.
            barrier.wait()
            return super().commit()

        def rollback(self):
            self.rollbacks += 1
            return super().rollback()

    def deliver(index):
        variant = index % 2 if mixed else 0
        body = AuditEventIn(
            event_type="ACCEPTANCE_CONCURRENCY", event_key=key,
            detail={"variant": variant}, occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        with RacingSession(bind=engine) as db:
            response = Response(status_code=201)
            try:
                result = record_audit_event(body, response, db)
                item = {"status": response.status_code, "id": result["id"],
                        "variant": variant, "duplicate": result["duplicate"]}
            except HTTPException as exc:
                item = {"status": exc.status_code, "variant": variant}
            item["rollbacks"] = db.rollbacks
            return item

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(deliver, range(8)))
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT id,detail,occurred_at FROM audit_events WHERE event_key=:key"
        ), {"key": key}).mappings().all()
    require(len(rows) == 1, "Concurrent audit delivery did not retain exactly one row")
    stored = rows[0]
    successes = [item for item in results if item["status"] in (200, 201)]
    require(sum(item["status"] == 201 for item in results) == 1,
            "Expected one original audit creation")
    require(sum(item["rollbacks"] for item in results) == 7,
            "The forced race did not exercise seven native unique-conflict rollbacks")
    require(all(item["id"] == stored["id"] for item in successes),
            "Replay acknowledgements identify different audit rows")
    if mixed:
        require(len(successes) == 4 and sum(item["status"] == 409 for item in results) == 4,
                "Changed-content audit race did not preserve strict conflicts")
        require(all(item["variant"] == stored["detail"]["variant"] for item in successes),
                "Changed-content delivery was incorrectly acknowledged")
    else:
        require(len(successes) == 8, "Matching concurrent audit deliveries failed")

    # An ordinary later replay must also retain the first event time.
    with Session(bind=engine) as db:
        response = Response(status_code=201)
        result = record_audit_event(AuditEventIn(
            event_type="ACCEPTANCE_CONCURRENCY", event_key=key,
            detail=stored["detail"], occurred_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        ), response, db)
        require(response.status_code == 200 and result["id"] == stored["id"],
                "Later matching replay did not acknowledge the existing row")
    with engine.connect() as connection:
        retained = connection.execute(text(
            "SELECT occurred_at FROM audit_events WHERE event_key=:key"
        ), {"key": key}).scalar_one()
    require(retained == stored["occurred_at"], "Replay changed the original event time")
    return {"workers": 8, "results": results, "stored_id": stored["id"],
            "native_conflict_rollbacks": 7, "original_time_retained": True}


def counter_race(engine):
    from rule_lifecycle_manager import record_rule_outcome

    with engine.begin() as connection:
        rule = connection.execute(text(
            "INSERT INTO generated_rules(rule_yaml) VALUES ('counter-acceptance') RETURNING id"
        )).scalar_one()
    barrier = threading.Barrier(8, timeout=20)

    def update(index):
        barrier.wait()
        for _ in range(10):
            record_rule_outcome(rule, index % 2 == 0)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(8)))
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT true_positives,false_positives FROM rule_performance WHERE rule_id=:rule"
        ), {"rule": rule}).all()
    require(len(rows) == 1 and tuple(rows[0]) == (40, 40),
            "Concurrent rule outcomes lost increments or created duplicate rows")
    return {"workers": 8, "updates": 80, "performance_rows": 1,
            "true_positives": 40, "false_positives": 40}


def review_lock(engine):
    from fastapi import HTTPException
    from sqlalchemy.orm import Session
    from routes.rules import _review_session

    with engine.begin() as connection:
        rule = connection.execute(text(
            "INSERT INTO generated_rules(rule_yaml) VALUES ('review-acceptance') RETURNING id"
        )).scalar_one()
    with Session(bind=engine) as db:
        with _review_session(db, rule) as held:
            owner_pid = held.execute(text("SELECT pg_backend_pid()")).scalar_one()
            held.commit()
            # A second thread uses an independent session while the first is pinned.

            def compete():
                with Session(bind=engine) as other:
                    other_pid = other.execute(text("SELECT pg_backend_pid()")).scalar_one()
                    try:
                        with _review_session(other, rule):
                            raise CheckFailed("Competing review entered the held guard")
                    except HTTPException as exc:
                        require(exc.status_code == 409, "Unexpected competing review failure")
                    return other_pid

            with ThreadPoolExecutor(max_workers=1) as pool:
                contender_pid = pool.submit(compete).result(timeout=30)
            require(owner_pid != contender_pid, "Review test reused the owner's DB session")
            require(held.execute(text("SELECT pg_backend_pid()")).scalar_one() == owner_pid,
                    "Review connection was not pinned across commit")
            held.commit()
        with _review_session(db, rule) as released:
            released.execute(text("SELECT 1"))
            released.commit()

        class DeliberateFailure(Exception):
            pass
        try:
            with _review_session(db, rule):
                raise DeliberateFailure()
        except DeliberateFailure:
            pass
        with _review_session(db, rule) as released:
            released.execute(text("SELECT 1"))
            released.commit()
    return {"independent_sessions": True, "held_across_commit": True,
            "contender_status": 409, "reacquired_after_release": True,
            "reacquired_after_exception": True}


def run_worker(root, name):
    worker_target(os.environ.get("DATABASE_URL", ""), name)
    check_sources(root)
    sys.path[:0] = [str(root / "backend-api"), str(root / "rule-synthesis-engine")]
    from database import engine

    report: dict[str, Any] = {"passed": False, "checks": {}, "details": {}, "errors": []}
    try:
        with engine.connect() as connection:
            require(connection.execute(text("SELECT current_database()")).scalar_one() == name,
                    "Worker connected to an unexpected database")
            require(connection.execute(text("SHOW statement_timeout")).scalar_one() == "20s",
                    "Worker statement timeout is missing")
            require(connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 0,
                    "Worker database is not fresh")
        for label, function in (
            ("audit_matching_race", lambda: audit_race(engine)),
            ("audit_changed_content_race", lambda: audit_race(engine, mixed=True)),
            ("rule_counter_concurrency", lambda: counter_race(engine)),
            ("review_lock_concurrency", lambda: review_lock(engine)),
        ):
            print("Checking " + label + "...", flush=True)
            report["details"][label] = function()
            report["checks"][label] = True
        report["passed"] = True
    except Exception as exc:
        # Database error strings can include connection credentials or payloads.
        report["errors"].append(str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__)
    finally:
        engine.dispose()
        Path(os.environ["SELFSENTRY_CONCURRENCY_REPORT"]).write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return 0 if report["passed"] else 1


def run_parent(root):
    os.umask(0o077)
    check_sources(root)
    sys.path.insert(0, str(root / "backend-api"))
    from database import engine

    source = engine.url
    require(engine.dialect.name == "postgresql"
            and source.host in ("localhost", "127.0.0.1", "::1")
            and source.username and source.database, "Reviewed local PostgreSQL required")
    pg_environment(source, source.database)  # Refuse unreviewed libpq URL options.
    tools = {name: shutil.which(name) for name in ("sudo", "psql", "createdb", "dropdb")}
    require(all(tools.values()), "Required PostgreSQL administrator tools are missing")
    before = monitor_status()
    require(before.get("healthy") and type(before.get("pid")) is int,
            "A healthy monitor is required")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    folder = root / "state/evaluation" / ("postgres-concurrency-" + stamp)
    folder.mkdir(parents=True, mode=0o700)
    name = "ss_accept_" + uuid.uuid4().hex[:12] + "_migrate"
    owned = set()
    report: dict[str, Any] = {"passed": False, "checks": {}, "cleanup": {}, "errors": [],
                              "temporary_database": name}
    admin_env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    admin = [tools["sudo"], "-n", "-u", "postgres"]
    connection_args = ["--no-password", "--host=/var/run/postgresql",
                       "--port=" + str(source.port or 5432)]

    def command(argv, label, env, cwd="/tmp", timeout=60, check=True):
        completed = subprocess.run(argv, env=env, cwd=cwd, timeout=timeout,
                                   capture_output=True, text=True)
        (folder / (label + ".log")).write_text(completed.stdout + completed.stderr)
        require(not check or completed.returncode == 0,
                label + " failed; inspect its retained local log")
        return completed.stdout.strip()

    try:
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL statement_timeout = '10s'"))
            identity = connection.execute(text(IDENTITY)).scalar_one()
        admin_identity = command([
            *admin, tools["psql"], *connection_args, "--no-psqlrc", "--tuples-only",
            "--no-align", "--dbname=" + str(source.database), "--command=" + IDENTITY,
        ], "cluster-identity", admin_env)
        require(json.loads(admin_identity) == identity, "Administrator cluster identity differs")
        report["checks"]["same_local_cluster"] = True
        print("Creating a fresh temporary database...", flush=True)
        report["cleanup"][name] = "creation not confirmed; inspect before any removal"
        command([*admin, tools["createdb"], *connection_args, "--template=template0",
                 "--owner=" + str(source.username), name], "create", admin_env)
        owned.add(name)
        target = target_url(source, name, owned)
        env = dict(os.environ, DATABASE_URL=target.render_as_string(hide_password=False),
                   AUTO_ISOLATION_ENABLED="false",
                   SELFSENTRY_CONCURRENCY_REPORT=str(folder / "worker-results.json"))
        # Remove inherited libpq service/host options; explicit DATABASE_URL selects the target.
        env = {key: value for key, value in env.items() if not key.startswith("PG")}
        env["PGOPTIONS"] = "-c statement_timeout=20000 -c lock_timeout=10000"
        command([sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"),
                 "upgrade", "head"], "migrate", env, cwd=root, timeout=120)
        report["checks"]["fresh_migration"] = True
        print("Running native audit, counter and review-lock races...", flush=True)
        command([sys.executable, str(Path(__file__).resolve()), "--repo", str(root),
                 "--worker-name", name], "concurrency-worker", env, cwd=root,
                timeout=180, check=False)
        worker = json.loads((folder / "worker-results.json").read_text())
        report["checks"].update(worker["checks"])
        report["details"] = worker["details"]
        require(worker["passed"] and not worker["errors"],
                "Worker checks did not pass: " + "; ".join(worker["errors"]))
        report["checks"]["data_checks_passed"] = True
    except Exception as exc:
        report["errors"].append(str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__)
    finally:
        for database in owned:
            try:
                target_url(source, database, owned)
                command([*admin, tools["dropdb"], *connection_args, database], "cleanup", admin_env)
                report["cleanup"][database] = "removed"
            except Exception as exc:
                report["cleanup"][database] = "needs review"
                report["errors"].append("Temporary database cleanup: " + type(exc).__name__)
        try:
            after = monitor_status()
            report["checks"]["monitor_healthy_after"] = after.get("healthy") is True
            report["checks"]["monitor_not_restarted"] = after.get("pid") == before.get("pid")
            require(report["checks"]["monitor_healthy_after"]
                    and report["checks"]["monitor_not_restarted"],
                    "Live monitor health/PID changed")
        except Exception as exc:
            report["errors"].append("Monitor verification: " + type(exc).__name__)
        engine.dispose()
        report["passed"] = (not report["errors"]
                            and report["checks"].get("data_checks_passed") is True)
        (folder / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        summary = {key: report[key] for key in ("passed", "checks", "cleanup", "errors")}
        print(json.dumps(summary, indent=2))
        print("Evidence:", folder / "results.json")
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "selfsentry")
    parser.add_argument("--worker-name", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.repo.expanduser().resolve()
    if args.worker_name:
        return run_worker(root, args.worker_name)
    return run_parent(root)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise CheckFailed("Interrupted; attempting owned database cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except Exception as exc:
        message = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
        print("Stopped:", message, file=sys.stderr)
        raise SystemExit(2)
