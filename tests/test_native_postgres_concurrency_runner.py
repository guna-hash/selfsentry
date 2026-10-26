"""Test target boundaries and cleanup without requiring a PostgreSQL installation."""

import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
import verify_postgres_concurrency as check  # noqa: E402

NAME = "ss_accept_012345abcdef_migrate"
SOURCE = make_url("postgresql+psycopg2://operator:private@localhost:5432/selfsentry_db")


@pytest.mark.parametrize("name,url", [
    ("selfsentry_db", SOURCE),
    (NAME, SOURCE),
    (NAME, SOURCE.set(database=NAME, host="remote.example")),
    (NAME, make_url("sqlite://")),
    ("ss_accept_bad_migrate", SOURCE.set(database="ss_accept_bad_migrate")),
])
def test_worker_refuses_wrong_or_unreviewed_target(name, url):
    with pytest.raises(check.CheckFailed):
        check.worker_target(str(url), name)


def test_worker_accepts_exact_disposable_target():
    target = SOURCE.set(database=NAME)
    assert check.worker_target(target.render_as_string(hide_password=False), NAME) == target


def test_ownership_guard_refuses_active_and_unknown_databases():
    with pytest.raises(check.CheckFailed):
        check.target_url(SOURCE, SOURCE.database, {SOURCE.database})
    with pytest.raises(check.CheckFailed):
        check.target_url(SOURCE, NAME, set())
    assert check.target_url(SOURCE, NAME, {NAME}).database == NAME


def test_source_hashes_detect_modified_files(tmp_path, monkeypatch):
    script = tmp_path / "package/verify_concurrency.py"
    script.parent.mkdir()
    (script.parent / "source-hashes.json").write_text(json.dumps({"source.py": "wrong"}))
    (tmp_path / "source.py").write_text("changed")
    monkeypatch.setattr(check, "__file__", str(script))
    with pytest.raises(check.CheckFailed, match="Source differs"):
        check.check_sources(tmp_path)


class Connection:
    def __init__(self):
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, statement):
        self.statements.append(str(statement))
        return SimpleNamespace(scalar_one=lambda: {"cluster": "same"})


@pytest.fixture
def harness(tmp_path, monkeypatch):
    connection = Connection()
    engine = SimpleNamespace(url=SOURCE, dialect=SimpleNamespace(name="postgresql"),
                             connect=lambda: connection, dispose=lambda: None)
    monkeypatch.setitem(sys.modules, "database", SimpleNamespace(engine=engine))
    monkeypatch.setattr(check, "check_sources", lambda root: None)
    monkeypatch.setattr(check.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(check, "monitor_status", lambda: {"healthy": True, "pid": 123})
    monkeypatch.setattr(check.uuid, "uuid4", lambda: SimpleNamespace(hex="012345abcdef0000"))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--worker-name" in argv:
            target = make_url(kwargs["env"]["DATABASE_URL"])
            assert target.database == NAME and target != SOURCE
            assert kwargs["env"]["PGOPTIONS"] == (
                "-c statement_timeout=20000 -c lock_timeout=10000"
            )
            assert kwargs["timeout"] == 180
            Path(kwargs["env"]["SELFSENTRY_CONCURRENCY_REPORT"]).write_text(json.dumps({
                "passed": True, "checks": {"worker_passed": True}, "details": {}, "errors": [],
            }))
        if "--command=" + check.IDENTITY in argv:
            stdout = json.dumps({"cluster": "same"})
        else:
            stdout = ""
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(check.subprocess, "run", run)
    return tmp_path, connection, calls, run


def test_parent_only_writes_owned_database_and_preserves_monitor(harness):
    root, connection, calls, _ = harness
    assert check.run_parent(root) == 0
    assert connection.statements[0] == "SET TRANSACTION READ ONLY"
    assert all("INSERT" not in query and "UPDATE" not in query
               for query in connection.statements)
    create = next(argv for argv, _ in calls if "/usr/bin/createdb" in argv)
    drop = next(argv for argv, _ in calls if "/usr/bin/dropdb" in argv)
    assert create[-1] == drop[-1] == NAME
    assert "--force" not in drop
    assert not any("systemctl" in str(argv) or "docker" in str(argv) for argv, _ in calls)
    for argv, options in calls:
        assert "private" not in " ".join(argv)
        assert options["timeout"] > 0
    report = json.loads(next((root / "state/evaluation").glob("*/results.json")).read_text())
    assert report["passed"] and report["cleanup"] == {NAME: "removed"}


def test_worker_timeout_still_cleans_only_owned_database(harness, monkeypatch):
    root, _, calls, original = harness

    def timeout(argv, **kwargs):
        if "--worker-name" in argv:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return original(argv, **kwargs)

    monkeypatch.setattr(check.subprocess, "run", timeout)
    assert check.run_parent(root) == 1
    assert any("/usr/bin/dropdb" in argv and argv[-1] == NAME for argv, _ in calls)
    report = json.loads(next((root / "state/evaluation").glob("*/results.json")).read_text())
    assert not report["passed"] and report["cleanup"][NAME] == "removed"


def test_wrong_cluster_stops_before_creation(harness, monkeypatch):
    root, _, calls, original = harness

    def wrong_cluster(argv, **kwargs):
        if "--command=" + check.IDENTITY in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"cluster": "different"}), "")
        return original(argv, **kwargs)

    monkeypatch.setattr(check.subprocess, "run", wrong_cluster)
    assert check.run_parent(root) == 1
    assert not any("/usr/bin/createdb" in argv or "/usr/bin/dropdb" in argv for argv, _ in calls)


def test_failed_creation_does_not_drop_an_unowned_database(harness, monkeypatch):
    root, _, calls, original = harness

    def failure(argv, **kwargs):
        if "/usr/bin/createdb" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "creation failed")
        return original(argv, **kwargs)

    monkeypatch.setattr(check.subprocess, "run", failure)
    assert check.run_parent(root) == 1
    assert not any("/usr/bin/dropdb" in argv for argv, _ in calls)


def test_pg_environment_does_not_inherit_target_overrides(monkeypatch):
    monkeypatch.setenv("PGSERVICE", "unreviewed")
    monkeypatch.setenv("PGHOST", "remote.example")
    env = check.pg_environment(SOURCE, NAME)
    assert "PGSERVICE" not in env
    assert env["PGHOST"] == "localhost" and env["PGDATABASE"] == NAME
    assert env["PGPASSWORD"] == "private"
