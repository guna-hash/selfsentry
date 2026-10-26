"""Real SQLite publication, old checkpoint replay and evidence-reader regressions."""

from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "monitor-service"))
sys.path.insert(0, str(ROOT / "tests"))
from journal_archive import (  # noqa: E402
    ArchiveError, SCHEMA, archive_batch, candidates, event_rows, seen_event,
)
from test_behavior_pipeline import event, setup, START, CID  # noqa: E402


def database(tmp_path):
    db = sqlite3.connect(tmp_path / "pipeline.sqlite")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE events (key TEXT PRIMARY KEY, container TEXT, bucket INTEGER,
                             kind TEXT, body TEXT);
        CREATE TABLE windows (container TEXT,bucket INTEGER,PRIMARY KEY(container,bucket));
    """ + SCHEMA)
    with db:
        db.executemany("INSERT INTO windows VALUES (?,?)", [(CID, 60), (CID, 120)])
        db.executemany("INSERT INTO events VALUES (?,?,?,?,?)", [
            ("old", CID, 60, "baseline", '{"original": "  exact \\u2603 "}'),
            ("alert", CID, 60, "alert", '{"priority":"Warning"}'),
            ("new", CID, 120, "baseline", '{}'),
            ("open", CID, 0, "baseline", '{}'),
        ])
    return db


def original_rows(db):
    return sorted(event_rows(db, CID, 0, 999))


def test_exact_readback_protected_alert_open_and_recent_windows(tmp_path):
    with closing(database(tmp_path)) as db:
        expected = original_rows(db)
        report = archive_batch(db, 120, 60)
        assert report["archived"] == 1
        assert original_rows(db) == expected
        assert seen_event(db, "old")
        assert db.execute("SELECT key FROM events ORDER BY key").fetchall() == [
            ("alert",), ("new",), ("open",)
        ]
        assert db.execute("SELECT count(*) FROM windows").fetchone() == (2,)
        assert (tmp_path / "journal-archives" / report["archive"]).stat().st_mode & 0o777 == 0o600
        assert archive_batch(db, 120, 60) == {"archived": 0}
        assert archive_batch(db, 180, 60)["archived"] == 1
        assert original_rows(db) == expected


@pytest.mark.parametrize("phase", ["before_publication", "after_publication", "before_commit"])
def test_failures_preserve_source_and_retry_without_duplicates(tmp_path, phase):
    with closing(database(tmp_path)) as db:
        expected = original_rows(db)

        def fault(stage):
            if stage == phase:
                raise OSError("simulated full disk or interrupted publication")

        with pytest.raises(OSError):
            archive_batch(db, 120, 60, fault=fault)
        assert original_rows(db) == expected
        assert db.execute("SELECT count(*) FROM events").fetchone() == (4,)
        assert db.execute("SELECT count(*) FROM archived_events").fetchone() == (0,)
        assert archive_batch(db, 120, 60)["archived"] == 1
        assert original_rows(db) == expected


@pytest.mark.parametrize("phase", ["after_publication", "before_commit", "after_commit"])
def test_process_death_publication_recovery(tmp_path, phase):
    with closing(database(tmp_path)) as db:
        expected = original_rows(db)
    code = """
import os, sqlite3, sys
from journal_archive import archive_batch
db = sqlite3.connect(sys.argv[1])
def fault(stage):
    if stage == sys.argv[2]: os._exit(71)
archive_batch(db, 120, 60, fault=fault)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path / "pipeline.sqlite"), phase],
        env=dict(os.environ, PYTHONPATH=str(ROOT / "monitor-service")), timeout=15,
    )
    assert result.returncode == 71
    with closing(sqlite3.connect(tmp_path / "pipeline.sqlite")) as db:
        assert original_rows(db) == expected
        assert seen_event(db, "old")
        assert archive_batch(db, 120, 60)["archived"] == (0 if phase == "after_commit" else 1)
        assert original_rows(db) == expected


@pytest.mark.parametrize("problem", ["missing", "corrupt", "symlink", "index", "catalog"])
def test_missing_or_changed_archive_refuses_partial_evidence(tmp_path, problem):
    with closing(database(tmp_path)) as db:
        report = archive_batch(db, 120, 60)
        path = tmp_path / "journal-archives" / report["archive"]
        if problem == "missing":
            path.unlink()
        elif problem == "corrupt":
            with path.open("r+b") as stream:
                stream.write(b"broken")
        elif problem == "symlink":
            moved = path.with_suffix(".moved")
            path.rename(moved)
            path.symlink_to(moved)
        elif problem == "index":
            with db:
                db.execute("UPDATE archived_events SET body_sha256='changed'")
        else:
            with db:
                db.execute("DELETE FROM event_archives")
        with pytest.raises(ArchiveError):
            original_rows(db)
        # Replay identities are still known, without reprocessing a missing body.
        assert seen_event(db, "old")
        assert not seen_event(db, "unseen")


def test_live_snapshot_survives_concurrent_archive_publication(tmp_path):
    with closing(database(tmp_path)) as writer:
        expected = original_rows(writer)
        with closing(sqlite3.connect(tmp_path / "pipeline.sqlite")) as reader:
            iterator = event_rows(reader, CID, 0, 999)
            first = next(iterator)  # Pins the old view before live-row removal.
            archive_batch(writer, 120, 60)
            assert sorted([first, *iterator]) == expected
        assert original_rows(writer) == expected


def test_real_pipeline_replay_does_not_repeat_late_event_or_lifecycle_change(tmp_path):
    pipe, clock, audit = setup(tmp_path)
    try:
        first = event(key="archived-replay")
        pipe.handle_baseline_event(first)
        clock[0] = START + 130
        pipe.tick()
        original = sorted(event_rows(pipe.db, CID, START, START + 60))
        archive_batch(pipe.db, START + 60, 60)
        audits = list(audit.items)
        pipe.close()
        # Rebuild the monitor pipeline from disk, then replay an old checkpoint.
        from behavior_pipeline import BehaviorPipeline
        from monitor_status import StatusBoard
        pipe = BehaviorPipeline(pipe.config, StatusBoard(tmp_path / "status.json"), audit,
                                clock=lambda: clock[0])
        lifecycle = json.loads(json.dumps(pipe.lifecycle))
        pipe.handle_baseline_event(first)
        assert pipe.lifecycle == lifecycle
        assert audit.items == audits
        assert pipe.db.execute("SELECT count(*) FROM events").fetchone() == (0,)
        assert sorted(event_rows(pipe.db, CID, START, START + 60)) == original
        # New late security evidence still enters the live journal and outbox.
        pipe.handle_alert(event(key="late-security", security=True))
        assert pipe.db.execute("SELECT kind FROM events").fetchall() == [("alert",)]
        assert pipe.db.execute("SELECT key FROM outbox WHERE key='late-security'").fetchone()
    finally:
        pipe.close()


def test_plan_and_old_schema_read_do_not_mutate_database(tmp_path):
    with closing(database(tmp_path)) as db:
        with db:
            db.execute("DROP TABLE archived_events")
            db.execute("DROP TABLE event_archives")
        expected = original_rows(db)
        assert len(candidates(db, 120, 60)) == 1
        assert original_rows(db) == expected
        assert seen_event(db, "old")
        with pytest.raises(ArchiveError, match="updated monitor"):
            archive_batch(db, 120, 60)


def test_apply_rollback_on_retained_identity_conflict(tmp_path):
    with closing(database(tmp_path)) as db:
        with db:
            db.execute("INSERT INTO archived_events VALUES (?,?,?,?,?,?)",
                       ("old", CID, 60, "baseline", "missing", "missing"))
        with pytest.raises(sqlite3.IntegrityError):
            archive_batch(db, 120, 60)
        assert db.execute("SELECT count(*) FROM events").fetchone() == (4,)
        assert db.execute("SELECT count(*) FROM event_archives").fetchone() == (0,)


@pytest.mark.parametrize("limit", [0, 5001])
def test_invalid_batch_size(tmp_path, limit):
    with closing(database(tmp_path)) as db:
        with pytest.raises(ArchiveError):
            candidates(db, 120, 60, limit)


def test_cli_plan_runs_live_but_apply_refuses_owner_without_truncating_pid(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "archive_journal.py").write_bytes((ROOT / "scripts/archive_journal.py").read_bytes())
    modules = tmp_path / "monitor-service"
    modules.mkdir()
    (modules / "journal_archive.py").write_bytes(
        (ROOT / "monitor-service/journal_archive.py").read_bytes()
    )
    (modules / "monitor_config.py").write_text(
        "from types import SimpleNamespace\nfrom pathlib import Path\n"
        "def load_config(): return SimpleNamespace(state_dir=Path.cwd(), window_seconds=60)\n"
    )
    with closing(database(tmp_path)) as db:
        expected = original_rows(db)
        lock_path = tmp_path / "monitor.lock"
        lock_path.write_text("12345")
        command = [sys.executable, str(scripts / "archive_journal.py"),
                   "--before", "1970-01-01T00:02:00+00:00"]
        with lock_path.open("a+") as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            plan = subprocess.run(command, capture_output=True, text=True, timeout=10)
            assert plan.returncode == 0, plan.stderr
            assert json.loads(plan.stdout)["candidate_rows"] == 1
            refused = subprocess.run(command + ["--apply"], capture_output=True,
                                     text=True, timeout=10)
            assert refused.returncode != 0 and "Stop the monitor" in refused.stderr
        assert lock_path.read_text() == "12345"
        assert original_rows(db) == expected
        assert not (tmp_path / "journal-archives").exists()
