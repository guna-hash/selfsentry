"""Native acceptance wrapper runs against a disposable pre-archive fixture."""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

ROOT = Path(os.environ.get("SELFSENTRY_TEST_REPO", str(Path(__file__).resolve().parents[1])))


@pytest.mark.parametrize("larger_limits", [False, True])
@pytest.mark.parametrize("archive_state", ["legacy", "empty", "archived_events", "event_archives"])
def test_disposable_acceptance_and_original_snapshot_preservation(
    tmp_path, archive_state, larger_limits
):
    project = tmp_path / "project"
    project.mkdir()
    (project / "monitor-service").symlink_to(ROOT / "monitor-service", target_is_directory=True)
    (project / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
    source = tmp_path / "original"
    source.mkdir()
    path = source / "pipeline.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.executescript("""
            CREATE TABLE events(key TEXT PRIMARY KEY,container TEXT,bucket INTEGER,
                                kind TEXT,body TEXT);
            CREATE TABLE windows(container TEXT,bucket INTEGER);
            CREATE TABLE lifecycle(container TEXT,body TEXT);
            INSERT INTO events VALUES ('baseline','aaaaaaaaaaaa',60,'baseline','{}');
            INSERT INTO events VALUES ('alert','aaaaaaaaaaaa',60,'alert','{}');
            INSERT INTO windows VALUES ('aaaaaaaaaaaa',60);
            INSERT INTO lifecycle VALUES ('aaaaaaaaaaaa','{}');
        """)
    if archive_state != "legacy":
        sys.path.insert(0, str(ROOT / "monitor-service"))
        from journal_archive import SCHEMA

        with closing(sqlite3.connect(path)) as db:
            db.executescript(SCHEMA)
            if archive_state == "event_archives":
                db.execute("INSERT INTO event_archives VALUES ('existing.sqlite', 'hash', 1)")
            elif archive_state == "archived_events":
                db.execute("INSERT INTO archived_events VALUES "
                           "('old', 'aaaaaaaaaaaa', 0, 'baseline', 'existing.sqlite', 'hash')")
            db.commit()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (source / "manifest.json").write_text(json.dumps({
        "passed": True, "data_verified": True, "export_sha256": digest,
    }))
    script = Path(__file__).resolve().parents[1] / "evaluation/verify_archive_copy.py"
    command = [
        sys.executable, str(script), "--repo", str(project), "--snapshot", str(source),
        "--offline",
    ]
    if larger_limits:
        command += ["--max-database-mib", "1024", "--max-table-rows", "500000",
                    "--deadline-seconds", "600"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    report = json.loads(next((project / "state/evaluation").glob("*.json")).read_text())
    assert report["export_limits"]["table_rows"] == (500000 if larger_limits else 100000)
    if archive_state in ("archived_events", "event_archives"):
        assert result.returncode == 1
        assert report["passed"] is False
        assert "no existing archived rows or archive references" in report["errors"][0]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        return
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["passed"] and all(report["checks"].values())
    assert report["live_rows_changed"] is False
    assert "monitor_healthy_after" not in report["checks"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
