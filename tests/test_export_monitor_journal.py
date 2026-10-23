"""Real disposable SQLite snapshots, including concurrent WAL writes and failure boundaries."""

from contextlib import closing
import sqlite3
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
import export_monitor_journal as exporter  # noqa: E402


def test_export_copies_and_verifies_referenced_archives(tmp_path):
    from journal_archive import archive_batch, event_rows
    from test_journal_archive import database

    live = tmp_path / "live"
    live.mkdir()
    with closing(database(live)) as db:
        expected = sorted(event_rows(db, "a" * 12, 0, 999))
        archive_batch(db, 120, 60)
    output = tmp_path / "output"
    output.mkdir()
    result = exporter.snapshot(live / "pipeline.sqlite", output / "pipeline.sqlite")
    assert result["archive_readback_matches"] and len(result["archives"]) == 1
    with closing(sqlite3.connect(output / "pipeline.sqlite")) as db:
        assert sorted(event_rows(db, "a" * 12, 0, 999)) == expected
    for path in (live / "journal-archives").iterdir():
        path.unlink()
    with closing(sqlite3.connect(output / "pipeline.sqlite")) as db:
        assert sorted(event_rows(db, "a" * 12, 0, 999)) == expected


def test_missing_archive_cannot_produce_a_successful_export(tmp_path):
    from journal_archive import archive_batch, ArchiveError
    from test_journal_archive import database

    live = tmp_path / "live"
    live.mkdir()
    with closing(database(live)) as db:
        report = archive_batch(db, 120, 60)
    (live / "journal-archives" / report["archive"]).unlink()
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(ArchiveError):
        exporter.snapshot(live / "pipeline.sqlite", output / "pipeline.sqlite")


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "source.sqlite"
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript('''
            CREATE TABLE samples(a,b);
            CREATE TABLE "quoted""table"(value TEXT);
            CREATE TABLE sequence_test(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT);
            CREATE INDEX sample_index ON samples(a);
            INSERT INTO "quoted""table" VALUES ('retained');
            INSERT INTO sequence_test(value) VALUES ('sequence-retained');
            PRAGMA user_version=7;
            PRAGMA application_id=42;
        ''')
        db.executemany("INSERT INTO samples VALUES (?,?)", [
            (None, b"\x00\xff"), (None, b"\x00\xff"), (1, 1.0), (1.0, 1),
            ("unicode \u2603", "text"),
        ])
    return path


def values(path):
    with closing(sqlite3.connect(path)) as db:
        return db.execute("SELECT * FROM samples").fetchall()


def test_export_verifies_schema_types_duplicates_and_readback(source, tmp_path):
    before = values(source)
    destination = tmp_path / "export.sqlite"
    result = exporter.snapshot(source, destination)
    assert result["data_verified"] and result["readback_matches"]
    assert result["fingerprints"]["tables"]["samples"]["rows"] == 5
    assert result["fingerprints"]["user_version"] == 7
    assert result["fingerprints"]["application_id"] == 42
    assert result["export_sha256"] == exporter.file_sha(destination)
    assert values(source) == before == values(destination)
    assert destination.stat().st_mode & 0o777 == 0o600


def test_concurrent_wal_write_does_not_change_the_held_export_snapshot(
    source, tmp_path, monkeypatch
):
    real_copy = exporter.copy_snapshot

    def writer_during_export(connection, destination, deadline):
        with closing(sqlite3.connect(source)) as writer, writer:
            writer.execute("INSERT INTO samples VALUES ('new','after-snapshot')")
        real_copy(connection, destination, deadline)

    monkeypatch.setattr(exporter, "copy_snapshot", writer_during_export)
    destination = tmp_path / "export.sqlite"
    result = exporter.snapshot(source, destination)
    assert result["readback_matches"]
    assert len(values(source)) == 6 and len(values(destination)) == 5


def test_committed_source_wal_rows_are_in_the_single_exported_file(source, tmp_path):
    destination = tmp_path / "export.sqlite"
    with closing(sqlite3.connect(source)) as writer:
        writer.execute("INSERT INTO samples VALUES ('committed','in-wal')")
        writer.commit()
        assert source.with_name(source.name + "-wal").stat().st_size > 0
        result = exporter.snapshot(source, destination)
        assert result["single_file_readback_matches"]
        with closing(exporter.readonly(destination, time.monotonic() + 5,
                                       immutable=True)) as db:
            assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 6


def test_fingerprints_preserve_duplicate_multiplicity_and_value_types():
    assert exporter.digest_rows([(1,)]) != exporter.digest_rows([(1.0,)])
    assert exporter.digest_rows([(1,)]) != exporter.digest_rows([(1,), (1,)])
    assert exporter.digest_rows([(1,), (2,)]) == exporter.digest_rows([(2,), (1,)])
    assert exporter.digest_rows([(b"a",)]) != exporter.digest_rows([("a",)])


def test_source_connection_cannot_write(source):
    with closing(exporter.readonly(source, time.monotonic() + 5)) as db:
        with pytest.raises(sqlite3.OperationalError):
            db.execute("DELETE FROM samples")
    assert len(values(source)) == 5


def test_existing_destination_is_never_overwritten(source, tmp_path):
    destination = tmp_path / "export.sqlite"
    destination.write_bytes(b"retained existing file")
    with pytest.raises(exporter.ExportFailed, match="target exists"):
        exporter.snapshot(source, destination)
    assert destination.read_bytes() == b"retained existing file"


def test_source_cannot_be_its_own_destination(source):
    with pytest.raises(exporter.ExportFailed, match="its export target"):
        exporter.snapshot(source, source)
    assert len(values(source)) == 5


def test_symlink_destination_is_refused(source, tmp_path):
    destination = tmp_path / "export.sqlite"
    destination.symlink_to(tmp_path / "absent-target")
    with pytest.raises(exporter.ExportFailed, match="target exists"):
        exporter.snapshot(source, destination)
    assert not (tmp_path / "absent-target").exists()


def test_wrong_readback_is_rejected_without_changing_source(source, tmp_path, monkeypatch):
    real_copy = exporter.copy_snapshot

    def corrupt_readback(connection, destination, deadline):
        real_copy(connection, destination, deadline)
        with closing(sqlite3.connect(destination)) as changed, changed:
            changed.execute("UPDATE samples SET b='wrong'")

    monkeypatch.setattr(exporter, "copy_snapshot", corrupt_readback)
    before = values(source)
    with pytest.raises(exporter.ExportFailed, match="fingerprints differ"):
        exporter.snapshot(source, tmp_path / "export.sqlite")
    assert values(source) == before


def test_database_size_limit_stops_before_copy(source, tmp_path, monkeypatch):
    monkeypatch.setattr(exporter, "MAX_DATABASE_BYTES", 1)
    destination = tmp_path / "export.sqlite"
    with pytest.raises(exporter.ExportFailed, match="size limit"):
        exporter.snapshot(source, destination)
    assert not destination.exists()


def test_row_limit_stops_before_copy(source, tmp_path, monkeypatch):
    monkeypatch.setattr(exporter, "MAX_TABLE_ROWS", 2)
    destination = tmp_path / "export.sqlite"
    with pytest.raises(exporter.ExportFailed, match="row limit"):
        exporter.snapshot(source, destination)
    assert not destination.exists()


def test_cell_limit_is_enforced_by_sqlite_before_python_decodes_it(source, monkeypatch):
    with closing(sqlite3.connect(source)) as db, db:
        db.execute("INSERT INTO samples VALUES (?,?)", ("x" * 1000, "large"))
    monkeypatch.setattr(exporter, "MAX_CELL_BYTES", 100)
    with closing(exporter.readonly(source, time.monotonic() + 5)) as db:
        with pytest.raises(sqlite3.DataError):
            db.execute("SELECT a FROM samples").fetchall()


def test_insufficient_space_refuses_copy(source, tmp_path, monkeypatch):
    monkeypatch.setattr(exporter.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    destination = tmp_path / "export.sqlite"
    with pytest.raises(exporter.ExportFailed, match="free space"):
        exporter.snapshot(source, destination)
    assert not destination.exists()


def test_expired_copy_deadline_retains_failure_without_pruning(source, tmp_path):
    before = values(source)
    destination = tmp_path / "export.sqlite"
    with closing(exporter.readonly(source, time.monotonic() + 5)) as db:
        db.execute("BEGIN")
        with pytest.raises(exporter.ExportFailed, match="export deadline"):
            exporter.copy_snapshot(db, destination, time.monotonic() - 1)
        db.rollback()
    assert values(source) == before


def test_output_inside_the_project_is_refused_before_contacting_services(tmp_path, monkeypatch):
    def no_contact():
        pytest.fail("A refused output path contacted the backend")

    monkeypatch.setattr(exporter, "monitor_status", no_contact)
    with pytest.raises(exporter.ExportFailed, match="outside the project"):
        exporter.run(tmp_path, tmp_path / "state/exports")


def test_byte_hash_reads_the_file_without_loading_all_of_it(tmp_path):
    import hashlib

    path = tmp_path / "data"
    path.write_bytes(b"known-data" * 200000)
    assert exporter.file_sha(path) == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def project(source, tmp_path, monkeypatch):
    root = tmp_path / "project"
    (root / "monitor-service").mkdir(parents=True)
    (root / "monitor-service/monitor_config.py").write_text("# fixture configuration\n")
    state = root / "state/monitor"
    state.mkdir(parents=True)
    (state / "pipeline.sqlite").write_bytes(source.read_bytes())
    (state / "monitor.lock").write_text("123")
    config = SimpleNamespace(state_dir=state)
    monkeypatch.setitem(sys.modules, "monitor_config", SimpleNamespace(load_config=lambda: config))
    return root, state, tmp_path / "exports"


def test_full_export_records_private_manifest_and_successful_service_checks(project, monkeypatch):
    import json

    root, _, output = project
    monkeypatch.setattr(exporter, "monitor_status", lambda: {"healthy": True, "pid": 123})
    assert exporter.run(root, output) == 0
    path = next(output.glob("*/manifest.json"))
    report = json.loads(path.read_text())
    assert report["passed"] and report["data_verified"] and report["monitor_not_restarted"]
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_post_export_health_failure_is_not_reported_as_overall_success(project, monkeypatch):
    import json

    root, state, output = project
    responses = iter([{"healthy": True, "pid": 123}, {"healthy": False, "pid": 123}])
    monkeypatch.setattr(exporter, "monitor_status", lambda: next(responses))
    assert exporter.run(root, output) == 1
    report = json.loads(next(output.glob("*/manifest.json")).read_text())
    assert report["data_verified"] and not report["passed"]
    assert len(values(state / "pipeline.sqlite")) == 5


def test_wrong_monitor_state_pid_stops_before_creating_an_export(project, monkeypatch):
    root, _, output = project
    monkeypatch.setattr(exporter, "monitor_status", lambda: {"healthy": True, "pid": 456})
    with pytest.raises(exporter.ExportFailed, match="running monitor"):
        exporter.run(root, output)
    assert not output.exists()
