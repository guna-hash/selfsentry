"""Exercise archival on a disposable copy of an already verified journal export."""

import argparse
from typing import Any
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

import requests


def status():
    response = requests.get("http://127.0.0.1:8000/monitor/status", timeout=10)
    response.raise_for_status()
    result = response.json()
    if result.get("healthy") is not True:
        raise ValueError("Healthy live monitor required for before/after observation")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "selfsentry")
    parser.add_argument("--snapshot", type=Path, required=True,
                        help="Private pre-archive export directory with manifest.json")
    parser.add_argument("--offline", action="store_true", help="Local fixture validation only")
    parser.add_argument("--max-database-mib", type=int, default=512)
    parser.add_argument("--max-table-rows", type=int, default=100000)
    parser.add_argument("--deadline-seconds", type=int, default=120,
                        help="Export snapshot deadline; not a whole-verifier deadline")
    args = parser.parse_args()
    root, original = args.repo.expanduser().resolve(), args.snapshot.expanduser().resolve()
    sys.path[:0] = [str(root / "monitor-service"), str(root / "scripts")]
    import export_monitor_journal as exporter
    limits = exporter.limits_from_args(args)
    with exporter.export_limits(limits):
        return verify(root, original, args.offline)


def verify(root, original, offline):
    from journal_archive import (SCHEMA, ArchiveError, archive_batch, candidates,
                                 event_rows, seen_event)
    from export_monitor_journal import fingerprint, digest_rows, snapshot

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    manifest = json.loads((original / "manifest.json").read_text())
    source = original / "pipeline.sqlite"
    from export_monitor_journal import current_limits, limit_record
    if source.stat().st_size > current_limits().database_bytes:
        raise ValueError("Source export exceeds selected byte limit")
    with source.open("rb") as stream:
        original_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    require(manifest.get("passed") is True and manifest.get("data_verified") is True,
            "An already verified export is required")
    require(original_sha == manifest.get("export_sha256"), "Source export checksum differs")
    before = {} if offline else status()
    report: dict[str, Any] = {
        "passed": False, "checks": {}, "errors": [],
        "export_limits": limit_record(),
        "source_export_sha256": original_sha, "live_rows_changed": False,
        "scope": "disposable-copy archive/readback; no live retention applied"}

    def logical(db):
        containers = db.execute(
            "SELECT container FROM events UNION SELECT container FROM archived_events"
        ).fetchall()
        return {cid: digest_rows(event_rows(db, cid, -(2**62), 2**62)) for (cid,) in containers}

    try:
        with tempfile.TemporaryDirectory(prefix="selfsentry-archive-check-") as temp:
            work = Path(temp)
            live = work / "pipeline.sqlite"
            with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
                # Monitor startup creates empty archive metadata tables. Only
                # populated metadata requires an archive-aware source-copy runner.
                for table in ("archived_events", "event_archives"):
                    exists = src.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()
                    require(not exists or not src.execute(
                        f"SELECT 1 FROM {table} LIMIT 1").fetchone(),
                        "Use an export with no existing archived rows or archive references")
                with closing(sqlite3.connect(live)) as db:
                    src.backup(db)
            with closing(sqlite3.connect(live)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript(SCHEMA)
                expected = logical(db)
                protected = {name: value for name, value in fingerprint(db)["tables"].items()
                             if name not in ("events", "archived_events", "event_archives")}
                alerts = digest_rows(db.execute("SELECT * FROM events WHERE kind!='baseline'"))
                end = db.execute("SELECT max(bucket) FROM windows").fetchone()[0]
                require(end is not None, "No closed windows available")
                selected = candidates(db, end + 60, 60, 1000)
                require(bool(selected), "No eligible baseline payloads in the snapshot")
                result = archive_batch(db, end + 60, 60, 1000)
                report["archived_on_copy"] = result["archived"]
                report["checks"]["all_logical_events_match"] = logical(db) == expected
                report["checks"]["all_replay_keys_retained"] = all(
                    seen_event(db, row[0]) for row in selected)
                actual = fingerprint(db)["tables"]
                report["checks"]["protected_tables_unchanged"] = all(
                    actual[name] == value for name, value in protected.items())
                report["checks"]["alerts_unchanged"] = alerts == digest_rows(db.execute(
                    "SELECT * FROM events WHERE kind!='baseline'"))
                report["checks"]["repeat_has_no_duplicate_identity"] = not any(
                    db.execute("SELECT 1 FROM events WHERE key=?", (row[0],)).fetchone()
                    for row in selected)
                cold = work / "journal-archives" / result["archive"]
                hidden = cold.with_suffix(".hidden")
                cold.rename(hidden)
                try:
                    logical(db)
                except ArchiveError:
                    report["checks"]["missing_archive_refuses_evidence"] = True
                else:
                    report["checks"]["missing_archive_refuses_evidence"] = False
                finally:
                    hidden.rename(cold)
            with closing(sqlite3.connect(live)) as db:
                report["checks"]["reopen_preserves_events"] = logical(db) == expected
            output = work / "export"
            output.mkdir(mode=0o700)
            exported = snapshot(live, output / "pipeline.sqlite")
            report["checks"]["archive_aware_export_verified"] = (
                exported["data_verified"] and exported["archive_readback_matches"])
            with closing(sqlite3.connect(output / "pipeline.sqlite")) as db:
                report["checks"]["exported_logical_events_match"] = logical(db) == expected
        report["checks"]["temporary_copy_removed"] = not work.exists()
        with source.open("rb") as stream:
            report["checks"]["source_snapshot_unchanged"] = (
                hashlib.file_digest(stream, "sha256").hexdigest() == original_sha)
        if not offline:
            after = status()
            report["checks"]["monitor_healthy_after"] = after.get("healthy") is True
            report["checks"]["monitor_not_restarted"] = after.get("pid") == before.get("pid")
        report["passed"] = all(report["checks"].values())
    except Exception as exc:
        report["errors"].append(str(exc))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = root / "state/evaluation" / f"journal-archive-check-{stamp}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))
    print("Evidence:", path)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
