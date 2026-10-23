"""Manual baseline payload archives; replay identities and closed windows stay live.

Publish and sync an immutable archive before the live transaction references it.
A crash before that commit can leave an unreferenced file, never missing payloads.
Archives are application evidence, not disposable caches or whole-app backups.
"""

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid


SCHEMA = """
CREATE TABLE IF NOT EXISTS event_archives (
    name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, row_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS archived_events (
    key TEXT PRIMARY KEY, container TEXT NOT NULL, bucket INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind='baseline'), archive TEXT NOT NULL,
    body_sha256 TEXT NOT NULL, FOREIGN KEY(archive) REFERENCES event_archives(name));
CREATE INDEX IF NOT EXISTS archived_events_window ON archived_events(container,bucket);
"""
MAX_ROWS = 5000
MAX_BODY = 4 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024


class ArchiveError(ValueError):
    """Archive verification or a preservation precondition failed."""


def has_archives(db):
    return bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='archived_events'"
    ).fetchone())


def seen_event(db, key):
    if db.execute("SELECT 1 FROM events WHERE key=?", (key,)).fetchone():
        return True
    return has_archives(db) and bool(db.execute(
        "SELECT 1 FROM archived_events WHERE key=?", (key,)
    ).fetchone())


def body_digest(body):
    if not isinstance(body, str) or len(body.encode()) > MAX_BODY:
        raise ArchiveError("Event body is missing or exceeds the archive limit")
    json.loads(body)
    return hashlib.sha256(body.encode()).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def state_directory(db):
    path = db.execute("PRAGMA database_list").fetchone()[2]
    if not path:
        raise ArchiveError("A file-backed journal is required")
    return Path(path).resolve().parent


@contextmanager
def read_snapshot(db):
    owned = not db.in_transaction
    if owned:
        db.execute("BEGIN")
    try:
        yield
    finally:
        if owned:
            db.rollback()


def verified_archive(db, name):
    if not re.fullmatch(r"[a-f0-9]{32}\.sqlite", name):
        raise ArchiveError("Invalid archive filename")
    record = db.execute(
        "SELECT sha256,row_count FROM event_archives WHERE name=?", (name,)
    ).fetchone()
    if not record:
        raise ArchiveError("Archive catalog entry is missing")
    directory = state_directory(db) / "journal-archives"
    path = directory / name
    if directory.is_symlink() or path.is_symlink() or not path.is_file():
        raise ArchiveError("Archive file is missing or is a symlink")
    if path.stat().st_size > MAX_ARCHIVE or file_digest(path) != record[0]:
        raise ArchiveError("Archive checksum or size verification failed")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as cold:
        cold.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BODY)
        if cold.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ArchiveError("Archive integrity check failed")
        rows = cold.execute(
            "SELECT key,container,bucket,kind,body FROM events ORDER BY key"
        ).fetchmany(MAX_ROWS + 1)
    expected = db.execute(
        "SELECT key,container,bucket,kind,body_sha256 FROM archived_events "
        "WHERE archive=? ORDER BY key", (name,)
    ).fetchmany(MAX_ROWS + 1)
    actual = [(key, cid, bucket, kind, body_digest(body))
              for key, cid, bucket, kind, body in rows]
    if len(rows) > MAX_ROWS or len(rows) != record[1] or actual != expected:
        raise ArchiveError("Archived rows do not match retained identities")
    if file_digest(path) != record[0]:
        raise ArchiveError("Archive changed during readback")
    return rows


def event_rows(db, cid, start, end):
    """Yield original key/bucket/kind/body rows, or refuse incomplete evidence.

    Callers sort as needed. A read snapshot pins live rows and archive references
    together across concurrent publication. Every referenced file is checked in
    full before its selected rows are returned. Missing archives are errors.
    """
    with read_snapshot(db):
        yield from db.execute(
            "SELECT key,bucket,kind,body FROM events "
            "WHERE container=? AND bucket>=? AND bucket<=?", (cid, start, end)
        )
        if not has_archives(db):
            return
        names = db.execute(
            "SELECT DISTINCT archive FROM archived_events "
            "WHERE container=? AND bucket>=? AND bucket<=?", (cid, start, end)
        ).fetchall()
        for (name,) in names:
            for key, container, bucket, kind, body in verified_archive(db, name):
                if container == cid and start <= bucket <= end:
                    if db.execute("SELECT 1 FROM events WHERE key=?", (key,)).fetchone():
                        raise ArchiveError("Event identity exists in both stores")
                    yield key, bucket, kind, body


def candidates(db, before, window_seconds, limit=MAX_ROWS):
    if not 1 <= limit <= MAX_ROWS or window_seconds < 1:
        raise ArchiveError("Invalid archive batch or window size")
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BODY)
    cursor = db.execute(
        "SELECT e.key,e.container,e.bucket,e.kind,e.body FROM events e "
        "JOIN windows w ON e.container=w.container AND e.bucket=w.bucket "
        "WHERE e.kind='baseline' AND e.bucket<=? ORDER BY e.bucket,e.key LIMIT ?",
        (before - window_seconds, limit),
    )
    total = 0
    rows = []
    for row in cursor:
        body = row[4]
        body_digest(body)
        total += len(body.encode())
        if total > MAX_ARCHIVE // 2:
            raise ArchiveError("Batch payloads exceed 32 MiB; use a smaller --limit")
        rows.append(row)
    return rows


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def archive_batch(db, before, window_seconds, limit=MAX_ROWS, fault=lambda stage: None):
    """Caller must hold monitor.lock; this transaction also excludes SQL writers.

    The cutoff refers to the end of a closed window, not an event arrival time.
    No alert/rejected/workflow/model/window record is removed. Keys remain in
    archived_events indefinitely. No vacuum or file cleanup is automatic.
    """
    if db.in_transaction:
        raise ArchiveError("Archiving requires its own transaction")
    if not has_archives(db):
        raise ArchiveError("Start the updated monitor once before archiving")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("BEGIN IMMEDIATE")
    try:
        rows = candidates(db, before, window_seconds, limit)
        if not rows:
            db.rollback()
            return {"archived": 0}
        directory = state_directory(db) / "journal-archives"
        if directory.is_symlink():
            raise ArchiveError("Archive directory must not be a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        sync_directory(directory.parent)
        name = uuid.uuid4().hex + ".sqlite"
        partial = directory / (name + ".partial")
        final = directory / name
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(partial)) as cold:
            cold.execute("PRAGMA synchronous=FULL")
            cold.execute("CREATE TABLE events (key TEXT PRIMARY KEY, container TEXT, "
                         "bucket INTEGER, kind TEXT, body TEXT)")
            with cold:
                cold.executemany("INSERT INTO events VALUES (?,?,?,?,?)", rows)
            if cold.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ArchiveError("New archive failed integrity check")
            if cold.execute("SELECT * FROM events ORDER BY key").fetchall() != sorted(rows):
                raise ArchiveError("New archive failed exact readback")
        if partial.stat().st_size > MAX_ARCHIVE:
            raise ArchiveError("New archive exceeds the file size limit")
        with partial.open("rb") as stream:
            os.fsync(stream.fileno())
        checksum = file_digest(partial)
        fault("before_publication")
        os.link(partial, final)  # No replacement of an existing destination.
        partial.unlink()
        sync_directory(directory)
        fault("after_publication")
        db.execute("INSERT INTO event_archives VALUES (?,?,?)", (name, checksum, len(rows)))
        db.executemany("INSERT INTO archived_events VALUES (?,?,?,?,?,?)", [
            (key, cid, bucket, kind, name, body_digest(body))
            for key, cid, bucket, kind, body in rows
        ])
        # Verify the published file against the retained index before removal.
        verified_archive(db, name)
        for key, cid, bucket, kind, body in rows:
            result = db.execute(
                "DELETE FROM events WHERE key=? AND container=? AND bucket=? "
                "AND kind=? AND body=?", (key, cid, bucket, kind, body)
            )
            if result.rowcount != 1:
                raise ArchiveError("Source event changed during publication")
        fault("before_commit")
        db.commit()
        fault("after_commit")
        return {"archived": len(rows), "archive": name, "sha256": checksum,
                "payload_bytes": sum(len(row[4].encode()) for row in rows)}
    except BaseException:
        db.rollback()
        # Unreferenced partial/published files are retained for manual review.
        raise
