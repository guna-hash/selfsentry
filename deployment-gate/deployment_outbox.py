"""Durable gate-decision journal. HTTP replays use the backend's audit event key."""

import json
import logging
import os
import fcntl
import math
import re
import stat
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import uuid

import requests
from backend_auth import backend_headers

ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)
MAX_COMMAND_SECONDS = 300
OUTCOME_WRITE_GRACE_SECONDS = 5


class OutboxConflict(ValueError):
    """A stable event key cannot identify two different journal payloads."""


def _attempt_key(key=None):
    if key is None:
        return uuid.uuid4().hex
    if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{32}", key) is None:
        raise ValueError("Attempt ownership requires a UUID hexadecimal key")
    return key


def _ownership_path(key):
    return (Path(os.environ.get("SELFSENTRY_STATE_DIR", ROOT / "state"))
            / "deployment-action-locks" / (key + ".lock"))


@contextmanager
def operation_lease(timeout_seconds):
    """Own one bounded command before its durable intent becomes visible.

    A process exit releases flock, including an exit between Docker and outcome
    persistence. A hung/suspended owner cannot hide an unfinished attempt beyond
    its command deadline plus the small outcome-write allowance.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_COMMAND_SECONDS:
        raise ValueError("Invalid operation ownership timeout")
    key = _attempt_key()
    path = _ownership_path(key)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.monotonic()
        metadata = json.dumps({"key": key, "started_monotonic": started,
                               "deadline_monotonic": started + timeout_seconds
                               + OUTCOME_WRITE_GRACE_SECONDS}).encode()
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(metadata)
            stream.flush()
            os.fsync(stream.fileno())
        yield key
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Completed operation ownership file could not be removed")
        finally:
            os.close(fd)  # Releases ownership even if metadata cleanup failed.


def _operation_active(key):
    """Check ownership without creating, deleting or repairing any file."""
    if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{32}", key) is None:
        return False
    try:
        fd = os.open(_ownership_path(key), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                return False
            metadata = json.loads(raw)
            started = metadata["started_monotonic"]
            deadline = metadata["deadline_monotonic"]
            if any(type(value) not in (int, float) or not math.isfinite(value)
                   for value in (started, deadline)):
                return False
            return (metadata["key"] == key and 0 <= started <= time.monotonic() < deadline
                    and started < deadline
                    <= started + MAX_COMMAND_SECONDS + OUTCOME_WRITE_GRACE_SECONDS)
        else:
            return False  # A leftover file alone is never evidence of a live operation.
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return False
    finally:
        os.close(fd)


def connect():
    path = Path(os.environ.get("SELFSENTRY_STATE_DIR", ROOT / "state")) / "deployments.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=1)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS decisions (key TEXT PRIMARY KEY, body TEXT)")
        db.execute("""CREATE TABLE IF NOT EXISTS decision_rejections (
            key TEXT PRIMARY KEY, body TEXT, status INTEGER,
            reason TEXT NOT NULL, observed_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS deployment_actions (
            key TEXT PRIMARY KEY, container_id TEXT NOT NULL, action TEXT NOT NULL,
            decision_body TEXT, outcome TEXT NOT NULL, created_at TEXT NOT NULL,
            completed_at TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS creation_attempts (
            key TEXT PRIMARY KEY, container_id TEXT, outcome TEXT NOT NULL,
            created_at TEXT NOT NULL, completed_at TEXT)""")
    except BaseException:
        db.close()
        raise
    return db


def inspect_actions(limit=50, offset=0):
    """Read a bounded, consistent journal snapshot without initializing or repairing it."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("Inspection limit must be 1–200")
    if type(offset) is not int or not 0 <= offset <= 2**63 - 1:
        raise ValueError("Inspection offset must be a nonnegative SQLite integer")
    path = Path(os.environ.get("SELFSENTRY_STATE_DIR", ROOT / "state")) / "deployments.sqlite"
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        db.execute("PRAGMA query_only = ON")
        db.execute("BEGIN")
        counts = dict(db.execute("""SELECT outcome,count(*) FROM (
            SELECT outcome FROM deployment_actions UNION ALL
            SELECT outcome FROM creation_attempts) GROUP BY outcome""").fetchall())
        pending = db.execute("""SELECT count(*) FROM decisions d WHERE NOT EXISTS (
            SELECT 1 FROM decision_rejections r WHERE r.key IS d.key)""").fetchone()[0]
        rejected = db.execute("SELECT count(*) FROM decision_rejections").fetchone()[0]
        rows = db.execute("""SELECT * FROM (
            SELECT 'action' AS kind,key,container_id,action,outcome,created_at,completed_at
            FROM deployment_actions UNION ALL
            SELECT 'creation' AS kind,key,container_id,'create',outcome,created_at,completed_at
            FROM creation_attempts) ORDER BY created_at,key,kind LIMIT ? OFFSET ?""",
                          (limit + 1, offset)).fetchall()
        columns = ("kind", "key", "container_id", "action", "outcome", "created_at",
                   "completed_at")
        if any(not isinstance(outcome, str) for outcome in counts):
            raise ValueError("Invalid journal outcome metadata")
        for row in rows:
            if any(not isinstance(row[i], str) for i in (0, 1, 3, 4, 5)) or any(
                row[i] is not None and not isinstance(row[i], str) for i in (2, 6)
            ):
                raise ValueError("Invalid journal attempt metadata")
        return {"outcome_counts": counts, "pending_decisions": pending,
                "retained_rejections": rejected, "limit": limit, "offset": offset,
                "has_more": len(rows) > limit,
                "attempts": [dict(zip(columns, row)) for row in rows[:limit]]}
    finally:
        db.close()


def enqueue(record):
    key = record.get("event_key")
    if key is None:
        key = uuid.uuid4().hex
        record["event_key"] = key
    if not isinstance(key, str) or not 1 <= len(key) <= 128:
        raise ValueError("Journal event_key must contain 1–128 characters")
    encoded = json.dumps(record, sort_keys=True, allow_nan=False)
    db = connect()
    try:
        with db:
            db.execute(
                "INSERT OR IGNORE INTO decisions VALUES (?,?)",
                (key, encoded),
            )
            stored = db.execute("SELECT body FROM decisions WHERE key=?", (key,)).fetchone()[0]
            try:
                same = json.dumps(json.loads(stored), sort_keys=True, allow_nan=False) == encoded
            except (ValueError, TypeError):
                same = False
            if not same:
                raise OutboxConflict(
                    "Event key already identifies different or invalid journal data"
                )
    finally:
        db.close()


def begin_creation(*, key=None):
    """Record a create attempt without storing Docker arguments or guessing identity."""
    key = _attempt_key(key)
    db = connect()
    try:
        with db:
            db.execute("INSERT INTO creation_attempts VALUES (?,NULL,?,?,NULL)",
                       (key, "outcome_not_recorded", datetime.now(timezone.utc).isoformat()))
    finally:
        db.close()
    return key


def finish_creation(key, container_id=None):
    """Record CLI failure or its returned full ID; unknown outcomes stay unfinished."""
    if container_id is not None and (
        not isinstance(container_id, str) or len(container_id) != 64
        or any(c not in "0123456789abcdef" for c in container_id)
    ):
        raise ValueError("Creation outcome requires a full Docker hexadecimal ID")
    db = connect()
    try:
        with db:
            changed = db.execute(
                """UPDATE creation_attempts SET container_id=?,outcome=?,completed_at=?
                WHERE key=? AND outcome='outcome_not_recorded'""",
                (container_id, "command_succeeded" if container_id else "command_failed",
                 datetime.now(timezone.utc).isoformat(), key),
            )
            if changed.rowcount != 1:
                raise OutboxConflict("Creation attempt is missing or already completed")
    finally:
        db.close()


def begin_action(container_id, action, record=None, *, key=None):
    """Commit intent before Docker; unfinished intents are never automatically executed."""
    if action not in ("start", "remove") or not container_id:
        raise ValueError("Invalid deployment action")
    key = _attempt_key(key)
    if record is not None:
        if record.get("event_key") is not None:
            raise ValueError("Action requires a new deployment event")
        record["event_key"] = key
    body = json.dumps(record, sort_keys=True, allow_nan=False) if record is not None else None
    db = connect()
    try:
        with db:
            db.execute("INSERT INTO deployment_actions VALUES (?,?,?,?,?,?,NULL)",
                       (key, container_id, action, body, "outcome_not_recorded",
                        datetime.now(timezone.utc).isoformat()))
    finally:
        db.close()
    return key


def finish_action(key, succeeded):
    """Atomically persist outcome and queue only confirmed completed decisions."""
    db = connect()
    try:
        with db:
            row = db.execute("SELECT decision_body,outcome FROM deployment_actions WHERE key=?",
                             (key,)).fetchone()
            if row is None or row[1] != "outcome_not_recorded":
                raise OutboxConflict("Action is missing or already has a recorded outcome")
            if succeeded and row[0] is not None:
                db.execute("INSERT INTO decisions VALUES (?,?)", (key, row[0]))
            db.execute("UPDATE deployment_actions SET outcome=?,completed_at=? WHERE key=?",
                       ("command_succeeded" if succeeded else "command_failed",
                        datetime.now(timezone.utc).isoformat(), key))
    finally:
        db.close()


def action_health():
    """Distinguish bounded, owned commands from unfinished work requiring review."""
    db = connect()
    try:
        failed_query = """SELECT
            (SELECT count(*) FROM deployment_actions WHERE outcome='command_failed') +
            (SELECT count(*) FROM creation_attempts WHERE outcome='command_failed')"""
        failed = db.execute(failed_query).fetchone()[0]
        rows = db.execute("""SELECT 'deployment_actions',key FROM deployment_actions
            WHERE outcome='outcome_not_recorded' UNION ALL
            SELECT 'creation_attempts',key FROM creation_attempts
            WHERE outcome='outcome_not_recorded'""").fetchall()
        result = {"active": 0, "outcome_not_recorded": 0, "command_failed": failed}
        for table, key in rows:
            if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{32}", key) is None:
                result["outcome_not_recorded"] += 1
                continue  # Corrupt/legacy identities cannot prove liveness or a unique completion.
            if _operation_active(key):
                result["active"] += 1
            else:
                # Completion may have committed after the first read and released
                # its ownership file. Re-read so that race cannot report an orphan.
                current = db.execute("SELECT outcome FROM " + table + " WHERE key=?",
                                     (key,)).fetchone()
                if current and current[0] == "outcome_not_recorded":
                    result["outcome_not_recorded"] += 1
                elif current and current[0] == "command_failed":
                    result["command_failed"] += 1
        return result
    finally:
        db.close()


def acknowledge(key):
    db = connect()
    try:
        with db:
            db.execute("DELETE FROM decisions WHERE key=?", (key,))
    finally:
        db.close()


def valid_acknowledgement(response, record) -> bool:
    if response.status_code != 201:
        return False
    try:
        body = response.json()
    except (ValueError, TypeError):
        return False
    return (
        isinstance(body, dict)
        and type(body.get("id")) is int
        and body["id"] > 0
        and record.get("decision") in ("allowed", "blocked", "overridden")
        and body.get("decision") == record.get("decision")
    )


def _retain_rejection(key, body, status, reason):
    db = connect()
    try:
        with db:
            db.execute(
                "INSERT OR IGNORE INTO decision_rejections VALUES (?,?,?,?,?)",
                (key, body, status, reason, datetime.now(timezone.utc).isoformat()),
            )
    finally:
        db.close()
    logger.error("Deployment journal entry %r retained for operator review: %s", key, reason)


def flush(backend_url):
    db = connect()
    try:
        rows = db.execute("""SELECT d.key,d.body FROM decisions d
            WHERE NOT EXISTS (SELECT 1 FROM decision_rejections r WHERE r.key IS d.key)
            ORDER BY d.rowid LIMIT 20""").fetchall()
    finally:
        db.close()
    for key, body in rows:
        try:
            record = json.loads(body)
            if (
                not isinstance(key, str)
                or not 1 <= len(key) <= 128
                or not isinstance(record, dict)
                or record.get("event_key") != key
            ):
                raise ValueError("journal payload/key mismatch")
            json.dumps(record, allow_nan=False)
        except (ValueError, TypeError):
            _retain_rejection(key, body, None, "Invalid journal JSON or event-key mismatch")
            continue
        try:
            result = requests.post(
                backend_url + "/deployments/",
                json=record,
                timeout=5,
                headers=backend_headers(),
            )
            if result.status_code in (400, 409, 422):
                _retain_rejection(
                    key,
                    body,
                    result.status_code,
                    f"Backend rejected deployment record: HTTP {result.status_code}",
                )
                continue
            if not valid_acknowledgement(result, record):
                break  # Keep transient failures and ambiguous acknowledgements replayable.
        except requests.RequestException:
            break
        acknowledge(key)
    db = connect()
    try:
        pending = db.execute("""SELECT count(*) FROM decisions d WHERE NOT EXISTS
            (SELECT 1 FROM decision_rejections r WHERE r.key IS d.key)""").fetchone()[0]
        rejected = db.execute("""SELECT count(*) FROM decisions d WHERE EXISTS
            (SELECT 1 FROM decision_rejections r WHERE r.key IS d.key)""").fetchone()[0]
        return {"pending": pending, "rejected": rejected}
    finally:
        db.close()
