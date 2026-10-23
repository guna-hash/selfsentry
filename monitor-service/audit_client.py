"""
audit_client.py
-----------------
Delivers audit events to the backend (POST /audit/) with local retry journals.

  - Valid acknowledgement (HTTP 200/201 with positive ID and duplicate flag): done.
    The backend ignores a repeated event_key, so a retry
    after a lost response cannot create a duplicate.
  - Backend unreachable or HTTP 5xx: the event is appended to an on-disk spool
    (audit_spool.jsonl) and retried later, in order.
  - HTTP 400/422: retain rejected payloads in audit_rejected.jsonl for inspection.
  - Authentication, throttling and ambiguous responses remain queued for later retry.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from backend_auth import backend_headers

logger = logging.getLogger(__name__)


class AuditJournalError(ValueError):
    """Persisted audit input is invalid; leave it untouched for operator review."""


class AuditEventConflict(ValueError):
    """A pending event key already identifies different data; preserve the original."""


def _decode_payload(raw):
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Audit payload must be a JSON object")
    json.dumps(payload, allow_nan=False)
    return payload


def _event_key(value):
    if value is None:
        return uuid.uuid4().hex
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ValueError("Audit event_key must contain 1–128 characters")
    return value


def make_event_key(*parts) -> str:
    """Stable idempotency key for an audit event."""
    return hashlib.sha1("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditClient:
    def __init__(self, backend_url: str, spool_path, timeout_seconds: float = 10.0):
        self._backend_url = backend_url.rstrip("/")
        self._spool_path = Path(spool_path)
        self._rejected_path = self._spool_path.with_name("audit_rejected.jsonl")
        self._timeout = timeout_seconds
        self.last_outcome: str | None = None  # "ok" | "retry" | "rejected"

    def emit(
        self,
        event_type: str,
        severity: str = "info",
        container_id: str | None = None,
        container_name: str | None = None,
        image_name: str | None = None,
        detail: dict | None = None,
        event_key: str | None = None,
        occurred_at: str | None = None,
    ) -> bool:
        """Send (or spool) one audit event. Returns True only if it was delivered."""
        payload = {
            "event_type": event_type,
            "severity": severity,
            "source": "monitor",
            "event_key": _event_key(event_key),
            "container_id": container_id,
            "container_name": container_name,
            "image_name": image_name,
            "detail": detail or {},
            "occurred_at": occurred_at or _utc_now(),
        }
        if self.spool_size() > 0:
            self.flush_spool()  # keep ordering: older spooled events go first
        outcome = "retry" if self.spool_size() > 0 else self._post(payload)
        if outcome == "ok":
            return True
        if outcome == "rejected":
            self._dead_letter(payload)
        else:
            self._append_spool(payload)
        return False

    def flush_spool(self) -> int:
        """Try to deliver spooled events in order; stop at the first failure."""
        pending = self._read_spool()
        if not pending:
            return 0
        remaining = list(pending)
        sent = 0
        for payload in pending:
            outcome = self._post(payload)
            if outcome == "retry":
                break
            if outcome == "rejected":
                self._dead_letter(payload)
            else:
                sent += 1
            remaining.pop(0)
        if len(remaining) != len(pending):
            self._write_spool(remaining)
        return sent

    def spool_size(self) -> int:
        return len(self._read_spool())

    def _post(self, payload: dict) -> str:
        try:
            response = requests.post(
                f"{self._backend_url}/audit/",
                json=payload,
                timeout=self._timeout,
                headers=backend_headers(),
            )
        except requests.RequestException as exc:
            logger.warning("audit backend unreachable (%s)", type(exc).__name__)
            self.last_outcome = "retry"
            return "retry"
        if response.status_code in (200, 201):
            try:
                body = response.json()
            except (ValueError, TypeError):
                body = None
            if (
                isinstance(body, dict)
                and type(body.get("id")) is int and body["id"] > 0
                and type(body.get("duplicate")) is bool
                and body["duplicate"] == (response.status_code == 200)
            ):
                self.last_outcome = "ok"
                return "ok"
            logger.warning("audit backend acknowledgement invalid: HTTP %s", response.status_code)
            self.last_outcome = "retry"
            return "retry"
        if response.status_code in (400, 422):
            logger.error(
                "audit backend rejected %s: HTTP %s",
                payload.get("event_type"),
                response.status_code,
            )
            self.last_outcome = "rejected"
            return "rejected"
        logger.warning("audit backend error: HTTP %s", response.status_code)
        self.last_outcome = "retry"
        return "retry"

    def _read_spool(self) -> list[dict]:
        try:
            raw_lines = self._spool_path.read_text().splitlines()
        except FileNotFoundError:
            return []
        except UnicodeError:
            raise AuditJournalError("Audit spool is not valid text; retained for review") from None
        except OSError as exc:
            logger.error("cannot read audit spool %s: %s", self._spool_path, exc)
            raise
        events = []
        for line_number, raw in enumerate(raw_lines, start=1):
            if not raw.strip():
                continue
            try:
                events.append(_decode_payload(raw))
            except (ValueError, TypeError):
                raise AuditJournalError(
                    f"Invalid audit spool record at line {line_number}; retained for review"
                ) from None
        return events

    def _append_line(self, path: Path, line: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            logger.error("cannot write %s: %s", path, exc)
            raise

    def _append_spool(self, payload: dict) -> None:
        self._append_line(self._spool_path, json.dumps(payload))

    def _dead_letter(self, payload: dict) -> None:
        self._append_line(self._rejected_path, json.dumps(payload))

    def _write_spool(self, events: list[dict]) -> None:
        if not events:
            try:
                self._spool_path.unlink()
            except FileNotFoundError:
                pass
            return
        tmp_path = self._spool_path.with_suffix(".tmp")
        tmp_path.write_text("".join(json.dumps(event) + "\n" for event in events))
        os.replace(tmp_path, self._spool_path)


class DurableAuditClient(AuditClient):
    """Nonblocking emit to a WAL journal; only the control worker performs HTTP delivery.

    Keeps/replays the pre-existing JSONL spool first for upgrade compatibility. SQLite
    connections are short-lived so the ingest and control threads never share a connection.
    """

    def __init__(self, backend_url, spool_path, timeout_seconds=5):
        super().__init__(backend_url, spool_path, timeout_seconds)
        import sqlite3

        self._journal = self._spool_path.with_name("audit.sqlite")
        self._journal.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self._journal)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS audit_outbox (key TEXT PRIMARY KEY, body TEXT)")

    def emit(
        self,
        event_type,
        severity="info",
        container_id=None,
        container_name=None,
        image_name=None,
        detail=None,
        event_key=None,
        occurred_at=None,
    ):
        import sqlite3

        key = _event_key(event_key)
        payload = dict(
            event_type=event_type,
            severity=severity,
            source="monitor",
            container_id=container_id,
            container_name=container_name,
            image_name=image_name,
            detail=detail or {},
            event_key=key,
            occurred_at=occurred_at or _utc_now(),
        )
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
        with closing(sqlite3.connect(self._journal, timeout=1)) as db, db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("INSERT OR IGNORE INTO audit_outbox VALUES (?,?)", (key, encoded))
            stored_raw = db.execute(
                "SELECT body FROM audit_outbox WHERE key=?", (key,)
            ).fetchone()[0]
            try:
                stored = _decode_payload(stored_raw)
                if stored.get("event_key") != key:
                    raise ValueError("Audit journal key mismatch")
            except (ValueError, TypeError):
                raise AuditJournalError(
                    "Invalid existing audit SQLite record; retained for review"
                ) from None
            comparison = dict(payload)
            if occurred_at is None or occurred_at == "":
                # A retry without an explicit time keeps the original event timestamp.
                comparison["occurred_at"] = stored.get("occurred_at")
            if json.dumps(stored, sort_keys=True, allow_nan=False) != json.dumps(
                comparison, sort_keys=True, allow_nan=False
            ):
                raise AuditEventConflict("Pending audit event key identifies different data")
        return False

    def spool_size(self):
        import sqlite3

        with closing(sqlite3.connect(self._journal, timeout=1)) as db, db:
            count = db.execute("SELECT count(*) FROM audit_outbox").fetchone()[0]
        return count + len(self._read_spool())

    def flush_spool(self):
        import sqlite3

        sent = super().flush_spool()
        if self._read_spool():
            return sent
        with closing(sqlite3.connect(self._journal, timeout=1)) as db, db:
            rows = db.execute(
                "SELECT key,body FROM audit_outbox ORDER BY rowid LIMIT 50"
            ).fetchall()
        # Validate the selected batch before sending any of its records.
        pending = []
        for key, body in rows:
            try:
                payload = _decode_payload(body)
                if (
                    not isinstance(key, str) or not 1 <= len(key) <= 128
                    or payload.get("event_key") != key
                ):
                    raise ValueError("Audit journal key mismatch")
            except (ValueError, TypeError):
                raise AuditJournalError(
                    "Invalid audit SQLite record or event key; retained for review"
                ) from None
            pending.append((key, payload))
        # No database transaction or lock is held across network I/O.
        for key, payload in pending:
            outcome = self._post(payload)
            if outcome == "retry":
                break
            if outcome == "rejected":
                self._dead_letter(payload)
            else:
                sent += 1
            with closing(sqlite3.connect(self._journal, timeout=1)) as db, db:
                db.execute("DELETE FROM audit_outbox WHERE key=?", (key,))
        return sent
