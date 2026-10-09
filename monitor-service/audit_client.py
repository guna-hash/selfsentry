"""
audit_client.py
-----------------
Delivers audit events to the backend (POST /audit/) without ever silently losing one.

  - Delivered (HTTP 200/201): done. The backend ignores a repeated event_key, so a retry
    after a lost response cannot create a duplicate.
  - Backend unreachable or HTTP 5xx: the event is appended to an on-disk spool
    (audit_spool.jsonl) and retried later, in order.
  - HTTP 4xx (the backend rejected the payload): retrying cannot help, so the event is
    moved to audit_rejected.jsonl for inspection and an error is logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


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
            "event_key": event_key,
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
                f"{self._backend_url}/audit/", json=payload, timeout=self._timeout
            )
        except requests.RequestException as exc:
            logger.warning("audit backend unreachable: %s", exc)
            self.last_outcome = "retry"
            return "retry"
        if response.status_code in (200, 201):
            self.last_outcome = "ok"
            return "ok"
        if 400 <= response.status_code < 500:
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
        except OSError as exc:
            logger.error("cannot read audit spool %s: %s", self._spool_path, exc)
            return []
        events = []
        for raw in raw_lines:
            if not raw.strip():
                continue
            try:
                events.append(json.loads(raw))
            except ValueError:
                logger.error("unreadable audit spool line moved to dead letters")
                self._append_line(self._rejected_path, raw)
        return events

    def _append_line(self, path: Path, line: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as handle:
                handle.write(line + "\n")
        except OSError as exc:
            logger.error("cannot write %s: %s", path, exc)

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
