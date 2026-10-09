"""
monitor_status.py
-------------------
Thread-safe status board for the monitor, persisted atomically to
<state_dir>/status.json so `monitor_service.py --status` (and later the dashboard)
can report what the running service is doing.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class StatusBoard:
    def __init__(self, path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data = {
            "pid": os.getpid(),
            "started_at": _now(),
            "running": False,
            "updated_at": None,
            "last_event_at": None,
            "components": {},
            "counters": {},
        }

    def set_running(self, running: bool) -> None:
        with self._lock:
            self._data["running"] = running

    def set_value(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value

    def set_component(self, name: str, state: str, detail: str | None = None) -> None:
        with self._lock:
            current = self._data["components"].get(name)
            since = current["since"] if current and current["state"] == state else _now()
            self._data["components"][name] = {"state": state, "detail": detail, "since": since}

    def incr(self, counter: str, amount: int = 1) -> None:
        with self._lock:
            counters = self._data["counters"]
            counters[counter] = counters.get(counter, 0) + amount

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    def write(self) -> None:
        self.set_value("updated_at", _now())
        data = self.snapshot()
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2))
            os.replace(tmp_path, self._path)
        except OSError as exc:
            logger.error("could not write status file %s: %s", self._path, exc)


def read_status(path) -> dict | None:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
