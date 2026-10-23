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
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
STATUS_STALE_SECONDS = 30
_REQUIRED_COMPONENTS = {"docker", "falco_ingest", "control", "backend"}
_HEALTHY_STATES = {"ok", "connected"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class StatusBoard:
    def __init__(self, path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
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
        result = json.loads(Path(path).read_text())
        json.dumps(result, allow_nan=False)  # Refuse nonfinite JSON telemetry, including 1e999.
        if (
            not isinstance(result, dict) or type(result.get("running")) is not bool
            or not isinstance(result.get("components", {}), dict)
        ):
            return None
        return result
    except (OSError, ValueError):
        return None


def describe_status(snapshot: dict | None, now: datetime | None = None) -> dict:
    """Shared API/CLI interpretation; a recent completed cycle is not a watchdog guarantee."""
    if snapshot is None:
        return {
            "status_available": False, "running": None, "healthy": False,
            "heartbeat_fresh": False, "degraded_components": [],
            "control_progress_fresh": False, "control_status_age_seconds": None,
            "reason": "Monitor status is unavailable or malformed; process state is unknown",
        }
    result = copy.deepcopy(snapshot)
    components = result.setdefault("components", {})
    for name, item in components.items():
        if not isinstance(item, dict) or not isinstance(item.get("state"), str):
            components[name] = {"state": "unknown", "detail": "Invalid recorded component status"}
    now = now if now is not None else datetime.now(timezone.utc)
    try:
        age = (now - datetime.fromisoformat(result["updated_at"])).total_seconds()
    except (KeyError, TypeError, ValueError):
        age = None
    progress = result.get("control_updated_at")
    progress_age = None
    if isinstance(progress, (int, float)) and not isinstance(progress, bool):
        try:
            numeric_progress = float(progress)
        except OverflowError:
            numeric_progress = math.inf
        if math.isfinite(numeric_progress):
            progress_age = now.timestamp() - numeric_progress
    result["status_available"] = True
    result["status_age_seconds"] = age
    result["heartbeat_fresh"] = age is not None and 0 <= age < STATUS_STALE_SECONDS
    result["control_status_age_seconds"] = progress_age
    result["control_progress_fresh"] = (
        progress_age is not None and 0 <= progress_age < STATUS_STALE_SECONDS
    )
    degraded = _REQUIRED_COMPONENTS - components.keys()
    for name, item in components.items():
        allowed = (
            _HEALTHY_STATES if name in _REQUIRED_COMPONENTS else _HEALTHY_STATES | {"disabled"}
        )
        if item["state"] not in allowed:
            degraded.add(name)
    if not result["control_progress_fresh"]:
        degraded.add("control")
    result["degraded_components"] = sorted(degraded)
    result["healthy"] = result["running"] and result["heartbeat_fresh"] and not degraded
    if not result["running"]:
        result["health_reason"] = "Monitor reports stopped"
    elif not result["heartbeat_fresh"]:
        result["health_reason"] = (
            "Monitor heartbeat is stale, invalid or ahead of the backend clock"
        )
    elif not result["control_progress_fresh"]:
        result["health_reason"] = (
            "No recent completed control cycle; long-running work or a stall requires inspection"
        )
    elif degraded:
        result["health_reason"] = "Components require attention: " + ", ".join(sorted(degraded))
    else:
        result["health_reason"] = "Fresh heartbeat, completed control cycle and reported components"
    return result
