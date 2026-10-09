"""
container_watcher.py
----------------------
Tracks container starts, stops and removals and detects containers started OUTSIDE the
Deployment Gate.

Registration (trust) rule: a container is "registered" only if the backend holds a
deployment record for its container ID with decision allowed or overridden (written by
bin/selfsentry-run). The container NAME is never used as proof of approval.

Race handling: the gate starts a container and records the decision slightly afterwards,
so an unregistered container is re-checked until a grace period expires before
UNAPPROVED_CONTAINER_START is raised. If the registration lookup fails (backend down), the
last definitive answer is used at the deadline; with no definitive answer the container is
reported as REGISTRATION_UNKNOWN instead of being called unapproved.

Detecting an unapproved container does not stop or isolate it. The policy "alert"
(default) records the audit event; "ignore" records only CONTAINER_STARTED.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone

import docker
import requests

from audit_client import make_event_key
from monitor_config import MonitorConfig

logger = logging.getLogger(__name__)

RECENT_REMOVAL_SECONDS = 600
SEEN_EVENT_WINDOW = 2000


class BackendRegistrationLookup:
    """Looks up gate registrations through the backend (GET /deployments/).

    Only the newest 500 deployment records are considered.
    """

    APPROVED_DECISIONS = ("allowed", "overridden")

    def __init__(self, backend_url: str, timeout_seconds: float = 10.0):
        self._backend_url = backend_url.rstrip("/")
        self._timeout = timeout_seconds

    def is_registered(self, short_id: str) -> bool | None:
        """True / False, or None if the lookup itself failed."""
        try:
            response = requests.get(
                f"{self._backend_url}/deployments/",
                params={"limit": 500},
                timeout=self._timeout,
            )
            response.raise_for_status()
            deployments = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("registration lookup failed: %s", exc)
            return None
        return any(
            d.get("container_id") == short_id and d.get("decision") in self.APPROVED_DECISIONS
            for d in deployments
        )


class DockerInspector:
    """Thin wrapper over the Docker SDK so the watcher can be tested with fakes."""

    def __init__(self, client_factory=docker.from_env):
        self._client_factory = client_factory

    @staticmethod
    def _describe(container) -> dict:
        state = container.attrs.get("State") or {}
        return {
            "name": container.name,
            "image": (container.attrs.get("Config") or {}).get("Image"),
            "started_at": state.get("StartedAt"),
        }

    def inspect(self, full_id: str) -> dict | None:
        try:
            container = self._client_factory().containers.get(full_id)
        except docker.errors.NotFound:
            return None
        return self._describe(container)

    def list_running(self) -> list[dict]:
        containers = self._client_factory().containers.list()
        return [{"id": c.id, **self._describe(c)} for c in containers]


@dataclass
class TrackedContainer:
    full_id: str
    name: str | None
    image: str | None
    started_at: str
    running: bool = True
    registration: str = "pending"


@dataclass
class _Pending:
    tracked: TrackedContainer
    deadline: float
    next_check: float
    last_definitive: bool | None
    detection_method: str


def _iso_from_event(event: dict) -> str:
    seconds = event.get("timeNano", 0) / 1e9 if event.get("timeNano") else event.get("time")
    if not seconds:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def _event_stamp(event: dict):
    return event.get("timeNano") or event.get("time")


class ContainerWatcher:
    def __init__(
        self,
        config: MonitorConfig,
        audit,
        lookup,
        inspector,
        clock=time.monotonic,
    ):
        self._config = config
        self._audit = audit
        self._lookup = lookup
        self._inspector = inspector
        self._clock = clock
        self._tracked: dict[str, TrackedContainer] = {}
        self._pending: dict[str, _Pending] = {}
        self._recently_removed: dict[str, tuple[str, float]] = {}
        self._seen_events: OrderedDict[tuple, None] = OrderedDict()

    @property
    def tracked_count(self) -> int:
        return len(self._tracked)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    # ---- public entry points -------------------------------------------------

    def handle_docker_event(self, event: dict) -> None:
        action = event.get("Action") or event.get("status")
        actor = event.get("Actor") or {}
        full_id = actor.get("ID") or event.get("id")
        if not full_id or action not in ("start", "die", "destroy"):
            return
        key = (full_id, action, event.get("timeNano") or event.get("time"))
        if key in self._seen_events:
            return
        self._seen_events[key] = None
        while len(self._seen_events) > SEEN_EVENT_WINDOW:
            self._seen_events.popitem(last=False)

        attrs = actor.get("Attributes") or {}
        name, image = attrs.get("name"), attrs.get("image")
        event_time = _iso_from_event(event)
        if action == "start":
            self._on_start(full_id, name, image, event_time, "docker_event")
        elif action == "die":
            self._on_stop(full_id, name, image, attrs.get("exitCode"), event)
        else:
            self._on_removed(full_id, name, image, event)

    def reconcile(self) -> int:
        """Register containers that are already running (startup or after a reconnect)."""
        count = 0
        for info in self._inspector.list_running():
            full_id = info["id"]
            known = self._tracked.get(full_id)
            if known and known.running and known.started_at == info.get("started_at"):
                continue
            self._on_start(
                full_id, info.get("name"), info.get("image"), info.get("started_at"),
                "startup_reconcile", immediate=True,
            )
            count += 1
        return count

    def tick(self) -> int:
        """Re-check pending registrations; returns how many were resolved."""
        now = self._clock()
        resolved = 0
        for full_id, pending in list(self._pending.items()):
            if now < pending.next_check and now < pending.deadline:
                continue
            status = self._lookup.is_registered(full_id[:12])
            if status is not None:
                pending.last_definitive = status
            if status is True or now >= pending.deadline:
                effective = status if status is not None else pending.last_definitive
                self._resolve(full_id, pending, effective)
                resolved += 1
            else:
                pending.next_check = now + self._config.registration_retry_seconds
        return resolved

    # ---- event handlers ------------------------------------------------------

    def _safe_inspect(self, full_id: str) -> dict:
        try:
            return self._inspector.inspect(full_id) or {}
        except docker.errors.DockerException as exc:
            logger.warning("could not inspect %s, using event data: %s", full_id[:12], exc)
            return {}

    def _on_start(self, full_id, name, image, event_time, method, immediate=False) -> None:
        info = self._safe_inspect(full_id)
        tracked = TrackedContainer(
            full_id=full_id,
            name=info.get("name") or name,
            image=info.get("image") or image,
            started_at=info.get("started_at") or event_time,
        )
        self._tracked[full_id] = tracked
        self._pending.pop(full_id, None)

        status = self._lookup.is_registered(full_id[:12])
        if status is True:
            self._resolve_registered(tracked, method)
            return
        now = self._clock()
        pending = _Pending(
            tracked=tracked,
            deadline=now if immediate else now + self._config.registration_grace_seconds,
            next_check=now + self._config.registration_retry_seconds,
            last_definitive=status,
            detection_method=method,
        )
        self._pending[full_id] = pending
        if immediate:
            self._resolve(full_id, pending, status)

    def _on_stop(self, full_id, name, image, exit_code, event) -> None:
        tracked = self._tracked.get(full_id)
        if tracked:
            tracked.running = False
        self._emit(
            "CONTAINER_STOPPED", "info", full_id,
            tracked.name if tracked else name,
            tracked.image if tracked else image,
            {"exit_code": exit_code},
            make_event_key("CONTAINER_STOPPED", full_id, _event_stamp(event)),
            _iso_from_event(event),
        )

    def _on_removed(self, full_id, name, image, event) -> None:
        tracked = self._tracked.pop(full_id, None)
        resolved_name = tracked.name if tracked else name
        if resolved_name:
            self._recently_removed[resolved_name] = (full_id[:12], self._clock())
        self._emit(
            "CONTAINER_REMOVED", "info", full_id, resolved_name,
            tracked.image if tracked else image, {},
            make_event_key("CONTAINER_REMOVED", full_id, _event_stamp(event)),
            _iso_from_event(event),
        )

    # ---- resolution ----------------------------------------------------------

    def _resolve(self, full_id: str, pending: _Pending, status: bool | None) -> None:
        tracked = pending.tracked
        self._pending.pop(full_id, None)
        if status is True:
            self._resolve_registered(tracked, pending.detection_method)
            return
        detail = {"detection_method": pending.detection_method, "started_at": tracked.started_at}
        previous = self._previous_holder_of(tracked.name)
        if previous:
            detail["name_previously_used_by"] = previous

        if status is None:
            tracked.registration = "unknown"
            detail["registration_status"] = "unknown"
            self._emit(
                "REGISTRATION_UNKNOWN", "warning", tracked.full_id, tracked.name, tracked.image,
                detail, make_event_key("REGISTRATION_UNKNOWN", tracked.full_id, tracked.started_at),
                tracked.started_at,
            )
            return

        tracked.registration = "unregistered"
        detail["registration_status"] = "unregistered"
        detail["policy"] = self._config.unapproved_start_policy
        if self._config.unapproved_start_policy == "alert":
            self._emit(
                "UNAPPROVED_CONTAINER_START", "warning", tracked.full_id, tracked.name,
                tracked.image, detail,
                make_event_key("UNAPPROVED_CONTAINER_START", tracked.full_id, tracked.started_at),
                tracked.started_at,
            )
        else:
            self._emit(
                "CONTAINER_STARTED", "info", tracked.full_id, tracked.name, tracked.image,
                detail, make_event_key("CONTAINER_STARTED", tracked.full_id, tracked.started_at),
                tracked.started_at,
            )

    def _resolve_registered(self, tracked: TrackedContainer, method: str) -> None:
        tracked.registration = "registered"
        self._emit(
            "CONTAINER_STARTED", "info", tracked.full_id, tracked.name, tracked.image,
            {"registration_status": "registered", "detection_method": method,
             "started_at": tracked.started_at},
            make_event_key("CONTAINER_STARTED", tracked.full_id, tracked.started_at),
            tracked.started_at,
        )

    def _previous_holder_of(self, name: str | None) -> str | None:
        if not name or name not in self._recently_removed:
            return None
        short_id, removed_at = self._recently_removed[name]
        if self._clock() - removed_at > RECENT_REMOVAL_SECONDS:
            return None
        return short_id

    def _emit(self, event_type, severity, full_id, name, image, detail, event_key, occurred_at):
        self._audit.emit(
            event_type=event_type,
            severity=severity,
            container_id=full_id[:12],
            container_name=name,
            image_name=image,
            detail=detail,
            event_key=event_key,
            occurred_at=occurred_at,
        )
