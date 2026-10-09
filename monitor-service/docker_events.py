"""
docker_events.py
------------------
Background thread that follows Docker's container event stream (start, die, destroy)
and puts each event on a queue for the monitor loop.

If the stream breaks (daemon restart, socket error) the thread reconnects with bounded
exponential backoff, resuming from the last event time it saw. Replayed events are
harmless because the watcher ignores duplicates. Every successful (re)connect sets
`reconnected`, which tells the monitor to reconcile the list of running containers so
nothing started while the stream was down is missed.
"""

from __future__ import annotations

import logging
import queue
import threading

logger = logging.getLogger(__name__)

EVENT_FILTERS = {"type": "container", "event": ["start", "die", "destroy"]}


class DockerEventPump(threading.Thread):
    def __init__(
        self,
        client_factory,
        out_queue: queue.Queue,
        stop_event: threading.Event,
        retry_base_seconds: float = 1.0,
        retry_max_seconds: float = 30.0,
    ):
        super().__init__(name="docker-event-pump", daemon=True)
        self._client_factory = client_factory
        self._queue = out_queue
        self._stop_event = stop_event
        self._retry_base = retry_base_seconds
        self._retry_max = retry_max_seconds
        self._last_time: int | None = None
        self.reconnected = threading.Event()
        self.state = "starting"
        self.last_error: str | None = None

    def _remember_time(self, event: dict) -> None:
        stamp = event.get("time")
        if isinstance(stamp, int):
            self._last_time = stamp

    def run(self) -> None:
        delay = self._retry_base
        while not self._stop_event.is_set():
            try:
                client = self._client_factory()
                stream = client.events(decode=True, since=self._last_time, filters=EVENT_FILTERS)
                self.state, self.last_error = "connected", None
                self.reconnected.set()
                delay = self._retry_base
                for event in stream:
                    self._remember_time(event)
                    self._queue.put(event)
                    if self._stop_event.is_set():
                        return
            except Exception as exc:  # noqa: BLE001 - supervisor loop: log, back off, retry
                self.state, self.last_error = "unavailable", str(exc)
                logger.warning("Docker event stream unavailable: %s", exc)
            if self._stop_event.wait(delay):
                return
            delay = min(self._retry_max, delay * 2)
