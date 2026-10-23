"""Isolate slow backend/Docker workflows from durable Falco ingestion and feature windows."""

from __future__ import annotations

import logging
import queue
from typing import Any
import sqlite3
import threading
import time
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deployment-gate"))
from deployment_outbox import flush as flush_deployments, action_health  # noqa: E402
from incident_pipeline import IncidentPipeline  # noqa: E402

logger = logging.getLogger(__name__)
DOCKER_EVENT_QUEUE_SIZE = 1000


class ControlWorker:
    """Watcher-compatible nonblocking proxy; one thread owns its SQLite connection."""

    def __init__(self, config, watcher, audit, status):
        self.config, self.watcher, self.audit, self.status = config, watcher, audit, status
        self.events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=DOCKER_EVENT_QUEUE_SIZE)
        self.reconcile_requested = threading.Event()
        self.reconcile_requested.set()
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.ids, self.tracked, self.pending = [], 0, 0
        self.status.set_component("control", "starting")
        self.thread = threading.Thread(
            target=self._run_guarded, name="selfsentry-control", daemon=True
        )

    def start(self):
        self.thread.start()

    @property
    def container_ids(self):
        with self.lock:
            return list(self.ids)

    @property
    def tracked_count(self):
        with self.lock:
            return self.tracked

    @property
    def pending_count(self):
        with self.lock:
            return self.pending

    def handle_docker_event(self, event):
        try:
            self.events.put_nowait(event)
        except queue.Full:
            return False
        return True

    def reconcile(self):
        self.reconcile_requested.set()
        return 0

    def tick(self):
        # Invoked by MonitorService; slow work belongs exclusively to run().
        return 0

    def request_stop(self):
        self.stopping.set()

    def stop(self):
        self.request_stop()
        # The monitor must retain its instance lock until response work exits.
        if self.thread.ident is not None:
            self.thread.join()

    def _run_guarded(self):
        while not self.stopping.is_set():
            try:
                self.run()
                return
            except Exception as exc:
                logger.exception("control worker initialization failed; retrying")
                self.status.set_component("control", "degraded", type(exc).__name__)
                self.stopping.wait(1)

    def run(self):
        db = sqlite3.connect(self.config.state_dir / "pipeline.sqlite", timeout=1)
        pipeline = None
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            behavior = SimpleNamespace(
                config=self.config, db=db, status=self.status, audit=self.audit
            )
            pipeline = IncidentPipeline(behavior)
            next_reconcile = 0.0
            while not self.stopping.is_set():
                try:
                    # Bounded batches prevent a busy host from starving response delivery.
                    for _ in range(100):
                        if self.stopping.is_set():
                            break
                        try:
                            event = self.events.get_nowait()
                        except queue.Empty:
                            break
                        try:
                            self.watcher.handle_docker_event(event)
                        except Exception:
                            logger.exception(
                                "control Docker event failed; reconciliation will retry"
                            )
                            self.status.incr("docker_event_errors")
                    if self.stopping.is_set():
                        break
                    if self.reconcile_requested.is_set() or time.monotonic() >= next_reconcile:
                        # Consume this request before work; a new request during
                        # reconciliation must remain pending for the next cycle.
                        self.reconcile_requested.clear()
                        try:
                            self.watcher.reconcile()
                        except Exception:
                            self.reconcile_requested.set()
                            raise
                        next_reconcile = time.monotonic() + 15
                    if self.stopping.is_set():
                        break
                    self.watcher.tick()
                    with self.lock:
                        self.ids = self.watcher.container_ids
                        self.tracked = self.watcher.tracked_count
                        self.pending = self.watcher.pending_count
                    if self.stopping.is_set():
                        break
                    pipeline.tick()
                    if self.stopping.is_set():
                        break
                    self.audit.flush_spool()
                    if self.stopping.is_set():
                        break
                    delivery = flush_deployments(self.config.backend_url)
                    self.status.set_value("deployment_outbox", delivery)
                    actions = action_health()
                    self.status.set_value("deployment_actions", actions)
                    attention = actions["outcome_not_recorded"] > 0 or actions["command_failed"] > 0
                    self.status.set_component(
                        "deployment_actions", "degraded" if attention else "ok",
                        f"{actions['outcome_not_recorded']} without recorded outcome; "
                        f"{actions['command_failed']} failed commands; operator review required"
                        if attention else (f"{actions['active']} active gate commands"
                                           if actions.get("active") else None),
                    )
                    if delivery is not None:
                        unavailable = delivery["pending"] > 0 or delivery["rejected"] > 0
                        self.status.set_component(
                            "deployment_backend", "degraded" if unavailable else "ok",
                            f"{delivery['pending']} pending; {delivery['rejected']} require review"
                            if unavailable else None,
                        )
                    self.status.set_component("control", "ok")
                    self.status.set_value("control_updated_at", time.time())
                except Exception as exc:
                    logger.exception("control workflow failed; ingestion remains independent")
                    self.status.incr("control_errors")
                    self.status.set_component("control", "degraded", str(exc))
                self.stopping.wait(self.config.poll_interval_seconds)
        finally:
            try:
                if pipeline is not None and pipeline.executor:
                    pipeline.executor.shutdown(wait=True, cancel_futures=True)
            finally:
                db.close()
