"""Isolate slow backend/Docker workflows from durable Falco ingestion and feature windows."""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deployment-gate"))
from deployment_outbox import flush as flush_deployments  # noqa: E402
from incident_pipeline import IncidentPipeline  # noqa: E402

logger = logging.getLogger(__name__)


class ControlWorker:
    """Watcher-compatible nonblocking proxy; one thread owns its SQLite connection."""

    def __init__(self, config, watcher, audit, status):
        self.config, self.watcher, self.audit, self.status = config, watcher, audit, status
        self.events = queue.Queue()
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
        self.events.put(event)

    def reconcile(self):
        self.reconcile_requested.set()
        return 0

    def tick(self):
        # Invoked by MonitorService; slow work belongs exclusively to run().
        return 0

    def stop(self):
        self.stopping.set()
        self.thread.join(timeout=15)

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
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        behavior = SimpleNamespace(config=self.config, db=db, status=self.status, audit=self.audit)
        pipeline = IncidentPipeline(behavior)
        next_reconcile = 0
        try:
            while not self.stopping.is_set():
                try:
                    # Bounded batches prevent a busy host from starving response delivery.
                    for _ in range(100):
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
                    if self.reconcile_requested.is_set() or time.monotonic() >= next_reconcile:
                        self.watcher.reconcile()
                        self.reconcile_requested.clear()
                        next_reconcile = time.monotonic() + 15
                    self.watcher.tick()
                    with self.lock:
                        self.ids = self.watcher.container_ids
                        self.tracked = self.watcher.tracked_count
                        self.pending = self.watcher.pending_count
                    self.status.set_component("control", "ok")
                    self.status.set_value("control_updated_at", time.time())
                    pipeline.tick()
                    self.audit.flush_spool()
                    flush_deployments(self.config.backend_url)
                except Exception as exc:
                    logger.exception("control workflow failed; ingestion remains independent")
                    self.status.incr("control_errors")
                    self.status.set_component("control", "degraded", str(exc))
                self.stopping.wait(self.config.poll_interval_seconds)
        finally:
            if pipeline.executor:
                pipeline.executor.shutdown(wait=False, cancel_futures=True)
            db.close()
