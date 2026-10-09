"""
monitor_service.py
--------------------
SelfSentry continuous monitor (milestone M1: ingestion and container discovery).

  python3 monitor-service/monitor_service.py            run until stopped (Ctrl+C / SIGTERM)
  python3 monitor-service/monitor_service.py --status   show what the running monitor reports
  python3 monitor-service/monitor_service.py --once     run a single iteration (diagnostics)

Each loop iteration: read a batch of new Falco lines (checkpointed), classify and hand
them to the alert sink, drain Docker container events into the watcher, re-check pending
gate registrations, and flush spooled audit events. Failures of one event are logged and
counted; they never stop the service. Only configuration errors and a second running
instance are fatal.

M1 scope: security alerts and baseline events are counted and logged. Incident creation,
baselines, auto-confirmation and isolation are added in later milestones.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import signal
import sys
import threading
from datetime import datetime, timezone

import docker

from audit_client import AuditClient, make_event_key
from container_watcher import BackendRegistrationLookup, ContainerWatcher, DockerInspector
from docker_events import DockerEventPump
from event_classifier import MalformedEvent, classify_line
from falco_ingest import FalcoTailer, IngestUnavailable
from monitor_config import ConfigError, MonitorConfig, load_config
from monitor_status import StatusBoard, read_status

logger = logging.getLogger("selfsentry.monitor")

STATUS_STALE_SECONDS = 30


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CountingSink:
    """M1 alert sink: counts and logs events. Replaced by the incident pipeline in M3."""

    def __init__(self, status: StatusBoard):
        self._status = status

    def handle_alert(self, event: dict) -> None:
        self._status.incr("alerts_seen")
        logger.info(
            "security alert: container=%s rule=%s priority=%s",
            event.get("container_name") or event.get("container_id"),
            event.get("rule"),
            event.get("priority"),
        )

    def handle_baseline_event(self, event: dict) -> None:
        self._status.incr("baseline_events_seen")


class MonitorService:
    def __init__(
        self,
        config: MonitorConfig,
        tailer,
        watcher,
        audit,
        status: StatusBoard,
        sink,
        docker_events: queue.Queue,
        pump=None,
    ):
        self._config = config
        self._tailer = tailer
        self._watcher = watcher
        self._audit = audit
        self._status = status
        self._sink = sink
        self._docker_events = docker_events
        self._pump = pump
        self._ingest_ok: bool | None = None

    # ---- one iteration -------------------------------------------------------

    def run_once(self) -> int:
        processed = self._ingest_falco()
        self._drain_docker_events()
        self._reconcile_if_needed()
        self._guarded("watcher_errors", "registration re-check", self._watcher.tick)
        self._guarded("audit_flush_errors", "audit spool flush", self._audit.flush_spool)
        self._update_status()
        return processed

    def _guarded(self, counter: str, what: str, func) -> None:
        try:
            func()
        except Exception:  # noqa: BLE001 - one failing step must not stop the service
            logger.exception("%s failed", what)
            self._status.incr(counter)

    # ---- Falco ---------------------------------------------------------------

    def _ingest_falco(self) -> int:
        try:
            batch = self._tailer.read_batch()
        except IngestUnavailable as exc:
            self._set_ingest_state(False, str(exc))
            return 0
        self._set_ingest_state(True)

        for line, key in zip(batch.lines, batch.keys):
            self._handle_line(line, key)
        if batch.skipped_duplicates:
            self._status.incr("duplicates_skipped", batch.skipped_duplicates)
        if batch.keys or batch.end_offset != self._tailer.offset:
            self._tailer.commit(batch)
        return len(batch.lines)

    def _handle_line(self, line: str, key: str) -> None:
        try:
            classified = classify_line(line, key)
        except MalformedEvent as exc:
            self._status.incr("malformed_events")
            logger.warning("malformed Falco event skipped: %s", exc)
            return
        if classified is None:
            self._status.incr("host_events_skipped")
            return
        try:
            if classified.kind == "baseline":
                self._sink.handle_baseline_event(classified.event)
            else:
                self._sink.handle_alert(classified.event)
        except Exception:  # noqa: BLE001 - logged and counted, then the next event proceeds
            logger.exception("event processing failed (rule=%s)", classified.event.get("rule"))
            self._status.incr("processing_errors")
            return
        self._status.incr("falco_lines_processed")
        self._status.set_value("last_event_at", _now())

    def _set_ingest_state(self, ok: bool, detail: str | None = None) -> None:
        previous = self._ingest_ok
        self._ingest_ok = ok
        self._status.set_component("falco_ingest", "ok" if ok else "unavailable", detail)
        if not ok and previous is not False:
            logger.error("Falco ingestion unavailable: %s", detail)
            self._audit_transition("FALCO_INGEST_UNAVAILABLE", "warning", detail)
        elif ok and previous is False:
            logger.warning("Falco ingestion recovered")
            self._audit_transition("FALCO_INGEST_RECOVERED", "info", None)

    def _audit_transition(self, event_type: str, severity: str, detail: str | None) -> None:
        stamp = _now()
        self._audit.emit(
            event_type=event_type,
            severity=severity,
            detail={"reason": detail} if detail else {},
            event_key=make_event_key(event_type, stamp),
            occurred_at=stamp,
        )

    # ---- Docker --------------------------------------------------------------

    def _drain_docker_events(self) -> None:
        while True:
            try:
                event = self._docker_events.get_nowait()
            except queue.Empty:
                return
            try:
                self._watcher.handle_docker_event(event)
            except Exception:  # noqa: BLE001 - logged and counted; reconcile can catch up
                logger.exception("Docker event handling failed")
                self._status.incr("docker_event_errors")

    def _reconcile_if_needed(self) -> None:
        if self._pump is None or not self._pump.reconnected.is_set():
            return
        self._pump.reconnected.clear()
        try:
            count = self._watcher.reconcile()
            logger.info("reconciled running containers (%d newly registered)", count)
        except Exception:  # noqa: BLE001
            logger.exception("container reconcile failed")
            self._status.incr("reconcile_errors")
            self._pump.reconnected.set()  # try again on the next iteration

    # ---- status --------------------------------------------------------------

    def _update_status(self) -> None:
        if self._pump is not None:
            self._status.set_component("docker", self._pump.state, self._pump.last_error)
        outcome = self._audit.last_outcome
        backend_state = {"ok": "ok", "retry": "unavailable", "rejected": "degraded"}.get(
            outcome, "unknown"
        )
        self._status.set_component("backend", backend_state)
        self._status.set_value("audit_spool_size", self._audit.spool_size())
        self._status.set_value(
            "containers",
            {
                "tracked": self._watcher.tracked_count,
                "pending_registration": self._watcher.pending_count,
            },
        )
        self._status.write()

    # ---- lifecycle -----------------------------------------------------------

    def run_forever(self, stop_event: threading.Event) -> None:
        self._status.set_running(True)
        logger.info("SelfSentry monitor started (pid %d)", os.getpid())
        failures = 0
        try:
            while not stop_event.is_set():
                processed = self.run_once()
                if self._ingest_ok is False:
                    failures += 1
                    delay = min(
                        self._config.retry_max_seconds,
                        self._config.retry_base_seconds * 2 ** min(failures, 10),
                    )
                else:
                    failures = 0
                    delay = self._config.poll_interval_seconds if processed == 0 else 0
                if delay > 0:
                    stop_event.wait(delay)
        finally:
            self._status.set_running(False)
            self._status.write()
            logger.info("SelfSentry monitor stopped")


# ---- process wiring ----------------------------------------------------------


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(log_format: str) -> None:
    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


def acquire_lock(state_dir):
    """One monitor at a time: two instances would duplicate every action."""
    import fcntl

    handle = open(state_dir / "monitor.lock", "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def build_service(config: MonitorConfig):
    state_dir = config.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    status = StatusBoard(state_dir / "status.json")
    audit = AuditClient(config.backend_url, state_dir / "audit_spool.jsonl")
    tailer = FalcoTailer(
        config.falco_log_path,
        state_dir / "falco_checkpoint.json",
        start_from=config.start_from,
        dedup_window=config.dedup_window,
        max_batch_lines=config.max_batch_lines,
    )
    watcher = ContainerWatcher(
        config,
        audit,
        BackendRegistrationLookup(config.backend_url),
        DockerInspector(docker.from_env),
    )
    events: queue.Queue = queue.Queue()
    stop_event = threading.Event()
    pump = DockerEventPump(
        docker.from_env, events, stop_event, config.retry_base_seconds, config.retry_max_seconds
    )
    service = MonitorService(
        config, tailer, watcher, audit, status, CountingSink(status), events, pump
    )
    return service, pump, stop_event


def print_status(config: MonitorConfig) -> int:
    status = read_status(config.state_dir / "status.json")
    if status is None:
        print("No status file found: the monitor has not run (or state dir differs).")
        return 1
    updated = status.get("updated_at")
    age = None
    if updated:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(updated)).total_seconds()
    print(json.dumps(status, indent=2))
    healthy = bool(status.get("running")) and age is not None and age < STATUS_STALE_SECONDS
    print(f"\nrunning={status.get('running')} last_update_age_seconds={age}")
    return 0 if healthy else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="monitor_service", description=__doc__.split("\n")[1])
    parser.add_argument("--status", action="store_true", help="print the monitor's status")
    parser.add_argument("--once", action="store_true", help="run one iteration and exit")
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"ERROR: invalid configuration: {exc}", file=sys.stderr)
        return 2
    if args.status:
        return print_status(config)

    setup_logging(config.log_format)
    config.state_dir.mkdir(parents=True, exist_ok=True)
    lock = acquire_lock(config.state_dir)
    if lock is None:
        print("ERROR: another monitor instance is already running.", file=sys.stderr)
        return 3

    service, pump, stop_event = build_service(config)
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    pump.start()
    if args.once:
        service.run_once()
        return 0
    service.run_forever(stop_event)
    return 0


if __name__ == "__main__":
    sys.exit(main())
