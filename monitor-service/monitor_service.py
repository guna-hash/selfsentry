"""
monitor_service.py
--------------------
SelfSentry continuous monitor (milestone M1: ingestion and container discovery).

  python3 monitor-service/monitor_service.py            run until stopped (Ctrl+C / SIGTERM)
  python3 monitor-service/monitor_service.py --status   show what the running monitor reports
  python3 monitor-service/monitor_service.py --once     run a single iteration (diagnostics)

Falco ingestion, feature extraction and window correlation run independently of the
control worker that handles Docker discovery/response, backend delivery, audit replay
and candidate synthesis. Model fitting uses a bounded pool. A per-event/window failure
is contained; durable storage failures retain the checkpoint for retry. Running workloads
have no alert-triggered unsubscribe or stop-monitoring path. Paused workloads remain in
inventory and produce no new process activity until resumed.

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
from contextlib import ExitStack
from datetime import datetime, timezone

import docker

from audit_client import AuditJournalError, DurableAuditClient, make_event_key
from container_watcher import BackendRegistrationLookup, ContainerWatcher, DockerInspector
from docker_events import DockerEventPump
from event_classifier import MalformedEvent, classify_line
from falco_ingest import FalcoTailer, IngestUnavailable
from monitor_config import ConfigError, MonitorConfig, load_config
from monitor_status import StatusBoard, read_status, describe_status
from behavior_pipeline import BehaviorPipeline
from control_worker import ControlWorker, DOCKER_EVENT_QUEUE_SIZE

logger = logging.getLogger("selfsentry.monitor")


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
        incident_pipeline=None,
        control_worker=None,
    ):
        self._config = config
        self._tailer = tailer
        self._watcher = watcher
        self._audit = audit
        self._status = status
        self._sink = sink
        self._docker_events = docker_events
        self._pending_docker_event = None
        self._pump = pump
        self._incident_pipeline = incident_pipeline
        self._control_worker = control_worker
        self._ingest_ok: bool | None = None

    # ---- one iteration -------------------------------------------------------

    def run_once(self) -> int:
        processed = self._ingest_falco()
        self._drain_docker_events()
        self._reconcile_if_needed()
        if hasattr(self._watcher, "container_ids") and hasattr(self._sink, "discover"):
            for cid in self._watcher.container_ids:
                self._guarded(
                    "discovery_errors", "baseline discovery", lambda: self._sink.discover(cid)
                )
        self._guarded("watcher_errors", "registration re-check", self._watcher.tick)
        if hasattr(self._sink, "tick"):
            self._guarded("pipeline_errors", "behavior pipeline", self._sink.tick)
        if self._incident_pipeline is not None:
            self._guarded("incident_errors", "incident outbox", self._incident_pipeline.tick)
        if self._control_worker is None:
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
        for line, key in zip(batch.lines, batch.keys):
            self._handle_line(line, key)
        if batch.skipped_duplicates:
            self._status.incr("duplicates_skipped", batch.skipped_duplicates)
        if batch.keys or batch.end_offset != self._tailer.offset:
            try:
                self._tailer.commit(batch)
            except IngestUnavailable as exc:
                self._set_ingest_state(False, str(exc))
                return len(batch.lines)
        self._set_ingest_state(True)
        return len(batch.lines)

    def _handle_line(self, line: str, key: str) -> None:
        try:
            classified = classify_line(line, key)
        except MalformedEvent as exc:
            if hasattr(self._sink, "record_rejected_line"):
                self._sink.record_rejected_line(line, key, str(exc))
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
            if hasattr(self._sink, "accept"):
                # A durable sink failure (e.g. disk full) must stop checkpoint advancement.
                raise
            return
        self._status.incr("falco_lines_processed")
        self._status.set_value("last_event_at", _now())
        # Receipt freshness and event-time freshness describe different things.
        # Replay/backlog and clock faults can all produce a large difference.
        event_time = datetime.fromisoformat(
            classified.event["timestamp"].replace("Z", "+00:00")
        )
        received_at = datetime.now(timezone.utc)
        lag = (received_at - event_time).total_seconds()
        self._status.set_value("event_time_observation", {
            "event_timestamp": classified.event["timestamp"],
            "received_at": received_at.isoformat(),
            "receipt_minus_event_seconds": lag,
            "warning": abs(lag) > 30,
            "interpretation": (
                "Clock skew or delivery delay; historical replay may explain lag"
                if abs(lag) > 30 else
                "Latest processed event timestamp is within 30 seconds of receipt"
            ),
            "scope": "Latest successfully processed container event only",
        })

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
        # Leave bursts queued in FIFO order so Falco ingestion and window closure
        # get another turn even when Docker events keep arriving.
        for _ in range(self._config.max_batch_lines):
            event = self._pending_docker_event
            if event is None:
                try:
                    event = self._docker_events.get_nowait()
                except queue.Empty:
                    return
            try:
                if self._watcher.handle_docker_event(event) is False:
                    self._pending_docker_event = event
                    return
            except Exception:  # noqa: BLE001 - logged and counted; reconcile can catch up
                logger.exception("Docker event handling failed")
                self._status.incr("docker_event_errors")
            self._pending_docker_event = None

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
        cfg = self._config
        self._status.set_value("configuration", {
            "auto_isolation_enabled": cfg.auto_isolation_enabled,
            "auto_isolation_threshold": cfg.auto_isolation_threshold,
            "protected_containers": list(cfg.protected_containers),
            "auto_confirm_enabled": cfg.auto_confirm_enabled,
            "anomaly_proposals_enabled": cfg.auto_confirm_anomaly_enabled,
            "rule_candidates_enabled": cfg.rule_candidates_enabled,
        })
        self._status.set_value("docker_event_queue_depth", self._docker_events.qsize())
        self._status.set_value("docker_event_pending", self._pending_docker_event is not None)
        if self._control_worker is not None:
            self._status.set_value("control_event_queue_depth", self._control_worker.events.qsize())
        if self._pump is not None:
            self._status.set_component("docker", self._pump.state, self._pump.last_error)
        outcome = self._audit.last_outcome
        probe = getattr(self._audit, "backend_probe_outcome", None)
        # An unavailable readiness probe overrides old delivery success. A healthy
        # probe resolves idle startup, but never hides a failed delivery outcome.
        if probe == "retry" or outcome is None:
            outcome = probe or outcome
        backend_state = {"ok": "ok", "retry": "unavailable", "rejected": "degraded"}.get(
            outcome, "unknown"
        )
        self._status.set_component("backend", backend_state)
        try:
            spool_size = self._audit.spool_size()
        except AuditJournalError as exc:
            self._status.set_value("audit_spool_size", None)
            self._status.set_component("audit_spool", "degraded", str(exc))
        else:
            self._status.set_value("audit_spool_size", spool_size)
            self._status.set_component(
                "audit_spool", "ok", "Depth readable; payload validation occurs during delivery"
            )
        self._status.set_value(
            "containers",
            {
                "tracked": self._watcher.tracked_count,
                "pending_registration": self._watcher.pending_count,
            },
        )
        self._status.set_value(
            "monitored_container_ids",
            self._watcher.container_ids if hasattr(self._watcher, "container_ids") else [],
        )
        self._status.write()

    # ---- lifecycle -----------------------------------------------------------

    def run_forever(self, stop_event: threading.Event) -> None:
        self._status.set_running(True)
        logger.info("SelfSentry monitor started (pid %d)", os.getpid())
        failures = 0
        try:
            while not stop_event.is_set():
                try:
                    processed = self.run_once()
                except Exception:
                    logger.exception("monitor iteration failed; checkpoint retained for retry")
                    self._status.incr("iteration_errors")
                    stop_event.wait(self._config.retry_max_seconds)
                    continue
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
            logger.info("monitor ingestion loop stopped; background cleanup pending")


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
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


def acquire_lock(state_dir):
    """One monitor at a time: two instances would duplicate every action."""
    import fcntl

    # A competing opener must not truncate the current owner's PID before flock.
    handle = open(state_dir / "monitor.lock", "a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def build_service(config: MonitorConfig):
    state_dir = config.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    status = StatusBoard(state_dir / "status.json")
    audit = DurableAuditClient(config.backend_url, state_dir / "audit_spool.jsonl")
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
    pipeline = BehaviorPipeline(config, status, audit, async_training=True)
    control = ControlWorker(config, watcher, audit, status)
    events: queue.Queue = queue.Queue(maxsize=DOCKER_EVENT_QUEUE_SIZE)
    stop_event = threading.Event()
    pump = DockerEventPump(
        docker.from_env, events, stop_event, config.retry_base_seconds, config.retry_max_seconds
    )
    service = MonitorService(
        config, tailer, control, audit, status, pipeline, events, pump, control_worker=control
    )
    return service, pump, stop_event


def print_status(config: MonitorConfig) -> int:
    status = describe_status(read_status(config.state_dir / "status.json"))
    print(json.dumps(status, indent=2))
    print(f"\nrunning={status.get('running')} "
          f"last_update_age_seconds={status.get('status_age_seconds')}")
    return 0 if status["healthy"] else 1


def shutdown_service(service, pump, stop_event):
    """Keep the caller's instance lock held until background work has exited."""
    stop_event.set()
    service._control_worker.request_stop()
    service._status.set_component("shutdown", "stopping")
    service._status.write()
    with ExitStack() as cleanup:
        cleanup.callback(service._sink.close)
        cleanup.callback(service._control_worker.stop)
        if pump.ident is not None:
            cleanup.callback(pump.join)
        cleanup.callback(pump.stop)
    service._status.set_running(False)
    service._status.set_component("shutdown", "stopped")
    service._status.write()
    logger.info("SelfSentry monitor background cleanup complete")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="monitor_service", description=__doc__.split("\n")[1])
    parser.add_argument("--status", action="store_true", help="print the monitor's status")
    parser.add_argument("--once", action="store_true", help="run one iteration and exit")
    parser.add_argument("--reset-baseline", metavar="CONTAINER_ID")
    parser.add_argument("--review-baseline", metavar="CONTAINER_ID")
    parser.add_argument("--reviewed-by", help="explicit human baseline reviewer")
    parser.add_argument(
        "--evidence-key",
        action="append",
        default=[],
        help="late-alert event key; repeat for all reviewed alerts",
    )
    parser.add_argument("--reason", help="required reason for a baseline reset/review")
    args = parser.parse_args(argv)
    if args.reset_baseline and args.review_baseline:
        parser.error("reset and review cannot be combined")
    if args.review_baseline and (not args.reason or not args.reviewed_by or not args.evidence_key):
        parser.error("--review-baseline requires --reason, --reviewed-by and --evidence-key")
    if args.reset_baseline and not args.reason:
        parser.error("--reset-baseline requires --reason")

    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
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

    with lock:
        if args.reset_baseline or args.review_baseline:
            pipeline = None
            try:
                board = StatusBoard(config.state_dir / "status.json")
                audit = DurableAuditClient(
                    config.backend_url, config.state_dir / "audit_spool.jsonl", timeout_seconds=2.0
                )
                pipeline = BehaviorPipeline(config, board, audit)
                if args.review_baseline:
                    from baseline_review import review_baseline
                    from behavior_pipeline import container_identity

                    report = review_baseline(
                        pipeline,
                        container_identity(args.review_baseline),
                        args.reviewed_by,
                        args.reason,
                        args.evidence_key,
                    )
                    print(json.dumps({"status": "reviewed", **report}, indent=2))
                else:
                    pipeline.reset_baseline(args.reset_baseline, args.reason)
                    print(f"Baseline reset for {args.reset_baseline}; prior data archived.")
                return 0
            except (OSError, ValueError, KeyError, TypeError) as exc:
                print(f"ERROR: baseline action refused: {exc}", file=sys.stderr)
                return 2
            finally:
                if pipeline is not None:
                    pipeline.close()
        service, pump, stop_event = build_service(config)
        try:
            signal.signal(signal.SIGINT, lambda *_: stop_event.set())
            signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
            pump.start()
            service._control_worker.start()
            if args.once:
                service.run_once()
            else:
                service.run_forever(stop_event)
            return 0
        finally:
            shutdown_service(service, pump, stop_event)


if __name__ == "__main__":
    sys.exit(main())
