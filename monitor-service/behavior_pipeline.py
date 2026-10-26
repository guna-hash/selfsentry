"""Durable windowed telemetry, baseline lifecycle and existing scorer integration.

SQLite is the local inbox/outbox, not a second incident database. Events are journaled
before the Falco offset advances. Closed windows and outbound payloads share a transaction.
Models are rebuilt from validated JSON datasets after restart; no untrusted pickle loads.
"""

from __future__ import annotations

import json
import logging
import math
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("behavioral-engine", "correlation-engine"):
    sys.path.insert(0, str(ROOT / folder))

from anomaly_model import AnomalyModel  # noqa: E402
from baseline_builder import BaselineStore  # noqa: E402
from baseline_collector import parse_baseline_event  # noqa: E402
from feature_extractor import extract_features, security_alert_to_raw_event, EventType  # noqa: E402
from risk_scorer import compute_risk_score  # noqa: E402
from event_router import route_incident  # noqa: E402
from audit_client import make_event_key  # noqa: E402
from observed_timeline import build_observed_timeline  # noqa: E402
from baseline_review import overlaps_training  # noqa: E402
from journal_archive import SCHEMA as ARCHIVE_SCHEMA, seen_event  # noqa: E402

logger = logging.getLogger(__name__)
MAX_TRAINING_JOBS = 2
STATES = (
    "NO_BASELINE",
    "LEARNING",
    "BASELINE_READY",
    "MODEL_TRAINING",
    "MODEL_READY",
    "MODEL_UNAVAILABLE",
)


def timestamp(value):
    stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("event timestamp requires a timezone")
    return stamp.astimezone(timezone.utc)


def container_identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{12,64}", value):
        raise ValueError("container identity must be a Docker hex ID of 12-64 characters")
    # Matches the established Falco / gate short-ID contract. Response resolves full ID.
    return value[:12]


class BehaviorPipeline:
    def __init__(
        self, config, status, audit, clock=time.time, model_factory=None, async_training=False
    ):
        self.config, self.status, self.audit, self.clock = config, status, audit, clock
        self.store = BaselineStore(config.baseline_dir)
        self.model_factory = model_factory or (
            lambda cid: AnomalyModel(cid, algorithm=config.anomaly_algorithm)
        )
        from concurrent.futures import ThreadPoolExecutor

        self.training_pool = (
            ThreadPoolExecutor(max_workers=MAX_TRAINING_JOBS) if async_training else None
        )
        self.training_jobs = {}
        self.models = {}
        self.lifecycle = {}
        config.state_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(config.state_dir / "pipeline.sqlite")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS rejected_events (
                key TEXT PRIMARY KEY, body TEXT, error TEXT);
            CREATE TABLE IF NOT EXISTS events (
              key TEXT PRIMARY KEY, container TEXT, bucket INTEGER, kind TEXT, body TEXT);
            CREATE INDEX IF NOT EXISTS events_window ON events(container, bucket);
            CREATE TABLE IF NOT EXISTS windows (
              container TEXT, bucket INTEGER, PRIMARY KEY(container, bucket));
            CREATE TABLE IF NOT EXISTS lifecycle (container TEXT PRIMARY KEY, body TEXT);
            CREATE TABLE IF NOT EXISTS outbox (
              key TEXT PRIMARY KEY, body TEXT, stage TEXT DEFAULT 'pending',
              incident_id INTEGER, attempts INTEGER DEFAULT 0,
              next_retry REAL DEFAULT 0, error TEXT);
        """)
        self.db.executescript(ARCHIVE_SCHEMA)
        for cid, body in self.db.execute("SELECT container, body FROM lifecycle"):
            self.lifecycle[cid] = json.loads(body)
        self._restored = set()

    def _audit(self, kind, cid, detail, key):
        self.audit.emit(
            event_type=kind,
            container_id=cid,
            detail=detail,
            event_key=make_event_key(kind, cid, key),
        )

    def _transition(self, cid, state, reason=None):
        item = self.lifecycle[cid]
        old = item.get("state")
        item.update(state=state, reason=reason)
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO lifecycle VALUES (?,?)", (cid, json.dumps(item))
            )
        if old != state:
            self._audit(
                "BASELINE_STATE_CHANGED",
                cid,
                {"from": old, "to": state, "reason": reason},
                f"{state}:{self.clock()}",
            )

    def discover(self, cid):
        cid = container_identity(cid)
        if cid not in self.lifecycle:
            discovered_at = self.clock()
            # Train only on buckets beginning after observation starts.
            # Persist this boundary so restart/replay cannot admit the
            # partially observed discovery bucket.
            self.lifecycle[cid] = {
                "started_at": discovered_at,
                "samples": 0,
                "learn_after": discovered_at,
            }
            self._transition(cid, "NO_BASELINE", "no validated baseline")
        if cid not in self._restored:
            self._restored.add(cid)
            if self.lifecycle[cid].get("requires_review"):
                self._transition(cid, "MODEL_UNAVAILABLE", "baseline requires operator review")
                return cid
            try:
                dataset = self.store.load(cid, allow_missing=True)
                self._validate(dataset)
                self.lifecycle[cid]["samples"] = dataset.sample_count
                duration = (
                    (
                        timestamp(dataset.feature_vectors[-1].window_end)
                        - timestamp(dataset.feature_vectors[0].window_start)
                    ).total_seconds()
                    if dataset.feature_vectors
                    else 0
                )
                if (
                    dataset.sample_count >= self.config.min_samples
                    and duration >= self.config.learning_seconds
                ):
                    self._train(cid, dataset)
                elif self.config.learning_enabled:
                    self._transition(cid, "LEARNING", "insufficient baseline windows")
                else:
                    self._transition(cid, "MODEL_UNAVAILABLE", "learning disabled")
            except Exception as exc:
                logger.exception("baseline unavailable for %s", cid)
                self._transition(cid, "MODEL_UNAVAILABLE", str(exc))
        return cid

    def reset_baseline(self, cid, reason):
        """Operator-only local reset, preserving previous data and all incident/action records."""
        cid = container_identity(cid)
        if not reason.strip():
            raise ValueError("baseline reset requires a reason")
        path = self.config.baseline_dir / f"{cid}.json"
        if path.exists():
            import uuid

            path.replace(path.with_suffix(f".{uuid.uuid4().hex}.archived"))
        self.models.pop(cid, None)
        job = self.training_jobs.pop(cid, None)
        if job:
            job.cancel()
        self.lifecycle[cid] = {
            "started_at": self.clock(),
            "samples": 0,
            "learn_after": self.clock(),
        }
        self._restored.add(cid)
        self._transition(
            cid,
            "LEARNING" if self.config.learning_enabled else "MODEL_UNAVAILABLE",
            f"operator reset: {reason}",
        )
        self._audit("BASELINE_RESET", cid, {"reason": reason}, self.clock())

    def _validate(self, dataset):
        seen = set()
        for vector in dataset.feature_vectors:
            if vector.container_id != dataset.container_id:
                raise ValueError("baseline contains another container's features")
            start, end = timestamp(vector.window_start), timestamp(vector.window_end)
            if abs((end - start).total_seconds() - self.config.window_seconds) > 0.01:
                raise ValueError("baseline window length differs from MONITOR_WINDOW_SECONDS")
            if (start, end) in seen:
                raise ValueError("baseline contains duplicate windows")
            seen.add((start, end))
            if any(not math.isfinite(x) or x < 0 for x in vector.to_array()):
                raise ValueError("baseline features must be finite and nonnegative")

    def _train(self, cid, dataset):
        self._validate(dataset)
        if len({tuple(v.to_array()) for v in dataset.feature_vectors}) < 2:
            self._transition(cid, "MODEL_UNAVAILABLE", "baseline has no feature variation")
            return
        self._transition(cid, "BASELINE_READY")
        if self.training_pool and len(self.training_jobs) >= MAX_TRAINING_JOBS:
            self._transition(cid, "BASELINE_READY", "waiting for model training capacity")
            return
        self._transition(cid, "MODEL_TRAINING")
        if self.training_pool:
            self.training_jobs[cid] = self.training_pool.submit(self._fit_model, cid, dataset)
            return
        self.models[cid] = self._fit_model(cid, dataset)
        self.lifecycle[cid]["model_algorithm"] = self.config.anomaly_algorithm
        self._transition(cid, "MODEL_READY")

    def _fit_model(self, cid, dataset):
        # Worker never touches lifecycle, SQLite, audit or status.
        model = self.model_factory(cid)
        model.fit(dataset)
        probe = model.score_event(dataset.feature_vectors[-1])
        if (
            probe.container_id != cid
            or not math.isfinite(probe.anomaly_score)
            or not 0 <= probe.anomaly_score <= 1
        ):
            raise ValueError("model failed readiness validation")
        return model

    def _finish_training(self):
        for cid, job in list(self.training_jobs.items()):
            if not job.done():
                continue
            self.training_jobs.pop(cid)
            item = self.lifecycle[cid]
            if item.get("requires_review") or item["state"] != "MODEL_TRAINING":
                continue
            try:
                self.models[cid] = job.result()
                item["model_algorithm"] = self.config.anomaly_algorithm
                self._transition(cid, "MODEL_READY")
            except Exception as exc:
                self._transition(cid, "MODEL_UNAVAILABLE", str(exc))

    def close(self):
        try:
            if self.training_pool:
                self.training_pool.shutdown(wait=True, cancel_futures=True)
        finally:
            self.db.close()

    def _enqueue(self, payload, key):
        self.db.execute(
            "INSERT OR IGNORE INTO outbox(key,body) VALUES (?,?)", (key, json.dumps(payload))
        )

    def accept(self, event, kind):
        cid = container_identity(event.get("container_id"))
        stamp = timestamp(event["timestamp"])
        if stamp.timestamp() > self.clock() + 30:
            raise ValueError("event timestamp too far in the future")
        key = event.get("event_key") or make_event_key(kind, json.dumps(event, sort_keys=True))
        if seen_event(self.db, key):
            return
        bucket = int(stamp.timestamp() // self.config.window_seconds) * self.config.window_seconds
        normalized = dict(event, container_id=cid)
        if kind == "baseline":
            raw = parse_baseline_event(event["raw_line"])
            if raw is None:
                raise ValueError("unknown baseline rule or unusable telemetry")
            # Require the field that makes this sample meaningful.
            field = {
                "process_spawn": "proc_name",
                "network_connect": "dest_ip",
                "file_access": "file_path",
                "syscall": "syscall_name",
            }[raw.event_type.value]
            if not isinstance(getattr(raw, field), str) or getattr(raw, field) in (
                "",
                "<NA>",
                "<na>",
            ):
                raise ValueError("baseline feature must be a usable string")
            if raw.parent_proc_name is not None and not isinstance(raw.parent_proc_name, str):
                raise ValueError("parent process name must be a string")
            if raw.dest_port is not None and not 0 <= raw.dest_port <= 65535:
                raise ValueError("destination port out of range")
            if getattr(raw, field) in (None, "", "<NA>", "<na>"):
                raise ValueError("baseline event has no usable feature")
        self.discover(cid)
        self.lifecycle[cid]["last_event_at"] = self.clock()
        closed = self.db.execute(
            "SELECT 1 FROM windows WHERE container=? AND bucket=?", (cid, bucket)
        ).fetchone()
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)",
                (key, cid, bucket, kind, json.dumps(normalized)),
            )
            if closed and kind == "alert":
                # Late security evidence is still delivered, without claiming correlation.
                late_payload = self._payload(cid, bucket, [normalized], None, "late")
                late_payload["event_key"] = key
                self._enqueue(late_payload, key)
        if closed:
            detail = {"kind": kind, "event_key": key, "event_timestamp": normalized["timestamp"]}
            if kind == "alert":
                # A late event invalidates training only when its window could
                # have contributed a sample. Keep post-training incidents live.
                try:
                    dataset = self.store.load(cid, allow_missing=True)
                    self._validate(dataset)
                    if not dataset.sample_count and (
                        cid in self.models or self.lifecycle[cid].get("samples", 0)
                    ):
                        raise ValueError("previous baseline samples are missing")
                    start = datetime.fromtimestamp(bucket, timezone.utc)
                    end = start + timedelta(seconds=self.config.window_seconds)
                    overlap = overlaps_training(dataset, start, end)
                    detail["training_overlap"] = overlap
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    overlap = True  # Unknown exposure remains fail-closed.
                    detail.update(training_overlap=None, baseline_check_error=str(exc))
                if overlap:
                    self.models.pop(cid, None)
                    self.lifecycle[cid]["requires_review"] = True
                    self._transition(
                        cid, "MODEL_UNAVAILABLE", "late security alert; review baseline"
                    )
            self._audit("LATE_EVENT", cid, detail, key)
        self.status.incr("alerts_seen" if kind == "alert" else "baseline_events_seen")

    def handle_alert(self, event):
        self._handle(event, "alert")

    def handle_baseline_event(self, event):
        self._handle(event, "baseline")

    def record_rejected_line(self, line, key, reason):
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO rejected_events VALUES (?,?,?)",
                (key, json.dumps({"raw_line": line}), reason),
            )

    def _handle(self, event, kind):
        try:
            self.accept(event, kind)
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            key = event.get("event_key") or make_event_key(json.dumps(event, sort_keys=True))
            with self.db:
                self.db.execute(
                    "INSERT OR IGNORE INTO rejected_events VALUES (?,?,?)",
                    (key, json.dumps(event), str(exc)),
                )
            logger.warning("unusable event retained for review: %s", exc)
            self.status.incr("unusable_events")
            self._audit("EVENT_REJECTED", event.get("container_id"), {"reason": str(exc)}, key)

    def _payload(self, cid, bucket, alerts, anomaly, availability, reason=None):
        alerts = sorted(
            alerts, key=lambda item: compute_risk_score([item], [])[0]["risk_score"], reverse=True
        )
        scored = compute_risk_score(
            alerts,
            [anomaly] if anomaly else [],
            timedelta(seconds=self.config.correlation_seconds),
        )
        if not scored:
            return None
        # Keep the strongest incident; all alerts are preserved as recorded evidence.
        payload = max(scored, key=lambda item: route_incident(item).effective_score)
        decision = route_incident(payload)
        payload.update(event_key=make_event_key("window", cid, bucket), defer_ai=True)
        payload["monitor_evidence"] = {
            "baseline_state": self.lifecycle[cid]["state"],
            "anomaly_status": availability,
            "anomaly_reason": reason,
            "cross_layer_agreement": bool(payload["falco_alert"] and payload["anomaly_features"]),
            "effective_score": decision.effective_score,
            "window_start": datetime.fromtimestamp(bucket, timezone.utc).isoformat(),
            "window_end": datetime.fromtimestamp(
                bucket + self.config.window_seconds, timezone.utc
            ).isoformat(),
            "falco_alerts": alerts,
            "observed_timeline": build_observed_timeline(alerts, anomaly),
            "score_formula": (
                "Falco base + 40*anomaly + 20 agreement; cap 100; confidence adjustment"
            ),
            "policy_version": "monitor-v1",
        }
        return payload

    def tick(self):
        self._finish_training()
        if self.training_pool:
            for cid, item in self.lifecycle.items():
                if len(self.training_jobs) >= MAX_TRAINING_JOBS:
                    break
                if item["state"] == "BASELINE_READY" and not item.get("requires_review"):
                    try:
                        self._train(cid, self.store.load(cid))
                    except Exception as exc:
                        self._transition(cid, "MODEL_UNAVAILABLE", str(exc))
        cutoff = self.clock() - self.config.lateness_seconds - self.config.window_seconds
        rows = list(
            self.db.execute(
                """
            SELECT DISTINCT e.container, e.bucket FROM events e
            LEFT JOIN windows w ON e.container=w.container AND e.bucket=w.bucket
            WHERE w.bucket IS NULL AND e.bucket <= ? ORDER BY e.bucket LIMIT 100
        """,
                (cutoff,),
            )
        )
        for cid, bucket in rows:
            try:
                self._close_window(cid, bucket)
            except Exception as exc:
                logger.exception("window processing failed for %s", cid)
                self.status.incr("window_errors")
                # Keep the journal rows pending for retry; never advance an outbox on failure.
                self.status.set_component("behavior", "degraded", str(exc))
        self.status.set_value("baselines", self.lifecycle)
        self.status.set_value("models_ready", len(self.models))
        self.status.set_value(
            "containers_learning",
            sum(item.get("state") == "LEARNING" for item in self.lifecycle.values()),
        )
        self.status.set_value(
            "incident_outbox_size",
            self.db.execute(
                "SELECT count(*) FROM outbox WHERE stage NOT IN ('done','rejected')"
            ).fetchone()[0],
        )

    def _close_window(self, cid, bucket):
        self.discover(cid)
        events = [
            (kind, json.loads(body))
            for kind, body in self.db.execute(
                "SELECT kind,body FROM events WHERE container=? AND bucket=? ORDER BY key",
                (cid, bucket),
            )
        ]
        alerts = [event for kind, event in events if kind == "alert"]
        raw = []
        for kind, event in events:
            if kind == "baseline":
                parsed = parse_baseline_event(event["raw_line"])
                if parsed is None:
                    raise ValueError("Stored baseline record is not a recognized baseline event")
                raw.append(parsed)
        for alert in alerts:
            converted = security_alert_to_raw_event(alert)
            if converted is None:
                continue
            # Default-rule output may omit the parent present in baseline output.
            # Credit the shell once while retaining the richer baseline context.
            overlap = any(
                r.event_type == EventType.PROCESS_SPAWN
                and r.timestamp == converted.timestamp
                and r.proc_name == converted.proc_name
                and (
                    not r.parent_proc_name
                    or not converted.parent_proc_name
                    or r.parent_proc_name == converted.parent_proc_name
                )
                for r in raw
            )
            if not overlap:
                raw.append(converted)
        # Falco rule_matching=all may emit the same syscall more than once.
        unique = {
            (
                r.timestamp,
                r.event_type,
                r.proc_name,
                r.parent_proc_name,
                r.dest_ip,
                r.dest_port,
                r.file_path,
                r.syscall_name,
            ): r
            for r in raw
        }
        raw = list(unique.values())
        for event in raw:
            event.container_id = cid
        start = datetime.fromtimestamp(bucket, timezone.utc)
        end = start + timedelta(seconds=self.config.window_seconds)
        vector = extract_features(raw, cid, start, end)
        anomaly = None
        state = self.lifecycle[cid]["state"]
        availability = "learning" if state == "LEARNING" else "unavailable"
        reason = self.lifecycle[cid].get("reason")
        assessment = None
        if cid in self.models and raw:
            try:
                result = self.models[cid].score_event(vector)
                if not math.isfinite(result.anomaly_score) or not 0 <= result.anomaly_score <= 1:
                    raise ValueError("model produced invalid score")
                availability = "used"
                assessment = {
                    "model_algorithm": self.config.anomaly_algorithm,
                    "anomaly_score": float(result.anomaly_score),
                    "raw_decision_function": float(result.raw_decision_function),
                    "model_is_anomaly": bool(result.is_anomaly),
                    "threshold": self.config.anomaly_threshold,
                    "qualifies": bool(
                        result.is_anomaly and result.anomaly_score >= self.config.anomaly_threshold
                    ),
                    "features": vector.to_dict(),
                }
                if result.is_anomaly and result.anomaly_score >= self.config.anomaly_threshold:
                    anomaly = result.to_event_dict()
                    anomaly["timestamp"] = max(r.timestamp for r in raw).isoformat()
            except Exception as exc:
                availability, reason = "failed", str(exc)
                self.models.pop(cid, None)
                self._transition(cid, "MODEL_UNAVAILABLE", reason)
        elif (
            state == "LEARNING"
            and raw
            and not alerts
            and bucket >= self.lifecycle[cid].get("learn_after", 0)
        ):
            self.store.append(vector)
            dataset = self.store.load(cid)
            self.lifecycle[cid]["samples"] = dataset.sample_count
            duration = (
                timestamp(dataset.feature_vectors[-1].window_end)
                - timestamp(dataset.feature_vectors[0].window_start)
            ).total_seconds()
            if (
                dataset.sample_count >= self.config.min_samples
                and duration >= self.config.learning_seconds
            ):
                try:
                    self._train(cid, dataset)
                except Exception as exc:
                    logger.exception("model training failed")
                    self._transition(cid, "MODEL_UNAVAILABLE", str(exc))
            else:
                self._transition(cid, "LEARNING", "awaiting sample count and learning duration")
        elif not raw:
            reason = "no usable baseline telemetry in this window"
        payload = self._payload(cid, bucket, alerts, anomaly, availability, reason)
        if payload:
            payload["monitor_evidence"]["anomaly_assessment"] = assessment
            if anomaly and not alerts:
                # Preserve a real literal witness; aggregated counts cannot generate a rule.
                candidates = [e for kind, e in events if kind == "baseline"]
                for event in candidates:
                    parsed = json.loads(event["raw_line"])
                    fields = parsed.get("output_fields") or {}
                    process = fields.get("proc.name")
                    process_pair = (
                        event.get("rule") == "Baseline Process Spawn"
                        and process
                        and fields.get("proc.pname")
                    )
                    file_write = (
                        event.get("rule") == "Baseline File Write"
                        and process
                        and fields.get("fd.name")
                    )
                    if process_pair or file_write:
                        payload["monitor_evidence"]["synthesis_evidence"] = {
                            **event,
                            "output_fields": fields,
                        }
                        break
        with self.db:
            if payload:
                self._enqueue(payload, payload["event_key"])
            self.db.execute("INSERT OR IGNORE INTO windows VALUES (?,?)", (cid, bucket))
        self.lifecycle[cid]["last_window_at"] = self.clock()
        self.status.incr("windows_processed")
