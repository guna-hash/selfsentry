"""Explicit recovery of legacy late-alert holds; never certify a workload as benign."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone


class BaselineReviewError(ValueError):
    """Evidence is insufficient to remove a baseline review hold."""


def utc_timestamp(value):
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise BaselineReviewError("Evidence timestamp has no timezone")
    return result.astimezone(timezone.utc)


def overlaps_training(dataset, start, end):
    """Half-open event windows: adjacent windows do not overlap."""
    return any(
        start < utc_timestamp(v.window_end) and utc_timestamp(v.window_start) < end
        for v in dataset.feature_vectors
    )


def review_baseline(pipeline, cid, reviewed_by, reason, evidence_keys):
    """Called only with the monitor's exclusive lock held and ingestion stopped.

    Check every journaled security event, plus operator-specified late-alert keys.
    Refuse missing evidence, contaminated/invalid data, and unrelated failure holds.
    A successful fit/probe precedes any lifecycle mutation. No baseline is rewritten.
    """
    if not reviewed_by.strip() or reviewed_by.strip().lower() == "selfsentry-auto":
        raise BaselineReviewError("An explicit human reviewer is required")
    if not reason.strip():
        raise BaselineReviewError("A baseline review reason is required")
    if not evidence_keys or any(not isinstance(key, str) or not key for key in evidence_keys):
        raise BaselineReviewError("Provide the late-alert event keys from the audit evidence")
    item = pipeline.lifecycle.get(cid)
    if (
        not item
        or not item.get("requires_review")
        or item.get("reason")
        not in (
            "late security alert; review baseline",
            "baseline requires operator review",
        )
    ):
        raise BaselineReviewError("Only an existing late-alert baseline hold can be reviewed")
    path = pipeline.config.baseline_dir / f"{cid}.json"
    original = path.read_bytes()
    dataset = pipeline.store.load(cid)
    pipeline._validate(dataset)
    if dataset.sample_count < pipeline.config.min_samples:
        raise BaselineReviewError("Baseline has insufficient samples")
    starts = [utc_timestamp(v.window_start) for v in dataset.feature_vectors]
    ends = [utc_timestamp(v.window_end) for v in dataset.feature_vectors]
    if (max(ends) - min(starts)).total_seconds() < pipeline.config.learning_seconds:
        raise BaselineReviewError("Baseline has insufficient learning duration")
    if len({tuple(v.to_array()) for v in dataset.feature_vectors}) < 2:
        raise BaselineReviewError("Baseline has no feature variation")

    required, found, witnesses = set(evidence_keys), set(), []
    count = 0
    for key, bucket, body in pipeline.db.execute(
        "SELECT key, bucket, body FROM events WHERE container=? AND kind='alert'", (cid,)
    ):
        event = json.loads(body)
        if event.get("container_id") != cid:
            raise BaselineReviewError(f"Journal event identity mismatch: {key}")
        stamp = utc_timestamp(event["timestamp"])
        expected = int(stamp.timestamp() // pipeline.config.window_seconds)
        expected *= pipeline.config.window_seconds
        if bucket != expected:
            raise BaselineReviewError(f"Journal event bucket mismatch: {key}")
        start = datetime.fromtimestamp(bucket, timezone.utc)
        end = start + timedelta(seconds=pipeline.config.window_seconds)
        if overlaps_training(dataset, start, end):
            raise BaselineReviewError(f"Security event overlaps training baseline: {key}")
        count += 1
        if key in required:
            if not pipeline.db.execute(
                "SELECT 1 FROM windows WHERE container=? AND bucket=?", (cid, bucket)
            ).fetchone():
                raise BaselineReviewError(f"Evidence window is not closed: {key}")
            found.add(key)
            witnesses.append(
                {
                    "event_key": key,
                    "timestamp": event["timestamp"],
                    "rule": event.get("rule"),
                    "training_overlap": False,
                }
            )
    if found != required:
        raise BaselineReviewError(f"Missing journal evidence keys: {sorted(required - found)}")

    model = pipeline._fit_model(cid, dataset)
    if not math.isfinite(pipeline.clock()):
        raise BaselineReviewError("Invalid host clock")
    if path.read_bytes() != original:
        raise BaselineReviewError("Baseline changed during review")
    reviewed_at = datetime.fromtimestamp(pipeline.clock(), timezone.utc)
    review_id = uuid.uuid4().hex
    backup = pipeline.config.state_dir / "baseline-reviews" / review_id
    backup.mkdir(parents=True)
    (backup / "baseline.json").write_bytes(original)
    with sqlite3.connect(backup / "pipeline.sqlite") as destination:
        pipeline.db.backup(destination)
    report = {
        "review_id": review_id,
        "container_id": cid,
        "reviewed_by": reviewed_by.strip(),
        "reason": reason.strip(),
        "reviewed_at": reviewed_at.isoformat(),
        "baseline_sha256": hashlib.sha256(original).hexdigest(),
        "samples": dataset.sample_count,
        "training_start": min(starts).isoformat(),
        "training_end": max(ends).isoformat(),
        "journal_alerts_checked": count,
        "evidence_events": witnesses,
        "backup_directory": str(backup),
        "scope": (
            "journal event-time overlap and model validation; "
            "not a benignness or clock attestation"
        ),
    }
    (backup / "review.json").write_text(json.dumps(report, indent=2) + "\n")
    pipeline._audit("BASELINE_REVIEWED", cid, report, review_id)
    pipeline.models[cid] = model
    item.update(
        requires_review=False,
        samples=dataset.sample_count,
        operator_review=report,
        model_algorithm=pipeline.config.anomaly_algorithm,
    )
    pipeline._restored.add(cid)
    pipeline._transition(cid, "MODEL_READY", "human review: no journal alert overlaps training")
    return report
