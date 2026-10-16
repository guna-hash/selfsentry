"""Option B eligibility: existing effective score plus validated independent evidence."""

from __future__ import annotations
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "correlation-engine"))
from datetime import datetime, timezone  # noqa: E402


def _stamp(value):
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return result.astimezone(timezone.utc)


def eligible(payload, config, action="confirm", now=None):
    enabled = config.auto_confirm_enabled if action == "confirm" else config.auto_isolation_enabled
    threshold = (
        config.auto_confirm_threshold if action == "confirm" else config.auto_isolation_threshold
    )
    if payload.get("monitor_workflow", {}).get("disposition", {}).get("status") == "benign":
        return False, "operator dismissed incident as benign"
    if not enabled:
        return False, f"auto-{action} disabled"
    from event_router import route_incident

    if action == "confirm" and payload.get("anomaly_features") and not payload.get("falco_alert"):
        return _eligible_anomaly_candidate(payload, config, now)
    score = route_incident(payload).effective_score
    if not math.isfinite(score) or score < threshold:
        return False, "effective score below threshold"
    evidence = payload.get("monitor_evidence") or {}
    falco, anomaly = payload.get("falco_alert"), payload.get("anomaly_features")
    if not falco or not anomaly or evidence.get("anomaly_status") != "used":
        return False, "both detection layers must be available"
    if evidence.get("baseline_state") != "MODEL_READY":
        return False, "model not ready"
    cid = payload.get("container_id")
    if falco.get("container_id") != cid or anomaly.get("container_id") != cid:
        return False, "wrong-container evidence"
    if str(falco.get("rule", "")).startswith("Baseline "):
        return False, "baseline telemetry is not security evidence"
    if str(falco.get("priority", "")).upper() not in (
        "EMERGENCY",
        "ALERT",
        "CRITICAL",
        "ERROR",
        "WARNING",
        "NOTICE",
    ):
        return False, "Falco evidence does not qualify"
    try:
        anomaly_score = float(anomaly["anomaly_score"])
        if not math.isfinite(anomaly_score) or not config.anomaly_threshold <= anomaly_score <= 1:
            return False, "anomaly evidence below threshold"
        fts, ats = _stamp(falco["timestamp"]), _stamp(anomaly["timestamp"])
        if abs((fts - ats).total_seconds()) > config.correlation_seconds:
            return False, "evidence outside correlation window"
        start, end = _stamp(evidence["window_start"]), _stamp(evidence["window_end"])
        if not start <= fts <= end or not start <= ats <= end:
            return False, "evidence outside feature window"
        if now is not None:
            age = now - max(fts.timestamp(), ats.timestamp())
            if age < -30 or age > config.response_max_age_seconds:
                return False, "historical or future evidence requires human review"
    except (KeyError, ValueError, TypeError):
        return False, "invalid evidence values or timestamps"
    return True, f"both layers qualify; effective score {score} >= {threshold}"


def _eligible_anomaly_candidate(payload, config, now):
    """Authorize a proposal, never isolation; confirmation is policy acceptance, not truth."""
    if not config.auto_confirm_anomaly_enabled:
        return False, "anomaly-only proposal confirmation disabled"
    evidence = payload.get("monitor_evidence") or {}
    assessment = evidence.get("anomaly_assessment") or {}
    witness = evidence.get("synthesis_evidence") or {}
    anomaly = payload.get("anomaly_features") or {}
    cid = payload.get("container_id")
    if (
        evidence.get("baseline_state") != "MODEL_READY"
        or evidence.get("anomaly_status") != "used"
        or not assessment.get("qualifies")
    ):
        return False, "validated ready-model evidence required"
    if anomaly.get("container_id") != cid or witness.get("container_id") != cid:
        return False, "wrong-container anomaly witness"
    try:
        score = float(anomaly["anomaly_score"])
        if not math.isfinite(score) or not config.auto_confirm_anomaly_threshold <= score <= 1:
            return False, "anomaly below proposal confirmation threshold"
        start, end = _stamp(evidence["window_start"]), _stamp(evidence["window_end"])
        stamp, observed = _stamp(anomaly["timestamp"]), _stamp(witness["timestamp"])
        if not start <= stamp <= end or not start <= observed <= end:
            return False, "anomaly witness outside feature window"
        if (
            now is not None
            and not -30 <= now - stamp.timestamp() <= config.response_max_age_seconds
        ):
            return False, "historical or future anomaly evidence requires review"
        from pattern_extractor import extract_pattern
        from rule_template_generator import generate_rule

        generate_rule(extract_pattern(payload), payload.get("id", 0))
    except (KeyError, TypeError, ValueError, RuntimeError):
        return False, "missing or unsupported literal syscall witness"
    return True, "ready-model anomaly with literal witness; rule proposal only, no isolation"
