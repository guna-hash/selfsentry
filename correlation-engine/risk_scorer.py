"""
risk_scorer.py
----------------
Module 5a of SelfSentry: Correlation Engine.

Merges Falco's rule-based alerts (interface shape #1) and the behavioral
engine's anomaly events (interface shape #2) into a list of incident
payloads ready to POST to backend-api's real POST /incidents/ endpoint
(see backend-api/routes/incidents.py + models/db_models.py).

IMPORTANT - this shape was corrected against the REAL backend, not the
original speculative design in docs/interfaces.md:
  - No incident_id is generated here anymore - the database assigns it
    on insert (Incident.id is auto-increment). Generating our own would
    just be discarded/ignored by the real API.
  - "confidence" (a 3-tier string: high/medium/low) replaces the earlier
    boolean "dual_layer_agreement" - matches db_models.py's actual
    `confidence = Column(String(16))` field. The frontend (Alerts.jsx)
    displays this value raw with no special-casing, so the exact tier
    labels are our choice, not a hard external constraint.
  - No "status" field - confirmation state lives in the separate
    ConfirmedIncident table on the backend side (via a different
    endpoint), not as a field on the incident payload itself.
  - "anomaly_features" (matching the real DB column name) holds the FULL
    shape #2 dict, not just its inner "features" key - see docs/
    interfaces.md for why, and flag to the Phase 8 owner if that
    assumption is wrong.

Design notes carried over from the original design:
  - Falco alerts and anomaly events are matched by container_id AND a
    time-window tolerance (CORRELATION_WINDOW), not exact timestamp
    equality.
  - Every unmatched Falco alert AND every unmatched anomaly event still
    becomes its own incident (single-layer) - never silently dropped,
    since single-layer detections (especially anomaly-only, i.e. novel
    attacks with no matching rule yet) are exactly what this project's
    hybrid design exists to catch.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

# --- Falco priority -> base risk score -------------------------------
FALCO_PRIORITY_SCORES: dict[str, int] = {
    "EMERGENCY": 100,
    "ALERT": 95,
    "CRITICAL": 80,
    "ERROR": 70,
    "WARNING": 50,
    "NOTICE": 20,
    "INFORMATIONAL": 10,
    "DEBUG": 5,
}
DEFAULT_FALCO_SCORE = 30

# --- Anomaly event -> bonus points ------------------------------------
ANOMALY_SCORE_WEIGHT = 40

# --- Dual-layer agreement bonus ---------------------------------------
DUAL_LAYER_BONUS = 20

# --- Matching tolerance -------------------------------------------------
CORRELATION_WINDOW = timedelta(seconds=60)

# --- Confidence tiering -------------------------------------------------
# Falco priorities strong enough, on their own (no anomaly corroboration),
# to count as "medium" confidence rather than "low".
STRONG_FALCO_PRIORITIES = {"EMERGENCY", "ALERT", "CRITICAL"}
# Anomaly score threshold, on its own, for the same "medium" tier.
STRONG_ANOMALY_THRESHOLD = 0.8


def _parse_ts(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Incident:
    """One correlated incident payload - matches the REAL POST /incidents/
    request body, not the earlier speculative shape #3."""

    container_id: str
    risk_score: int
    confidence: str  # "high" | "medium" | "low"
    falco_alert: Optional[dict]
    anomaly_features: Optional[dict]  # full shape #2 dict, see module docstring

    def to_dict(self) -> dict:
        return {
            "container_id": self.container_id,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "falco_alert": self.falco_alert,
            "anomaly_features": self.anomaly_features,
        }


def _falco_base_score(falco_alert: dict) -> int:
    priority = (falco_alert.get("priority") or "").upper()
    return FALCO_PRIORITY_SCORES.get(priority, DEFAULT_FALCO_SCORE)


def _anomaly_bonus(anomaly_event: dict) -> int:
    score = float(anomaly_event.get("anomaly_score", 0.0))
    return round(score * ANOMALY_SCORE_WEIGHT)


def _compute_confidence(
    dual_layer: bool, falco_alert: Optional[dict], anomaly_event: Optional[dict]
) -> str:
    """
    3-tier confidence label:
      - "high":   both detection layers fired on the same container/window
      - "medium": only one layer fired, but with a strong signal on its own
                  (Falco EMERGENCY/ALERT/CRITICAL, or anomaly_score >= 0.8)
      - "low":    only one layer fired, and it wasn't a strong signal
    """
    if dual_layer:
        return "high"

    if falco_alert is not None:
        priority = (falco_alert.get("priority") or "").upper()
        if priority in STRONG_FALCO_PRIORITIES:
            return "medium"

    if anomaly_event is not None:
        score = float(anomaly_event.get("anomaly_score", 0.0))
        if score >= STRONG_ANOMALY_THRESHOLD:
            return "medium"

    return "low"


def compute_risk_score(falco_alerts: list[dict], anomaly_events: list[dict]) -> list[dict]:
    """
    Public entry point. Correlates two alert streams into a list of
    incident payload dicts, ready to POST one-by-one to backend-api's
    POST /incidents/ endpoint.
    """
    incidents: list[Incident] = []
    matched_anomaly_indices: set[int] = set()

    # Pass 1: every Falco alert, try to find its matching anomaly event.
    for falco_alert in falco_alerts:
        f_container = falco_alert["container_id"]
        f_ts = _parse_ts(falco_alert["timestamp"])

        matched_event, matched_idx = None, None
        for idx, anomaly_event in enumerate(anomaly_events):
            if idx in matched_anomaly_indices:
                continue
            if anomaly_event["container_id"] != f_container:
                continue
            if abs(_parse_ts(anomaly_event["timestamp"]) - f_ts) <= CORRELATION_WINDOW:
                matched_event, matched_idx = anomaly_event, idx
                break

        base = _falco_base_score(falco_alert)
        bonus = _anomaly_bonus(matched_event) if matched_event else 0
        dual = matched_event is not None
        risk_score = min(100, base + bonus + (DUAL_LAYER_BONUS if dual else 0))
        confidence = _compute_confidence(dual, falco_alert, matched_event)

        if matched_idx is not None:
            matched_anomaly_indices.add(matched_idx)

        incidents.append(
            Incident(
                container_id=f_container,
                risk_score=risk_score,
                confidence=confidence,
                falco_alert=falco_alert,
                anomaly_features=matched_event,
            )
        )

    # Pass 2: any anomaly event nobody claimed becomes its own incident.
    for idx, anomaly_event in enumerate(anomaly_events):
        if idx in matched_anomaly_indices:
            continue
        risk_score = min(100, _anomaly_bonus(anomaly_event))
        confidence = _compute_confidence(False, None, anomaly_event)
        incidents.append(
            Incident(
                container_id=anomaly_event["container_id"],
                risk_score=risk_score,
                confidence=confidence,
                falco_alert=None,
                anomaly_features=anomaly_event,
            )
        )

    return [inc.to_dict() for inc in incidents]
