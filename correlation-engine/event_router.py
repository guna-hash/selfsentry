"""
event_router.py
------------------
Module 5b of SelfSentry: Correlation Engine.

Decides WHAT HAPPENS NEXT for an already-scored incident (output of
risk_scorer.py's compute_risk_score()). Does not compute risk itself -
that's risk_scorer.py's job - this module only routes.

ROUTING MODEL (real-world SOC-style, not a single flat threshold):
  risk_score alone is not a safe routing signal on its own - a single
  noisy layer (e.g. anomaly-only, low confidence) hitting a high raw
  score should NOT get the same response as a dual-layer-confirmed
  incident at the same raw score. So routing is based on an
  "effective_score" = risk_score adjusted by confidence tier:

      confidence == "high"    -> no adjustment (full trust)
      confidence == "medium"  -> -10 (single strong signal, but only one layer)
      confidence == "low"     -> -20 (single weak signal - likely noise)

  This has a useful side-effect: AUTO_ISOLATE (the most consequential
  action) becomes mathematically very hard to reach on "low" confidence
  alone, since even a perfect risk_score=100 only nets effective_score=80.
  That's intentional - isolating a container is disruptive, and doing it
  off a single noisy signal is exactly the false-positive-driven
  automation this project's design explicitly wants to avoid.

TIERS (on effective_score, 0-100):
  < 40            -> LOG_ONLY
  40 - 69         -> LOG + AI_ANALYSIS_NOTED   (routine, no human paged)
  70 - 89         -> LOG + AI_ANALYSIS_NOTED + ANALYST_ALERT (paged, human must act)
  >= 90           -> LOG + AI_ANALYSIS_NOTED + ANALYST_ALERT + AUTO_ISOLATE

The routing result describes score tiers, not permission to take a response action.
The continuous monitor's IncidentPipeline owns automatic isolation: it checks the
configured opt-in, both detection layers, freshness, full Docker identity, protection,
and durable attempt/audit state. The diagnostic dispatcher below only logs suggestions.
Optional AI enrichment also belongs to the monitor, outside backend incident creation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# --- Confidence -> effective-score adjustment --------------------------
CONFIDENCE_ADJUSTMENT: dict[str, int] = {
    "high": 0,
    "medium": -10,
    "low": -20,
}

# --- Routing tier thresholds (on effective_score) -----------------------
AI_ANALYSIS_THRESHOLD = 40
ANALYST_ALERT_THRESHOLD = 70
AUTO_ISOLATE_THRESHOLD = 90

# Action name constants - used both in RoutingDecision.actions and by
# dispatch_incident() below, kept as constants so a typo becomes a
# NameError instead of a silently-never-matched string.
ACTION_LOG = "log"
ACTION_AI_ANALYSIS_NOTED = "ai_analysis_noted"
ACTION_ANALYST_ALERT = "analyst_alert"
ACTION_AUTO_ISOLATE = "auto_isolate"


@dataclass
class RoutingDecision:
    """What should happen to one already-scored incident."""

    container_id: str
    risk_score: float
    confidence: str
    effective_score: float
    actions: list[str] = field(default_factory=list)

    @property
    def should_isolate(self) -> bool:
        return ACTION_AUTO_ISOLATE in self.actions

    @property
    def should_page_analyst(self) -> bool:
        return ACTION_ANALYST_ALERT in self.actions

    def to_dict(self) -> dict:
        return {
            "container_id": self.container_id,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "effective_score": self.effective_score,
            "actions": self.actions,
        }


def _effective_score(risk_score: float, confidence: str) -> float:
    adjustment = CONFIDENCE_ADJUSTMENT.get(confidence, CONFIDENCE_ADJUSTMENT["low"])
    # Never let a bad/unknown confidence string silently grant full trust -
    # default to the harshest adjustment ("low") if it's not one of the
    # three known tiers, rather than assuming 0.
    return max(0.0, min(100.0, risk_score + adjustment))


def route_incident(incident: dict) -> RoutingDecision:
    """
    Public entry point for a single incident. `incident` is expected to be
    one of risk_scorer.py's Incident.to_dict() outputs (or the equivalent
    dict fetched back from GET /incidents/ - both share the same fields
    this function actually reads: container_id, risk_score, confidence).
    """
    risk_score = float(incident["risk_score"])
    confidence = str(incident.get("confidence", "low")).lower()

    effective = _effective_score(risk_score, confidence)

    actions = [ACTION_LOG]
    if effective >= AI_ANALYSIS_THRESHOLD:
        actions.append(ACTION_AI_ANALYSIS_NOTED)
    if effective >= ANALYST_ALERT_THRESHOLD:
        actions.append(ACTION_ANALYST_ALERT)
    if effective >= AUTO_ISOLATE_THRESHOLD:
        actions.append(ACTION_AUTO_ISOLATE)

    return RoutingDecision(
        container_id=incident["container_id"],
        risk_score=risk_score,
        confidence=confidence,
        effective_score=effective,
        actions=actions,
    )


def route_incidents(incidents: list[dict]) -> list[RoutingDecision]:
    """Batch convenience wrapper - routes a whole list at once."""
    return [route_incident(inc) for inc in incidents]


# --- Dispatch: actually perform the side-effecting actions --------------

def dispatch_incident(incident: dict, decision: RoutingDecision) -> dict:
    """
    Log diagnostic routing suggestions without invoking security response actions.
    A score tier cannot authorize isolation; use the durable monitor workflow.
    """
    results: dict[str, str] = {}

    for action in decision.actions:
        if action == ACTION_LOG:
            logger.info(
                "[%s] incident logged - risk_score=%s confidence=%s effective=%s",
                decision.container_id,
                decision.risk_score,
                decision.confidence,
                decision.effective_score,
            )
            results[ACTION_LOG] = "done"

        elif action == ACTION_AI_ANALYSIS_NOTED:
            results[ACTION_AI_ANALYSIS_NOTED] = "advisory enrichment belongs to monitor workflow"

        elif action == ACTION_ANALYST_ALERT:
            logger.warning(
                "[%s] ANALYST ALERT - effective_score=%s requires human review",
                decision.container_id,
                decision.effective_score,
            )
            results[ACTION_ANALYST_ALERT] = (
                "logged for analyst review; no paging channel configured"
            )

        elif action == ACTION_AUTO_ISOLATE:
            results[ACTION_AUTO_ISOLATE] = (
                "not_attempted: diagnostic routing cannot authorize isolation; "
                "use the durable monitor workflow"
            )

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Quick manual smoke test - three incidents at the same risk_score
    # but different confidence, to see the tiering actually differ.
    demo_incidents = [
        {"container_id": "c1", "risk_score": 90, "confidence": "high"},
        {"container_id": "c2", "risk_score": 90, "confidence": "medium"},
        {"container_id": "c3", "risk_score": 90, "confidence": "low"},
    ]
    for inc in demo_incidents:
        decision = route_incident(inc)
        print(decision.to_dict())
        dispatch_incident(inc, decision)
