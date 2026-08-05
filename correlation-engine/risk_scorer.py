"""
risk_scorer.py
-----------------
Module 6 of ContainerGuard AI: Correlation Engine (scoring half).

STATUS: NOT YET IMPLEMENTED — Phase 5 stub.

Planned responsibility:
Merge Falco rule-based alerts (Phase 3) and anomaly-model alerts
(Phase 4) by container + time-window into one unified, confidence-
weighted risk score. Dual-layer agreement (both Falco AND the anomaly
model flagging the same container/window) should produce a
higher-confidence score than either alone.

Planned interface:
    def compute_risk_score(falco_alerts: list[dict], anomaly_alerts: list[dict]) -> dict:
        \"\"\"
        Returns {"container_id": ..., "risk_score": float 0-100,
        "confidence": "low"|"medium"|"high", "contributing_alerts": [...]}
        \"\"\"
        raise NotImplementedError("Phase 5 not yet built")
"""

# Intentionally left as a stub. Implement in Phase 5, after Phases 3 and 4
# are both producing real alert streams to correlate.
