"""Idempotently persist deterministic guidance for historical rows; schema is unchanged."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend-api"), str(ROOT / "correlation-engine")]
from database import SessionLocal  # noqa: E402
from models.db_models import Incident, Deployment, ScanResult  # noqa: E402
from risk_explanation import explain_incident, explain_deployment  # noqa: E402


def backfill(session):
    count = 0
    for incident in session.query(Incident).yield_per(100):
        if (incident.ai_summary or {}).get("risk_explanation"):
            continue
        payload = {
            key: getattr(incident, key)
            for key in (
                "container_id",
                "risk_score",
                "confidence",
                "falco_alert",
                "anomaly_features",
            )
        }
        incident.ai_summary = {
            **(incident.ai_summary or {}),
            "risk_explanation": explain_incident(payload),
        }
        count += 1
    for deployment in session.query(Deployment).yield_per(100):
        if (deployment.policy_summary or {}).get("risk_explanation"):
            continue
        scan = (
            session.get(ScanResult, deployment.scan_result_id)
            if deployment.scan_result_id
            else None
        )
        payload = {
            key: getattr(deployment, key)
            for key in (
                "decision",
                "container_name",
                "image_name",
                "override_reason",
                "policy_violations",
            )
        }
        payload["scan"] = (
            {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "secrets_found": scan.secrets_found,
            }
            if scan
            else None
        )
        deployment.policy_summary = {
            **(deployment.policy_summary or {}),
            "risk_explanation": explain_deployment(payload),
        }
        count += 1
    session.commit()
    return count


if __name__ == "__main__":
    with SessionLocal() as session:
        print(f"Historical explanations persisted: {backfill(session)}")
