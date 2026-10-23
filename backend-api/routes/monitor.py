"""Read monitor health and persist workflow metadata in the existing backend."""

import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "monitor-service"))
from monitor_status import read_status, describe_status  # noqa: E402
from monitor_config import load_config  # noqa: E402
from database import get_db  # noqa: E402
from models.db_models import MonitorIncident, Incident, ConfirmedIncident  # noqa: E402

router = APIRouter(prefix="/monitor", tags=["monitor"])


@router.get("/status")
def status(db: Session = Depends(get_db)):
    cfg = load_config()
    result = read_status(cfg.state_dir / "status.json")
    if result is None:
        return describe_status(None)
    try:
        result["unconfirmed_incidents"] = (
            db.query(Incident)
            .outerjoin(
                ConfirmedIncident,
                ConfirmedIncident.incident_id == Incident.id,
            )
            .filter(ConfirmedIncident.id.is_(None))
            .count()
        )
        result.setdefault("components", {})["database"] = {"state": "ok"}
    except SQLAlchemyError:
        result["unconfirmed_incidents"] = None
        result.setdefault("components", {})["database"] = {"state": "unavailable"}
    result["backend_configuration"] = {
        "auto_isolation_enabled": cfg.auto_isolation_enabled,
        "auto_isolation_threshold": cfg.auto_isolation_threshold,
        "protected_containers": list(cfg.protected_containers),
        "auto_confirm_enabled": cfg.auto_confirm_enabled,
        "anomaly_proposals_enabled": cfg.auto_confirm_anomaly_enabled,
        "rule_candidates_enabled": cfg.rule_candidates_enabled,
    }
    result.setdefault("configuration", {})
    return describe_status(result)


@router.post("/incidents/{incident_id}/workflow")
def workflow(incident_id: int, body: dict, db: Session = Depends(get_db)):
    incident = (
        db.query(Incident).filter(Incident.id == incident_id)
        .populate_existing().with_for_update().first()
    )
    meta = (
        db.query(MonitorIncident).filter(MonitorIncident.incident_id == incident_id)
        .populate_existing().first()
    )
    if meta is None:
        raise HTTPException(404, "Monitor incident not found")
    if incident is None:
        raise HTTPException(409, "Monitor metadata refers to a missing incident")
    allowed = {"confirmation", "response", "candidate", "explanation", "confirmation_policy"}
    if set(body) - allowed:
        raise HTTPException(422, "Unknown workflow field")
    if any(not isinstance(value, dict) for value in body.values()):
        raise HTTPException(422, "Workflow fields must be objects")
    if "explanation" in body:
        explanation = body["explanation"]
        if explanation.get("status") == "ready" and not isinstance(
            explanation.get("result"), dict
        ):
            raise HTTPException(422, "Ready explanation requires an object result")
    meta.workflow = {**(meta.workflow or {}), **body}
    if "explanation" in body:
        explanation = body["explanation"]
        if explanation.get("status") == "ready":
            incident.ai_summary = {
                **(explanation.get("result") or {}),
                "risk_explanation": (incident.ai_summary or {}).get("risk_explanation"),
            }
    db.commit()
    return meta.workflow
