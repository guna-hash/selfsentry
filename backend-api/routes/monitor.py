"""Read monitor health and persist workflow metadata in the existing backend."""

import sys
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "monitor-service"))
from monitor_status import read_status  # noqa: E402
from monitor_config import load_config  # noqa: E402
from database import get_db  # noqa: E402
from models.db_models import MonitorIncident, Incident, ConfirmedIncident  # noqa: E402

router = APIRouter(prefix="/monitor", tags=["monitor"])


@router.get("/status")
def status(db: Session = Depends(get_db)):
    cfg = load_config()
    result = read_status(cfg.state_dir / "status.json")
    if result is None:
        return {"running": False, "healthy": False, "reason": "monitor has not reported status"}
    try:
        updated = datetime.fromisoformat(result["updated_at"])
        age = (datetime.now(timezone.utc) - updated).total_seconds()
    except (KeyError, TypeError, ValueError):
        age = None
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
    result["status_age_seconds"] = age
    result["healthy"] = bool(result.get("running")) and age is not None and 0 <= age < 30
    return result


@router.post("/incidents/{incident_id}/workflow")
def workflow(incident_id: int, body: dict, db: Session = Depends(get_db)):
    meta = db.query(MonitorIncident).filter(MonitorIncident.incident_id == incident_id).first()
    if meta is None:
        raise HTTPException(404, "Monitor incident not found")
    allowed = {"confirmation", "response", "candidate", "explanation", "confirmation_policy"}
    if set(body) - allowed:
        raise HTTPException(422, "Unknown workflow field")
    meta.workflow = {**(meta.workflow or {}), **body}
    if "explanation" in body:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        explanation = body["explanation"]
        if explanation.get("status") == "ready":
            incident.ai_summary = explanation.get("result")
    db.commit()
    return meta.workflow
