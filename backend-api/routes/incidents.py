import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "ai-analysis"))
from fastapi import APIRouter, Depends, HTTPException  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from database import get_db  # noqa: E402
from models.db_models import Incident, ConfirmedIncident, MonitorIncident  # noqa: E402

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "correlation-engine"))
from risk_explanation import explain_incident  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from fastapi.encoders import jsonable_encoder  # noqa: E402


class IncidentIn(BaseModel):
    container_id: str = Field(min_length=1, max_length=128)
    risk_score: float = Field(ge=0, le=100, allow_inf_nan=False)
    confidence: str | None = None
    falco_alert: dict | None = None
    anomaly_features: dict | None = None
    event_key: str | None = Field(default=None, max_length=128)
    monitor_evidence: dict | None = None
    defer_ai: bool = False


def serialize(incident, db):
    db.refresh(incident)
    result = jsonable_encoder(incident)
    meta = db.query(MonitorIncident).filter(MonitorIncident.incident_id == incident.id).first()
    if meta:
        result.update(
            event_key=meta.event_key, monitor_evidence=meta.evidence, monitor_workflow=meta.workflow
        )
    confirmed = (
        db.query(ConfirmedIncident).filter(ConfirmedIncident.incident_id == incident.id).first()
    )
    result["confirmation"] = (
        {"confirmed_by": confirmed.confirmed_by, "confirmed_at": confirmed.confirmed_at}
        if confirmed
        else None
    )
    result["risk_explanation"] = (incident.ai_summary or {}).get(
        "risk_explanation"
    ) or explain_incident(result)
    return result


router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    return [serialize(incident, db) for incident in incidents]


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize(incident, db)


@router.post("/")
def create_incident(incident_data: IncidentIn, db: Session = Depends(get_db)):
    incident_data = incident_data.model_dump()
    key = incident_data.get("event_key")
    if key:
        existing = db.query(MonitorIncident).filter(MonitorIncident.event_key == key).first()
        if existing:
            return serialize(
                db.query(Incident).filter(Incident.id == existing.incident_id).one(), db
            )
    new_incident = Incident(
        container_id=incident_data["container_id"],
        risk_score=incident_data["risk_score"],
        confidence=incident_data.get("confidence"),
        falco_alert=incident_data.get("falco_alert"),
        anomaly_features=incident_data.get("anomaly_features"),
    )
    new_incident.ai_summary = {"risk_explanation": explain_incident(incident_data)}
    db.add(new_incident)
    try:
        db.flush()
        from routes.rules import record_native_refires

        record_native_refires(db, new_incident, incident_data)
        if key:
            db.add(
                MonitorIncident(
                    event_key=key,
                    incident_id=new_incident.id,
                    evidence=incident_data.get("monitor_evidence"),
                    workflow={},
                )
            )
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(MonitorIncident).filter(MonitorIncident.event_key == key).first()
        if not existing:
            raise
        return serialize(db.query(Incident).filter(Incident.id == existing.incident_id).one(), db)
    db.refresh(new_incident)

    # Deterministic guidance is persisted before response. Optional AI runs in the monitor worker.
    return serialize(new_incident, db)


@router.post("/{incident_id}/confirm")
def confirm_incident(incident_id: int, confirmed_by: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).with_for_update().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    existing = (
        db.query(ConfirmedIncident).filter(ConfirmedIncident.incident_id == incident_id).first()
    )
    if existing:
        return {
            "status": "already_confirmed",
            "incident_id": incident_id,
            "confirmed_by": existing.confirmed_by,
            "confirmed_incident_id": existing.id,
        }

    if confirmed_by == "selfsentry-auto":
        from automation_policy import eligible
        from monitor_config import load_config
        import time

        permitted, reason = eligible(serialize(incident, db), load_config(), now=time.time())
        if not permitted:
            raise HTTPException(409, reason)
    confirmed = ConfirmedIncident(incident_id=incident_id, confirmed_by=confirmed_by)
    db.add(confirmed)
    db.commit()
    db.refresh(confirmed)

    return {
        "status": "confirmed",
        "incident_id": incident_id,
        "confirmed_by": confirmed_by,
        "confirmed_incident_id": confirmed.id,
    }


@router.post("/{incident_id}/dismiss")
def dismiss_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    meta = db.query(MonitorIncident).filter(MonitorIncident.incident_id == incident_id).first()
    if meta:
        meta.workflow = {**(meta.workflow or {}), "disposition": {"status": "benign"}}
        db.commit()
    return {"status": "dismissed", "incident_id": incident_id}
