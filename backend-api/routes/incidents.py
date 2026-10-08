import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "ai-analysis"))
from fastapi import APIRouter, Depends, HTTPException  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from database import get_db  # noqa: E402
from models.db_models import Incident, ConfirmedIncident  # noqa: E402
from root_cause_summarizer import summarize_incident  # noqa: E402

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/")
async def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    return incidents


@router.get("/{incident_id}")
async def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/")
async def create_incident(incident_data: dict, db: Session = Depends(get_db)):
    new_incident = Incident(
        container_id=incident_data["container_id"],
        risk_score=incident_data["risk_score"],
        confidence=incident_data.get("confidence"),
        falco_alert=incident_data.get("falco_alert"),
        anomaly_features=incident_data.get("anomaly_features"),
    )
    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)

    # Advisory-only: AI explains the already-scored incident, never scores it itself
    ai_result = summarize_incident({
        "incident_id": new_incident.id,
        "container_id": new_incident.container_id,
        "risk_score": new_incident.risk_score,
        "falco_alert": new_incident.falco_alert,
    })
    new_incident.ai_summary = ai_result
    db.commit()
    db.refresh(new_incident)

    return new_incident


@router.post("/{incident_id}/confirm")
async def confirm_incident(incident_id: int, confirmed_by: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    existing = (
        db.query(ConfirmedIncident)
        .filter(ConfirmedIncident.incident_id == incident_id)
        .first()
    )
    if existing:
        return {
            "status": "already_confirmed",
            "incident_id": incident_id,
            "confirmed_by": existing.confirmed_by,
            "confirmed_incident_id": existing.id,
        }

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
async def dismiss_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "dismissed", "incident_id": incident_id}
