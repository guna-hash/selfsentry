import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "ai-analysis"))
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models.db_models import Incident
from root_cause_summarizer import summarize_incident
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
    # NOTE: Actual Rule Synthesis Engine trigger is Phase 6 (teammate's responsibility).
    # This endpoint only records the human confirmation.
    return {"status": "confirmed", "incident_id": incident_id, "confirmed_by": confirmed_by}


@router.post("/{incident_id}/dismiss")
async def dismiss_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "dismissed", "incident_id": incident_id}