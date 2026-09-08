from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from database import get_db
from models.db_models import GeneratedRule

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("/pending")
async def list_pending_rules(db: Session = Depends(get_db)):
    rules = db.query(GeneratedRule).filter(GeneratedRule.status == "pending_review").all()
    return rules


@router.post("/{rule_id}/approve")
async def approve_rule(rule_id: int, reviewed_by: str, db: Session = Depends(get_db)):
    rule = db.query(GeneratedRule).filter(GeneratedRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.status = "approved"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    # NOTE: Actual deployment (rule_deployer.py) is Phase 6 (teammate's responsibility).
    # This endpoint only records human approval.
    return {"status": "approved", "rule_id": rule_id, "reviewed_by": reviewed_by}


@router.post("/{rule_id}/reject")
async def reject_rule(rule_id: int, reviewed_by: str, reason: str, db: Session = Depends(get_db)):
    rule = db.query(GeneratedRule).filter(GeneratedRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.status = "rejected"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "rejected", "rule_id": rule_id, "reason": reason}


@router.post("/{rule_id}/deprecate")
async def deprecate_rule(rule_id: int, reviewed_by: str, db: Session = Depends(get_db)):
    rule = db.query(GeneratedRule).filter(GeneratedRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.status = "retired"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "retired", "rule_id": rule_id}