import os
import sys
from datetime import datetime, timezone

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "rule-synthesis-engine"))

from database import get_db  # noqa: E402
from models.db_models import ConfirmedIncident, GeneratedRule  # noqa: E402
from rule_deployer import RuleDeploymentError, deploy_rule  # noqa: E402

router = APIRouter(prefix="/rules", tags=["rules"])

# A confirmed incident may only have one rule in any of these states at a time.
ACTIVE_STATUSES = ("pending_review", "approved", "deployed")


class CandidateRuleIn(BaseModel):
    confirmed_incident_id: int
    rule_yaml: str
    backtested_fp_rate: float


def _get_rule_or_404(db: Session, rule_id: int) -> GeneratedRule:
    rule = db.query(GeneratedRule).filter(GeneratedRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


def _validate_rule_yaml(text: str) -> None:
    """Reject anything that is not a non-empty list of Falco rules."""
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"rule_yaml is not valid YAML: {exc}")
    valid = (
        isinstance(parsed, list)
        and len(parsed) > 0
        and all(isinstance(r, dict) and "rule" in r and "condition" in r for r in parsed)
    )
    if not valid:
        raise HTTPException(
            status_code=422,
            detail="rule_yaml must be a list of Falco rules, each with 'rule' and 'condition'",
        )


@router.get("/pending")
async def list_pending_rules(db: Session = Depends(get_db)):
    """Rules awaiting action: pending_review, plus approved-but-not-yet-deployed
    (a failed deployment leaves a rule approved so it can be retried from the queue)."""
    return (
        db.query(GeneratedRule)
        .filter(GeneratedRule.status.in_(("pending_review", "approved")))
        .order_by(GeneratedRule.id)
        .all()
    )


@router.post("/", status_code=201)
async def submit_rule(body: CandidateRuleIn, db: Session = Depends(get_db)):
    """Queue a backtested candidate rule for human review. Nothing is deployed here."""
    _validate_rule_yaml(body.rule_yaml)

    confirmed = (
        db.query(ConfirmedIncident)
        .filter(ConfirmedIncident.id == body.confirmed_incident_id)
        .first()
    )
    if not confirmed:
        raise HTTPException(status_code=404, detail="Confirmed incident not found")

    duplicate = (
        db.query(GeneratedRule)
        .filter(
            GeneratedRule.confirmed_incident_id == body.confirmed_incident_id,
            GeneratedRule.status.in_(ACTIVE_STATUSES),
        )
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=409,
            detail=f"Rule {duplicate.id} already exists for this confirmed incident "
            f"(status: {duplicate.status})",
        )

    rule = GeneratedRule(
        confirmed_incident_id=body.confirmed_incident_id,
        rule_yaml=body.rule_yaml,
        backtested_fp_rate=body.backtested_fp_rate,
        status="pending_review",
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "status": rule.status}


@router.post("/{rule_id}/approve")
async def approve_rule(rule_id: int, reviewed_by: str, db: Session = Depends(get_db)):
    """Record the human approval, then deploy through the guarded rule_deployer.

    If deployment fails the rule stays 'approved' (the decision is kept) and the
    request can be retried; deploy_rule() is idempotent.
    """
    rule = _get_rule_or_404(db, rule_id)
    if rule.status not in ("pending_review", "approved"):
        raise HTTPException(
            status_code=409,
            detail=f"Rule is '{rule.status}'; expected pending_review or approved",
        )

    rule.status = "approved"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()

    try:
        deploy_rule(str(rule.id), rule.rule_yaml)
    except (RuleDeploymentError, OSError) as exc:
        raise HTTPException(
            status_code=502, detail=f"Rule approved but deployment failed: {exc}"
        ) from exc

    rule.status = "deployed"
    db.commit()
    return {"status": "deployed", "rule_id": rule_id, "reviewed_by": reviewed_by}


@router.post("/{rule_id}/reject")
async def reject_rule(rule_id: int, reviewed_by: str, reason: str, db: Session = Depends(get_db)):
    rule = _get_rule_or_404(db, rule_id)
    if rule.status not in ("pending_review", "approved"):
        raise HTTPException(
            status_code=409,
            detail=f"Rule is '{rule.status}'; expected pending_review or approved",
        )
    rule.status = "rejected"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "rejected", "rule_id": rule_id, "reason": reason}


@router.post("/{rule_id}/deprecate")
async def deprecate_rule(rule_id: int, reviewed_by: str, db: Session = Depends(get_db)):
    rule = _get_rule_or_404(db, rule_id)
    rule.status = "retired"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "retired", "rule_id": rule_id}
