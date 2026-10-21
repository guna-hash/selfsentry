import os
import sys
import hashlib
from contextlib import contextmanager
from sqlalchemy import text
from pathlib import Path
from datetime import datetime, timezone

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "rule-synthesis-engine"))

from database import get_db  # noqa: E402
from models.db_models import ConfirmedIncident, GeneratedRule, AuditEvent  # noqa: E402
from rule_deployer import RuleDeploymentError, deploy_rule  # noqa: E402
from rule_backtester import backtest_rule, BacktestError  # noqa: E402
from rule_deduplicator import guard, InventoryError, DuplicateRule  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "monitor-service"))
from monitor_config import load_config  # noqa: E402
from submit_candidate import _load_benign_events  # noqa: E402
from fastapi.encoders import jsonable_encoder  # noqa: E402

router = APIRouter(prefix="/rules", tags=["rules"])

# A confirmed incident may only have one rule in any of these states at a time.
ACTIVE_STATUSES = ("pending_review", "approved", "deployed")


class CandidateRuleIn(BaseModel):
    confirmed_incident_id: int
    rule_yaml: str
    backtested_fp_rate: float = Field(ge=0, le=0.05, allow_inf_nan=False)


def _audit_rule(db, event_type, rule, detail):
    db.add(
        AuditEvent(
            event_type=event_type,
            source="backend",
            severity="warning" if event_type == "RULE_DUPLICATE_REJECTED" else "info",
            detail={"rule_id": rule.id, **detail},
            occurred_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
    )


def _verified_backtest(rule_yaml):
    path = load_config().benign_log_path
    if not path:
        raise HTTPException(503, "Validated benign corpus not configured")
    try:
        before = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        result = backtest_rule(rule_yaml, _load_benign_events(path))
        after = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if before != after:
            raise HTTPException(409, "Benign corpus changed during backtest; retry")
    except (OSError, BacktestError, ValueError) as exc:
        raise HTTPException(422, f"Backtest unavailable: {type(exc).__name__}") from exc
    if result["verdict"] != "pass" or not result["events_tested"]:
        raise HTTPException(422, {"reason": "Candidate failed authoritative backtest", **result})
    return {**result, "benign_sha256": before}


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
        and len(parsed) == 1
        and all(isinstance(r, dict) and "rule" in r and "condition" in r for r in parsed)
    )
    if not valid:
        raise HTTPException(
            status_code=422,
            detail="rule_yaml must be a list of Falco rules, each with 'rule' and 'condition'",
        )


@router.get("/history")
def rule_history(db: Session = Depends(get_db)):
    rows = db.query(GeneratedRule).order_by(GeneratedRule.id.desc()).limit(100).all()
    audits = db.query(AuditEvent).filter(AuditEvent.event_type.like("RULE_%")).all()
    result = []
    for rule in rows:
        item = jsonable_encoder(rule)
        confirmed = db.get(ConfirmedIncident, rule.confirmed_incident_id)
        events = [jsonable_encoder(a) for a in audits if (a.detail or {}).get("rule_id") == rule.id]
        item.update(
            incident_id=confirmed.incident_id if confirmed else None,
            confirmation_source=confirmed.confirmed_by if confirmed else None,
            lifecycle_events=events,
            backtest=next(
                (
                    (a.get("detail") or {}).get("backtest")
                    for a in reversed(events)
                    if (a.get("detail") or {}).get("backtest")
                ),
                None,
            ),
            rejection_reason=next(
                (
                    (a.get("detail") or {}).get("reason")
                    for a in reversed(events)
                    if a["event_type"] in ("RULE_DUPLICATE_REJECTED", "RULE_REJECTED")
                ),
                None,
            ),
            native_refires=[a for a in events if a["event_type"] == "RULE_NATIVE_REFIRE"],
        )
        result.append(item)
    return result


@router.get("/pending")
def list_pending_rules(db: Session = Depends(get_db)):
    """Rules awaiting action: pending_review, plus approved-but-not-yet-deployed
    (a failed deployment leaves a rule approved so it can be retried from the queue)."""
    return (
        db.query(GeneratedRule)
        .filter(GeneratedRule.status.in_(("pending_review", "approved")))
        .order_by(GeneratedRule.id)
        .all()
    )


@router.get("/for-confirmed/{confirmed_incident_id}")
def active_candidate(confirmed_incident_id: int, db: Session = Depends(get_db)):
    rule = (
        db.query(GeneratedRule)
        .filter(
            GeneratedRule.confirmed_incident_id == confirmed_incident_id,
            GeneratedRule.status.in_(ACTIVE_STATUSES),
        )
        .order_by(GeneratedRule.id.desc())
        .first()
    )
    if not rule:
        raise HTTPException(404, "No active candidate")
    return rule


@contextmanager
def _inventory_guard(db):
    # Serialize even across backend hosts when they share PostgreSQL. All callers
    # acquire the DB lock before the host lock. Commit occurs inside the guard.
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(1936026727)"))
    try:
        with guard() as registry:
            yield registry
    except DuplicateRule:
        raise
    except (InventoryError, OSError) as exc:
        raise HTTPException(503, f"Rule guard unavailable: {exc}") from exc


def _check_duplicate(db, registry, rule_yaml, exclude_id=None):
    # A deployment audit survives retirement and later status changes.
    audits = db.query(AuditEvent).filter(AuditEvent.event_type == "RULE_DEPLOYED").all()
    deployed_ids = {(a.detail or {}).get("rule_id") for a in audits}
    rows = db.query(GeneratedRule).all()
    protected = [
        r.rule_yaml
        for r in rows
        if r.id != exclude_id
        and (r.status in ACTIVE_STATUSES or r.id in deployed_ids or r.status == "retired")
    ]
    return registry.check(rule_yaml, protected)


def _reject_duplicate(db, body, exc, rule=None):
    if rule is None:
        # Repeated attempts reuse the rejected record instead of flooding history.
        rule = (
            db.query(GeneratedRule)
            .filter(
                GeneratedRule.confirmed_incident_id == body.confirmed_incident_id,
                GeneratedRule.rule_yaml == body.rule_yaml,
                GeneratedRule.status == "rejected_duplicate",
            )
            .first()
        )
    if rule is None:
        rule = GeneratedRule(
            confirmed_incident_id=body.confirmed_incident_id,
            rule_yaml=body.rule_yaml,
            status="rejected_duplicate",
        )
        db.add(rule)
        db.flush()
    rule.status = "rejected_duplicate"
    _audit_rule(
        db, "RULE_DUPLICATE_REJECTED", rule, {"reason": exc.reason, "matched_rule": exc.name}
    )
    db.commit()
    return {"id": rule.id, "status": rule.status, "rejection_reason": exc.reason}


@router.post("/preflight")
def preflight_rule(body: CandidateRuleIn, db: Session = Depends(get_db)):
    """Run before local backtesting; duplicates become terminal history, never pending."""
    _validate_rule_yaml(body.rule_yaml)
    if not db.get(ConfirmedIncident, body.confirmed_incident_id):
        raise HTTPException(404, "Confirmed incident not found")
    with _inventory_guard(db) as registry:
        try:
            _check_duplicate(db, registry, body.rule_yaml)
        except DuplicateRule as exc:
            return _reject_duplicate(db, body, exc)
        registry.revalidate()
    return {"status": "unique"}


@router.post("/", status_code=201)
def submit_rule(body: CandidateRuleIn, db: Session = Depends(get_db)):
    """Queue a backtested candidate rule for human review. Nothing is deployed here."""
    _validate_rule_yaml(body.rule_yaml)

    with _inventory_guard(db) as registry:
        confirmed = (
            db.query(ConfirmedIncident)
            .filter(ConfirmedIncident.id == body.confirmed_incident_id)
            .with_for_update()
            .first()
        )
        if not confirmed:
            raise HTTPException(status_code=404, detail="Confirmed incident not found")

        try:
            _check_duplicate(db, registry, body.rule_yaml)
        except DuplicateRule as exc:
            return _reject_duplicate(db, body, exc)

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

        try:
            verified = _verified_backtest(body.rule_yaml)
        except HTTPException as exc:
            db.add(
                AuditEvent(
                    event_type="RULE_CANDIDATE_BLOCKED",
                    source="backend",
                    severity="warning",
                    detail={
                        "incident_id": confirmed.incident_id,
                        "confirmed_incident_id": confirmed.id,
                        "reason": exc.detail,
                    },
                )
            )
            db.commit()
            raise
        registry.revalidate()
        rule = GeneratedRule(
            confirmed_incident_id=body.confirmed_incident_id,
            rule_yaml=body.rule_yaml,
            backtested_fp_rate=verified["false_positive_rate"],
            status="pending_review",
        )
        db.add(rule)
        db.flush()
        _audit_rule(
            db,
            "RULE_CANDIDATE_CREATED",
            rule,
            {"backtest": verified, "incident_id": confirmed.incident_id},
        )
        db.commit()
        db.refresh(rule)
        return {"id": rule.id, "status": rule.status}


@router.post("/{rule_id}/approve")
def approve_rule(rule_id: int, reviewed_by: str, db: Session = Depends(get_db)):
    """Record the human approval, then deploy through the guarded rule_deployer.

    If deployment fails the rule stays 'approved' (the decision is kept) and the
    request can be retried; deploy_rule() is idempotent.
    """
    if not reviewed_by.strip() or reviewed_by.strip() == "selfsentry-auto":
        raise HTTPException(422, "An explicit human reviewer identity is required")
    rule = _get_rule_or_404(db, rule_id)
    if rule.status not in ("pending_review", "approved"):
        raise HTTPException(
            status_code=409,
            detail=f"Rule is '{rule.status}'; expected pending_review or approved",
        )

    with _inventory_guard(db) as registry:
        try:
            if not registry.receipt(str(rule.id), rule.rule_yaml):
                _check_duplicate(db, registry, rule.rule_yaml, exclude_id=rule.id)
        except DuplicateRule as exc:
            result = _reject_duplicate(db, rule, exc, rule=rule)
            raise HTTPException(409, result)

    try:
        verified = _verified_backtest(rule.rule_yaml)
    except HTTPException as exc:
        _audit_rule(db, "RULE_BACKTEST_BLOCKED_DEPLOYMENT", rule, {"reason": exc.detail})
        db.commit()
        raise
    rule.backtested_fp_rate = verified["false_positive_rate"]
    _audit_rule(db, "RULE_BACKTEST_REVALIDATED", rule, {"backtest": verified})
    rule.status = "approved"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    _audit_rule(db, "RULE_APPROVED", rule, {"reviewed_by": reviewed_by})
    db.commit()

    try:
        deploy_rule(str(rule.id), rule.rule_yaml)
    except DuplicateRule as exc:
        result = _reject_duplicate(db, rule, exc, rule=rule)
        raise HTTPException(409, result) from exc
    except (RuleDeploymentError, OSError) as exc:
        _audit_rule(
            db, "RULE_DEPLOYMENT_FAILED", rule, {"reason": str(exc), "reviewed_by": reviewed_by}
        )
        db.commit()
        raise HTTPException(
            status_code=502, detail=f"Rule approved but deployment failed: {exc}"
        ) from exc

    rule.status = "deployed"
    _audit_rule(db, "RULE_DEPLOYED", rule, {"reviewed_by": reviewed_by})
    db.commit()
    return {"status": "deployed", "rule_id": rule_id, "reviewed_by": reviewed_by}


@router.post("/{rule_id}/reject")
def reject_rule(rule_id: int, reviewed_by: str, reason: str, db: Session = Depends(get_db)):
    if not reviewed_by.strip() or reviewed_by.strip() == "selfsentry-auto":
        raise HTTPException(422, "An explicit human reviewer identity is required")
    rule = _get_rule_or_404(db, rule_id)
    if rule.status not in ("pending_review", "approved"):
        raise HTTPException(
            status_code=409,
            detail=f"Rule is '{rule.status}'; expected pending_review or approved",
        )
    if not reason.strip():
        raise HTTPException(422, "Rejection reason is required")
    _audit_rule(db, "RULE_REJECTED", rule, {"reviewed_by": reviewed_by, "reason": reason})
    rule.status = "rejected"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "rejected", "rule_id": rule_id, "reason": reason}


@router.post("/{rule_id}/deprecate")
def deprecate_rule(rule_id: int, reviewed_by: str, db: Session = Depends(get_db)):
    rule = _get_rule_or_404(db, rule_id)
    rule.status = "retired"
    rule.reviewed_by = reviewed_by
    rule.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "retired", "rule_id": rule_id}


def record_native_refires(db, incident, payload):
    """Observed native matches are evidence, not automatically labeled true positives."""
    alerts = list((payload.get("monitor_evidence") or {}).get("falco_alerts") or [])
    if payload.get("falco_alert"):
        alerts.append(payload["falco_alert"])
    names = {a.get("rule") for a in alerts}
    if not any(str(name).startswith("Auto_Generated_") for name in names):
        return
    for rule in db.query(GeneratedRule).filter(GeneratedRule.status == "deployed").all():
        definitions = yaml.safe_load(rule.rule_yaml) or []
        for definition in definitions:
            if definition.get("rule") in names:
                _audit_rule(
                    db,
                    "RULE_NATIVE_REFIRE",
                    rule,
                    {
                        "incident_id": incident.id,
                        "container_id": incident.container_id,
                        "native_rule_name": definition["rule"],
                        "evidence": [a for a in alerts if a.get("rule") == definition["rule"]],
                    },
                )
