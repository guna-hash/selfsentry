from typing import Literal
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "correlation-engine"))
from risk_explanation import explain_deployment  # noqa: E402

from fastapi import APIRouter, Depends, HTTPException  # noqa: E402
from pydantic import BaseModel, Field, field_validator  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

from database import get_db  # noqa: E402
from models.db_models import Deployment, ScanResult, AuditEvent  # noqa: E402

router = APIRouter(prefix="/deployments", tags=["deployments"])


class DeploymentIn(BaseModel):
    event_key: str | None = Field(default=None, min_length=1, max_length=128)
    container_name: str = Field(min_length=1, max_length=256)
    container_id: str | None = Field(default=None, min_length=1, max_length=128)
    image_name: str = Field(min_length=1, max_length=256)
    decision: Literal["allowed", "blocked", "overridden"]
    override_reason: str | None = Field(default=None, max_length=512)
    requested_by: str | None = Field(default=None, max_length=128)
    scan_summary: dict = Field(default_factory=dict)
    scan_findings: list[dict] = Field(default_factory=list)
    policy_summary: dict = Field(default_factory=dict)
    policy_violations: list[dict] = Field(default_factory=list)

    @field_validator("scan_summary")
    @classmethod
    def validate_scan_counts(cls, summary: dict) -> dict:
        if not summary:
            return summary  # Unavailable scan; persist no scan row rather than invented zeros.
        for name in (
            "critical",
            "high",
            "total_vulnerabilities",
            "secrets_found",
            "misconfigurations_found",
        ):
            count = summary.get(name)
            if type(count) is not int or not 0 <= count <= 2147483647:
                raise ValueError(f"scan_summary.{name} must be a nonnegative 32-bit integer")
        return summary


def _serialize(deployment: Deployment, scan: ScanResult | None) -> dict:
    result = {
        "id": deployment.id,
        "container_name": deployment.container_name,
        "container_id": deployment.container_id,
        "image_name": deployment.image_name,
        "decision": deployment.decision,
        "override_reason": deployment.override_reason,
        "requested_by": deployment.requested_by,
        "created_at": deployment.created_at,
        "policy_summary": deployment.policy_summary,
        "policy_violations": deployment.policy_violations or [],
        "scan": (
            None
            if scan is None
            else {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "secrets_found": scan.secrets_found,
                "misconfigurations_found": scan.misconfigurations_found,
                "top_findings": (scan.raw_json or {}).get("top_findings", []),
            }
        ),
    }

    result["risk_explanation"] = (deployment.policy_summary or {}).get(
        "risk_explanation"
    ) or explain_deployment(result)
    return result


def _request_fingerprint(body: DeploymentIn) -> str:
    try:
        encoded = json.dumps(
            body.model_dump(exclude={"event_key"}),
            sort_keys=True,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Deployment record must contain finite JSON values") from exc
    return hashlib.sha256(encoded.encode()).hexdigest()


def _replay(body: DeploymentIn, event: AuditEvent, db: Session) -> dict:
    detail = event.detail or {}
    if (
        not isinstance(detail, dict)
        or event.source != "gate"
        or event.event_type != "DEPLOYMENT_" + body.decision.upper()
    ):
        raise HTTPException(409, "Event key belongs to another operation")
    if "request_sha256" in detail and (
        detail.get("request_fingerprint_version") != 1
        or detail["request_sha256"] != _request_fingerprint(body)
    ):
        raise HTTPException(409, "Event key was already used for a different deployment record")
    deployment_id = detail.get("deployment_id")
    if type(deployment_id) is not int or deployment_id <= 0:
        raise HTTPException(409, "Deployment replay has an invalid deployment identity")
    deployment = db.query(Deployment).filter(Deployment.id == deployment_id).first()
    if deployment is None or detail.get("decision") != deployment.decision:
        raise HTTPException(409, "Deployment replay refers to missing or inconsistent state")
    names = (
        "container_name",
        "container_id",
        "image_name",
        "decision",
        "override_reason",
        "requested_by",
        "policy_violations",
    )
    if any(getattr(deployment, name) != getattr(body, name) for name in names):
        raise HTTPException(409, "Event key was already used for a different deployment record")
    if not isinstance(deployment.policy_summary, dict):
        raise HTTPException(409, "Deployment replay has invalid stored policy data")
    stored_policy = {
        key: value
        for key, value in (deployment.policy_summary or {}).items()
        if key != "risk_explanation"
    }
    supplied_policy = {
        key: value for key, value in body.policy_summary.items() if key != "risk_explanation"
    }
    scan = (
        db.query(ScanResult).filter(ScanResult.id == deployment.scan_result_id).first()
        if deployment.scan_result_id is not None
        else None
    )
    if deployment.scan_result_id is not None and scan is None:
        raise HTTPException(409, "Deployment replay refers to a missing scan")
    if scan is not None and not isinstance(scan.raw_json, dict):
        raise HTTPException(409, "Deployment replay has invalid stored scan data")
    stored_counts = (
        {}
        if scan is None
        else {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "secrets_found": scan.secrets_found,
            "misconfigurations_found": scan.misconfigurations_found,
        }
    )
    supplied_counts = {
        key: body.scan_summary[key] for key in stored_counts if key in body.scan_summary
    }
    stored_findings = (scan.raw_json or {}).get("top_findings", []) if scan is not None else []
    if (
        stored_policy != supplied_policy
        or bool(scan) != bool(body.scan_summary)
        or stored_counts != supplied_counts
        or stored_findings != body.scan_findings
    ):
        raise HTTPException(409, "Event key was already used for a different deployment record")
    return {"id": deployment.id, "decision": deployment.decision}


@router.post("/", status_code=201)
def record_deployment(body: DeploymentIn, db: Session = Depends(get_db)):
    """Record a gate decision (and the scan that informed it) for the dashboard history."""
    if body.decision == "overridden" and not (body.override_reason or "").strip():
        raise HTTPException(status_code=422, detail="an override requires override_reason")
    if body.scan_findings and not body.scan_summary:
        raise HTTPException(422, "Scan findings require a complete scan summary")
    fingerprint = _request_fingerprint(body)

    if body.event_key:
        existing = db.query(AuditEvent).filter(AuditEvent.event_key == body.event_key).first()
        if existing:
            return _replay(body, existing, db)
    scan_result_id = None
    if body.scan_summary:
        summary = body.scan_summary
        scan = ScanResult(
            image_name=body.image_name,
            critical_count=summary.get("critical", 0),
            high_count=summary.get("high", 0),
            total_vulnerabilities=summary.get("total_vulnerabilities", 0),
            secrets_found=summary.get("secrets_found", 0),
            misconfigurations_found=summary.get("misconfigurations_found", 0),
            raw_json={"top_findings": body.scan_findings},
        )
        db.add(scan)
        db.flush()
        scan_result_id = scan.id

    deployment = Deployment(
        container_name=body.container_name,
        container_id=body.container_id,
        image_name=body.image_name,
        decision=body.decision,
        override_reason=body.override_reason,
        requested_by=body.requested_by,
        scan_result_id=scan_result_id,
        policy_summary={
            **body.policy_summary,
            "risk_explanation": explain_deployment(body.model_dump()),
        },
        policy_violations=body.policy_violations,
    )
    db.add(deployment)
    db.flush()
    db.add(
        AuditEvent(
            event_type="DEPLOYMENT_" + body.decision.upper(),
            source="gate",
            severity="warning" if body.decision != "allowed" else "info",
            container_id=body.container_id,
            container_name=body.container_name,
            image_name=body.image_name,
            event_key=body.event_key,
            detail={
                "deployment_id": deployment.id,
                "decision": body.decision,
                "requested_by": body.requested_by,
                "override_reason": body.override_reason,
                "request_sha256": fingerprint,
                "request_fingerprint_version": 1,
            },
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(AuditEvent).filter(AuditEvent.event_key == body.event_key).first()
            if body.event_key
            else None
        )
        if existing:
            return _replay(body, existing, db)
        raise
    db.refresh(deployment)
    return {"id": deployment.id, "decision": deployment.decision}


@router.get("/")
def list_deployments(limit: int = 100, db: Session = Depends(get_db)):
    """Newest-first deployment history with the scan results behind each decision."""
    rows = (
        db.query(Deployment, ScanResult)
        .outerjoin(ScanResult, Deployment.scan_result_id == ScanResult.id)
        .order_by(Deployment.id.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return [_serialize(deployment, scan) for deployment, scan in rows]


@router.get("/registration/{container_id}")
def registration(container_id: str, db: Session = Depends(get_db)):
    """Exact ID lookup over all records, independent of dashboard history pagination."""
    record = (
        db.query(Deployment)
        .filter(
            Deployment.container_id == container_id,
            Deployment.decision.in_(("allowed", "overridden")),
        )
        .first()
    )
    return {"container_id": container_id, "registered": record is not None}
