from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models.db_models import Deployment, ScanResult

router = APIRouter(prefix="/deployments", tags=["deployments"])


class DeploymentIn(BaseModel):
    container_name: str
    container_id: str | None = None
    image_name: str
    decision: Literal["allowed", "blocked", "overridden"]
    override_reason: str | None = None
    requested_by: str | None = None
    scan_summary: dict = {}
    scan_findings: list = []
    policy_summary: dict = {}
    policy_violations: list = []


def _serialize(deployment: Deployment, scan: ScanResult | None) -> dict:
    return {
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
        "scan": None
        if scan is None
        else {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "secrets_found": scan.secrets_found,
            "misconfigurations_found": scan.misconfigurations_found,
            "top_findings": (scan.raw_json or {}).get("top_findings", []),
        },
    }


@router.post("/", status_code=201)
def record_deployment(body: DeploymentIn, db: Session = Depends(get_db)):
    """Record a gate decision (and the scan that informed it) for the dashboard history."""
    if body.decision == "overridden" and not (body.override_reason or "").strip():
        raise HTTPException(status_code=422, detail="an override requires override_reason")

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
        policy_summary=body.policy_summary,
        policy_violations=body.policy_violations,
    )
    db.add(deployment)
    db.commit()
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
