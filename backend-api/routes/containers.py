import os
import sys

import docker
import requests
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "response-engine"))

sys.path[:0] = [
    os.path.join(os.path.dirname(__file__), "..", "..", folder)
    for folder in ("monitor-service", "correlation-engine")
]
import auto_isolate  # noqa: E402
from database import get_db  # noqa: E402
from models.db_models import Incident, AuditEvent  # noqa: E402
from container_health import monitoring_health  # noqa: E402
from monitor_config import load_config  # noqa: E402
from monitor_status import read_status  # noqa: E402
from risk_explanation import explain_incident  # noqa: E402

router = APIRouter(prefix="/containers", tags=["containers"])


def _docker_client():
    return docker.from_env()


def _docker_unavailable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail=f"Docker is not available: {exc}")


def _latest_incident(db: Session, container):
    identifiers = [container.id, container.short_id, container.name]
    return (
        db.query(Incident)
        .filter(Incident.container_id.in_(identifiers))
        .order_by(Incident.id.desc())
        .first()
    )


def _describe(container, db: Session, monitor_status=None) -> dict:
    record_error = None
    try:
        record = auto_isolate.get_isolation_record(container.id)
    except auto_isolate.IsolationRecordError as exc:
        record, record_error = None, str(exc)
    isolated = None if record_error else record is not None and record.get("state") in (
        "isolated",
        "isolating",
        "isolation_failed",
        "resuming",
        "resume_failed",
    )
    disconnected = not ((container.attrs.get("NetworkSettings") or {}).get("Networks"))
    verified = isolated and container.status == "paused" and disconnected
    incident = _latest_incident(db, container)
    return {
        "id": container.short_id,
        "full_id": container.id,
        "protected": auto_isolate.is_protected(container),
        "monitoring": monitoring_health(container, monitor_status),
        "containment_state": "record_unavailable" if record_error else (
            record.get("state") if record else None
        ),
        "containment_label": (
            "Recovery record unavailable — containment unverified; operator repair required"
            if record_error else
            "Isolated – Paused + Network Disconnected"
            if verified
            else (
                "Containment incomplete — inspect and retry resume"
                if isolated
                else container.status
            )
        ),
        "isolation_error": record_error or (record.get("error") if record else None),
        "risk_explanation": (
            explain_incident(
                {
                    "container_id": incident.container_id,
                    "risk_score": incident.risk_score,
                    "confidence": incident.confidence,
                    "falco_alert": incident.falco_alert,
                    "anomaly_features": incident.anomaly_features,
                }
            )
            if incident
            else None
        ),
        "name": container.name,
        "image": (container.attrs.get("Config") or {}).get("Image"),
        "status": container.status,
        "isolated": isolated,
        "isolation_reason": record.get("reason") if record and isolated else None,
        "isolated_at": record.get("isolated_at") if record and isolated else None,
        "latest_risk_score": incident.risk_score if incident else None,
        "latest_incident_id": incident.id if incident else None,
        "latest_incident_at": incident.created_at if incident else None,
    }


def _audit(db, event_type, container_id, detail):
    db.add(
        AuditEvent(
            event_type=event_type,
            source="backend",
            severity="info",
            container_id=container_id,
            detail=detail,
        )
    )
    db.commit()


@router.get("/")
def list_containers(db: Session = Depends(get_db)):
    """All containers on the host (live from Docker) with isolation state and latest risk."""
    try:
        client = _docker_client()
        try:
            containers = client.containers.list(all=True)
        finally:
            client.close()
    except (docker.errors.DockerException, requests.RequestException) as exc:
        raise _docker_unavailable(exc) from exc
    monitor_status = read_status(load_config().state_dir / "status.json")
    return sorted(
        (_describe(c, db, monitor_status) for c in containers), key=lambda item: item["name"]
    )


@router.post("/{container_id}/resume")
def resume_container(
    container_id: str, resumed_by: str, recheck: bool = False, db: Session = Depends(get_db)
):
    """Admin action: unpause an isolated container and restore its networks."""
    try:
        _audit(db, "CONTAINER_RESUME_REQUESTED", container_id, {"resumed_by": resumed_by})
        result = auto_isolate.resume_container(container_id, resumed_by)
        _audit(db, "CONTAINER_RESUMED", result["container_id"], result)
        if recheck:
            try:
                sys.path.insert(
                    0, os.path.join(os.path.dirname(__file__), "..", "..", "policy-checker")
                )
                from deploy_policy_validator import check_deployment_config

                client = _docker_client()
                try:
                    live = client.containers.get(result["container_id"])
                    live.reload()
                    policy = check_deployment_config(live.attrs)
                    result["policy_recheck"] = policy.summary()
                finally:
                    client.close()
                result["behavior_recheck"] = "Automatic on the next complete activity window"
                _audit(db, "CONTAINER_RESUME_RECHECK", result["container_id"], result)
            except Exception as exc:
                result["policy_recheck"] = {"status": "unavailable", "reason": type(exc).__name__}
                _audit(db, "CONTAINER_RESUME_RECHECK_FAILED", result["container_id"], result)
        return result
    except ValueError as exc:
        _audit(db, "CONTAINER_RESUME_FAILED", container_id, {"reason": str(exc)})
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except auto_isolate.ContainerNotFound as exc:
        _audit(db, "CONTAINER_RESUME_FAILED", container_id, {"reason": str(exc)})
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except auto_isolate.ResumeError as exc:
        _audit(db, "CONTAINER_RESUME_FAILED", container_id, {"reason": str(exc)})
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (docker.errors.DockerException, requests.RequestException) as exc:
        _audit(db, "CONTAINER_RESUME_FAILED", container_id, {"reason": str(exc)})
        raise _docker_unavailable(exc) from exc


@router.post("/{container_id}/isolate")
def isolate_container(
    container_id: str, isolated_by: str, reason: str, db: Session = Depends(get_db)
):
    """Admin action: manually quarantine a container (pause + cut networks)."""
    if not isolated_by.strip() or not reason.strip():
        raise HTTPException(422, "Actor and reason must be non-empty")
    _audit(
        db,
        "CONTAINER_ISOLATION_REQUESTED",
        container_id,
        {"isolated_by": isolated_by, "reason": reason},
    )
    try:
        auto_isolate.isolate_container(container_id, f"manual, by {isolated_by}: {reason}")
    except auto_isolate.ContainerNotFound as exc:
        _audit(db, "CONTAINER_ISOLATION_FAILED", container_id, {"reason": str(exc)})
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except auto_isolate.IsolationError as exc:
        _audit(db, "CONTAINER_ISOLATION_FAILED", container_id, {"reason": str(exc)})
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (docker.errors.DockerException, requests.RequestException) as exc:
        _audit(db, "CONTAINER_ISOLATION_FAILED", container_id, {"reason": str(exc)})
        raise _docker_unavailable(exc) from exc
    _audit(db, "CONTAINER_ISOLATED", container_id, {"isolated_by": isolated_by, "reason": reason})
    return {"status": "isolated", "container_id": container_id}
