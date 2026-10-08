import os
import sys

import docker
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "response-engine"))

import auto_isolate  # noqa: E402
from database import get_db  # noqa: E402
from models.db_models import Incident  # noqa: E402

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


def _describe(container, db: Session) -> dict:
    record = auto_isolate.get_isolation_record(container.id)
    isolated = auto_isolate.is_isolated(record)
    incident = _latest_incident(db, container)
    return {
        "id": container.short_id,
        "name": container.name,
        "image": (container.attrs.get("Config") or {}).get("Image"),
        "status": container.status,
        "isolated": isolated,
        "isolation_reason": record.get("reason") if isolated else None,
        "isolated_at": record.get("isolated_at") if isolated else None,
        "latest_risk_score": incident.risk_score if incident else None,
        "latest_incident_id": incident.id if incident else None,
        "latest_incident_at": incident.created_at if incident else None,
    }


@router.get("/")
def list_containers(db: Session = Depends(get_db)):
    """All containers on the host (live from Docker) with isolation state and latest risk."""
    try:
        containers = _docker_client().containers.list(all=True)
    except docker.errors.DockerException as exc:
        raise _docker_unavailable(exc) from exc
    return sorted((_describe(c, db) for c in containers), key=lambda item: item["name"])


@router.post("/{container_id}/resume")
def resume_container(container_id: str, resumed_by: str):
    """Admin action: unpause an isolated container and restore its networks."""
    try:
        return auto_isolate.resume_container(container_id, resumed_by)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except auto_isolate.ContainerNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except auto_isolate.ResumeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except docker.errors.DockerException as exc:
        raise _docker_unavailable(exc) from exc


@router.post("/{container_id}/isolate")
def isolate_container(container_id: str, isolated_by: str, reason: str):
    """Admin action: manually quarantine a container (pause + cut networks)."""
    try:
        auto_isolate.isolate_container(container_id, f"manual, by {isolated_by}: {reason}")
    except auto_isolate.ContainerNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except auto_isolate.IsolationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except docker.errors.DockerException as exc:
        raise _docker_unavailable(exc) from exc
    return {"status": "isolated", "container_id": container_id}
