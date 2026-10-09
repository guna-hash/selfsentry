from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models.db_models import AuditEvent

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventIn(BaseModel):
    event_type: str
    severity: Literal["info", "warning", "critical"] = "info"
    source: str = "monitor"
    event_key: str | None = None
    container_id: str | None = None
    container_name: str | None = None
    image_name: str | None = None
    detail: dict = {}
    occurred_at: datetime | None = None


def _to_naive_utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _serialize(event: AuditEvent) -> dict:
    return {
        "id": event.id,
        "event_key": event.event_key,
        "event_type": event.event_type,
        "severity": event.severity,
        "source": event.source,
        "container_id": event.container_id,
        "container_name": event.container_name,
        "image_name": event.image_name,
        "detail": event.detail or {},
        # occurred_at is stored as naive UTC; mark it explicitly so browsers do not
        # reinterpret it as local time.
        "occurred_at": event.occurred_at.isoformat() + "Z" if event.occurred_at else None,
        "created_at": event.created_at,
    }


@router.post("/", status_code=201)
def record_audit_event(body: AuditEventIn, response: Response, db: Session = Depends(get_db)):
    """Append an audit event. A repeated event_key is acknowledged without a second row."""
    if body.event_key:
        existing = db.query(AuditEvent).filter(AuditEvent.event_key == body.event_key).first()
        if existing:
            response.status_code = 200
            return {"id": existing.id, "duplicate": True}

    event = AuditEvent(
        event_key=body.event_key,
        event_type=body.event_type,
        severity=body.severity,
        source=body.source,
        container_id=body.container_id,
        container_name=body.container_name,
        image_name=body.image_name,
        detail=body.detail,
        occurred_at=_to_naive_utc(body.occurred_at),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"id": event.id, "duplicate": False}


@router.get("/")
def list_audit_events(
    event_type: str | None = None,
    container_id: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Newest-first audit log, optionally filtered by event type or container."""
    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if container_id:
        query = query.filter(AuditEvent.container_id == container_id)
    rows = query.order_by(AuditEvent.id.desc()).limit(max(1, min(limit, 500))).all()
    return [_serialize(row) for row in rows]
