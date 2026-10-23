from datetime import datetime, timezone
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from database import get_db
from models.db_models import AuditEvent

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=64)
    severity: Literal["info", "warning", "critical"] = "info"
    source: str = Field(default="monitor", min_length=1, max_length=64)
    event_key: str | None = Field(default=None, min_length=1, max_length=128)
    container_id: str | None = Field(default=None, min_length=1, max_length=128)
    container_name: str | None = Field(default=None, min_length=1, max_length=256)
    image_name: str | None = Field(default=None, min_length=1, max_length=256)
    detail: dict = Field(default_factory=dict)
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
        "occurred_at": (
            event.occurred_at.isoformat() + "Z" if event.occurred_at else None
        ),
        "created_at": event.created_at,
    }


def _acknowledge_duplicate(existing: AuditEvent, body: AuditEventIn, response: Response):
    fields = ("event_type", "severity", "source", "container_id", "container_name", "image_name")
    matches = all(getattr(existing, field) == getattr(body, field) for field in fields)
    try:
        matches = matches and json.dumps(
            existing.detail if existing.detail is not None else {},
            sort_keys=True, allow_nan=False,
        ) == json.dumps(body.detail, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError):
        matches = False  # Invalid historical data must not produce a duplicate success.
    if not matches:
        raise HTTPException(status_code=409, detail="Audit event key identifies different data")
    # Event time is first-write metadata, not identity: retries may regenerate it.
    response.status_code = 200
    return {"id": existing.id, "duplicate": True}


@router.post("/", status_code=201)
def record_audit_event(
    body: AuditEventIn, response: Response, db: Session = Depends(get_db)
):
    """Append an event or acknowledge a matching key/content replay; retain the first time."""
    try:
        json.dumps(body.detail, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422, detail="Audit detail must contain finite JSON values"
        ) from None
    if body.event_key:
        existing = (
            db.query(AuditEvent).filter(AuditEvent.event_key == body.event_key).first()
        )
        if existing:
            return _acknowledge_duplicate(existing, body, response)

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
    try:
        db.commit()
    except IntegrityError:
        # Another delivery can commit the same key after our initial lookup.
        # Roll back before querying and comparing the winning row.
        db.rollback()
        existing = (
            db.query(AuditEvent).filter(AuditEvent.event_key == body.event_key).first()
            if body.event_key
            else None
        )
        if existing is None:
            raise
        return _acknowledge_duplicate(existing, body, response)
    db.refresh(event)
    return {"id": event.id, "duplicate": False}


@router.get("/")
def list_audit_events(
    event_type: str | None = None,
    container_id: str | None = None,
    limit: int = 100,
    event_id: int | None = Query(default=None, gt=0),
    before_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    """Newest-first audit log, optionally filtered by event type or container."""
    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if container_id:
        query = query.filter(AuditEvent.container_id == container_id)
    if event_id is not None:
        query = query.filter(AuditEvent.id == event_id)
    if before_id is not None:
        query = query.filter(AuditEvent.id < before_id)
    rows = query.order_by(AuditEvent.id.desc()).limit(max(1, min(limit, 500))).all()
    return [_serialize(row) for row in rows]
