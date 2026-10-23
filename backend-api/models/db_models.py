from sqlalchemy import Integer, String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from typing import Any

from database import Base


class Container(Base):
    __tablename__ = "containers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    container_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    image_name: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    container_id: Mapped[str] = mapped_column(String(128), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    falco_alert: Mapped[Any] = mapped_column(JSON, nullable=True)
    anomaly_features: Mapped[Any] = mapped_column(JSON, nullable=True)
    ai_summary: Mapped[Any] = mapped_column(JSON, nullable=True)  # Phase 7 output, advisory only
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    image_name: Mapped[str] = mapped_column(String(256), nullable=False)
    critical_count: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    high_count: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    total_vulnerabilities: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    secrets_found: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    misconfigurations_found: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    raw_json: Mapped[Any] = mapped_column(JSON, nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )


class MonitorIncident(Base):
    """Additive monitor metadata; existing Incident columns/API remain compatible."""

    __tablename__ = "monitor_incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    event_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id"), unique=True, nullable=False
    )
    evidence: Mapped[Any] = mapped_column(JSON, nullable=True)
    workflow: Mapped[Any] = mapped_column(JSON, nullable=True)


class ConfirmedIncident(Base):
    __tablename__ = "confirmed_incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=True
    )
    confirmed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )


class GeneratedRule(Base):
    __tablename__ = "generated_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    confirmed_incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("confirmed_incidents.id"), nullable=True
    )
    rule_yaml: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str | None] = mapped_column(String(32), default="pending_review", nullable=True)
    backtested_fp_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RulePerformance(Base):
    __tablename__ = "rule_performance"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    rule_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("generated_rules.id"), unique=True, nullable=True
    )
    true_positives: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    false_positives: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    last_updated: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    container_name: Mapped[str] = mapped_column(String(256), nullable=False)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    image_name: Mapped[str] = mapped_column(String(256), nullable=False)
    decision: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # allowed / blocked / overridden
    override_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scan_result_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("scan_results.id"), nullable=True
    )
    policy_summary: Mapped[Any] = mapped_column(JSON, nullable=True)
    policy_violations: Mapped[Any] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    event_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="monitor")
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    container_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    image_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail: Mapped[Any] = mapped_column(JSON, nullable=True)
    occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )  # stored as naive UTC
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )
