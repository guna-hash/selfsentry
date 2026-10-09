from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func

from database import Base


class Container(Base):
    __tablename__ = "containers"

    id = Column(Integer, primary_key=True)
    container_id = Column(String(128), unique=True, nullable=False)
    image_name = Column(String(256), nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True)
    container_id = Column(String(128), nullable=False)
    risk_score = Column(Float, nullable=False)
    confidence = Column(String(16))
    falco_alert = Column(JSON)
    anomaly_features = Column(JSON)
    ai_summary = Column(JSON)  # Phase 7 output, advisory only
    created_at = Column(DateTime, server_default=func.now())


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    image_name = Column(String(256), nullable=False)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    secrets_found = Column(Integer, default=0)
    misconfigurations_found = Column(Integer, default=0)
    raw_json = Column(JSON)
    scanned_at = Column(DateTime, server_default=func.now())


class ConfirmedIncident(Base):
    __tablename__ = "confirmed_incidents"

    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    confirmed_by = Column(String(128), nullable=False)
    confirmed_at = Column(DateTime, server_default=func.now())


class GeneratedRule(Base):
    __tablename__ = "generated_rules"

    id = Column(Integer, primary_key=True)
    confirmed_incident_id = Column(Integer, ForeignKey("confirmed_incidents.id"))
    rule_yaml = Column(String, nullable=False)
    status = Column(String(32), default="pending_review")
    backtested_fp_rate = Column(Float)
    created_at = Column(DateTime, server_default=func.now())
    reviewed_by = Column(String(128))
    reviewed_at = Column(DateTime)


class RulePerformance(Base):
    __tablename__ = "rule_performance"

    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("generated_rules.id"))
    true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    last_updated = Column(DateTime, server_default=func.now())



class Deployment(Base):
    __tablename__ = "deployments"

    id = Column(Integer, primary_key=True)
    container_name = Column(String(256), nullable=False)
    container_id = Column(String(128))
    image_name = Column(String(256), nullable=False)
    decision = Column(String(16), nullable=False)  # allowed / blocked / overridden
    override_reason = Column(String(512))
    requested_by = Column(String(128))
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"))
    policy_summary = Column(JSON)
    policy_violations = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())
