"""
db_models.py
---------------
Module 11 support: SQLAlchemy ORM models for PostgreSQL.

STATUS: NOT YET IMPLEMENTED — Phase 8 stub.

Planned tables (see database/schema.sql for the full DDL draft):
  - containers            : monitored container metadata
  - scan_results           : Phase 1 image scan history
  - incidents               : correlated risk-scored incidents (Phase 5)
  - confirmed_incidents      : human-confirmed incidents feeding Phase 6
  - generated_rules           : auto-generated rule text + status + backtested FP rate
  - rule_performance            : ongoing TP/FP tracking per deployed rule

Example planned skeleton (once sqlalchemy is installed - see requirements.txt):

    from sqlalchemy import Column, Integer, String, Float, DateTime
    from sqlalchemy.orm import declarative_base

    Base = declarative_base()

    class Incident(Base):
        __tablename__ = "incidents"
        # raise NotImplementedError - fill in columns during Phase 8
"""
