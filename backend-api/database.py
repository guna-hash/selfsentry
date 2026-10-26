"""Backend metadata/sessions; PostgreSQL uses the declared psycopg2 dependency."""

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import sessionmaker, DeclarativeBase

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Configure DATABASE_URL before starting the backend")


def create_database_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    # SQLAlchemy 2.1 changed the unqualified PostgreSQL default to psycopg 3.
    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg2")
    if url.drivername == "postgresql+psycopg2":
        supplied = url.query.get("connect_timeout", "5")
        try:
            if not isinstance(supplied, str):
                raise ValueError
            timeout = int(supplied)
            if timeout <= 0:
                raise ValueError
        except ValueError:
            raise ValueError(
                "PostgreSQL connect_timeout must be a positive whole number"
            ) from None
        options = url.query.get("options", "")
        if not isinstance(options, str):
            raise ValueError("PostgreSQL connection options must be a single string")
        # Naive timestamp columns and API serialization use UTC. Set it in the
        # startup packet, before even the first transaction, rather than a SET
        # statement that a pool reset/rollback could undo. Preserve other libpq
        # options, but make our timezone the last assignment. PGOPTIONS and a
        # host/database default must not change the meaning of stored timestamps.
        options = (options + " -c timezone=UTC").strip()
        return create_engine(
            url, pool_pre_ping=True, pool_timeout=5,
            connect_args={"connect_timeout": timeout, "options": options},
        )
    return create_engine(url)


engine = create_database_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Shared SQLAlchemy metadata for the backend schema."""


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
