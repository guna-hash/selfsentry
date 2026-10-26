from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import os
import secrets
import logging
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, TimeoutError as DatabasePoolTimeout
from sqlalchemy.orm import Session

from database import engine, Base, get_db

# Imported so Base.metadata.create_all() sees every table.
from models.db_models import (  # noqa: F401
    Container,
    Incident,
    ScanResult,
    ConfirmedIncident,
    GeneratedRule,
    RulePerformance,
    Deployment,
    AuditEvent,
    MonitorIncident,
)
from routes import audit, containers, deployments, incidents, rules, monitor

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SelfSentry Backend")
logger = logging.getLogger(__name__)


@app.exception_handler(OperationalError)
@app.exception_handler(DatabasePoolTimeout)
async def database_operation_unavailable(request: Request, exc: Exception):
    # Driver errors can include SQL, parameters and credentials. Do not echo or log them.
    logger.error("Database operation unavailable (%s); method=%s",
                 type(exc).__name__, request.method)
    detail = "Database operation unavailable."
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        detail += " A write may have completed; review recorded state before retrying."
    return JSONResponse(status_code=503, content={"detail": detail})


@app.middleware("http")
async def authorize_writes(request: Request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        token = os.environ.get("SELFSENTRY_API_TOKEN", "")
        if not token:
            return JSONResponse(
                status_code=503, content={"detail": "Configure SELFSENTRY_API_TOKEN"}
            )
        supplied = request.headers.get("Authorization", "")
        if token and not secrets.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
            return JSONResponse(status_code=401, content={"detail": "Bearer token required"})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incidents.router)
app.include_router(rules.router)
app.include_router(containers.router)
app.include_router(deployments.router)
app.include_router(audit.router)
app.include_router(monitor.router)


@app.get("/")
async def root():
    return {"status": "SelfSentry backend running"}


@app.get("/health/ready")
def readiness(request: Request, db: Session = Depends(get_db)):
    """Read-only database readiness, authenticated with the configured write token."""
    token = os.environ.get("SELFSENTRY_API_TOKEN", "")
    if not token:
        raise HTTPException(503, "Configure SELFSENTRY_API_TOKEN")
    supplied = request.headers.get("Authorization", "")
    if not secrets.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
        raise HTTPException(401, "Bearer token required")
    db.execute(text("SELECT 1"))
    return {"ready": True}
