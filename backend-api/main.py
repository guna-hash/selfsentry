from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os
import secrets
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base

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
