from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
from models.db_models import Container, Incident, ScanResult, ConfirmedIncident, GeneratedRule, RulePerformance
from routes import incidents, rules

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ContainerGuard AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incidents.router)
app.include_router(rules.router)


@app.get("/")
async def root():
    return {"status": "ContainerGuard AI backend running"}
