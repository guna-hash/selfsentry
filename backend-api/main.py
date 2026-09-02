from fastapi import FastAPI

from database import engine, Base
from models.db_models import Container, Incident, ScanResult, ConfirmedIncident, GeneratedRule, RulePerformance
from routes import incidents, rules

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ContainerGuard AI Backend")

app.include_router(incidents.router)
app.include_router(rules.router)


@app.get("/")
async def root():
    return {"status": "ContainerGuard AI backend running"}
