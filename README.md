# selfsentry

A hybrid rule-based + behavior-based container runtime security platform with a self-learning rule-generation feature. Academic/capstone project.

## What it does
Scans container images before deployment (Trivy), validates deployment configuration, monitors running containers with two parallel detection layers (Falco rule-matching + custom ML anomaly detection), correlates both into a unified risk score, uses an LLM to explain incidents in plain English, auto-isolates high-risk containers, and — the core novelty — automatically converts **confirmed** anomaly detections into new, backtested, human-approved Falco rules via a **Rule Synthesis Engine**.

Full design rationale, architecture, and academic materials live in `docs/` and the project's report deliverables (see `ContainerGuard_AI_*.pdf` / `.md` files generated during the design phase).

## Status
🚧 **In active implementation.** Phase 1 (Image Scanner) is complete and validated against real Trivy. Currently on **Phase 2 of 11** (Deployment Policy Checker) — code and tests done, manual `docker inspect` validation pending. See `ROADMAP.md` for the full phase plan and `TODO.md` for current task status.

## Modules (11 total)
1. Image Scanner (Trivy) — ✅ complete
2. Deployment Policy Checker — 🔶 code complete, manual validation pending
3. Falco Rule Engine
4. Behavioral Runtime Monitor
5. Anomaly Detection Model (Isolation Forest / One-Class SVM)
6. Correlation Engine
7. **Rule Synthesis Engine** (core novelty)
8. AI Threat Analysis (LLM)
9. Attack Timeline
10. Automated Response
11. Dashboard & Reports (React)

## Project structure
```
selfsentry/
├── image-scanner/       # Phase 1 — Trivy wrapper
├── policy-checker/      # Phase 2 — Deployment policy validator
├── tests/                # Unit tests for all modules
├── docs/                 # Per-phase documentation
├── requirements.txt
├── .env.example
├── TODO.md
├── CHANGELOG.md
└── ROADMAP.md
```
(More module directories — `runtime-monitor/`, `behavioral-engine/`, `correlation-engine/`, `rule-synthesis-engine/`, `ai-analysis/`, `response-engine/`, `backend-api/`, `frontend-dashboard/` — are added as their phases begin.)

## Setup
```bash
git clone <your-repo-url>
cd containerguard-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in real values, never commit .env
```

Phase 1 also requires the **Trivy CLI** installed separately: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

## Running tests
```bash
python3 -m unittest discover tests/ -v
# or
pytest tests/ -v
```

## Tech stack
Python, FastAPI, PostgreSQL, React + WebSockets, Trivy, Falco, eBPF, scikit-learn, Jinja2, OpenAI-compatible LLM API. Target OS: Linux (required for eBPF/Falco).

## License
TBD (academic project — set before public release if required by institution).
