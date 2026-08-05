# ContainerGuard AI

A hybrid rule-based + behavior-based container runtime security platform with a self-learning rule-generation feature. Academic/capstone project.

## What it does
Scans container images before deployment (Trivy), validates deployment configuration, monitors running containers with two parallel detection layers (Falco rule-matching + custom ML anomaly detection), correlates both into a unified risk score, uses an LLM to explain incidents in plain English, auto-isolates high-risk containers, and — the core novelty — automatically converts **confirmed** anomaly detections into new, backtested, human-approved Falco rules via a **Rule Synthesis Engine**.

Full design rationale, architecture, and academic materials live in `docs/` and the project's report deliverables (see `ContainerGuard_AI_*.pdf` / `.md` files generated during the design phase).

## Status
🚧 **In active implementation.** Currently on **Phase 1 of 11** (Image Scanner). See `ROADMAP.md` for the full phase plan and `TODO.md` for current task status.

## Modules (11 total)
1. Image Scanner (Trivy) — ✅ in progress
2. Deployment Policy Checker
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
Full scaffold for all 11 modules exists from day one — but **only `image-scanner/` has real, working code**. Everything else is an intentional stub (docstring explaining what it will do + `NotImplementedError`), so the architecture is visible without pretending unbuilt phases are done. Check each file's own docstring for its status.

```
containerguard-ai/
├── image-scanner/              # Phase 1 — ✅ REAL, working (Trivy wrapper)
├── policy-checker/             # Phase 2 — stub
├── runtime-monitor/            # Phase 3 — stub (Falco/eBPF integration)
├── behavioral-engine/          # Phase 4 — stub (baseline + anomaly model)
├── correlation-engine/         # Phase 5 — stub
├── rule-synthesis-engine/      # Phase 6 — stub (★ core novelty ★)
│   └── templates/               #   Jinja2 Falco rule template
├── ai-analysis/                # Phase 7 — stub (LLM root-cause + timeline)
├── response-engine/            # Phase 10 — stub (auto-isolate)
├── falco-rules/                # base-rules.yaml (hand-written) +
│                                #   auto-generated-rules.yaml (system-managed)
├── backend-api/                # Phase 8 — stub (FastAPI routes + models)
│   ├── routes/
│   └── models/
├── frontend-dashboard/         # Phase 9 — stub (React, incl. package.json)
│   └── src/pages/
├── database/                   # schema.sql — draft DDL for all tables
├── tests/                      # Unit tests (currently: image-scanner only)
├── docs/                       # Per-phase documentation
├── requirements.txt            # full dependency list, organized by phase
├── .env.example
├── TODO.md
├── CHANGELOG.md
└── ROADMAP.md
```

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
