# SelfSentry

SelfSentry is a host-local container security research platform. It combines Trivy
image scanning, Docker configuration checks, Falco alerts and per-container behavioral
models. It records incidents and can propose literal Falco rules for human review.
The goal is an explainable, supervised detection loop with preserved evidence.

This is an academic platform with production-oriented controls, **not a verified
Internet-facing production security service**. See the [repository audit](docs/repository-audit/report.md)
for current review coverage, executed checks and unresolved findings.

## Features and boundaries

- **Deployment gate:** creates a container, inspects it, scans its immutable image ID,
  checks runtime policy, then starts or removes it. Scan failures block deployment;
  an explicit override reason can authorize a blocked deployment. Creation and action intent
  persist before their Docker commands; confirmed decisions enter the backend replay queue. Uncertain/failed
  actions require operator review and are never automatically repeated. Plain `docker run`
  bypasses the gate.
- **Continuous monitor:** tails Falco JSON with checkpoints, deduplicates events, journals
  feature windows and delivers incidents through a durable outbox. Baseline capture rules
  supply behavioral telemetry; the project does not run an independent eBPF collector.
- **Behavioral detection:** container-specific JSON baselines feed Isolation Forest.
  Learning, unavailable and invalid-model states remain explicit. Scores are rankings,
  not calibrated probabilities. One-Class SVM is experimental. A calibrated LOF
  candidate was evaluated offline; it is not a live algorithm option or an approved replacement.
- **Response:** automatic isolation defaults off. The durable monitor requires qualifying
  dual-layer evidence, freshness and protection checks before attempting it. Manual isolation
  and recovery require the backend operator token. Recovery restores saved network membership
  and aliases; it does not restore every Docker endpoint option or static IP. Invalid or
  unreadable recovery records are preserved and block further actions for operator repair.
- **Rule proposals:** supported process/parent and process/file-write templates require
  authoritative benign backtesting and human approval. Missing evidence blocks progression.
  AI is optional advisory narration and cannot authorize rules or response actions. Native retirement
  has an opt-in, human-confirmed workflow with retained originals and reload receipts; it defaults
  disabled. Controlled native retirement and two supervised rule loops are recorded in the
  current audit update; broader failure coverage remains incomplete. Database-only retirement remains distinct.
- **Dashboard:** live inventory, incidents, audit, rule review, models and monitor health.
  `/sample/overview` is explicitly synthetic and read-only. `/evidence` shows historical
  reports, not current detection measurements.

## Architecture

| Directory | Responsibility |
| --- | --- |
| `image-scanner`, `policy-checker`, `deployment-gate` | Pre-start scanning, policy and decision replay |
| `runtime-monitor`, `falco-rules` | Falco parsing and telemetry/rule definitions |
| `behavioral-engine`, `correlation-engine` | Feature vectors, models, risk scoring and diagnostic routing |
| `monitor-service` | Continuous ingestion, local SQLite state and durable workflows |
| `backend-api` | FastAPI routes and SQLAlchemy/PostgreSQL persistence |
| `response-engine` | Locked Docker containment and network recovery |
| `rule-synthesis-engine` | Templates, backtests, duplicate registry and approved deployment |
| `ai-analysis` | Optional provider-backed narration |
| `frontend-dashboard` | React/Vite dashboard |
| `evaluation`, `tests`, `docs` | Evaluation tools, regressions and retained evidence |

The monitor journals events before advancing its Falco checkpoint. Windows produce
incident payloads; a separate control worker delivers them and handles response and proposals.
PostgreSQL stores incidents and audit records. Local SQLite journals support outage replay;
they are not a replacement for database backups. See [contracts](docs/interfaces.md) and
[developer guide](docs/repository-audit/developer-guide.md).

## Prerequisites

Full host operation requires Linux with `/proc` and `flock`, PostgreSQL, Docker,
Trivy, Falco with a compatible kernel/driver, and systemd for the configured Falco service.
Docker socket access grants powerful host privileges. Bind the backend to localhost.

The audit environment used Python 3.12 and Node 24. Frontend tests/build and Python
unit/SQLite tests can run without the host security services. Runtime compatibility
with other versions must be checked separately.

## Install and configure

For a new Ubuntu host, follow the [verified manual setup guide](docs/fresh-ubuntu-install.md).
It covers host packages, Docker group activation, fresh private credentials/database,
Alembic migration order and Falco list-merge/log permissions. Python and npm installation
alone do not install or configure those services. The [clean-install record](docs/repository-audit/clean-install-20261028.md)
documents the tested versions and scope; it is not an unattended installation guarantee.

```bash
git clone https://github.com/guna-hash/selfsentry.git
cd selfsentry
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.2.1
.venv/bin/python -m pip install -r requirements.lock
(cd frontend-dashboard && npm ci && npm run build)
cp -n .env.example .env
chmod 600 .env
```

Edit `.env` locally: configure a dedicated PostgreSQL database/role via `DATABASE_URL`,
generate a random `SELFSENTRY_API_TOKEN`, and set Falco paths. Keep
`AUTO_ISOLATION_ENABLED=false`. Never commit credentials, baseline datasets or runtime state.
For synthesis, supply an operator-validated benign JSONL corpus through
`MONITOR_BENIGN_LOG_PATH`; otherwise set `MONITOR_RULE_CANDIDATES_ENABLED=false` explicitly.
AI keys are optional.

A versioned Alembic baseline is available for new databases. Run
`.venv/bin/python -m alembic -c alembic.ini upgrade head` before starting a fresh backend.
For an existing installation, back up first and follow the schema comparison/adoption
procedure in [operations](docs/monitor_operations.md#schema-migrations-and-adoption).
Startup still creates missing tables for compatibility; `create_all` does not upgrade them. [Operations](docs/monitor_operations.md) explains host
prerequisites, PostgreSQL configuration, Falco capture rules, tokens and recovery.

Plain `postgresql://` URLs use the declared psycopg2 dependency. The backend defaults to a
five-second connection timeout and pool-checkout wait; positive URL `connect_timeout` overrides
connection establishment. These do not bound queries or complete API requests. See
[database behavior](docs/monitor_operations.md#postgresql-connection-and-pool-behavior).

## Run

After configuring the external services and building the dashboard:

```bash
bin/selfsentry start
bin/selfsentry status
# bin/selfsentry stop
# bin/selfsentry restart
```

Open `http://127.0.0.1:5173`. Enter the write token on the Monitor page for operator actions.
Managed startup validates prerequisites and refuses incomplete configuration. Stopping the
application does not stop Falco, PostgreSQL, Docker or workload containers.
Monitor shutdown waits for background work before releasing its instance lock. A blocked
dependency can delay exit; a failed stop command requires log/process inspection before restart.

For a gated deployment, use `bin/selfsentry-run -- <docker create arguments>`.
See [gate operations](docs/deployment_gate.md) for policy and overrides. Diagnostic
`correlation-engine/validate_pipeline.py` logs routing suggestions; it cannot isolate workloads.
Actual automatic response belongs to the durable monitor.

## Validate

```bash
.venv/bin/python -m pytest tests/ -q
.venv/bin/python scripts/verify_final_checks.py
(cd frontend-dashboard && npm test -- --run)
```

The release script records tests, whole-repository Python lint, scoped type checking and the frontend build under
`state/evaluation/`. The final audit checkpoint passes that lint check.
Unit tests use mocks and isolated SQLite; they do not prove native Falco, PostgreSQL
concurrency, real containment, restoration or detection accuracy. Optional live AI diagnostics
`test_manual_check.py` and `test_timeline_check.py` run only when invoked directly.

## Evidence, limitations and next work

Start with the [current acceptance review](docs/repository-audit/acceptance-review-20261028.md)
and [clean-install verification](docs/repository-audit/clean-install-20261028.md).
Earlier academic context is in the [academic handoff](docs/academic_handoff_20261021.md),
[case matrix](docs/academic_case_matrix.md), [demo](docs/demo_script.md), and
[known limitations](docs/known_limitations.md). Historical controlled measurements remain
in their original reports; they do not establish production accuracy or added coverage
beyond Falco. Screenshots and their synthetic/live provenance are documented in the
[screenshot guide](docs/dashboard_screenshots.md).

Current engineering limits include shared-token rather than per-person authorization,
unbounded total retained history, an unread-log rotation loss boundary, recurring event-clock
skew without a permanent fix, and incomplete representative model/load and failure validation.
Recorded native checks include PostgreSQL migration/restore/concurrency, keyed audit COMMIT
reply loss, bounded review locking, direct response and interruption recovery, and controlled
rule retirement/rollback and supervised re-fire. These passes do not cover every endpoint,
crash interleaving or production workload. Fresh Ubuntu setup and basic operator browser checks
also passed within the linked installation record; no data or secrets were copied from the
original host. Manual archive/export and explicit current-state observations are documented
in [operations](docs/monitor_operations.md#tracked-follow-up-tools). Keep automatic response
disabled during ordinary observation. Do not infer event-time freshness or detection quality
solely from a healthy monitor heartbeat.

<!-- redesign-gallery:start -->
<!-- redesign-gallery:end -->

## License and attribution

No license has been selected. Clarify licensing before redistribution. Preserve dependency
notices and document AI assistance according to institutional or submission requirements;
this review does not alter authorship or development history.

The migration revision template derives from Alembic 1.20.0; its
[upstream notice](database/migrations/ALEMBIC_TEMPLATE_LICENSE) is retained separately.
This does not select a license for SelfSentry.
