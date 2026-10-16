# SelfSentry continuous monitor: setup and operation

The completion extension builds on source `0dc6374`. Existing modules, tables and data are
preserved. Explanations use the existing Incident.ai_summary JSON (a deterministic
risk_explanation member); deployment guidance uses Deployment.policy_summary JSON. Rule
backtest/lifecycle/native-match evidence uses AuditEvent.detail. No schema migration is needed.

Operator-reported functional acceptance and its limits are recorded in
[16 October acceptance](completion_acceptance_20261016.md). Startup regression fixes close
Docker SDK context-manager compatibility and false port conflicts after shutdown.

Monitoring of running workloads has no alert-triggered suspension path: ingest/window work
continues independently of control delivery and other containers' isolation. Paused workloads
remain inventoried and audited; they cannot generate fresh process activity while paused.

## Single-command host operation

One-time setup on your existing VM:

```bash
cd ~/selfsentry
python3 -m venv .venv             # only if the environment does not exist
.venv/bin/python -m pip install -r requirements.txt
(cd frontend-dashboard && npm ci && npm run build)
# Configure .env as described below; do not replace an existing .env.
bin/selfsentry start
bin/selfsentry status
```

The CLI starts the local FastAPI backend (8000), monitor and built dashboard (5173), in
that order, after checking critical prerequisites. It rolls back processes it started when
readiness fails. It creates private logs in state/logs and stores PID/start-time identities
in state/run; a lock prevents overlapping start/stop commands. Stale PID files never authorize
signaling an unrelated process. `bin/selfsentry stop` and `restart` affect managed application
processes only; Docker, PostgreSQL, Falco and workload containers are retained. A separately
started stack must be stopped by its operator before adopting this manager. Stop refuses to
pretend success if a process does not exit within 15 seconds; records are retained for inspection.

Requirements: Linux /proc + flock, the repo .venv, PostgreSQL DATABASE_URL, a nonempty shared
API token, accessible Docker socket, Docker/Trivy/Falco binaries, active Falco systemd unit,
readable Falco config and JSON log, built frontend. Candidate generation requires an existing
operator-validated benign JSONL corpus at MONITOR_BENIGN_LOG_PATH. Disabling candidate generation
permits operation without a corpus, with the adaptation path explicitly disabled.

Falco must use json_output=true, time_format_iso_8601=true, rule_matching=all, and file_output
pointing at FALCO_LOG_PATH. rules_files must include the repo's baseline-capture-rules.yaml
and auto-generated-rules.yaml, alongside Falco's default rules/macros. The CLI checks falco.yaml
and config.d/*.yaml settings on disk and the active unit; this is not proof of the runtime's
loaded configuration or zero dropped kernel events. Keep service command-line/config overrides
consistent with these files. After applying changed capture rules, reload Falco and verify real
JSON baseline events. FALCO_SERVICE defaults to falco-modern-bpf; FALCO_CONFIG_PATH defaults to
/etc/falco/falco.yaml and also controls the deployer's config lookup. Human rule approval uses
`sudo -n systemctl reload <FALCO_SERVICE>` with a 20-second timeout; configure narrowly scoped
noninteractive reload permission locally. A reload failure remains visible/audited and retryable.

CLI lifecycle commands never print .env values. To inspect errors:

```bash
tail -n 50 state/logs/backend.log
tail -n 50 state/logs/monitor.log
tail -n 50 state/logs/frontend.log
```

Managed startup also backfills deterministic guidance for historical incident/deployment rows
idempotently after backend readiness. Direct/manual starts still render guidance for legacy
rows on read; run `.venv/bin/python ops/backfill_explanations.py` to persist it manually.

## Configure the shared API token

All non-read requests to the actual backend app require a bearer token. Without a configured
SELFSENTRY_API_TOKEN, writes return 503; invalid/missing credentials return 401. Reads remain
available on the local development interface. Bind the backend to 127.0.0.1. This shared-token
scheme does not implement per-person identities, role-based permissions or an Internet-facing
production auth system. Review names remain operator-supplied audit labels.

The following creates a random token only if no nonempty value exists. It preserves other .env
values and does not print credentials. Ensure your database URL remains configured.

```bash
cd ~/selfsentry
python3 - <<'PY'
from pathlib import Path
from dotenv import dotenv_values
import secrets
p = Path('.env')
text = p.read_text() if p.exists() else ''
if not dotenv_values(p).get('SELFSENTRY_API_TOKEN'):
    p.write_text(text.rstrip() + '\nSELFSENTRY_API_TOKEN=' + secrets.token_urlsafe(32) + '\n')
p.chmod(0o600)
print('Shared token configured; existing settings preserved.')
PY
```

The monitor, backend and deployment gate load .env from the repository using the existing
dotenv setup. For dashboard actions, enter that same token on the Monitor page (stored only
in sessionStorage). To display it locally for copying:

```bash
python3 -c "from dotenv import dotenv_values; print(dotenv_values('.env')['SELFSENTRY_API_TOKEN'])"
```

## Baseline discovery before enabling automation

Existing datasets are not included in Git. The default baseline directory is
behavioral-engine/baselines. Point MONITOR_BASELINE_DIR at your actual directory. Inspect
sample ownership and window length before changing MONITOR_WINDOW_SECONDS; never rename a
baseline file to another container ID or copy a model between containers merely by image/name.

```bash
python3 - <<'PY'
from pathlib import Path
from datetime import datetime
import json
for folder in (Path('behavioral-engine/baselines'), Path('baselines')):
    for path in folder.glob('*.json'):
        dataset = json.loads(path.read_text())
        rows = dataset.get('feature_vectors', [])
        duration = None
        if rows:
            start = datetime.fromisoformat(rows[0]['window_start'])
            end = datetime.fromisoformat(rows[0]['window_end'])
            duration = (end - start).total_seconds()
        print(path, 'owner=', dataset.get('container_id'), 'samples=', len(rows),
              'window_seconds=', duration)
PY
```

A mismatch, invalid ownership, nonfinite features or degenerate baseline keeps ML unavailable.
An old dataset is not proof of good baseline quality. Collect representative clean activity and
measure benign false positives before enabling isolation. Falco remains active during learning.
Security-alert windows are excluded from new training samples. Events arriving after a window
closes are retained/audited; a late security alert revokes model readiness until operator review.
Missing capture telemetry produces an explicit unavailable reason, not a score of zero.

## Start, stop and inspect

Backend terminal:

```bash
cd ~/selfsentry
source .venv/bin/activate
python3 -m uvicorn main:app --app-dir backend-api --host 127.0.0.1 --port 8000
```

Monitor terminal (Falco and Docker must already be running):

```bash
cd ~/selfsentry
source .venv/bin/activate
mkdir -p state/monitor
AUTO_ISOLATION_ENABLED=false MONITOR_LOG_FORMAT=json \
python3 monitor-service/monitor_service.py 2>>state/monitor/monitor.log
```

Ctrl+C or SIGTERM stops the foreground monitor. A single-instance lock prevents a second
monitor using the same state directory. To stop by the PID from status.json after checking it:

```bash
python3 monitor-service/monitor_service.py --status
# Then: kill -TERM <the monitor PID shown above>
```

Dashboard terminal:

```bash
cd ~/selfsentry/frontend-dashboard
npm run dev -- --host 127.0.0.1
```

Inspect status and logs:

```bash
cd ~/selfsentry
python3 monitor-service/monitor_service.py --status
curl -fsS http://127.0.0.1:8000/monitor/status
curl -fsS 'http://127.0.0.1:8000/audit/?limit=20'
tail -n 50 state/monitor/monitor.log
sudo journalctl -u falco-modern-bpf -n 50 --no-pager
```

`--once` performs one diagnostic iteration; fixed windows may not have closed yet, so it is
not an end-to-end attack demo. The status endpoint's healthy flag means running with a fresh
heartbeat (under 30 seconds), not that every component is healthy; inspect components too.

Stop the monitor before a baseline reset. The command archives its prior JSON dataset and
records a reason; it preserves all incident and response history. Only new complete windows
following the reset can contribute to learning. Do not remove the pipeline journal/checkpoint
as a retraining shortcut.

```bash
python3 monitor-service/monitor_service.py --reset-baseline <container-id> \
  --reason 'Reviewed clean workload; recapture representative baseline'
```

## Configuration

All settings come from environment/.env and are validated at startup. Paths can be absolute.

| Variable | Default | Purpose |
|---|---|---|
| SELFSENTRY_API_TOKEN | unset | Required shared credential for backend writes |
| SELFSENTRY_BACKEND_URL | http://localhost:8000 | Existing backend |
| FALCO_LOG_PATH | /var/log/falco/alerts.json | Falco JSON |
| MONITOR_STATE_DIR | repo/state/monitor | Journal, checkpoint, status and audit spool |
| MONITOR_START_FROM | end | Initial file position without checkpoint |
| MONITOR_POLL_INTERVAL | 0.5 | Idle polling interval, seconds |
| MONITOR_MAX_BATCH_LINES | 500 | Falco lines per iteration |
| MONITOR_DEDUP_WINDOW | 2000 | Recent raw-line hashes |
| MONITOR_REGISTRATION_GRACE_SECONDS | 15 | Gate registration race grace |
| MONITOR_REGISTRATION_RETRY_SECONDS | 5 | Registration retry spacing |
| MONITOR_UNAPPROVED_START_POLICY | alert | alert or ignore; does not prevent startup |
| MONITOR_RETRY_BASE_SECONDS / MONITOR_RETRY_MAX_SECONDS | 1 / 30 | Bounded retry delay |
| MONITOR_LOG_FORMAT | text | text or json |
| MONITOR_BASELINE_DIR | repo/behavioral-engine/baselines | Existing per-container JSON datasets |
| MONITOR_LEARNING_ENABLED | true | New-container learning |
| MONITOR_LEARNING_SECONDS | 900 | Minimum observed learning span |
| MONITOR_MIN_SAMPLES | 20 | Minimum valid windows, cannot be less than 20 |
| MONITOR_WINDOW_SECONDS | 60 | Fixed feature windows, matches baseline training |
| MONITOR_LATENESS_SECONDS | 10 | Extra time allowed for out-of-order arrivals |
| MONITOR_ANOMALY_THRESHOLD | 0.8 | Qualifying ML evidence, range 0.5–1 |
| MONITOR_CORRELATION_SECONDS | 60 | Same-container matching tolerance |
| MONITOR_ANOMALY_ALGORITHM | isolation_forest | Default forest or experimental one_class_svm; see anomaly_model_review.md |
| MONITOR_RETRAIN_POLICY | manual | Only supported retraining policy; use reset command |
| AUTO_CONFIRM_ENABLED / AUTO_CONFIRM_THRESHOLD | true / 90 | Option B; both layers must qualify |
| AUTO_ISOLATION_ENABLED / AUTO_ISOLATION_THRESHOLD | false / 90 | Independent, explicit response opt-in |
| MONITOR_PROTECTED_CONTAINERS | empty | Comma-separated exact names or full/12-character IDs |
| MONITOR_RESPONSE_MAX_AGE_SECONDS | 120 | No automatic response to old/replayed evidence |
| MONITOR_RULE_CANDIDATES_ENABLED | true | Auto-confirmed incident synthesis |
| MONITOR_BENIGN_LOG_PATH | unset | Independently validated benign Falco history; required for synthesis |
| GROQ_API_KEY / OPENAI_API_KEY | unset | Optional AI provider credential |
| AI_BASE_URL / AI_MODEL | Groq endpoint / openai/gpt-oss-20b | Existing summarizer, configurable provider |
| SELFSENTRY_STATE_DIR | repo/state | Existing isolation-record directory |

Option B auto-confirmation records selfsentry-auto, a confirmation timestamp in the existing
confirmed_incidents table, policy settings and evidence. A high score alone never qualifies.
Both layers must refer to the same ID and valid feature/correlation window, with ML used by a
ready model. Human-confirmed incidents retain their original confirmer. A dismissed monitor
incident remains ineligible for automation.

Risk calculation preserves the existing Falco priority scores, anomaly weight 40 and agreement
bonus 20 (cap 100). Existing confidence adjustment is high=0, medium=-10, low=-20. The monitor
only feeds qualifying anomalous evidence into agreement. Normal/missing ML does not get a
cross-layer bonus. Multiple alerts are grouped by fixed container/window key; the strongest
valid effective score is retained and all Falco alerts are recorded. Late alerts are separate
Falco-only evidence. Fixed windows deliberately do not merge adjacent-window incidents.

Isolation defaults to off. To enable it after controlled validation, set AUTO_ISOLATION_ENABLED
true and list your protected infrastructure. It resolves the incident ID through Docker to a
full ID, checks exclusions/status/age, records an attempt, disconnects networks and pauses.
Host/shared-network containers are refused. Network or pause failures are recorded as failures;
original attachments remain available for manual recovery. Automatic failed/ambiguous attempts
are never retried indefinitely; inspect them and use the existing Containers page to act.
Pausing plus disconnection is disruptive and does not constitute complete host compromise
remediation or kernel-level isolation. No container is stopped/removed by this response.

## Candidate rules and explanations

Set MONITOR_BENIGN_LOG_PATH to an offline Falco log that YOU have independently verified as
benign and representative. Do not point it at a mixed attack log or assume every learning event
is benign. With no corpus, incident/confirmation/response continue and candidate status is
unavailable. The existing extractor, literal Jinja2 template, backtester and rules API are used.
Process literals are bounded; quotes/control characters are refused. Empty or failed backtests
cannot enter the deployable review path; API rates above 5% are rejected. Source incident,
backtest result and candidate YAML remain recorded in monitor workflow.

Candidates stay pending_review. The monitor never calls approve or deploy. The existing review
page requires the operator token and reviewer identity; selfsentry-auto is not accepted as a
human reviewer. Approvals, rejections and deployment outcomes are audited. Native Falco
compilation/re-fire still needs validation on the test host; structural YAML checks and the
existing literal-condition backtester do not replace Falco's own semantic validation.

AI is advisory. One background provider request at a time avoids blocking core ingestion or
response. Provider absence or terminal failure records unavailable; the incident survives. HTTP 429 responses schedule up to three retries after the first request (four provider
attempts total per incident). The default cooldown is 120, 240 and 480 seconds; a longer
Retry-After is respected. One shared provider cooldown and attempt counts persist in SQLite.
The workflow exposes pending_retry with the scheduled retry time, ready, or unavailable.
No background sleep blocks ingestion; other provider errors are terminal. Old unavailable
incidents are not automatically requeued. Quota exhaustion can outlast the retry budget. Missing model data and actual response outcomes are included
in the prompt, and generated text is never interpreted as commands/rule approvals.

## Reliability and limits

SQLite inbox/outbox commits before the Falco checkpoint moves. Backend event_key is unique.
Window output and completion are transactional. Retries after lost responses resolve the same
incident. Baseline appends deduplicate window boundaries and replace JSON atomically. Models
are rebuilt from validated JSON on restart, never from downloaded pickle files.

Isolation intent/outcome are persistent locally. A restart between intent and outcome produces
unknown_after_restart and requires inspection instead of repeating a destructive action.
Backend outages retain pending incidents with capped exponential retry delays. Audit writes
are fsynced; a disk failure is surfaced and prevents silent processing acceptance. Check disk
space: local event/window/action history is retained and has no automated retention policy.

Remaining limits: replacement-style Falco rotation can lose unread lines in the old file;
container events that start and disappear during a monitor outage may escape startup discovery;
Docker event cursor is not persisted across process restarts. Fixed windows trade latency for
stable features and may split multi-window sequences. Docker socket access is root-equivalent.
Use a dedicated account, restrict log access, and bind the backend locally. No message broker,
Kubernetes support, cross-container profile reuse, production RBAC or automatic retraining is
introduced. There is no new systemd installer: use the foreground commands above or adapt your
service management with these same config/permissions. Monitoring does not prevent plain docker
run; a gate bypass produces an audit alert, with runtime response gated separately.

## Validation commands

```bash
cd ~/selfsentry
source .venv/bin/activate
python3 -m pytest tests/ -q
python3 -m flake8 monitor-service backend-api/main.py backend-api/routes/incidents.py \
  backend-api/routes/monitor.py backend-api/routes/rules.py backend-api/routes/deployments.py \
  behavioral-engine/baseline_builder.py response-engine/auto_isolate.py \
  rule-synthesis-engine/submit_candidate.py rule-synthesis-engine/confirmation_manager.py \
  rule-synthesis-engine/pattern_extractor.py rule-synthesis-engine/rule_template_generator.py \
  rule-synthesis-engine/rule_backtester.py ai-analysis/root_cause_summarizer.py \
  deployment-gate/deployment_gate.py evaluation --max-line-length=100
(cd frontend-dashboard && npm ci && npm run build)
```

Do not compare unit-test counts to attack detection percentages. See monitor_evaluation.md for
real controlled-trial collection and aggregation. Native VM acceptance and measured full-run/retrospective comparison are recorded in
monitor_final_review.md. Independent live variants and separate layer timings remain unmeasured.

## Current operating decisions and final verification

Normal demo operation keeps AUTO_ISOLATION_ENABLED=false explicitly in the monitor command.
Environment variables take precedence over .env. If you changed .env but a process uses an old
value, stop that process, unset the corresponding exported variable and restart it. Do not
paste tokens or database URLs into reports. A Vite dashboard can use localhost or 127.0.0.1
on port 5173; both origins are allowed by the backend. Alerts are available at / and /alerts.

The AI explanation state is shown alongside model assessment and response. Pending AI work
can keep the advisory outbox nonempty after the core incident has already been persisted.
Use its workflow and cooldown before diagnosing it as lost delivery. A fresh heartbeat is
not proof that the database/provider is healthy: inspect each component.

Keep the test baseline frozen when comparing trials. Stale historical lifecycle entries for
removed containers may remain in status; tracked containers and stored baselines are different
counts. Never delete the journal to make those counts match. Back up the journal/checkpoint and
baseline files while the monitor is stopped. Log rotation by replacement remains a documented
loss boundary; do not claim lossless unread-file rotation. No automated retention is provided.

Final checks after applying the polish patch:

```bash
python3 -m pytest tests/ -q
# Run the flake8 command above; include backend-api/database.py and the new retry tests.
(cd frontend-dashboard && npm run test -- --run --pool forks --poolOptions.forks.singleFork)
(cd frontend-dashboard && npm run build)
```

After restart, open the Alerts page and inspect incident 177 (ready AI) and a historical
unavailable incident. Retrying future incidents show pending_retry and its next time. Do not
intentionally flood the provider to force a 429. Native Falco rule 5 deployment/re-fire was
already verified; the final polish does not modify active Falco rule files.

Before committing, review git status and the staged diff. Added ignore rules do not untrack
previously committed baseline JSON. `git rm --cached --ignore-unmatch -- behavioral-engine/baselines/*.json`
removes them from the index while leaving the real files on disk. Do not commit .env, state,
raw benign/attack logs, baseline datasets or backup directories. Preserve measured evidence
separately; preserve the actual runtime source/versions for reproducibility. The existing
fingerprint covers configured baseline/rules and some settings, but does not hash runtime
source or fully capture exported AUTO_* overrides. A matching fingerprint alone is not proof
of identical runtime code or policy. See the reviewed source manifest and record the final commit.


## Monitoring continuity and parallel work

The production monitor multiplexes Falco events for all container IDs into per-container
fixed windows. Model fitting uses a bounded two-worker pool. Ingestion, feature extraction,
window correlation and SQLite journaling stay on their existing owner thread; a separate
control worker owns backend HTTP calls, registration lookups, Docker response, rule synthesis
and audit/deployment replay through its own SQLite connection. No database transaction is held
across network delivery. Low-risk incidents never unsubscribe a container. Isolating one
container never changes another container's event subscription, baseline or feature windows.

Backend outages retain incidents in pipeline.sqlite and audits in audit.sqlite. Legacy
JSONL audit spools remain replayable. Gate decisions are journaled in state/deployments.sqlite
and retried by the control worker; event keys in the existing audit table prevent duplicate
deployment records after lost responses. Disk/permissions failures are real degraded conditions;
no process can promise uninterrupted monitoring through host failure, disk exhaustion or a
stopped Falco service. Checkpoint advancement stops on durable ingest failure rather than
claiming events were safely processed.

“Monitoring Active” requires a fresh monitor heartbeat, usable Falco ingestion, container
tracking and recent container telemetry. It does not assert a trained model or an absence of
kernel event drops. An idle container without recent telemetry reports that it is waiting for
telemetry. Learning/unavailable model states are explicit. A paused container remains in live
Docker inventory and lifecycle audit, but produces no new process activity; it is never labeled
as actively producing monitored syscalls. After resume, existing per-ID tracking continues and
the next complete activity window is evaluated normally. Replacements do not inherit models.

## Response, explanations and adaptation

Both manual and automatic isolation check MONITOR_PROTECTED_CONTAINERS. Entries match exact
names (optional leading slash) or Docker IDs with at least 12 hexadecimal characters; glob
patterns are not used. Protection appears in inventory and monitor configuration. Isolation
and resume serialize per full container ID using an on-disk lock. Original network names, available network IDs and
aliases remain saved. Saved IDs prevent restoration to a different network reusing a name. Partial recovery is marked resume_failed and re-pauses the workload where
possible; it can be retried without discarding the original attachments. The dashboard only
claims “Paused + Network Disconnected” after checking live state. Host/shared network namespaces
are refused. Static IPs and every Docker endpoint option are not restored; current persistence
covers original network membership and aliases.

Resume requests, results and failures are audited. The dashboard requests a policy re-check;
API clients can opt in with `?recheck=true`. A policy re-check failure does not turn an already
completed resume into a false failure; its result is separately audited. Behavioral re-evaluation
uses the next complete normal window, not an invented immediate score or silent baseline reset.

Primary risk guidance is deterministic and present before any AI request, including Low risks.
AI failure/rate limits cannot remove or replace this guidance, alter severity, approve rules,
or isolate a container. Advisory retries remain bounded and run off the ingestion path.

AUTO_CONFIRM_ENABLED=true enables existing dual-layer confirmation. An additional proposal-only
path (AUTO_CONFIRM_ANOMALY_ENABLED=true, default threshold 0.95) accepts ready-model anomalous
windows with a same-container literal process/parent or file-write witness. This is policy
acceptance for candidate generation, not proof of malicious intent. Anomaly-only observations
never qualify for automatic isolation. To disable this new proposal path, set
AUTO_CONFIRM_ANOMALY_ENABLED=false. Existing .env values remain authoritative and are never
silently changed by startup; set the automation switches explicitly for your demo.

Rule submission and human approval both rerun the actual supported literal template against
MONITOR_BENIGN_LOG_PATH on the backend, recording the corpus SHA-256, usable events, FP and TN.
Missing/empty/unusable data, unsupported conditions and FP rates over 5% block progression.
`--allow-flagged` no longer bypasses a failed test. Unsupported or ambiguous observations are
audited/skipped; they do not require an administrator to invent a rule. TP is not measured on
benign-only data. Native re-fire evidence is recorded from later actual Falco alerts matching a
known deployed rule, linked to its triggering incident; it is not automatically counted as a
true positive. Historical rows without detailed evidence are labeled accordingly.

The only required human decision in the configured adaptation path is new-rule approval.
Optional deployment overrides, resume, benign disposition and maintenance remain admin actions.
Overrides use bin/selfsentry-run --override-reason with a nonempty justification, rerunning the
scan/policy gate and recording a new decision/audit. The dashboard shows that command; it does
not launch an old blocked container that the gate already removed.


## Dashboard inventory and audit history

The top bar reports **tracked containers**, the monitor watcher's inventory, including
containers that stopped but have not been removed. This is not the running-workload count.
Use Containers for current Docker running/paused/exited state. A stopped disposable test
container can therefore remain tracked without representing a running workload.

Audit cards show their database IDs. Audit ID lookup and event-type filtering query the
stored history on the backend, including entries outside the newest 200-record page.
Use Older records for cursor pagination and Latest records to return to the live head.
Clear the type filter when searching an ID of a different event type. The API supports
positive event_id and before_id parameters; no database schema change is required.
