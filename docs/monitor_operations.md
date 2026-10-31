# SelfSentry continuous monitor: setup and operation

For a fresh host, use [the verified Ubuntu setup procedure](fresh-ubuntu-install.md).
Current evidence and open boundaries are in the [acceptance review](repository-audit/acceptance-review-20261028.md).
Source-time unit-test descriptions below retain their original scope; later native
checks are credited only to the specific cases in the audit and clean-install record.

## Database timezone contract

The backend stores naive timestamps as UTC; the dashboard interprets them as UTC.
The application engine sets `timezone=UTC` in the psycopg2 startup options before
any transaction, including fresh pooled connections after a disconnect. This also
applies to tools and migrations using `create_database_engine`. Existing libpq
options are retained, with UTC taking precedence over an explicit timezone option.
External SQL clients must set their own session timezone when writing naive columns.
This is separate from Falco event-clock freshness and does not repair kernel timestamps.

This change affects future writes. Do not shift existing timestamps in bulk:
restored data may already be UTC. Correct only rows with independently established
provenance, retaining the original values and the reason for any correction.

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
.venv/bin/python -m pip install -r requirements.lock
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
pointing at FALCO_LOG_PATH. In the verified Falco package, config.d rules_files entries
append to the base list: place only additional repository paths in the override, not
another copy of the base default rule paths. Verify the actual loaded order with
`sudo falco --dry-run -o engine.kind=modern_ebpf`. rules_files must include the repo's baseline-capture-rules.yaml
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

All protected reads and writes to the backend app require a bearer token. Without a configured
SELFSENTRY_API_TOKEN, protected requests return 503; invalid/missing credentials return 401.
Only the fixed root service probe and CORS preflights are public. API docs are protected too.
Set the browser token under Monitor → Session credentials before reading live data. Bind the
backend to 127.0.0.1. This shared-token
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
closes are retained/audited; a late security alert that overlaps training (or whose training exposure cannot be checked)
revokes model readiness until operator review. Late post-training alerts retain their incident
and audit without disabling an unrelated baseline. See
[baseline_late_alert_recovery.md](baseline_late_alert_recovery.md) for evidence-checked recovery
of a previous late-alert hold.
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

Ctrl+C or SIGTERM requests shutdown of the foreground monitor. The control worker checks
for shutdown between tasks; it cannot interrupt a control Docker/backend operation already
running. The monitor cancels its Docker event stream and waits for the event/control threads
and running model/AI jobs before releasing its single-instance lock. Queued executor jobs are
cancelled. Status reports `shutdown=stopping` during cleanup and `stopped` only after completion.
There is no maximum shutdown time: unsupported stream cancellation (including SDK SSH transport)
or a stuck dependency can leave cleanup waiting with the lock held. `bin/selfsentry stop` still
reports failure after its 15-second wait and retains PID records if a process remains; it does
not force-kill it. Inspect the process and logs before retrying. Do not remove the lock file
to start another monitor alongside unfinished work. Docker/control queues are in memory
with 1,000-entry bounds each. Backpressure and a per-iteration drain limit prevent unbounded
entry growth and ingestion starvation, but do not guarantee replay after a process crash. Falco checkpoints and durable outboxes have separate
recovery paths. Forced process termination still needs separate crash-recovery validation.
To request shutdown by the PID from status.json after checking it:

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
# Uses the local .env token without printing it or putting it on a command line.
.venv/bin/python - <<'PYREAD'
import json
import sys
sys.path.insert(0, "monitor-service")
from backend_auth import backend_json
for path in ("/monitor/status", "/audit/?limit=20"):
    print(json.dumps(backend_json("http://127.0.0.1:8000", path), indent=2))
PYREAD
tail -n 50 state/monitor/monitor.log
sudo journalctl -u falco-modern-bpf -n 50 --no-pager
```

`--once` performs one diagnostic iteration; fixed windows may not have closed yet, so it is
not an end-to-end attack demo. `heartbeat_fresh` reports a timestamp under 30 seconds old
without future clock skew. Aggregate `healthy` additionally requires reported running state,
required component health and a successful API database read; inspect component details too.
A healthy snapshot is not an end-to-end attack or monitoring-continuity test.

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
| SELFSENTRY_API_TOKEN | unset | Required shared credential for backend reads and writes |
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

## Historical operating decisions and verification

Normal demo operation keeps AUTO_ISOLATION_ENABLED=false explicitly in the monitor command.
Environment variables take precedence over .env. If you changed .env but a process uses an old
value, stop that process, unset the corresponding exported variable and restart it. Do not
paste tokens or database URLs into reports. A Vite dashboard can use localhost or 127.0.0.1
on port 5173; both origins are allowed by the backend. The Overview is at / and /overview; incidents are at /alerts.

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
(cd frontend-dashboard && npm run test -- --run)
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

## Unavailable isolation recovery records

A missing record and a corrupt record are different conditions. Isolation/resume require a
record whose full Docker ID, lifecycle state and saved network structure validate. Invalid or
unreadable state blocks further response actions and stays untouched for operator inspection.
The inventory continues to load, but reports `containment_state=record_unavailable` and
`isolated=null`; this is unknown containment, not a claim that the workload is isolated or safe.
The dashboard disables both response buttons for that condition. API action failures remain
audited; the backend rechecks the file even if a dashboard snapshot is stale.

Do not delete a damaged record to bypass the check. Preserve a copy and compare it with a
known-good backup and the exact full Docker ID. Recovery needs verified original network
membership; do not guess it from an image/name or construct a replacement from the currently
disconnected container. If original attachments cannot be established, automated restoration
remains unavailable. No automatic repair, deletion or state migration is performed.

Record replacement uses a private temporary file, file fsync, atomic rename and containing-
directory fsync. A persistence failure is surfaced before further Docker work where the intent
write fails. This ordering is tested with fakes and controlled I/O errors; host power-loss,
filesystem-specific durability and real Docker recovery still require separate validation.

## Response, explanations and adaptation

Both manual and automatic isolation check MONITOR_PROTECTED_CONTAINERS. Entries match exact
names (optional leading slash) or Docker IDs with at least 12 hexadecimal characters; glob
patterns are not used. Protection appears in inventory and monitor configuration. Isolation
and resume serialize per full container ID using an on-disk lock. Original network names, available network IDs and
aliases remain saved. Saved IDs prevent restoration to a different network reusing a name.
Docker API errors and requests transport failures during disconnect do not skip the remaining
best-effort isolation steps: the engine still attempts pause and persists `isolation_failed`.
Partial recovery is marked `resume_failed` and re-pauses the workload where possible; it can be retried without discarding the original attachments. The dashboard only
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

## Audit follow-up: runtime settings and evaluation preconditions

After installing the audit patch, restart the monitor using the managed lifecycle command
and inspect `/monitor/status.configuration`. These settings now come from the running
monitor. The API's own environment is reported separately as `backend_configuration`.
An empty runtime configuration means unavailable, not isolation disabled. Evaluation
workload runners and the clock preflight refuse unknown or enabled isolation settings.
Keep the monitor unchanged throughout a controlled study; the preflight is not an atomic
lock against another operator restarting or reconfiguring services.

Docker event queues each hold at most 1,000 entries. A full queue applies backpressure;
Falco ingestion still gets a processing turn. Queue depth is visible on the Monitor page.
The queues remain memory-only. Monitor retained SQLite history, disk space and container/model
counts separately; no automatic retention deletion was introduced. Training allows two jobs
at a time, leaving other eligible baselines in `BASELINE_READY` until capacity is available.

The sensitive-syscall feature now includes `umount2`, matching the shipped capture rule.
Old baseline vectors are preserved. Recollect or explicitly review baseline compatibility
before comparing models trained before and after this change. Do not silently rewrite
historical evaluation results to reflect the new feature behavior.

## Schema migrations and adoption

Keep `DATABASE_URL` in the local environment or `.env`; do not put credentials in
`alembic.ini` or shell history. The backend's typed mappings preserve the existing SQL
schema. Startup remains compatible with legacy `create_all`; it is not a migration runner.

For a **new empty database**, from the repository root run:

```bash
.venv/bin/python -m alembic -c alembic.ini upgrade head
.venv/bin/python scripts/verify_schema.py
```

For an **existing installation**, first make and test a database backup using the
operator's PostgreSQL backup procedure. Run only `scripts/verify_schema.py` initially.
It returns 0 for a metadata match, 1 for differences, 2 for an unavailable check. It uses
read-only PostgreSQL transactions or SQLite query-only mode and performs no schema repair.
It checks tables, columns/types, nullability, keys and server defaults; it does not verify
row correctness, ownership/grants, triggers, extensions, backup quality or concurrency.

If differences exist, stop and review them against a disposable restored copy. Do not run
the historical `database/schema.sql`, delete conflicting data, or stamp merely to hide
differences. The initial revision refuses to run against existing tables. Alembic may create
its empty bookkeeping table before refusing; application data are not converted or erased.
Only after a matching comparison, backup validation and operator review, adopt the baseline:

```bash
.venv/bin/python -m alembic -c alembic.ini stamp head
.venv/bin/python -m alembic -c alembic.ini current
```

Stamping writes revision metadata; it does not change application tables or prove their
contents. Scoped native migration/adoption/restore acceptance is recorded in the audit;
fresh-database migration and schema comparison also passed on the independent Ubuntu host.
Neither result authorizes stamping or migrating a different existing database without review.
The current head includes a unique constraint on `rule_performance.rule_id`, matching
the previously documented Phase 6 database fix. Existing installations that already have
that constraint need no application-table change. Do not stamp only the initial revision
and then apply the same constraint again. The follow-up revision is for databases at the
initial revision without the constraint; it refuses duplicate non-null rule IDs without
deleting or merging records. Test adoption and upgrades on a restored copy first.
Future schema changes require a separate reviewed revision and disposable restore tests.
The baseline downgrade drops application tables and refuses execution without an explicit
`allow_destructive_downgrade=true` Alembic `-x` opt-in. Do not run it on retained data.
Use a tested backup/restoration plan for production recovery; no automatic destructive
downgrade or data retention policy is introduced by this audit.

Release checks now include `scripts/verify_types.py`. It checks annotated code,
top-level statements and untyped function bodies, with missing dependency stubs tolerated.
Dynamic values and external libraries still limit its coverage.

## Falco checkpoint integrity and repair

The monitor validates checkpoint shape, nonnegative inode/offset, hash keys and the
oversized-record discard flag before ingestion. A corrupt/unreadable checkpoint is
retained and reports `falco_ingest=unavailable`; it is never treated as a first start at
end-of-file. Other monitor work can continue. Do not delete state to make health green.
Preserve the checkpoint and retained Falco log, stop the monitor for a consistent backup,
then restore a known valid position or review a deliberate replay/reset plan. Once a valid
checkpoint is restored, the running tailer retries and can recover. Removing the bad file
alone does not silently reset an already-running reader. No repair was done on the user's VM.

Checkpoint replacement uses a private temporary file, file sync, atomic replacement and
parent-directory sync. A write/sync failure marks ingestion unavailable, retains the current
batch for replay and does not publish a new in-memory offset/dedup acknowledgement. If the
replacement succeeded but directory sync failed, a restart may observe the new checkpoint:
it covers only already-handled input. Sink/journal idempotency remains required; these are
at-least-once semantics, not exactly-once delivery. Fault-injected tests are not power-loss
or filesystem durability guarantees.

The reader now gets inode/size from the opened descriptor, avoiding a pathname stat/open
rotation race. Unread bytes left in an old rotated file remain a loss boundary. A log record
with no newline across the 4 MiB read limit is discarded through its terminating newline,
even across restarts, rather than interpreting its remainder as a separate event. This state
is the optional checkpoint field `discarding_line`; existing checkpoints default to false.
Avoid rolling back to an older reader in the middle of such a discard. Oversized discarded
input is logged and cannot be recovered from the checkpoint; retain the source log for review.

## Backend workflow write integrity

Use nonempty event keys (or null), explicit confirmation actors, and complete scan counts.
The production gate emits all five count fields. Older manual clients sending partial
nonempty summaries now receive 422; correct their evidence instead of filling unknown
counts with zeros. Retained historical database rows are not rewritten. Permanently rejected
gate records are now retained separately for review and bypassed during subsequent delivery;
transient failures preserve active FIFO order. Do not discard audit evidence to make the queue
appear healthy.

Concurrent workflow patches, confirmation and dismissal use one PostgreSQL parent-row
lock and refresh metadata before a merge. Native PostgreSQL contention/deadlock/failure
acceptance is still required; no lock-wait latency guarantee is made. A benign dismissal
is timestamped and audited once, with individual actor left unknown. Shared-token labels
do not provide per-person authorization. Operator dismissal is not synchronous cancellation
of an in-flight Docker action and does not resume an isolated container.

## Deployment journal replay and rejection review

`SELFSENTRY_STATE_DIR` (default repository `state`) contains `deployments.sqlite`.
`decisions` retains queued request JSON. Identical enqueues with a stable key are idempotent;
a changed payload with the same key is refused without replacing evidence. New keys are
generated only when missing/null. Invalid or non-finite JSON cannot be newly enqueued.

Both direct gate delivery and monitor replay require HTTP 201 with a positive integer
deployment ID and a matching decision before acknowledging the journal. Invalid/missing
JSON, wrong decisions, timeouts, authentication/permission errors, unknown routes, rate
limits and server errors keep records replayable; transient failures stop that active pass.

Malformed local JSON/key mismatches and backend 400/409/422 are retained for operator
review in `decision_rejections`, with the original `decisions` row unchanged. A raw copy,
observed timestamp, status (null for local corruption) and a bounded reason are retained.
Subsequent flushes skip those keys so later valid records progress. No rejection is silently
converted into success, dropped or repaired. The monitor publishes actual pending/rejected
counts under `deployment_outbox` and reports `deployment_backend=degraded` while either
count is nonzero; the Connections table displays this component. Counts are a last successful
local snapshot, so also inspect control health when journal access fails.

For review, stop the control worker/gate writers and make a consistent backup of this SQLite
journal before any edits. Inspect `key,status,reason,observed_at` from `decision_rejections`,
and compare retained bodies with authoritative backend deployment/audit records. No automatic
release/requeue/delete command or dashboard review workflow is introduced. After authoritative
reconciliation, an operator can explicitly retry the identical retained body via the existing
`deployment_gate.record_decision` function: it performs no Docker action, and only a validated
backend acknowledgement clears the pending row; the rejection copy remains. This recovery
composition is unit-tested with simulated HTTP acceptance, not a repaired live backend.
Any marker removal
or payload reconciliation requires an explicit operator decision and preservation of the
original error evidence. Never invent missing scan counts or change a key to disguise a retry
conflict. A corrected new operation needs its own key and a documented relation to the old one.

Updated backend workers bind event keys to request fingerprints and actual stored deployments.
Update all backend workers and gate/monitor readers together. Legacy events without fingerprints
are compared against persisted core fields, policy, counts and findings; old extra fields that
were never stored cannot be independently reconstructed. Fingerprints are request comparisons,
not signatures, verified identity or scan attestation.

## Deployment action intent and recovery

Before gate-controlled start/removal (including cleanup), `deployment_actions` in the same
SQLite journal records the full returned container ID, action, timestamp and, where available,
the policy/scan/override body. Intent must commit before Docker runs. Journal failure leaves
an existing created container unstarted rather than proceeding without evidence.
`command_succeeded` means the Docker CLI returned zero; it does not prove lasting runtime health.
`command_failed` records a nonzero CLI result, not an authoritative final host state. Unexpected
process errors, interruption or outcome-write failure leave `outcome_not_recorded`.

Successful outcome and delivery enqueue commit together. Failed/unfinished actions do not enter
the deployment delivery queue and cannot register a container through that decision. The monitor
reports actual unfinished/failed counts as `deployment_actions=degraded`; historical failures
remain visible. Unfinished may also mean a command is currently running. These counts are not
proof that a process crashed, and no failure is automatically cleared or retried.

For operator recovery, preserve a consistent backup of the SQLite file and WAL, stop relevant
writers, inspect `deployment_actions` and reconcile the full ID against Docker inspection/events
and backend audit evidence. Never invoke `finish_action` merely to silence health warnings:
it can enqueue a deployment. No automatic action executor, mutation/recovery UI or automatic
Docker replay exists. Explicit reviewed current-state reconciliation is implemented; see
[tracked follow-up tools](#tracked-follow-up-tools). It preserves the original uncertain
outcome and does not silently retry Docker commands. Retention policy remains open.

Creation now has its own `creation_attempts` intent before Docker runs. An unfinished create
retains a null container ID because no trustworthy result was durably recorded. A successful
create persists its full returned ID before inspection/scanning. A crash during later inspection
or scanning can still leave an unstarted orphan; its successful creation record is not proof of
gate completion. Docker and SQLite are not atomic. Controlled start/create/remove
interruption and explicit current-state reconciliation passed in the recorded private tests.
That does not establish arbitrary daemon/host crashes or filesystem durability.


### Gate Docker timeout recovery

The gate sets per-command CLI deadlines: create 300 s, inspect 30 s, start/remove 60 s.
The subprocess timeout kills/waits for the CLI; it cannot determine whether the daemon applied
an operation. A timed-out start/removal retains unknown intent, without automatic cleanup/retry
or a completed deployment delivery. Inspect timeout can attempt a separately journaled removal
of the known, unstarted created container. Create timeout has no authoritative returned ID;
no guessed container is removed. Use authoritative Docker/event evidence and preserve history
before retrying. A timeout exits the CLI with code 2. Real daemon/helper-process cancellation
remain unverified. Independent fresh-host setup passed separately; it does not
verify daemon cancellation or all timeout outcomes.


### Response transport failures and uncertain daemon state

The Docker SDK may raise requests timeouts/connection errors independently of its API errors.
During isolation, disconnect failures are retained per network while remaining disconnects and
pause are attempted. A pause or verification failure records incomplete isolation. Success is
never inferred from a lost response.

During operator recovery, unpause, reconnect and inspection failures enter the same failed
recovery path. The engine reloads state before re-pausing. If inspection fails, it still attempts
pause because the unpause request may have reached the daemon despite its lost response.
It then inspects again; failed pause/inspection is recorded explicitly in `resume_failed`.
Original network identities and aliases remain available for operator review and explicit retry.
No automatic recovery retry or safety-gate bypass is introduced. Pre-action Docker transport
failures return API 503 with a failure audit; action failures surfaced by the engine return 409
with a failure audit. Container listing transport failure returns 503 and closes its client.

Best-effort pause is not proof of containment when the daemon is unreachable. A process crash
or forced kill after unpause can still leave a running workload; Docker operations and local
records cannot be atomic. Recovery currently unpauses before reconnecting saved networks.
Recorded native checks cover direct isolation/resume and explicit retry after SIGKILL
between acknowledged unpause and network restoration. That interval left the disposable
workload running and disconnected; continuous containment is not claimed. Broader daemon
outage/restart and multi-process cases remain open. The original unit tests use fake Docker
with real temporary recovery files and local flock contention between two threads.


### Creation intent and unknown identity

`creation_attempts` stores `key,container_id,outcome,created_at,completed_at` in the same
SQLite journal. Intent must commit before even `docker create`. Docker arguments are not stored:
they may contain credentials. A zero CLI exit must return one full 64-character lowercase
hexadecimal ID; empty/malformed/multiple results remain unknown and exit 2. A nonzero exit has
`command_failed`; this describes the CLI result and does not establish host absence. Timeout,
interruption or outcome-write failure leaves `outcome_not_recorded`. Creation success cannot
queue a deployment decision or register a container. Prior delivery/action rows remain intact.

Actual failed/unfinished creation counts are included in `deployment_actions` health, with the
same caveat that unfinished may be currently running. Historical failures are retained; no
automatic clearing or action replay exists. If saving a known ID fails after creation, the gate
prints that full ID for operator inspection and performs no inspection/start/removal afterward.

For unknown identity, preserve the journal and correlate timestamps and authoritative Docker
creation/events evidence. No Docker label, guessed name, short-ID match or argument-derived
identity is used to select a cleanup target. This journal records an attempt; it cannot prove
which container an interrupted daemon created or that none exists. A completed creation record
can precede an interrupted scan/policy run and does not establish a final deployment outcome.
Never blindly repeat creation or delete containers to silence health warnings. Operator
reconciliation, retention and native crash/recovery acceptance remain open.


### Snapshot freshness and component health

The API now distinguishes `heartbeat_fresh` from `healthy`. The latter requires all four core
reports (`docker`, `falco_ingest`, `control`, `backend`) in `ok`/`connected`, a fresh timestamp,
a reported running process, a control cycle completed less than 30 seconds ago, and a successful
backend database count. Any reported component
outside `ok`/`connected`/optional `disabled` makes it false; disabled core services also make it
false. Missing core names appear in `degraded_components` without fabricated component rows.
`health_reason` explains the aggregate result and appears on the monitor page/global warning.

Missing/malformed status sets `status_available=false`, `running=null`, `healthy=false` and
`heartbeat_fresh=false`. The UI reports Unavailable, not Stopped. A corrupt individual component
is explicitly unknown while other valid recorded data remains available. Raw status readers
reject non-object JSON. No repair or replacement of the persisted diagnostic file occurs.

This tightens the former heartbeat-only meaning of `healthy`. API consumers wanting only
freshness should use `heartbeat_fresh` and `status_age_seconds`. Update backend and frontend
together; legacy clients interpreting `running=null` as false may incorrectly say Stopped.
Optional model learning/disabled features do not prove failure of core Falco monitoring.
Conversely, fresh healthy reports do not independently prove thread progress, fresh per-service
probes, reliable daemon state, full event delivery or native end-to-end detection. Component
states can remain old even while the enclosing heartbeat is refreshed. Native outage/browser
and monitoring-continuity acceptance remain NOT VERIFIED.


### Control progress and shared CLI/API status

`control_updated_at` is now a Unix timestamp saved only after a complete control iteration:
Docker event/reconciliation work, watcher tick, incident work, audit spool delivery, deployment
delivery and action-health reads must return before the marker and `control=ok` are published.
Failed/interrupted cycles do not refresh successful progress. Individual retained failures still
appear in their own component states; completing a cycle does not imply every action succeeded.

The shared `monitor_status.describe_status` computes API and CLI snapshot health. Both require
a recent completed control cycle as well as a recent main heartbeat. `control_progress_fresh`
and `control_status_age_seconds` expose that distinction; missing, stale, invalid or future
progress degrades control. Monitor displays cycle age. `--status` exits 1 for degraded/unavailable
snapshots or future timestamps; it cannot independently probe the API database. The API adds its
own database count result before invoking the same snapshot evaluator.

The 30-second observation horizon reuses the heartbeat freshness limit. Legitimately busy cycles
can exceed it and report degraded; it is not a tested latency SLA or proof of a dead worker.
There is no automatic restart, kill, replay or isolation action based on these fields. Restart
the updated monitor when integrating: older versions publish this timestamp before the slow
work finishes. A blocked-thread regression uses real local threading/status JSON with fake
pipeline/remote collaborators. Native long-cycle/outage/forced-termination acceptance remains
NOT VERIFIED. Per-component freshness other than completed control progress is not established.

The status reader rejects non-object/malformed snapshots and nonfinite JSON telemetry rather
than forwarding NaN/Infinity into a strict HTTP JSON response. It retains the original file.


### PostgreSQL connection and pool behavior

The backend's `create_database_engine` converts unqualified `postgresql://` URLs to
`postgresql+psycopg2://` internally. The locked SQLAlchemy 2.1 default would otherwise select
psycopg 3, which is not declared/installed by this project. The environment URL remains unchanged
for other consumers. Explicit drivers are respected; only the project's psycopg2 branch gets
these new connection/pool defaults. SQLite disposable development/test behavior is retained.

PostgreSQL/psycopg2 connection establishment defaults to `connect_timeout=5`. A single positive
whole-number URL query value overrides it, for example `?connect_timeout=10`. Zero/negative,
noninteger or duplicate timeout values fail configuration before engine construction; raw
values/credentials are not echoed by that validation. SSL, application-name and other URL
parameters are preserved. Connection-pool checkout waits up to five seconds. `pool_pre_ping`
checks stale pooled handles before transactional application work and can reconnect them; it
does not replay application queries, commits or Docker actions.

These are phase-specific limits, not end-to-end request deadlines. SQL execution, row/DDL locks,
network loss on established sockets, DNS and multi-host behavior, transaction outcomes and
native pool contention are not fully bounded or verified here. Server statement/lock timeouts
and keepalive policy need separate operational review. Do not automatically retry a mutation
whose commit/result is unknown. Existing API error handling is retained; not every DB failure
maps to HTTP 503. Engine use is shared by startup, Alembic and schema verification, so these
connection defaults apply there too; they do not authorize a migration or schema change.

Local checks construct real engines with the declared driver, preserve URL options, and run
real psycopg2/libpq against an owned silent loopback TCP listener: default five seconds and a
two-second URL override both timed out as expected. This is a connection-handshake failure
experiment, not a PostgreSQL server, authentication/SQL integration, restart/restore test or
performance benchmark. Real PostgreSQL migration/concurrency/backup/recovery acceptance
remains NOT VERIFIED.


### Database HTTP errors and uncertain mutations

The actual backend app returns sanitized 503 JSON for request-time SQLAlchemy OperationalError
and pool checkout TimeoutError. The handler logs only exception type/request method; it does
not echo driver messages, SQL parameters, headers or credentials. Allowed-origin CORS headers
remain available, so the dashboard can read the failure. Reads get an unavailable-operation
message. Writes are explicitly uncertain: a commit or external response action may already
have completed. The response supplies no Retry-After, and the backend does not replay SQL or
Docker actions. Do not infer that a 503 means no state changed.

After a mutation failure, inspect authoritative database/audit/local response state before
retrying. Reusing the identical audit event key is tested to deduplicate a retained write after
an injected lost commit acknowledgement; this is not blanket idempotency for every endpoint.
Current durable monitor delivery backoff/key behavior is preserved. Browser `apiFetch` performs
a single fetch and can display the sanitized detail; no automatic mutation retry is added.

The API session dependency closes the session on failure. Tests verify pooled connections
return and a request succeeds after releasing a real exhausted disposable SQLite QueuePool.
They also distinguish a pre-insert failure (no row) from an explicit commit-then-error injection
(one committed row), without claiming native PostgreSQL ambiguous-commit recovery. An initial
commit-event probe unexpectedly left a row visible on the reused SQLite connection; that did
not establish commit or rollback state. The final tests inject the two phases explicitly rather
than assuming a server outcome. A driver trace confirms a real SQLite COMMIT precedes the
injected error in the commit-then-error experiment; disk durability is not tested.

This handler does not catch every SQLAlchemy exception or change existing validation/route HTTP
errors. ProgrammingError/IntegrityError retain existing handling. Some dialects classify query
or configuration problems as OperationalError, so 503 is not a diagnosis of the underlying
cause. Startup/create_all failures remain fail-fast outside request handling. Scoped native PostgreSQL outage, connection and recovery checks are recorded separately.
The keyed audit endpoint also passed real wire-level COMMIT reply loss: PostgreSQL's actual
COMMIT reply was withheld, a committed row was independently observed, 503 reported write
uncertainty, and identical retry preserved one original row while changed replay returned 409.
This is not blanket endpoint idempotency, power-loss recovery or every cancellation scenario.
Full-request/SQL deadlines remain unresolved.

### Audit delivery failures

Audit HTTP 200/201 responses must contain the positive row ID and a boolean duplicate flag
matching the insert/replay status before a queued record is removed. A success status with
invalid JSON or missing fields now remains queued. If audit backlog grows, check backend
availability, the endpoint/response contract and the configured shared token. HTTP 401/403
and 429 are retryable rather than dead letters; 400/422 retain rejected payloads for review.
Transport error logs omit raw exception messages that may include connection details.

The durable client explicitly closes its short-lived SQLite connections after commit/rollback,
including initialization, enqueue, count, batch selection and acknowledgement deletion failures.
It holds no database connection across HTTP delivery. A controlled lost-response test commits
through the real audit route on disposable SQLite, retains the pending key, then accepts the
route's duplicate reply with only one backend row. This is an in-process route/client test,
not native PostgreSQL, a real network outage or power-loss acceptance. The five-second HTTP
transport setting and existing periodic flush behavior remain; total-request deadlines and
retention/backlog growth are still unresolved. Do not delete the journal to clear an outage.

Acknowledgements do not include the event key. Backend checks now compare keyed event content
as described below, with timestamps retained as first-write metadata. Never reuse one key for
distinct events. Legacy keyless events
cannot guarantee deduplication after an uncertain response. Malformed legacy spool recovery,
full journal-corruption recovery and cross-process delivery behavior remain separate concerns.

### Corrupt audit records

Spool size reads no longer append malformed legacy lines to dead letters. Invalid text,
non-object JSON and nonfinite numeric values raise a sanitized `AuditJournalError`, identifying
the legacy line when available. The spool and existing dead letters remain untouched. This
avoids repeated status polling generating duplicate rejection evidence or reporting zero for
an unreadable legacy backlog. Empty lines are ignored; this is structural validation, not the
backend's complete request schema validation.

The monitor records `audit_spool_size: null` and component `audit_spool: degraded` when the
legacy spool cannot be decoded. It continues ingestion and status persistence. A readable
size is reported as a number, with the component detail explaining that payload validation
occurs during delivery. Counting SQLite rows alone does not validate their content.

Durable delivery validates its selected batch of up to 50 SQLite entries before HTTP: each
payload must be a finite JSON object whose event key matches its nonempty journal key. An
invalid entry leaves the batch untouched and raises a sanitized error. The control worker
reports its existing workflow failure and retries later; delivery stages after audit flushing
can be delayed until repair. This is deliberate retention, not automatic quarantine or recovery.
It does not stop the independent ingestion loop. New events can still enqueue to SQLite if
that database remains writable. Full database corruption or I/O errors have separate behavior.

Investigate in a maintenance window with the relevant writer stopped and preserve the original
files plus associated SQLite WAL state using a consistent backup. Do not delete or rewrite
records based on their names, infer missing event keys or replay altered security events without
review. Resolve records from authoritative evidence and validate the repaired copy before
resuming delivery. Tests simulate an explicit operator repair on disposable files, preserving a
backup and checking legacy-before-SQLite ordering. No operator repair tool, production migration,
cross-process repair protocol, disk-failure recovery or native crash acceptance is provided.
The legacy reader still loads its whole file, and journal retention/memory limits remain open.

### Keys for new audit events

Both monitor audit clients now generate an event key when a new `emit` call omits it. The legacy
client generates before HTTP and retains that same key if delivery must be spooled; the durable
client retains its generated key in SQLite. Replaying the queued payload after a lost response
or client restart therefore reuses its identity. Explicit caller keys are preserved unchanged;
invalid supplied keys (non-string, empty or over 128 characters) raise ValueError before HTTP
or new journal insertion rather than silently generating a replacement identity.

One new `emit` call generates one identity. A second keyless call is a distinct event, even with
identical content; callers retrying the same logical operation across calls must supply a stable
key. Historical keyless spool data is not assigned guessed keys, and the direct audit API still
accepts keyless requests. Those old/direct events do not gain replay deduplication from this
change. This also does not close the legacy crash gap between remote commit and saving a failed
reply, uncertain local commits, reused-key/content conflicts or native power-loss recovery.
Tests use the real route on disposable SQLite with a controlled lost response and a newly
constructed client: one generated key is replayed, one backend row remains. No native network
or PostgreSQL failure was induced.

### Conflicting pending audit events

The durable client now refuses changed data under a pending event key with `AuditEventConflict`.
Inspect the caller/workflow producing the collision; the original queued record remains intact.
The exception omits keys and payload values, and no conflicting body is automatically written
to dead letters or substituted into the original. Do not work around a collision by assigning
a fresh key unless evidence establishes that this is a separate event.

Identical retries without an explicit event time retain the first pending timestamp, so a
later wall clock alone does not create a conflict. Explicitly changed timestamps or other
fields conflict. Corrupt original data instead raises `AuditJournalError`; it is not repaired.
The check is atomic with enqueue under the existing SQLite transaction and one-second lock
wait. Two real threads against disposable SQLite demonstrate one winner and one explicit
conflict. This is not native PostgreSQL or an independent multi-process/crash verification.

Once a local record has been delivered and deleted, it is no longer available for comparison.
Backend content validation below now covers keyed delivery after local deletion; legacy JSONL
replay still lacks local comparison. Keep stable keys unique to one logical event. The local
check does not provide a permanent local identity ledger or
change the previously documented uncertain-commit/power-loss limits.

### Backend audit conflicts after local delivery

The backend now refuses a repeated key with changed event fields/detail using HTTP 409 rather
than acknowledging the old row as delivery of new data. This also applies after a local outbox
entry has been delivered and deleted. Both clients retain the conflicting request for review;
no new automatic retry loop, dead-letter removal or replacement of the original is introduced.
Check the producer's key selection and preserved workflow evidence. Do not delete backlog or
assign replacement keys simply to bypass a conflict. Ordered audit delivery can remain blocked.

The first occurred_at/created_at values stay unchanged. Timestamps are not identity fields at
the API, so a duplicate with a regenerated time still succeeds if all compared content matches.
For distinct occurrences, assign distinct event keys. The local pending durable check remains
stricter when a caller explicitly changes its timestamp. Keyless direct/historical deliveries
still lack replay deduplication. Backend detail validation now rejects nonfinite JSON with a
sanitized 422; malformed historical rows are not repaired or silently acknowledged.

Tests use actual route/ORM/disposable SQLite for direct and controlled competing inserts, and
both real client implementations routed through TestClient after local delivery. This proves
retention and unchanged stored content under those conditions, not native PostgreSQL concurrent
transactions, production network authenticity, storage durability or complete incident recovery.

## Start observations across monitor restarts

A Docker start event and startup reconciliation can observe the same container start.
Their `detection_method` values differ, so they must not share an audit key: the backend
checks key/content consistency and correctly returns 409 for changed evidence.

Live Docker events retain their existing keys. Startup reconciliation uses a separate,
stable key scoped to its detection method for `CONTAINER_STARTED`,
`UNAPPROVED_CONTAINER_START` and `REGISTRATION_UNKNOWN`. Repeated reconciliation across
restarts deduplicates that observation. Two methods can therefore produce two audit rows
for one physical start; audit row count is not a count of distinct container starts.
Other payload conflicts still require review. Content binding and FIFO replay remain enabled.

An old queued reconciliation record may still use the Docker-event key. Source changes
alone cannot replay that record. Stop the app, back up the SQLite audit journal and verify
that the backend and queued record differ only in `detail.detection_method` before changing
its key to the corrected reconciliation identity. Preserve the original payload/key mapping
in a local repair report; do not delete the queued event or modify the stored backend row.
Different conflicts, missing identity evidence or an occupied replacement key require review.
Once repaired, restart the app and verify the queue drains and health recovers.

## Tracked follow-up tools

The 23 October follow-up integrates recovered acceptance/export tools and adds operator
observations and holdout accounting. See the [tool/precondition table](repository-audit/developer-guide.md#tracked-follow-up-tools--23-october-2026)
and [manual journal policy](journal_retention.md). Do not run every tool as a blanket
acceptance or automatically repeat historical VM tests.

The current export command is `.venv/bin/python scripts/export_monitor_journal.py --repo "$PWD"`.
It includes referenced archive files. After archival, a copy of `pipeline.sqlite` alone is
incomplete. Retain manifests/checksums and verify readback privately. No live pruning,
archive relocation or restoration has been performed by the source update.

Archival is disabled unless the operator explicitly applies a reviewed plan. The prompt
requires approval before runtime deletion/relocation; this source delivery supplies no
cutoff and does not grant it. Do not remove unreferenced partial archives automatically:
a publication/commit failure can leave recoverable evidence for inspection. This mechanism
reduces live payload rows only; SQLite file size, retained identities, archives, model count
and total disk still lack a retention bound.

Keep the backend bound to loopback. Use a dedicated PostgreSQL application role with only
necessary schema/table/sequence privileges; evaluate migrations separately from normal
runtime grants. Docker socket access is root-equivalent. Scope native reload privileges to
the actual configured Falco service rather than granting unrestricted sudo. Protect `.env`,
private logs, SQLite/archives, checkpoints, baselines and recovery records. The current shared
shared token authenticates possession, while reviewer names remain supplied labels. Local
files/ledgers are not tamper-proof against their owner. Multi-user identity/RBAC, public gateway
and TLS are outside the requested host-local deployment boundary.

A consistent whole-application recovery must coordinate PostgreSQL, every SQLite journal and
its archives, Falco offsets/log identity, baselines, rule files/registry, response records and
source/configuration. Restore only to disposable isolated services, with response automation
off and actions fenced, before claiming cross-store acceptance. No supplied runner restores
an active full application, recreates grants or accepts sequence correctness. Connection/pool
budgets still do not bound every established query, lock wait, blocked worker or shutdown.
