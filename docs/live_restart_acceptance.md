# Live pending-incident restart acceptance

Prepared against source `f134fdc5ed185124a9cf5ab1cb4c0164b326a77d`.
This is a controlled VM helper. One executed case has now been reviewed from the
operator-supplied evidence: incident 208. See the [reviewed result](live_restart_results_20261021.md)
for identifiers, artifact hash, checks and limits. Other fault cases remain unperformed.

## What is exercised

`evaluation/verify_postgres_recovery.py --restart-stack` extends the existing
database-outage check. It uses a real disposable Docker shell trigger, waits for
a failed-delivery incident in the monitor's existing SQLite outbox, gracefully
stops the managed backend/monitor/frontend, verifies that exact pending payload
remains, restores PostgreSQL, and starts the managed applications to replay it.

The case tests a graceful application restart with pending work combined with a
PostgreSQL outage. It is not a SIGKILL, power-loss, Falco restart, VM resume,
rotation, disk-full or arbitrary fault-extension test. Other matrix rows remain
unperformed unless separately evidenced. It creates a controlled shell incident;
the payload is not evidence of a genuine compromise or novel attack coverage.

## Preconditions and effects

- Run from the repo with its `.venv`. All three applications must already be
  lifecycle-managed; the API and recorded monitor PID must agree. The incident
  outbox must initially be empty, and PostgreSQL must be healthy.
- The running monitor must explicitly use `isolation_forest` and false values
  for isolation, confirmation and rule-candidate automation. The restart inherits
  that environment, including configured state paths; secrets are not printed.
- The local `nginx:1.25` image must exist. No image is pulled. The disposable
  fixture runs non-root, read-only, without capabilities or a network attachment.
- A failed fixture clock preflight aborts before the database fault. The check
  may still create/remove its own disposable fixture and record real baseline
  telemetry. Keep every resulting audit, incident and invalid report.
- PostgreSQL `postgresql@16-main` and all managed applications are temporarily
  unavailable during the test. Docker, Falco and existing workload containers
  are not stopped. Keep unrelated application work paused for this bounded test.
- Cleanup attempts to restore PostgreSQL and stopped applications on failures,
  Ctrl+C or SIGTERM, and removes only the generated fixture. SIGKILL/host failure
  cannot run cleanup. This helper does not reset existing baselines or clear queues.

## Run

First run the targeted offline regression checks:

```bash
cd ~/selfsentry
.venv/bin/python -m pytest tests/test_live_restart_acceptance.py -q
.venv/bin/python -m flake8 evaluation/verify_postgres_recovery.py \
  tests/test_live_restart_acceptance.py --max-line-length=100
```

Then perform the live case (typically a few minutes):

```bash
sudo -v
.venv/bin/python evaluation/verify_postgres_recovery.py --restart-stack
```

The existing command without `--restart-stack` retains its original
database-outage scope. No changes to runtime defaults or `.env` are required.

## Evidence and acceptance

A new UUID-named directory under `state/evaluation/acceptance/` retains the report,
before/after fixture clock checks and unique lifecycle logs. It records the pending
event key and full payload before/after stopping, source status, old/new monitor
PIDs, Falco PID, recovered incident ID, exact observed timeline, generated-rule
hashes and service/fixture cleanup results. Preserve failure reports as well.

Require all final checks true: database and application recovery; a changed,
healthy monitor PID; one recovered row for the original event key; no pending
target delivery; unchanged nonempty observed timeline and generated-rule hash;
unchanged Falco PID; valid post-recovery probe; no large clock discontinuity;
and no automatic response attempt. Duplicate observation is bounded (a second
query after five seconds), not an indefinite exactly-once guarantee. The helper
does not manufacture an ambiguous lost-HTTP-response case.

If it fails, share its output and report path before retrying. The final report
records cleanup success separately from functional success. For manual recovery,
restore `postgresql@16-main` first, then use `./bin/selfsentry restart`. Follow any
specific fixture-removal message. Never delete the SQLite journal to obtain a pass.
