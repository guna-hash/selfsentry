# Continuous monitor service (milestone M1)

## What it does (M1)
- Tails Falco's alert log continuously, with a checkpoint so a restart neither loses nor
  repeats events (at-least-once with replay protection).
- Separates security alerts from baseline-capture events; malformed lines are logged and
  counted, never fatal.
- Follows Docker's container events and, at startup, registers already-running containers.
- Detects containers started outside the Deployment Gate and records
  `UNAPPROVED_CONTAINER_START` in the audit log (dashboard: Audit log page).
- Reports its own health in `state/monitor/status.json`.

Not in M1: incident creation, baselines and learning mode, auto-confirmation, auto-isolation,
candidate-rule generation (milestones M2-M4). M1 only counts and logs security alerts.

## Run, stop, inspect
```bash
cd ~/selfsentry && source .venv/bin/activate
sudo chmod 644 /var/log/falco/alerts.json        # permissions reset whenever Falco restarts
python3 monitor-service/monitor_service.py       # foreground; Ctrl+C stops it gracefully
python3 monitor-service/monitor_service.py --status
python3 monitor-service/monitor_service.py --once   # one iteration, for diagnostics
```
Only one monitor can run at a time (a lock in the state directory prevents duplicates).
Logs go to stderr (`MONITOR_LOG_FORMAT=json` for structured JSON).

## Configuration (environment variables, validated at startup)
| Variable | Default | Meaning |
|---|---|---|
| SELFSENTRY_BACKEND_URL | http://localhost:8000 | Backend API |
| FALCO_LOG_PATH | /var/log/falco/alerts.json | Falco JSON output |
| MONITOR_STATE_DIR | state/monitor | Checkpoint, status, audit spool, lock |
| MONITOR_START_FROM | end | With no checkpoint: `end` (skip history) or `beginning` |
| MONITOR_POLL_INTERVAL | 0.5 | Seconds between polls when idle |
| MONITOR_MAX_BATCH_LINES | 500 | Lines handled per iteration |
| MONITOR_DEDUP_WINDOW | 2000 | Recent line hashes kept for replay protection |
| MONITOR_REGISTRATION_GRACE_SECONDS | 15 | Wait for the gate's record before calling a start unapproved |
| MONITOR_REGISTRATION_RETRY_SECONDS | 5 | Re-check interval during the grace period |
| MONITOR_UNAPPROVED_START_POLICY | alert | `alert` records UNAPPROVED_CONTAINER_START; `ignore` records a normal start |
| MONITOR_RETRY_BASE_SECONDS / MONITOR_RETRY_MAX_SECONDS | 1 / 30 | Bounded exponential backoff |
| MONITOR_LOG_FORMAT | text | `text` or `json` |

## Detection vs prevention
- Detecting an unapproved container: done (audit event).
- Alerting on it: done (warning event on the dashboard's Audit log page).
- Preventing it from starting: NOT possible from the monitor; a plain `docker run` cannot be
  blocked without a Docker authorization plugin (future work).
- Isolating an already-running container: separate response policy (milestone M3).

## Failure behaviour
- Falco log unreadable: status shows `falco_ingest: unavailable`, a `FALCO_INGEST_UNAVAILABLE`
  audit event is written once, the monitor keeps retrying with backoff and writes
  `FALCO_INGEST_RECOVERED` when it works again.
- Backend unreachable: audit events are spooled to `audit_spool.jsonl` and delivered in
  order later; a repeated `event_key` cannot create duplicates.
- Docker unreachable: the event stream reconnects with backoff and the running containers
  are reconciled on every reconnect.
- Registration lookup fails: the container is never called unapproved on the strength of a
  failed lookup (`REGISTRATION_UNKNOWN` instead).

## Privileges and limitations
- Needs read access to the Falco log and access to the Docker socket. Docker socket access
  is root-equivalent on the host; run the monitor as a dedicated user in the `docker` group
  and treat that account accordingly.
- Log rotation by replacement can lose lines written to the old file just before rotation.
- Identical raw log lines are treated as one event.
- Only the newest 500 deployment records are used to decide registration.
- Container IDs, not names, are the identity; a replaced container starts with no trust.
