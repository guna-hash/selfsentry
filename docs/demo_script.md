# SelfSentry: 5–7 minute demo

Target: your Ubuntu Docker/Falco/PostgreSQL VM. This script is written; no recording
or current-release live run is claimed. Keep isolation off for the standard demo.

## Prepare before timing

Apply source changes with backend/monitor stopped, preserving .env and state.
Configure the token and database per [monitor_operations.md](monitor_operations.md).
Falco must write readable JSON to FALCO_LOG_PATH and use rule_matching: all.

```bash
cd ~/selfsentry
source .venv/bin/activate
python3 scripts/verify_final_checks.py
docker pull alpine:3.20
python3 scripts/verify_live_reliability.py policy
```

The probe creates actual Docker containers and checks inspect data; it never starts
the privileged container. Privileged blocks; the clean configuration passes all
four rules. Writable rootfs alone is MEDIUM and does not independently block.

Start services in three terminals:

```bash
# Terminal 1
cd ~/selfsentry
source .venv/bin/activate
python3 -m uvicorn main:app --app-dir backend-api --host 127.0.0.1 --port 8000
```

```bash
# Terminal 2
cd ~/selfsentry
source .venv/bin/activate
AUTO_ISOLATION_ENABLED=false MONITOR_LOG_FORMAT=json \
python3 monitor-service/monitor_service.py
```

```bash
# Terminal 3
cd ~/selfsentry/frontend-dashboard
npm run dev -- --host 127.0.0.1
```

Open http://127.0.0.1:5173/monitor. Confirm heartbeat, Docker, Falco and database
state. Enter the shared token only for actions; keep it out of the recording.
Prepare one genuine pending rule from a previous confirmed incident if available.
An empty review queue is valid; do not inject fake live candidates for the demo.

## Timed sequence (~6 minutes)

| Time | Show / do | Say |
|---|---|---|
| 0:00–0:40 | README diagram | “SelfSentry connects image/policy checks, runtime evidence, correlation, recoverable response and reviewed rule adaptation.” |
| 0:40–1:20 | Run policy probe | “This is real inspect data: privileged fails; non-root, read-only and no-added-capabilities passes.” |
| 1:20–2:00 | Monitor | “Heartbeat and component state show service health. Baselines belong to container IDs.” |
| 2:00–3:30 | Run shell probe; show Monitor while waiting | “Falco's default shell rule enters the real parser and journal. Detection waits for a 60-second window plus 10 seconds lateness.” |
| 3:30–4:30 | Alerts, new ID, expanded timeline | “This incident and chronological evidence persist. Missing ML is explicit; AI is advisory.” |
| 4:30–5:20 | Rule Review | “Templates generate candidates. Backtesting estimates matches on benign history. A human reviews YAML and rate before deployment.” |
| 5:20–6:00 | Measured results and limitations | “The controlled run detected 100/100 attacks and 13/100 benign trials; extra attack coverage beyond Falco was not demonstrated.” |

Commands during the demo:

```bash
cd ~/selfsentry
source .venv/bin/activate
python3 scripts/verify_live_reliability.py policy
python3 scripts/verify_live_reliability.py shell --timeout 180
```

The shell probe creates its own non-root, read-only Alpine target and runs
`docker exec -t <its-full-id> sh -c 'echo SelfSentry-shell-probe'`. It waits for
the parsed default security alert and a monitor incident containing that same
rule/container, records JSON under state/evaluation, and removes only its own
container. Open the recorded incident ID on Alerts; confirm its rule, ID and
observed timeline. This visual check is separate from the probe result.

A new target has no model-ready baseline: expect learning/unavailable ML and no
automatic response. If shell process metadata is absent, the alert persists without
inventing a shell count. A bypass audit event may also appear because the probe
starts the container directly. Do not describe this as approved gate deployment.
If the probe fails, retain its report, inspect logs and rehearse after fixing it.

## Optional response segment (rehearse separately)

```bash
python3 scripts/verify_live_reliability.py isolation
```

Show independently inspected running/network-attached, paused/network-empty, and
resumed/network-restored states. The probe uses an internal disposable network.
Label this **direct response-function verification**, not automatic policy proof.
Automatic response needs a reviewed model-ready disposable target, eligible current
cross-layer evidence, sufficient score, enabled response and no protection exclusion.
Use the operations/evaluation guide and show both persisted workflow and Docker
inspect for that separate rehearsal. Keep original isolation records for audit.

## Images and recording

Use the VM desktop screenshot tool to capture:

- docs/screenshots/monitor-live.png: heartbeat, components and baseline states.
- docs/screenshots/alerts-live.png: real shell incident ID and expanded timeline.
- docs/screenshots/rule-review-live.png: real candidate/backtest or honest empty state.

Keep tokens, credentials and unrelated windows out. Any labeled synthetic UI
previews in README illustrate the interface and are not live acceptance evidence.
Rehearse twice, then record at 1080p with legible zoom. Save/link the real recording
after it exists; no placeholder recording establishes completion.

## Limitations & Future Work (one slide / 30 seconds)

- Controlled 200-trial run: 100% labeled-attack detection, 13% overall benign
  incident rate (21.67% of active benign trials), zero duplicate trial incidents.
- Comparison is retrospective; extra attack coverage beyond Falco is unproven.
- Median 68.154 s / p95 68.588 s attack-start-to-row timestamp; individual layer
  and containment timings unmeasured. Frozen results predate this source fix.
- New containers need representative clean baselines; optional AI can be unavailable.
- Future: independent comparison runs, drift/retraining, soak/fault tests, RBAC,
  retention and Kubernetes. Rule deployments always require human approval.

## Acceptance and release

Close Phase 2 only after A1 passes with retained evidence. Close Phase 3 after A2
passes and the same incident is visually confirmed. Automatic response acceptance
is separate. Finally:

```bash
python3 scripts/verify_final_checks.py
git status --short
git diff --check
git ls-files 'behavioral-engine/baselines/*'
```

The last command should print nothing. If the VM still tracks JSON, review paths
then use `git rm --cached -- <reviewed-path>` to preserve local files. Stage intended
source/docs, review `git diff --cached`, commit and push. Keep runtime evidence
separately; do not stage .env, state or baselines.
