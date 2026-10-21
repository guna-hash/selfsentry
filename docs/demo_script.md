# SelfSentry: academic demo — 6 minutes 40 seconds

> Current status: [21 October academic handoff](academic_handoff_20261021.md). It records the latest rule workflow, benign false positive and clock recurrence. Historical entries below retain their original scope.


SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

**Written talk track; C2 rehearsal/recording is deferred.** The operator's
[15 October mini-study](academic_results_20261015.md) is now backed by reviewed
saved artifacts; showing them is historical evidence, not a new live run. Main demo: Isolation Forest, isolation OFF, manual confirmation
and candidate submission, mandatory human rule approval. Optional SVM is an appendix.

## Prepare before timing

Apply reviewed source/docs first; preserve `.env`, target identity, baseline and state.
See [operations](monitor_operations.md) for database/token setup. Never display tokens.
Docker, PostgreSQL, Falco and backend must be ready. Falco needs readable JSON and
`rule_matching: all`. Inspect existing processes before starting another instance.
If a monitor is already running, stop it with Ctrl+C in its own terminal before
selecting the academic configuration. Do not delete locks or kill unknown processes.

Backend terminal, only if not already running:

```bash
cd ~/selfsentry
source .venv/bin/activate
python3 -m uvicorn main:app --app-dir backend-api --host 127.0.0.1 --port 8000
```

Monitor terminal:

```bash
cd ~/selfsentry
source .venv/bin/activate
MONITOR_ANOMALY_ALGORITHM=isolation_forest \
AUTO_ISOLATION_ENABLED=false AUTO_CONFIRM_ENABLED=false \
MONITOR_RULE_CANDIDATES_ENABLED=false MONITOR_LOG_FORMAT=json \
python3 monitor-service/monitor_service.py
```

Frontend terminal, only if not already running:

```bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
nvm use 24
cd ~/selfsentry/frontend-dashboard
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Preparation terminal:

```bash
cd ~/selfsentry
source .venv/bin/activate
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
nvm use 24
python3 scripts/verify_final_checks.py
python3 evaluation/clock_guard.py --container selfsentry-test
docker pull alpine:3.20
python3 scripts/verify_live_reliability.py policy
```

If the clock guard fails, stop the live rehearsal and retain diagnostics. A Falco
restart previously restored accuracy, but the recurring timestamp issue is unresolved.
Do not conceal invalid probes or present old screenshots as today's live results.
Stay awake/on AC as appropriate; do not suspend host/VM during the demonstration.

Open tabs: README architecture; `/monitor`; `/alerts`; Rule Review; measured-results
doc; [filled mini-study table](academic_results_20261015.md). Existing screenshots are real
historical VM evidence. The Alerts screenshot is incident 190, an experimental SVM
isolation case; it is not the default-IF/no-isolation example for the main talk.
Select a new standard shell incident or clearly label the historical appendix.

Use saved study evidence: incident 200 → rule 18 → incident 204's generated-rule
timeline; rule 19 rejected; backtest previews 0/36, 3/36 and 8/36; three later normal
windows with no learned-rule hits. Rule 18 is already deployed and rule 19 no longer
belongs in the pending queue; don't fabricate pending rows. Show current queue state
and saved reviewed records side by side. Actual YAML breadth matters, not only rate.
A fresh approval demonstration needs a new genuine candidate and separate evidence.

## Timed talk track

| Time | Screen / action | Spoken text |
|---|---|---|
| 0:00–0:35 | Title/problem | Read the exact thesis above. Add: “The question is whether we can turn reviewed runtime evidence into a traceable, supervised addition to detection rules.” |
| 0:35–1:15 | Adaptive-loop diagram in README | “Falco supplies rule matches and baseline telemetry. A per-container Isolation Forest scores behavioral windows. Correlation persists both signals. For supported incidents, operator confirmation leads to a literal template and benign backtest. A human approves or rejects. Approval reloads Falco; a repeat trigger must show the exact generated rule firing.” |
| 1:15–1:50 | Run policy probe | “This supporting check uses actual Docker inspect data. The privileged specimen is created but never started and is blocked; a non-root, read-only container with no added capabilities passes. Writable root alone is a medium finding, not an independent block.” |
| 1:50–3:10 | Run shell probe; show Monitor while waiting | “This is Falco's default terminal-shell rule entering the real monitor, journal and backend. Windows are 60 seconds plus 10 seconds lateness. The disposable target has no ready baseline, so ML is explicitly unavailable. This proves fallback, not two-layer agreement.” |
| 3:10–3:55 | New incident in Alerts, expanded observed timeline | “The rule, container ID and timestamp connect the incident to the trigger. Evidence survives persistence; an explanation is optional and advisory. A known shell behavior is a controlled simulation, not proof of compromise. Here isolation is off.” |
| 3:55–5:15 | Rule Review and linked mini-study artifacts, or clearly labeled historical evidence | “Incident 200 became rule 18 after human confirmation and a 0-of-36 benign backtest. The reviewer approved it; the exact generated rule re-fired in incident 204. Rule 19 passed backtesting but was explicitly rejected and stayed absent. Two broader pattern previews matched 3 and 8 of 36 benign events and were not submitted. Three later normal windows had no learned-rule hits. This is supervised adaptation; Falco already detected these behaviors. The later anomaly-only proposal path requires a literal syscall witness and still awaits live acceptance.” |
| 5:15–5:55 | Frozen measured-results table | “In the historical 200-trial run, incidents covered 100 of 100 labeled attack trials and 13 of 100 benign windows, including 40 quiet windows. Falco already flagged every attack. Retrospective ML replay added three benign flags and no attack coverage. These are bounded lab observations, not production accuracy.” |
| 5:55–6:40 | Limitations | Read the limitations script below. |

During the two trigger segments run these commands separately:

```bash
python3 scripts/verify_live_reliability.py policy
python3 scripts/verify_live_reliability.py shell --timeout 180
```

The shell probe creates its own non-root, read-only Alpine target; it runs a marker
through a TTY shell, waits for matching parsed alert and incident, saves its report
under `state/evaluation`, then removes only its container. Find the **incident ID**
in that report, then select the same ID in Alerts. Match rule, container and timeline.
The visual dashboard check is distinct from probe PASS. A gate-bypass audit can also
appear because the probe starts directly; do not call it an approved deployment.

If the shell probe exceeds the allocated 80 seconds, pause the rehearsal and adjust
pacing rather than claiming an instant result. Keep a labeled historical fallback
ready. No live rule approval is required in a timed presentation: inspect the real
pending row and show previously captured, correctly labeled approval/re-fire proof.

## Limitations — approximately 35–45 seconds

“Our results come from controlled simulations on one Docker virtual machine, using
a small per-container baseline. The historical run detected all one hundred labeled
attack trials, but Falco already detected those cases, so we have not demonstrated
additional attack coverage. Thirteen of one hundred benign windows produced incidents.
The later anomaly-only proposal path needs a literal syscall witness and still
awaits live acceptance. Backtests estimate matches on our benign corpus,
not production safety. SVM remains experimental after benign false positives, and
the VM has a recurring timestamp issue. Every rule deployment requires human approval.”

## Optional appendix: experimental response evidence

Keep outside the main 5–7 minute story. Show incident 190 and
`docs/reliability_acceptance_20261013.md`: opt-in One-Class SVM plus Falco, effective
score 100, enabled response threshold 90, recorded isolation. The operator independently
observed `Paused=true` and `Networks={}`, then resumed through SelfSentry and observed
bridge restored. The saved JSON contains incident plus **post-resume** inspect; the
paused observation is in the console transcript, not that export's Docker snapshot.
No containment latency was measured. This is functional response evidence, not default
Isolation Forest accuracy or representative SVM quality. The valid four-window benign
SVM follow-up generated two anomaly-only false positives. Never make SVM the default
for the academic story or enable isolation merely to strengthen a claim.

Direct response-function verification, if separately requested/rehearsed:

```bash
python3 scripts/verify_live_reliability.py isolation
```

Label this direct function verification, not automatic policy proof.

## Rehearsal and recording when C2 resumes

Rehearse twice; then record at 1080p with legible zoom. Capture real pages and retain
raw reports separately. Keep credentials/unrelated windows out. Link the actual
recording in README only after it exists and is checked. C2 stays unchecked until
then. Screenshots already exist; use their historical captions accurately.
