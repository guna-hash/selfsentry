# SelfSentry VM reliability acceptance — 13 October 2026

These results are operator-reported from the Ubuntu VMware VM in this conversation.
This documentation change records them; it does not claim the author ran Docker on
that VM or accessed its saved JSON directly. The runtime reports remain on the VM.

## Completed functional checks

| Item | Evidence | Scope |
|---|---|---|
| A1 deployment policy | reliability-policy-20261012T155121Z.json: PASS | Real created-container inspect: privileged blocked, clean passes; privileged specimen never started |
| A2 default security path | reliability-shell-20261012T165358Z.json: PASS; operator displayed Terminal shell in container at 16:54:00.937515665 UTC for 0b8922922981 | Real Falco -> parser -> monitor -> incident -> dashboard observed timeline |
| A2 normal config recheck | reliability-shell-20261012T174808Z.json: PASS | Temporary Falco diagnostic metrics configuration removed before recheck |
| A4 direct response | reliability-isolation-20261012T174616Z.json: PASS | Live disposable container isolation, independently inspected, resumed and cleaned up |
| A4 automatic response | incident 190 + operator Docker inspect; auto-isolation-incident-190.json saved | Controlled One-Class SVM/Falco qualification -> monitor worker -> actual pause/disconnect -> manual SelfSentry resume |
| A5 observed timeline | Incident 181 persisted timeline, and default-shell dashboard timeline confirmed | Observed evidence timeline; optional LLM narrative remains disconnected |
| A6 offline checks | final-checks-20261012T184355Z/results.json | 424 Python tests, release lint, 7 frontend tests, Vite production build passed on VM |

All runtime report paths above are beneath state/evaluation unless stated otherwise.
The read-only candidate journal check additionally confirmed the benign trial window
2026-10-12T18:49:00 UTC contained 24 baseline telemetry records and was closed; no
incident was returned for that window. This is one processed benign trial, not a
false-positive-rate evaluation. Later SVM trial incident 188 (19:09 UTC window) had
anomaly score 1.0, effective score 100 and response not_attempted (isolation disabled).

## Incident 190 automatic response

Target: selfsentry-test, full Docker ID
12160024642b6244d4ec9b81e5ac7d0010a8d30688e37d9ac4369f0bf2b693df.
Original container identity and its 20-window baseline were preserved after VM reboot.

The operator started exactly one monitor with:

- MONITOR_ANOMALY_ALGORITHM=one_class_svm
- AUTO_ISOLATION_ENABLED=true; AUTO_ISOLATION_THRESHOLD=90
- AUTO_CONFIRM_ENABLED=false; MONITOR_RULE_CANDIDATES_ENABLED=false

Controlled simulation: copy and execute the harmless /bin/true binary using the
existing new-binary-execution scenario. Trigger time: 2026-10-13T06:36:02.000583 UTC.
Recorded feature window: 06:36:00–06:37:00 UTC. No response latency was measured.

Persisted assessment and workflow reported by the operator:

- algorithm one_class_svm; baseline MODEL_READY
- anomaly_score 1.0; raw decision_function -0.21178190789970744
- model_is_anomaly true; qualification threshold 0.8; qualifies true
- effective score 100.0
- response status isolated, matching full target ID, threshold 90.0
- reason: both layers qualify; effective score 100.0 >= 90.0

Independent Docker inspect printed Paused=true and Networks={}.
The operator invoked:

```bash
python3 response-engine/auto_isolate.py selfsentry-test guna --resume
```

Resume reported restored bridge. Independent inspect then printed Paused=false
with bridge attached (172.17.0.2). The evidence-export command saved incident 190
and the post-resume Docker inspect to state/evaluation/auto-isolation-incident-190.json.
That file captures post-resume state, not an independently captured pre-resume inspect
snapshot; the paused/empty-network observation is retained in the operator console
transcript. The isolated workflow is historical; resume does not rewrite that outcome.

## What remains open

- Independent, representative benign evaluation of the opt-in SVM. The 20 training
  windows contain seven distinct vectors; offline LOO flagged 2/20 candidate samples.
  Default Isolation Forest still assigns identical low scores to incidents 186/187.
- Automatic response with default Isolation Forest, other workloads and broader faults
  is not established by this SVM trial. This trial does not validate auto-confirmation
  or candidate synthesis, which were disabled; separate earlier evidence covers those.
- No rerun of the original 200-trial benchmark, independent live comparison or new
  layer/containment latency measurements. Historical measurements remain unchanged.
- Actual dashboard screenshots/GIF, demo rehearsal and recording remain open.
- Final VM source/docs review, release commit and push remain open. Source commit,
  dependency versions and all selected monitor settings should accompany new results.

Ordinary observation should run with automatic isolation off. For the experimental
candidate, keep auto-confirmation and rule candidates off too until its evaluation
supports enabling them. A successful containment test does not establish production
model accuracy. Human approval is still mandatory for every rule deployment.
