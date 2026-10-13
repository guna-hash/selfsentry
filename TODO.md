# SelfSentry release checklist

Reconciled 13 October 2026 against source base `e781e02`, applied reliability/model
patches and operator-reported VM evidence. See [current acceptance](docs/reliability_acceptance_20261013.md)
and [earlier final review](docs/monitor_final_review.md). Source checks, live functional
passes and unmeasured quality/performance claims are identified separately.

## Phase A — Reliability and release

- [x] A1: operator VM policy probe passed on 2026-10-12; privileged blocks and
  clean passes. Evidence: reliability-policy-20261012T155121Z.json. Phase 2 closed.
- [x] A2: default shell parser/monitor/backend probe passed, and operator confirmed
  dashboard observed timeline at 16:54:00 UTC for container 0b8922922981. Probe also
  passed after removing diagnostic metrics: reliability-shell-20261012T174808Z.json.
  Phase 3 closed. A prior stale-clock/fresh-start incident remains in evidence.
- [x] A3: default terminal shell alerts with a usable shell process name now feed
  process-spawn scoring. Overlapping baseline/default records are deduplicated by
  the existing normalized-event identity. Security windows never train baselines.
- [x] A4: reconcile previous live isolation/resume evidence: see
  [known_limitations.md](docs/known_limitations.md) and
  [final review](docs/monitor_final_review.md). Earlier evidence includes a real
  paused/disconnected victim, not only the not-found case.
- [x] A4 direct current-release check: live isolation/resume probe passed on the VM;
  evidence: reliability-isolation-20261012T174616Z.json.
- [x] A4 controlled automatic response: SVM incident 190, effective score 100,
  response isolated; operator independently inspected Paused=true and Networks={},
  then resumed through SelfSentry and inspected Paused=false with bridge restored.
  Evidence: state/evaluation/auto-isolation-incident-190.json plus operator console
  output. Applies to opt-in one_class_svm, not default forest or production accuracy.
- [x] A5: observed Falco/anomaly timeline now persists in monitor incident evidence,
  survives SQLite outbox restart and backend database reload, and appears on Alerts.
  Advisory LLM narrative timeline integration remains future scope.
- [x] A6 source hygiene: no baseline JSON is tracked under behavioral-engine/baselines;
  ignore rules retain runtime files locally. Release verifier updated for current Vitest.
- [x] A6 VM offline checks: 424 Python tests, release lint, 7 frontend tests and build passed.
- [x] A6 VM release: source/docs committed and pushed in 3cb1e83;
  reviewed runtime rule snapshot pushed in 96f9827. Runtime evidence remains separate.

## Phase C — Demo and presentation

- [x] C1: exact 5–7 minute script in [docs/demo_script.md](docs/demo_script.md).
- [ ] C2: rehearse and record the real VM demo; no recording claimed by source checks.
- [x] C3: Mermaid architecture in README.
- [x] C4: four real VM screenshots reviewed and published with README captions
  in 56cef9e: Monitor, baseline/model status, incident 190 timeline and Rule Review.
- [x] C5: concise limitations/future work section in [docs/demo_script.md](docs/demo_script.md).

## Phase D — Documentation

- [x] D1: replace stale TODO/ROADMAP with current release status.
- [x] D2: refresh known-limitations header; distinguish resolved history from current gaps.
- [x] D3: record dashboard upgrade and reliability changes in CHANGELOG.

## Preserved constraints

AI is advisory. Every generated-rule deployment requires human review after
backtesting. Isolation defaults off. The 200-trial evaluation is controlled and
retrospective: it demonstrates no additional attack coverage beyond Falco.

## Model reliability follow-up (13 October 2026 IST)

- [x] Reproduce reported low scores; explain identical leaf paths for incidents 186/187.
- [x] Prepare opt-in scaled One-Class SVM candidate and offline replay/LOO comparison.
- [ ] Independent benign candidate validation and representative baseline review.
- [x] Controlled SVM automatic response and resume passed (incident 190).
- [ ] Independent benign/longer candidate evaluation before unattended use; keep
  isolation disabled during ordinary observation.

See docs/anomaly_model_review.md. Candidate replay passes are not live acceptance or
a production false-positive-rate measurement; default algorithm and thresholds remain.
