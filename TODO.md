# SelfSentry release checklist

> Current 23 October follow-up: see the [current repository assessment](docs/repository-audit/report.md)
> and [committed VM verification record](docs/repository-audit/vm-verification-20261023.md).
> Native migration/restore/concurrency, gate/shell and bounded workload/export passes are recorded;
> private raw VM evidence has not been inspected in this checkout. Current source checks do not
> establish full native acceptance or fresh-host/production readiness.


> Engineering review: [22 October repository audit](docs/repository-audit/report.md). Historical checked items below apply only to their recorded source/configuration; they are not acceptance of the audit patch.

> Current status: [21 October academic handoff](docs/academic_handoff_20261021.md). It records the latest rule workflow, benign false positive and clock recurrence. Historical entries below retain their original scope.


20 October priorities and closure criteria: [remaining-work ledger](docs/remaining_work_20261020.md).
Historical checked items below retain their original evidence scope; the ledger
does not mark new VM/browser checks passed.

## Dashboard redesign (stepwise review)

- [x] Step 1 implementation: theme tokens/toggle, responsive shell, health/isolation banners.
- [x] Step 1 automated verification: install, build and 16 frontend tests; token contrast.
- [x] Operator reports repaired dashboard, theme toggle, sidebar and isolation indicator working.
- [ ] Verify narrow/mobile shell layout explicitly.
- [x] User accepted Step 1 and authorized Step 2.
- [x] Step 2 shared components, table sort/filter interaction tests and formatter tests.
- [x] Step 2 clean install/build and 30 frontend tests passed.
- [ ] Step 2 native browser drawer focus-trap and visual checks.
- [x] Operator accepted Step 2 and authorized progression to Overview.
- [x] Step 3 Overview implementation and 47 frontend tests; clean install/build passed.
- [ ] Step 3 VM visual verification in both themes, filters, linked incident and refresh controls.
- [x] User accepted Step 3 and requested the next step.
- [x] Step 4 shared Alerts table, detail drawer, guarded actions and 69 frontend tests.
- [ ] Step 4 VM visual and controlled-action checks, including modal keyboard behavior.
- [x] User accepted Step 4 and requested Step 5.
- [x] Step 5 Rule Review Queue, YAML/backtest history and human confirmation dialogs.
- [x] Step 5 clean install/build and 96 frontend tests passed.
- [ ] Step 5 VM visual, modal keyboard and controlled review/reload acceptance.
- [x] User reviewed Step 5 and authorized Step 6.
- [x] Step 6 Containers, Deployments, Audit, Monitor and Models migration.
- [x] Step 6 clean install/build and 119 frontend tests passed.
- [ ] Step 6 VM review: both themes, sorting/filtering, historical audit IDs/CSV,
  protected workload guard, controlled restore verification and native modal keyboard use.
- [x] User authorized Step 7 after the Step 6 delivery.
- [x] Step 7 Evidence, presentation and explicitly bannered fixture modes.
- [x] Step 7 clean install/build and 146 frontend tests passed.
- [ ] Step 7 VM review: Evidence/provenance, missing-file states, presentation navigation,
  clear sample banner, disabled actions and no backend network requests in sample mode.
- [x] User authorized Step 8 after Step 7 delivery.
- [x] Step 8 eight browser screenshots in both themes, labelled README gallery and capture guide.
- [x] Step 8 bounded browser checks: native modal Tab/Shift+Tab/Escape, 390px navigation,
  no page overflow/backend requests/page errors in sample mode; all images visually inspected.
- [x] Step 8 clean install/build and 149 frontend tests passed.
- [ ] Operator final review of the screenshot gallery and controlled live workflows.
- [ ] Additional manual accessibility/browser combinations beyond the recorded smoke checks.



## Completion extension — 16 October 2026

- [x] Deterministic explanations, risk rationale and 1–3 fixes for every incident severity
  and deployment decision; persisted through existing JSON fields and historical backfill.
- [x] Local host lifecycle CLI: start/stop/status/restart, prerequisite validation, readiness,
  rollback, private logs and safe PID identity checks.
- [x] Resume request/result/failure audits; partial recovery visible/retryable, protected
  containers enforced at the shared response boundary, optional policy re-check.
- [x] Falco ingestion/windows isolated from slow control workflows; bounded parallel model
  fitting, durable audit/deployment replay and conservative per-container health badges.
- [x] Backend-authoritative backtests on submission and approval, process/file-write templates,
  ready-model anomaly witness proposals, lifecycle history and observed native re-fire links.
- [x] Unified dashboard overview, guidance cards, confirmation badges and operational docs.
- [x] Operator-reported VM functional acceptance: startup, Isolation Forest configuration,
  two-container continuity, audited resume, protection, PostgreSQL recovery, complete
  guidance, native rule re-fire and authoritative failed submission. See
  docs/completion_acceptance_20261016.md.
- [x] Final completion VM regression rerun: 472 Python tests, lint, 7 frontend tests and build.
- [x] Visibility follow-up: 475 VM Python tests, lint, 7 frontend tests and build passed; operator confirmed the label and audit lookups.
- [ ] New anomaly-only live chain and native process/file-write rule acceptance.
- [ ] Measure representative detection quality/load/dropped events for the new release;
  historical study results do not validate the extension automatically.

Earlier checked results below are preserved as historical evidence, not a claim that the
completion extension passed every possible live acceptance case.

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

## Academic evidence priorities — 15 October 2026

- [x] Prepare thesis-aligned mini-study protocol and capture helper; subsequent VM results linked below.
- [x] Prepare designed-case evidence matrix, conservative evaluation interpretation,
  timed talk track, limitations script, examiner answers and report outline.
- [x] Review supplied mini-study: 17 valid captures; one primary approved native re-fire
  chain (200 → rule 18 → 204), one human-rejected control (203 → rule 19), two failed
  backtest previews, three later benign windows with no hits/incidents. Calibration
  IF false-positive 199 retained; no extra attack coverage. See docs/academic_results_20261015.md.
- [ ] Optional study extension: actual failed-submission traces and sensitive/terminal
  after-runs were not performed; keep these labeled unrun, not required positive outcomes.
- [ ] Diagnose recurring Falco timestamp skew; restart is a temporary recovery only.
- [ ] C2 rehearsal/recording remains explicitly deferred by the operator.

See docs/academic_evidence_pack.md. No SVM default change, autonomous rule deployment,
production CWPP, fleet or Kubernetes expansion is part of this academic work.

## Remaining-work source follow-up — 23 October 2026

- [x] Reconcile ten missing paths and current additions; retain a concrete proposed-removal manifest.
- [x] Recover original native acceptance/workload/export source and provenance; run local safety tests.
- [x] Integrate manual archive-aware retention/export; no live cutoff or relocation applied.
- [x] Add explicit full-ID operator observations preserving original outcomes and local audit history.
- [x] Add independent holdout accounting without changing default model or claiming quality results.
- [ ] Inspect private VM evidence before independent native verification labels.
- [x] Implement opt-in human-reviewed native retirement/reload/recovery source and local regressions.
- [ ] Verify native retirement on disposable Falco and resolve unknown-create identity.
- [ ] Validate native outages/crashes, whole-app restore/grants/sequences and shutdown bounds.
- [ ] Complete fresh-host, live browser, representative detection/rule-loop/clock and sustained workloads.
- [ ] Obtain approval for specific proposed file removals and any live archival cutoff.
- [ ] Authorize a named isolated environment before real isolation/recovery; keep automation off.
- [ ] Review and merge follow-up/main only after maintainer acceptance; no push performed here.

- [x] Final remote recheck: PR #6 merged the original audit integration into main (`16ac05b`), with the same source tree as `a25fca0`. This continuation remains unmerged.

## Current acceptance update — 26 October 2026

- [x] Inspect operator release output: 1,268 Python tests, 104 subtests, 168 frontend tests, lint/types/build/whitespace passed.
- [x] Inspect seven disposable audit and five real-monitor replay checks; retain synthetic/native boundaries.
- [x] Record both supervised default-IF rule loops and verified native test-rule cleanup.
- [x] Record existing separate-host recovery, without relabeling it as clean installation.
- [ ] Complete current ten-criterion closure items in docs/repository-audit/report.md.

These entries supersede corresponding older open items only within the stated tested scope.
