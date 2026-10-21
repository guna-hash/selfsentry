# Remaining work — 20 October 2026

Source review: `5fba7a2` (merged dashboard redesign). This ledger reconciles the
operator's priorities with committed evidence; it is not a fresh VM acceptance run.
Historical results and runtime artifacts remain unchanged. Documentation commits
do not establish the configuration of a running monitor.

## Priorities and acceptance evidence

| Priority / item | Current evidence | Required to close |
|---|---|---|
| P0 / 1. Review documentation and research helper | Academic docs and `evaluation/capture_academic_case.py` are tracked; current review reconciles stale anomaly-only claims | Review/apply this documentation diff on the current VM; reconcile any local helper changes; retain every runtime artifact |
| P0 / 2. Freeze default IF/manual study; check fresh timestamps | Helper requires a ready IF model and explicit disabled automatic actions; past valid captures are historical | Record running process settings, source status, baseline/rule hashes and fresh target-specific Falco preflight/per-case checks; no current VM pass claimed |
| P0 / 3. Publish reviewed mini-study | Already committed: [results](academic_results_20261015.md) and [audit](academic_results_20261015.json), including hashes/IDs, 200 → 18 → 204, preview failures, incident 199 and unrun cases | Operator final review of the published claims and retained original evidence; do not rerun merely to replace inconvenient outcomes |
| P0 / 4. Dashboard acceptance | Eight labelled sample screenshots and bounded Chromium smoke checks are recorded in [capture guide](dashboard_screenshots.md); implementation/tests are distinct from live acceptance | Explicit operator narrow/mobile review; drawer focus trapping/focus return, modal keyboard and both themes; full Steps 3–7 VM visual/controlled actions; screenshot sign-off; additional accessibility/browser checks |
| P0 / 5. Designed-case live restart/fault extensions | [Matrix](academic_case_matrix.md) separates source tests, historical passes and supplied artifacts | Execute remaining predeclared disposable-lab cases; save fault point, IDs, queue counts, recovery/duplicate/timeline evidence and cleanup; keep each unexecuted case NOT RUN |
| P1 / 6. Evaluation interpretation | [Interpretation](academic_evaluation.md) already states 200-trial denominators, endpoints, retrospective layers and threats | Final report review with exact historical source/config limits; no transfer of historical quality metrics to the current release |
| P1 / 7. Narrative/report/viva | [Narrative](academic_narrative.md) and [demo script](demo_script.md) exist; current wording distinguishes implementation from live proof | Operator final review and report integration; C2 recording remains deferred |
| Reliability / 8. Recurring Falco clock skew | Detected by clock guard; restart has only restored accuracy temporarily | Collect diagnostics before restart; identify cause and demonstrate freshness across the triggering lifecycle, preserving invalid runs |
| Model / 9. Independent benign validation and baseline review | Small retained baseline; earlier SVM false positives documented | Independently label representative benign workloads; preserve training/validation separation and hashes; report all exclusions/results |
| Model / 10. Longer independent benign evaluation | No unattended-use validation established | Predeclare longer observation and denominators; keep isolation disabled; report all incidents and missing/unscored windows |
| Extension / 11. New anomaly-only chain and native process/file-write rules | Literal-witness path and templates exist with regression coverage | New qualifying live incident with no security alert, literal witness, confirmation, authoritative backtest, human approval, native load/re-fire and linked after incident; separately verify both template types |
| Extension / 12. Current-release detection quality/load/drops | Historical evaluation predates the extension | Freeze current source/config/workload; measure labelled detection outcomes, load and available loss counters with start/end snapshots; label unavailable counters unmeasured |

Optional: actual failed-submission traces, sensitive/terminal after-runs and broader
comparisons require new evidence only if pursued. The 15 October preview failures
were not actual failed submissions. A later 16 October authoritative rejection is
separate evidence, not a retroactive change to that study.

## Frozen study configuration

Use the existing [study startup procedure](academic_study.md#1-freeze-configuration-and-create-evidence-directory)
for exactly one monitor, with explicit running-process values:

```text
MONITOR_ANOMALY_ALGORITHM=isolation_forest
AUTO_ISOLATION_ENABLED=false
AUTO_CONFIRM_ENABLED=false
MONITOR_RULE_CANDIDATES_ENABLED=false
```

Do not infer these values from `.env.example`, a model badge or a healthy heartbeat.
Retain the same baseline, thresholds and rule snapshot within a declared experiment;
record any required change as a separate run. Every rule deployment still needs
human approval. This source review does not modify the VM configuration.

The existing clock CLI writes `state/evaluation/clock_check.json`. Preserve that
file before rerunning it. The capture helper creates a new `--out` directory and
refuses to overwrite an existing one. Use a new directory per attempt; retain raw
events, reports and invalid captures. Never clear checkpoints, outboxes, baseline
files, decision history or deployed rules to make a check pass.

## Live evidence record

For each case retain source commit and dirty status; target full ID/image digest;
baseline/corpus/rule hashes; explicit runtime flags; timezone-aware UTC endpoints;
native raw events and incident/rule/audit IDs; expected versus observed result;
PASS/FAIL/INVALID/NOT RUN; and recovery/cleanup result. Keep secrets out of shared
exports. An invalid clock run is retained and excluded with its reason, not counted
as a detector miss or silently replaced by a successful retry.

For restart/fault cases, establish pending work before the fault and show one
persisted incident after recovery with its original timeline. Record replay counts
and duplicate checks. A clean restart with no pending work does not test mid-flight
recovery. Perform controlled actions on disposable lab targets with an explicit
recovery route; do not treat source tests as new live evidence.

For dashboard review, record browser/version, viewport, theme, route, data mode,
keyboard sequence and actual result. Sample-mode screenshots prove interface
rendering only. Keep live acceptance and operator sign-off pending until observed.
