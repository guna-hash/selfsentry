# SelfSentry academic evidence pack

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

Prepared 15 October 2026 against GitHub main `f465de1`. This is a source/documentation
pack, subsequently updated from the operator's 15 October VM evidence. The
[reviewed mini-study results](academic_results_20261015.md) and
[machine-readable audit](academic_results_20261015.json) record actual outcomes;
historical 200-trial results are retained separately. C2 recording is deferred.
No detector defaults or rule-deployment gates are changed.

| Requested deliverable | Location | Status |
|---|---|---|
| 1. Mini-study commands + result table | [academic_study.md](academic_study.md) | Protocol + measured subset: one complete chain, two preview failures, rejection control |
| 2. Pre-filled designed-case matrix | [academic_case_matrix.md](academic_case_matrix.md) | Supplied study artifacts, historical passes and source tests distinguished |
| 3. Timed demo talk track | [demo_script.md](demo_script.md) | Written, 6:40; isolation OFF; no recording claimed |
| 4. Spoken limitations | [academic_narrative.md](academic_narrative.md) | Written; approximately 35–45 seconds |
| 5. Examiner answers | [academic_narrative.md](academic_narrative.md#examiner-answers) | Short, evidence-bounded answers |
| 6. Report outline | [academic_narrative.md](academic_narrative.md#report-section-outline) | Introduction → Design → Experiments → Results → Discussion → Limitations → Conclusion |

Additional support: [evaluation interpretation and validity threats](academic_evaluation.md);
[existing measured results](monitor_measured_results_20261011.md);
[historical reliability acceptance](reliability_acceptance_20261013.md);
[SVM benign findings](svm_benign_validation_20261013.md);
[current limitations](known_limitations.md).

## Read this claim boundary first

The 15 October study used process metadata from Falco security alerts. The 16 October
extension also accepts retained literal baseline syscall witnesses for anomaly-only
proposals; aggregate counts alone cannot generate rules. That extension still needs
a new live acceptance chain and does not change the earlier study's results. The exact thesis is the
framing; the supported subset is stated beside it wherever used. “Learning” means
human-supervised rule-set adaptation, not automatic model retraining. The strongest
new empirical result is one complete trace from before incident to confirmation,
template/backtest, human decision and exact native after re-fire (200 → rule 18 → 204).
One passing control was rejected (203 → rule 19); two previews failed backtests.
Workflow completion is distinct from added attack coverage. Both the historical run
and this study show no additional attack coverage over existing Falco rules.

## Recommended execution order

1. Read the study's implementation boundary and freeze the standard configuration:
   default Isolation Forest, automatic isolation/confirmation/candidates disabled.
2. Run clock preflight and collect a curated nonempty benign corpus. Preserve invalid
   runs. Do not reuse mixed attack logs as a purported benign corpus.
3. Capture all three before cases before changing rules. Confirm actual controlled
   incidents manually; template/backtest through the existing supported API path.
4. Record reviewer approval/rejection, native reload and repeat-trigger evidence;
   capture held-out benign behavior; fill every table row including failures.
5. Publish a concise measured study result and update the case matrix only where
   evidence supports it. Rehearse/record C2 only when explicitly resumed.

Source helper: `evaluation/capture_academic_case.py`; it captures a single controlled
window with fail-on-invalid timestamp checks. It never confirms, queues, approves,
deploys, retrains or isolates. No production platform expansion is required.
