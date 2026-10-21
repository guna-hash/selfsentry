# Evaluation: claims, denominators and threats to validity

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

The empirical boundary of the reviewed study is the Falco-backed process-pattern
synthesis path. The later extension supports anomaly-only proposals with retained
literal syscall witnesses, but its new live chain remains unverified. Aggregate-only
anomalies cannot generate rules. This
document interprets existing results and the operator-supplied
[15 October mini-study](academic_results_20261015.md). Its results are separate from
the frozen benchmark; it validates one supported chain, not ML-only discovery.

## What the frozen 200-trial results prove

The controlled full-pipeline run persisted incidents for 100/100 labeled attack
simulations and 13/100 benign windows; no duplicate trial incidents were recorded.
The attack proportion's Wilson 95% interval is 96.30–100%; the benign incident
proportion's interval is 7.76–20.98%. Those intervals summarize the sampled labels,
not independent production workloads. Forty benign windows were quiet; among the
60 active benign windows the incident proportion was 13/60 (21.67%).

Retrospective reconstruction reproduced all 200 union outcomes, not four independent
live experiments. All 100 attack incidents already had Falco security alerts.

| Observation in frozen run | Attack windows / 100 | Benign windows / 100 | Interpretation |
|---|---:|---:|---|
| Falco security flags | 100 | 10 | Existing rule evidence |
| Qualifying IF evidence | 7 | 3 | ML scored 100 attack and 60 active benign windows; 40 quiet unscored |
| Union / persisted incidents | 100 | 13 | Three added benign incidents, no added attack detections |
| Automatic confirmation | 5 | 0 | Restrictive historical policy; every rule deployment still needs a human |

The 10 benign HTTP-fixture detections came from Bash `/dev/tcp` and redirected
standard streams, matching the security behavior Falco monitors. Preserve them as
known-benign detections. A conventional `curl` workload is a new experiment, not a
retroactive correction of the labels or denominator. The remaining three benign
incidents were anomaly-only. See [measured source](monitor_measured_results_20261011.md).

## What they do not prove

They do not prove novel attack coverage over Falco, zero-day detection, high
production precision, unseen-workload generalization or autonomous learning. They
do not evaluate the completed approve/reload/re-fire loop across 200 trials: the
five candidates were pending, not 200 deployed-rule outcomes. The frozen run
predates later shell-feature/timeline fixes and the SVM candidate. A new source
release must not inherit its metrics as if freshly benchmarked.

Median 68.154 s and p95 68.588 s (100 attacks) measure **attack start to server row
timestamp**, explicitly interpreting naive DB times in Asia/Kolkata. They are not
Falco latency, transaction commit completion, API visibility, containment or learning
latency. Windows were 60 s plus 10 s lateness; phase-aligned starts constrain the
observed distribution. Measure arrival-to-visibility separately before claiming it.

## New learning-loop evidence: report separately

The [reviewed 15 October artifacts](academic_results_20261015.md) contain 17 valid
captures. One primary behavior completed confirmation/backtest/approval/native
re-fire (200 → rule 18 → 204); two pattern previews failed and were not submitted;
a passing control was explicitly rejected (203 → rule 19). No learned-rule hits or
incidents occurred in three later normal windows. One calibration window produced
anomaly-only benign incident 199. All primary before cases already had Falco
security detections and nonqualifying ML, so no extra coverage is demonstrated.
Actual failed submission calls and B2/B3 after-runs were not performed. Do not
infer those outcomes from the preview verdicts.

For subsequent studies, use the mini-study table with before rules, actual confirmed ID, candidate artifact,
nonempty benign counts, human decision, reload and exact native after alert. Primary
endpoint: completed supported workflow chain per attempted behavior. Secondary:
rejection integrity and generated-rule matches on held-out benign windows. Exploratory:
incremental coverage **only** with a genuine absence of before security detection.

Report numerator/denominator, rejected/failed/incomplete cases, revisions, baseline
and corpus hashes, rule-set changes and human operator. Do not pool corpus event-level
match rates, window-level incident proportions and trial-level confirmation precision.
No automatic model-weight update occurs when a Falco rule is deployed; adaptation is
of the rule set, supervised by the operator.

## Current model honesty

Isolation Forest remains default. The retained baseline has 20 samples and seven
distinct vectors. IF scores for incidents 186/187 saturate in identical forest
regions; they do not qualify although the labeled simulation differs from baseline.
One-Class SVM is an opt-in experiment: incident 190 proves one functional automatic
isolation/resume path, **not** comparative accuracy. A subsequent four-window benign
test was valid and produced two anomaly-only false positives, incidents 195/196.
The preceding 24-window batch had 19 invalid windows due to Falco clock skew.
Keep both datasets and all exclusions. See [SVM validation](svm_benign_validation_20261013.md).

## Threats to validity

| Threat | Effect on interpretation | Control / remaining limit |
|---|---|---|
| Single Ubuntu VMware host, Docker/Falco versions | Environment-specific behavior and recurring timestamp skew | Record versions, config, clock preflight and per-case skew; fail invalid captures; root cause remains open |
| 60 s windows + 10 s lateness | Measured time depends strongly on scheduling, not only processing cost | State timing endpoints and phase alignment; no stage-level speed claim |
| Small, low-diversity per-container baseline | Normal variation can look anomalous; model boundaries can miss simulations | Freeze baseline for testing; distinguish training/validation; future representative baseline study |
| Repeated controlled behaviors | Correlated samples; designed cases do not approximate the attack universe | Publish commands, all outcomes and limited class diversity; don't generalize 100/100 |
| Single-host, per-ID models | Replacement identities and other images may not share behavior | Keep full identity and image digest; do not claim cross-container transfer |
| Operator-in-the-loop decisions | Label/approval subjectivity, non-blinded review and variable time | Record criteria, reviewer, rejection reasons and timestamps; never imply autonomous decisions |
| Narrow template / custom backtester | Parent/process loses file or TTY context; backtester isn't Falco's full engine | Review exact YAML, freeze nonempty benign corpus, native after re-fire and held-out benign checks |
| Calibration/selection bias | Choosing only successful cases or tuning after failures inflates results | Predeclare cases; keep failed/rejected/invalid attempts; separate a new revised study |
| Historical source/config fingerprint | Dirty source and incomplete AUTO_* setting capture limit exact reproduction | Preserve source commit/status, package versions, configs and selected runtime flags; don't expose tokens |
| Enabled generated rules during experiments | Existing adaptation can contaminate before and after comparison | Snapshot/hash rule sets, list all before alerts, isolate candidate identity; never erase inconvenient hits |
| Observational layer comparison | Layers share telemetry and were not independently randomized | Label it retrospective replay; ML-only coverage remains unproven |
| Optional LLM and local shared-token auth | Explanation availability and reviewer identity don't establish strong access control | AI has no detection/deployment authority; demo-only trust model; no production security claim |

## How to present hybrid contribution

Use four evidence categories per **window**: Falco-only (qualifying security alert,
ML absent or nonqualifying); ML-only (qualifying assessment, no security alert);
both (independently inspect alert + `qualifies=true`); neither/unscored (distinguish
no telemetry from a valid normal assessment). Risk score alone is insufficient.
List rule names, model algorithm, baseline state and assessment. A stronger risk
score or stricter confirmation policy is a workflow contribution, not proof of
additional attack detection. Keep SVM outcomes in a separate appendix.
