# Continuous monitor evaluation

## Final reviewed status — 12 October 2026 IST

This section supersedes the original pending statements retained below as history.
Source reviewed: the uploaded final-review archive at HEAD 45c4dfa with uncommitted
changes; 153 manifest hashes matched. The final polish patch must be applied and its
checks rerun before recording a final release commit. No repository push is claimed.

| Milestone | Delivered and verified |
|---|---|
| M1 | Audit table/API, continuous checkpointed Falco ingestion, Docker discovery and unapproved-start auditing; authenticated writes, bypass and gate registration exercised |
| M2 | Per-container learning/readiness, anomaly scoring and explicit unavailable evidence; ready-model workload trials, live no-baseline fallback and five invalid-model regression cases passed |
| M3 | Durable incident creation/deduplication, both-layer auto-confirmation and opt-in isolation; live PostgreSQL recovery, controlled isolation/resume and protected-container integration passed |
| M4 | Candidate generation/backtesting/human approval, native Falco deployment/re-fire, advisory AI and status/dashboard pages; bounded retry tests and successful post-patch AI request verified |
| M5 | Operating guide, 406-test Python suite, dashboard build and measured 200-trial full run plus retrospective layer comparison delivered; measurement boundaries stated explicitly |

Measured frozen configuration: 100/100 attack trials produced incidents; 13/100
benign trials produced incidents; 5/100 attacks and 0/100 benign trials were
auto-confirmed; 0/200 trials had extra incident rows for their trial key.
Retrospective Falco flags were 100 attacks/10 benign, qualifying ML 7 attacks/3
benign. The union matches all 200 full-pipeline outcomes; quiet windows were not
ML-scored. This dataset does not demonstrate added attack coverage beyond Falco.
Attack-start to database-row timestamp: median 68.154 s, p95 68.588 s (n=100).
See monitor_measured_results_20261011.md for scenario counts and timing semantics.

Additional acceptance evidence:
- Incident 178: real Falco security alert in a new learning container, explicit ML
  unavailable, no agreement/auto-confirm/isolation; container removed.
- Incident 179: queued during a PostgreSQL outage and delivered exactly once after
  recovery; monitor PID unchanged, database active, container removed.
- Protection by name, short ID and full ID: real Docker identity/state with synthetic
  qualifying evidence and a fake backend; no isolation callback, no pause/network
  change; container removed. This is not a separate end-to-end attack trial.
- Invalid/degenerate model, invalid score and review-required paths: five automated
  cases passed. Existing deployed baselines were not corrupted to manufacture a test.
- Incident 177: ready AI explanation after HTTP 200; no isolation because disabled.
  Live 429-to-success recovery was not observed. Retry/cooldown/restart limits passed
  automated tests; the earlier frozen run had 50 HTTP 200 and 63 HTTP 429 responses.

The final polish makes AI ready/unavailable/pending_retry states visible in the
Alerts page, preserves severity when AI is absent, restores /alerts as an alias,
permits both local dashboard origins, clarifies advisory language and cleans lint.
It does not alter the frozen baseline, detection thresholds or recorded trial labels.

Release closeout: apply the polish patch, rerun Python tests/lint and dashboard
checks, restart services, then review and commit the intended source/docs. Baselines,
raw telemetry, state databases and local backups must remain outside the source commit.
No pending rule should be approved solely to make the queue empty.

Unmeasured / outside the completed controlled comparison: independent live
falco_only/hybrid/response runs; raw Falco receipt, ML-processing, correlation,
verified commit, containment and learning latencies; exhaustive daemon/disk faults,
replacement-log rotation under load, long-duration production soak and generalization
to production workloads. Keep these limitations rather than filling absent numbers.
The original four-live-variant design has not been executed; retrospective comparison
is the alternative delivered. Automatic isolation remains off for normal operation.


## Original implementation / evaluation snapshot (historical)

No live attack, false-positive, confirmation-accuracy or response-latency measurements were
collected during this implementation. Tests use isolated SQLite, real feature extraction /
Isolation Forest, simulated telemetry and fake side effects. Their pass count is evidence of
code behavior, not a production detection rate. Existing historical measurements elsewhere
in this repository remain historical; they do not validate this new continuous pipeline.

## Experiment design

Use a disposable VM, dedicated Docker networks and disposable containers. Explicitly protect
the database, backend and other infrastructure. Never conduct isolation experiments against
production containers. Keep the backend, Falco version, rules and workload fixed across runs.
Require `rule_matching: all`; verify baseline capture rules are loaded alongside security rules.
Use the same timestamped action sequences in each variant:

| Variant | Detection/response configuration |
|---|---|
| falco_only | Observe security alerts directly in the Falco JSON log; no ML or automated response |
| hybrid | Observe Falco security alerts and ready-model anomaly results separately |
| full | Continuous monitor with correlation/incident persistence; AUTO_ISOLATION_ENABLED=false |
| response | Same pipeline with isolation enabled for disposable containers |

Hybrid is an experimental comparison, not a new alternative monitor implementation. Record
both layers independently from incident evidence; use a ready, validated per-container model.
Test `NO_BASELINE/LEARNING` separately from `MODEL_READY`. Preserve a clean baseline before
attack trials. A replacement container must learn again; the image name does not transfer trust.

| Scenario | Required evidence / evaluation boundary |
|---|---|
| Container terminal shell | Relevant Falco security rule plus baseline process telemetry; compare ML score |
| Unexpected process spawn | Verify the enabled rule covers the chosen process; ML coverage must be measured |
| Sensitive-file access | Only claim coverage if an enabled security rule matches; baseline file feature captures writes |
| Privilege-related action | Use a safe isolated scenario matching an enabled Falco rule; verify captured syscall fields |
| Networking activity | Compare captured destination/port features and applicable security rules |
| Gate bypass | Plain docker run vs bin/selfsentry-run; exact container registration and audit evidence |
| Multiple related alerts | One incident per container/fixed window, full alert list, no duplicate response |
| Benign administration | Known-benign shell/maintenance actions to quantify false alarms and automation eligibility |
| Component interruption | Stop backend/restart monitor; restore backend; check incident keys and action state |
| Invalid model / no baseline | Falco incident continues; anomaly unavailable; automatic cross-layer confirmation denied |

Run at least 20 attack trials per supported scenario and at least 100 representative benign
windows per variant if practical. State actual denominators, workload, training sample count,
window length and repetitions. Include quiet workloads, workload variation and restarts.
These sample sizes are proposed, not completed measurements or a guarantee of statistical power.

## Measurements

Detection rate = detected attack trials / all labeled attack trials. False-positive rate =
benign trials producing detections / all labeled benign trials. Count an event once per labeled
trial, not once per Falco rule, and state the detection threshold used by each variant.

Use UTC timestamps plus monotonic timers inside one process for durations. Record attack start,
first security detection, correlation completion, database commit, response attempt, verified
containment completion, learning start and model ready. The default 60-second feature window
plus 10 seconds of lateness allowance adds windowing delay; it is not a measured detection
latency. Synchronous backend/Docker operations can add delay. Timestamp precision and polling
introduce measurement uncertainty; report it.

Confirmation accuracy = correctly auto-confirmed trials / all auto-confirmed trials (human
labels required). Duplicate incident rate = trials with extra incident rows for the same window
key / recorded trials. Candidate validity = candidates passing validation / attempted candidates.
Benign rule rejection rate = known-noisy candidates rejected by backtesting / tested noisy
candidates. Recovery success = interruption trials with no lost or duplicate actions / all
interruption trials. Record failures instead of excluding them.

## Aggregation tool

Create `state/evaluation/trials.jsonl`, one JSON object per real trial. Required keys:
`variant` (falco_only/hybrid/full/response), `scenario`, `label` (attack/benign), `detected`
(boolean). Optional paired timing keys are `detection_start/end`, `correlation_start/end`,
`incident_creation_start/end`, `isolation_start/end`, `learning_start/end`, and
`model_readiness_start/end`. Values must be timezone-bearing ISO timestamps.

Optional boolean observations: `auto_confirmation_accuracy`, `candidate_validity`,
`benign_rule_rejection`, `failure_recovery`. Only supply them when their relevant action was
actually observed and independently labeled. Optional `duplicate_incident_count` is a
nonnegative integer, counted from the database for that trial. Preserve failed/missed trials.

```bash
python3 evaluation/measure_results.py state/evaluation/trials.jsonl \
  --output state/evaluation/results.json
```

The tool emits rates, denominators, median and nearest-rank p95 latencies. Missing observations
remain null with n=0; it never substitutes a fabricated result. If no trials have been run,
record "not measured". Human-confirmed and auto-confirmed decisions must be reported separately.

## Acceptance still requiring your test host

- Ready-model baseline quality and false-positive rates for real workloads.
- Real Falco-to-incident replay, graceful service restart and PostgreSQL outage recovery.
- Isolation followed by verified network/process containment and successful manual resume.
- Candidate generation against independently labeled benign history; human approval, native
  Falco compile/load and actual generated-rule re-fire. Historical re-fire evidence is in
  docs/falco_rule_matching.md, but the newly integrated pipeline must also be exercised.
- All four comparison variants and timings above. No live evaluation result is claimed yet.

## Measured paired batch — 11 October 2026

Source: state/evaluation/frozen-batch-20261011.jsonl
Five paired binary-execution / benign-administration repetitions.
Configuration: 20-sample baseline, 60-second windows, 10-second lateness,
automatic isolation disabled, noisy ls rule disabled.

- Persisted attack incidents: 5/5.
- Benign trials producing incidents: 0/5.
- Trials with duplicate incident rows: 0/10.
- Median attack-to-API-visible-incident duration: 68.73 seconds.
- Maximum observed duration: 69.14 seconds.
- All five attack incidents contained Falco security alerts.
- ML anomaly score was 0.143008 for each attack: qualifying ML detections 0/5.
- Automatic confirmations: 0/5 attack trials.

These are controlled workload results, not general detection guarantees.
Earlier false positives and configuration changes remain part of the evaluation.
This batch does not establish an advantage over Falco-only detection.
Separate Falco-only timings and broader workload evaluation remain pending.
