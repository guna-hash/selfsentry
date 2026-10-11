# SelfSentry measured full-pipeline evaluation — 11 October 2026

## Evidence and configuration

Source: `selfsentry-full-evidence.tar.gz`, containing the 200 records in
`state/evaluation/full-20261011-only.jsonl`, their schedule, incident snapshot,
aggregated results, and the 20-sample target baseline.
All 200 trial IDs and schedule entries are unique; all records share configuration
fingerprint `961602fe18bdd46c05d5260cc19df8234fe789f9b1ff464f0656f41b9a0b65a9`.
The uploaded baseline SHA-256 matches the recorded fingerprint:
`f354809d2ad5fa7406e34024bb65c9f3aea37815493050b92741debac412fbba`.
Target: container `12160024642b`; 60-second windows, 10-second lateness;
automatic isolation off. No invalid trials or duplicate-incident trials were recorded.
The software working tree was dirty: the fingerprint does not establish identical
runtime code across future runs. Preserve the actual source used for this experiment.

## Measured outcomes

| Scenario | Labeled trials | Persisted incident | Qualifying ML evidence in persisted incidents | Auto-confirmed |
|---|---:|---:|---:|---:|
| Terminal shell | 20 attack | 20 | 1 | 0 |
| New binary execution | 20 attack | 20 | 0 | 0 |
| Sensitive file read | 20 attack | 20 | 2 | 2 |
| Symlink over sensitive file | 20 attack | 20 | 3 | 3 |
| Standard stream/socket redirection | 20 attack | 20 | 1 | 0 |
| Benign administration | 20 benign | 0 | 0 (retrospective replay) | 0 |
| Benign configuration read | 10 benign | 2 | 2 | 0 |
| Benign local HTTP fixture | 10 benign | 10 | 0 | 0 |
| Benign shell directory listing | 20 benign | 1 | 1 | 0 |
| Quiet | 40 benign | 0 | Not scored: no events | 0 |

Incident detection: 100/100 attacks (Wilson 95% interval 96.30–100%).
False-positive rate: 13/100 benign trials (7.76–20.98%). Forty benign trials
were quiet; among the 60 active benign trials, incidents occurred in 13/60 (21.67%).
Attack automatic-confirmation coverage: 5/100 (2.15–11.18%).
Confirmation precision under the controlled scenario labels: 5/5 (56.55–100%).
Controlled simulations are labels for this experiment, not evidence of genuine compromise.

All 100 attack incidents contain Falco security alerts. Only seven have qualifying
ML evidence; five meet automatic-confirmation policy. The evidence does not establish
an attack-detection advantage over Falco, nor an independently operated Falco-only trial.
The subsequent retrospective comparison covers all 200 windows and is recorded below.
Do not populate unrun live comparison variants by copying full-pipeline results into them.

## Timing boundary

Attack start to database row timestamp: median 68.154 seconds; nearest-rank p95
68.588 seconds; maximum 69.279 seconds, n=100. Naive database timestamps were explicitly
interpreted as Asia/Kolkata and converted to UTC. These server-generated row timestamps
are not verified transaction-commit completion timestamps. This scheduled run did not
poll incident visibility, or measure Falco receipt, ML qualification, correlation,
isolation, learning, or model readiness latencies. Those measurements remain unavailable.

## False-positive attribution

The ten benign HTTP incidents contain `Redirect STDOUT/STDIN to Network Connection in
Container`, two alert entries per incident. Their ML score is approximately 0.4582 and
does not qualify. The benign fixture uses Bash `/dev/tcp` plus redirected streams to
make a loopback HTTP request: it performs the operation this rule monitors. Preserve
these ten known-benign detections. A conventional HTTP-client fixture would constitute
a separate workload/configuration comparison; do not retrospectively relabel the trials,
exclude them, or disable the general socket-redirection security rule to remove this result.

The two configuration-read false positives are anomaly-only (score approximately 0.8430),
as is the directory-listing false positive (approximately 0.8455). None was confirmed.
No global threshold change can be justified solely from these individual examples.

## Workflow and AI evidence

Of 113 persisted incidents: 108 unconfirmed, five confirmed; all 113 responses are
not attempted because isolation is off. Five candidates are pending human review:
rule IDs 12–16 from incidents 70, 80, 94, 98 and 151. These are not deployment evidence;
their backtests and native validation need review before approval.
AI explanations: 50 ready, 63 unavailable. The operator's run-scoped JSON log
count reported 50 HTTP 200 responses, 63 HTTP 429 responses and 63 unavailable
warnings, with no unparseable log lines. This attributes the failures to provider
rate limiting; the specific request/token/quota limit was not established. AI
availability is not a detection/confirmation criterion. A bounded retry patch was installed afterward and the full test suite passed on the VM.
A post-patch request for incident 177 succeeded with HTTP 200. Live 429-to-success
recovery was not observed; cooldown, retry limits and restart persistence have
automated-test coverage.

## Acceptance and review closeout

No-baseline live fallback (incident 178), PostgreSQL outage recovery (179), and
real-Docker protected-container workflow checks (name/short/full ID) passed.
Five invalid/degenerate-model regression cases passed. All three acceptance
summaries were reviewed from the source archive. Protection used synthetic policy
evidence and a fake backend; the other two checks used the actual running pipeline.
A local review reproduced 406 Python test passes. Final polish requires a final VM
verification and release commit; it does not reclassify or replace the frozen trials.

Independent live comparison variants and separate layer/response/learning timings
remain unmeasured. Exhaustive fault injection and production soak remain limitations.
Human review of outstanding candidates remains an operator workflow, not a requirement
to deploy every generated rule. Old whoami-from-sh rule 32 is still enabled and broad;
review it before using automation on real workloads. The prior ls-from-sh rule 8 is disabled.

## Verified retrospective layer comparison

Local replay on the test VM verified all 113 saved incident assessments against
retained telemetry and the matching baseline. All 200 reconstructed union outcomes
matched persisted incident outcomes (zero mismatches).

| Layer observation | Attack flags / 100 | Benign flags / 100 |
|---|---:|---:|
| Stored Falco security alerts | 100 | 10 |
| Replayed ML qualification (threshold 0.8) | 7 | 3 |
| Union / persisted full-pipeline incidents | 100 | 13 |
| Automatic confirmation | 5 | 0 |

ML scored all 100 attack and 60 active benign windows. Forty quiet windows contained
no baseline telemetry and were not scored: absence of ML qualification there is not
an affirmative normal classification. Among scored benign windows, ML qualified 3/60.
The union of Falco and ML flags added three false positives and no additional attack
detections for these scenarios. This is an observation/replay comparison from one
full-pipeline execution, not four independently executed experimental variants.
Live Falco receipt and ML processing latencies remain unmeasured.

## Post-patch verification — 11 October UTC / 12 October IST

The operator reported the full Python suite passing after installing the AI retry
patch and updating obsolete evaluation-contract tests. The exact final pass count
was not pasted. Monitor PID 41437 restarted healthy; the existing target remained
MODEL_READY with 20 samples. Incident 177 was detected and auto-confirmed with no
duplicate incident, clock skew zero, and trial-start-to-API-visibility duration
70.0758 seconds. Its AI explanation became ready (HTTP 200); automatic isolation
was not attempted because it was disabled. This is a separate smoke test, not an
additional observation in the frozen 200-trial comparison.

AI wording that calls this controlled simulation a compromised container is an
advisory overstatement. The ground-truth scenario label remains a controlled test.
