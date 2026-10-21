# SelfSentry academic handoff — 21 October 2026

## Verified results
- Incident 208 survived queued graceful restart during a PostgreSQL outage,
  retaining its timeline with one incident in bounded duplicate checks.
- Incident 209 was confirmed by guna. Candidate 21 was rejected with a
  retained reason and audit 949; its rule was absent at the rejection check.
- New candidate 22 passed submission and approval backtests: 0/65 benign
  corpus matches. Audits 951–953 recorded revalidation, approval and deployment.
- One native generated-rule match linked incident 210 through audit 954.
  The operator confirmed its timeline persisted after refresh.
- Both disposable rule-review fixtures were removed; approved rule 22 remains.

## Benign pilot and anomaly-only evidence
Source: 9cbbf53. Evidence: state/evaluation/benign-pilot-b1qgvwts.
All six sampled one-minute windows were valid with zero observed skew.

| Workload | Round 1 events / incidents | Round 2 events / incidents |
|---|---|---|
| nginx -t | 25 / none | 23 / incident 211 |
| Static checksum | 19 / none | 19 / none |
| File metadata | 19 / none | 19 / none |

Incident 211 had no Falco security alert, IF score 0.821809 above 0.8,
and a literal nginx access-log write witness. It occurred during benign
activity: preserve it as a false positive, not an attack.
Its reviewed snapshot was unconfirmed, with no response or candidate.
The model used 22 deduplicated events versus 23 native capture records.

One incident-bearing window out of six is a small pilot observation,
not representative production FPR, independent workload validation,
or an uninterrupted twenty-minute soak. Baseline/rule hashes stayed fixed.
Earlier admin and twenty-file probes produced no incidents; separate
admin offline replay scored 0.143008. Historical studies remain separate.

## Reliability and outstanding work
Boot synchronization ordering passed one reboot; one operator-confirmed
suspend/resume cycle initially passed. Later same-boot clock jumps recurred,
with about 67.5s and 16437.6s event skew. Trigger unknown. Restart restored
freshness after initialization; permanent clock correction remains OPEN.
Preserve invalid attempts and keep automatic study actions disabled.

Anomaly-only incident creation and literal witness retention are observed.
Anomaly-only synthesis/backtest/approval/native process/file-write re-fire,
representative longer evaluation, current-release detection/load/drop
measurements, crash/SIGKILL, disk-full, rotation and broader accessibility
checks remain unverified. Do not claim these cases passed.

## Six-minute demonstration
1. 0:00–1:00: Explain the image gate, runtime layers and dashboard.
2. 1:00–3:00: Show incident 209, rejected rule 21 and approved rule 22.
3. 3:00–4:00: Show incident 210 native generated-rule event and audit 954.
4. 4:00–5:00: Show incident 211 and explain the benign false positive.
5. 5:00–6:00: State reliability/model limits and mandatory human approval.

Label saved evidence clearly. Before any live demonstration, check service
status and save a fresh native clock preflight. Retain failed probes.
Do not display credentials. Rehearsal/recording remains pending until
actually performed and reviewed by the operator.

Earlier VM release evidence: 538 Python tests plus 7 subtests, lint,
150 frontend tests and build at final-checks-20261021T092120Z.
This handoff reconciles supplied outputs, not independent VM operation
or full review of every raw artifact. Runtime evidence remains on the VM.

See live_rule_review_20261021.md, clock_boot_validation_20261021.md
and anomaly_only_probes_20261021.md for supporting records.

## Handoff verification
VM release checks passed: 538 Python tests plus 7 subtests, lint,
150 frontend tests and production build.
Evidence: state/evaluation/final-checks-20261021T164630Z.
