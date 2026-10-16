# Completion acceptance — 16 October 2026

Source base: `0dc6374` plus the completion extension and two launcher fixes.
Evidence below comes from operator-supplied VM console output. The underlying VM JSON files
have not been independently downloaded/reviewed in this session. This is functional
acceptance evidence, not a production readiness, attack coverage or accuracy measurement.

## Results

| Check | Observed result | VM evidence |
|---|---|---|
| Automated checks before launcher fixes | 468 Python tests, lint, 7 frontend tests and build passed | `state/evaluation/final-checks-20261016T044054Z` |
| Managed startup | Backend, monitor and frontend running; automatic isolation disabled | Operator console |
| Detector configuration | Target MODEL_READY with isolation_forest; new peer LEARNING; both Monitoring Active | Operator console |
| Two-container continuity | Peer paused/disconnected while target received newer telemetry and closed feature window 1792126860; monitor healthy | `state/evaluation/completion-live/continuity.json` |
| Resume | Peer running/unpaused, original network names/IDs restored; audit 816; policy compliant with zero violations | `state/evaluation/completion-live/resume.json` |
| Protection | Name, short ID and full ID prevented isolation; running/network state unchanged; disposable fixture removed | `state/evaluation/acceptance/selfsentry-protected-c7aa0964/evidence.json` |
| PostgreSQL outage | Monitor kept running; durable queued event delivered exactly once as incident 206; database restored; no response attempted | `state/evaluation/acceptance/selfsentry-db-recovery-fa8a25b0/evidence.json` |
| Guidance completeness | All 206 incidents and 6 deployment records had title, explanation, rationale and 1–3 fixes; deployments included 2 blocked and 2 overridden | Operator API output |
| Native Falco re-fire | Previously human-approved rule 18 from incident 200 fired on ss-study-true with parent sh; new incident 207 and audit 829 | `state/evaluation/completion-live/native-refire.json` |
| Authoritative rejection | Submitted FP rate 0 ignored; actual 25 FP / 65 benign events, 40 TN, rate 0.3846; HTTP 422, flag_for_revision, passed=true | `state/evaluation/completion-live/backtest-guard.json` |

The native replay used a harmless copy of /bin/true in a disposable temporary directory.
It verifies deployed-rule execution and evidence linkage, not malicious intent or added
coverage. The backtest corpus is benign-only: TP remains null/unmeasured.

## Fixes and regression coverage

The Docker prerequisite probe now explicitly closes its client rather than requiring a
context-manager protocol. The port probe uses SO_REUSEADDR to distinguish recently closed
TCP connections from an active listener. The acceptance helper loads .env before configuration
and leaves authoritative enforcement with the backend. Four additional regression tests cover
these cases and the helper against the real API route, raising the local suite to 472 tests.
Local full release verification passed: 472 Python tests, lint, 7 frontend tests and build.
The operator then passed the final VM rerun: 472 Python tests, lint, 7 frontend tests
and build, saved at state/evaluation/final-checks-20261016T061546Z.
A subsequent local dashboard visibility fix adds audit ID lookup/cursor tests: 475 Python
tests, lint, 7 frontend tests and build pass locally; operator VM verification also passed all four checks. Evidence: state/evaluation/final-checks-20261016T063151Z.

## Limits and follow-up

- Targeted operator visual checks passed: tracked-container labeling and audit lookup for IDs 816 and 829. The operator identified ambiguous tracked-container
  labeling and audit history access; the follow-up fixes those display issues. Complete
  visual acceptance is not yet claimed. Frontend tests/build are not visual QA.
- This run contains Low, High and Critical incidents. Medium guidance has automated coverage;
  no Medium live incident is invented for completeness.
- Paused containers remain visible/audited. They cannot emit new process telemetry until resumed.
- Running target telemetry and window closure continued during peer isolation; PostgreSQL
  outage delivery recovered. These tested cases do not prove uptime through host, disk,
  Falco or kernel failure, nor unlimited scale.
- The process rule was previously approved. This run does not establish a new anomaly-only
  discovery chain or a native process/file-write re-fire. No new automatic Isolation Forest
  isolation experiment was performed; automatic isolation remains disabled by default.
- The previously reported blocked/overridden records demonstrate stored guidance and decision
  visibility, not a new pre-deployment experiment during this acceptance run.
- No new precision/recall, latency, resource, drop-rate or representative corpus claim follows.
  Shared-token operator authorization and existing host-local deployment limits remain.

The institute contribution remains constrained template synthesis, authoritative benign
backtesting, human rule approval and native Falco re-fire within a supervised hybrid loop.
LLMs remain optional advisory enrichment; neither approval nor rule generation depends on them.
