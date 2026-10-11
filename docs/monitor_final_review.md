# SelfSentry final source and acceptance review

Reviewed the uploaded source archive on 12 October 2026 IST (11 October UTC).
Base commit: 45c4dfa; working tree has implementation/evaluation changes not committed.
All 153 supplied manifest hashes matched. The three acceptance summaries record passes
and cleanup. No .env or runtime database was included. This is a source review, not a
claim that changes were pushed to GitHub.

## Verified checks

- Reviewed source: 406 Python tests passed locally. Operator's VM full suite also passed.
- Final polish: Python suite, documented flake8 scope, four frontend severity tests and
  production dashboard build passed locally.
- Five invalid-model regression cases passed on the VM.
- Real no-baseline fallback: incident 178, no auto-confirm/isolation, explicit unavailable ML.
- PostgreSQL outage recovery: incident 179, durable queue, one recovered row, same monitor PID.
- Protection: three identity forms with actual Docker state and synthetic workflow evidence.
- Earlier isolation/resume, gate bypass/registration and native generated-rule re-fire passed.
- AI post-patch incident 177 was ready after HTTP 200. Live 429 recovery remains unobserved.

## Final polish fixes

Alerts now display AI workflow state/reason/retry time and recorded model assessment.
Missing AI cannot silently make a critical incident low severity. /alerts resolves to the
existing Alerts page. Both localhost and 127.0.0.1 Vite origins work. The AI prompt separates
observed behavior from conclusions and does not authorize actions. Evaluation/retry lint
issues are corrected without changing historical measurements or detection thresholds.
Ignore rules keep new baseline/log/backup artifacts out of future source staging; previously
tracked baseline JSON must still be removed from the index without deleting the VM files.

## Measured results and limits

The frozen 200-trial run detected 100/100 labeled attacks and raised incidents for 13/100
benign trials. Auto-confirmed: 5 attacks, no benign trials. Duplicate trial incidents: 0/200.
Falco flags: 100 attacks/10 benign. ML qualification: 7 attacks/3 benign. Union/full outcomes
agree; the 40 quiet windows were not ML-scored. No additional attack coverage beyond Falco
was demonstrated. Attack start to row timestamp: median 68.154 s, p95 68.588 s (n=100).
See monitor_measured_results_20261011.md for denominators and timestamp boundaries.

Independent live Falco-only/hybrid/response variants and raw layer/containment/learning
latencies remain unmeasured. Long-duration production soak, exhaustive daemon/disk faults,
mid-response live-kill injection and lossless replacement-log rotation are not validated.
Production RBAC, Kubernetes, broker, automatic retraining and journal retention are outside
the implemented scope. The shared token is for a local demo. Leave isolation off by default.

Rule candidates remain pending until a human reviews them; an empty review queue is not a
completion criterion. Legacy rule 32 (whoami from sh) remains enabled and broad; assess it
before wider automation. Rule 8 (ls from sh) is disabled. No rule changes were applied by polish.

## Release steps

Apply apply_final_monitor_polish.py while backend/monitor are stopped. Run python3 scripts/verify_final_checks.py,
restart backend/monitor/dashboard, inspect ready/unavailable AI display, and review/stage the
intended source/docs. Remove previously tracked training data from the index only; retain
all measured runtime evidence separately. Record the final source commit and dependency versions.
The evaluation fingerprint alone does not capture runtime source and all AUTO_* environment
settings; use the archive manifest and release commit when describing reproducibility.
