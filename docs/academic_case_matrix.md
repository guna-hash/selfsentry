# Designed-case coverage matrix

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

15 October 2026. **PASS-E**: supplied study artifacts checked offline; **PASS-H**:
earlier reported live pass; **TEST**: source test; **RE-RUN**: evidence still needed.
PASS-E does not mean the reviewer independently operated the VM.
Synthesis requires Falco process metadata; anomaly-only synthesis is unsupported.

| Case | Expected behavior | Evidence / next artifact | Pass–Fail |
|---|---|---|---|
| Falco-only high priority | Persist alert without invented agreement | Binary incidents 200/204: Critical stock alert, IF ~0.143 nonqualifying, responses off | PASS-E |
| No baseline / learning | Falco incident, explicit unavailable ML | Incident 178; shell probe `reliability-shell-20261012T174808Z.json` | PASS-H |
| Both layers agree | Falco + qualifying default IF assessment | Seven frozen attack windows; IF incident 177 | PASS-H; refresh current case |
| Confirm → candidate | Persist confirmation; template; nonempty backtest; pending queue | Incident 200 → rule 18; candidate JSON pending, reviewed export links confirmation | PASS-E for B1 |
| Anomaly-only synthesis | Explicit unsupported extraction; incident retained | `pattern_extractor.py`; SVM incidents 193–196 | Unsupported; TEST refusal |
| Reject → undeployed | Reviewer saved; exact candidate absent; reason audited | Rule 19 rejected; intermediate hash unchanged, rule 18 pending; final YAML/alerts omit `_203`; full reason/audit export missing | PASS-E core outcome; reason unexported |
| Approve → reload → re-fire | Human decision + active native rule | Rule 18 deployed; `_200` native event and incident 204 timeline; reload log not supplied | PASS-E re-fire; reload log absent |
| Monitor restart | Resume durable work without duplicate/timeline loss | `test_observed_timeline_survives_outbox_restart_in_chronological_order`; worker replay tests | TEST; live mid-flight RE-RUN |
| Backend/DB restart recovery | Queue drains to one incident after recovery | Incident 179 PostgreSQL outage in `monitor_final_review.md` | PASS-H for recorded outage |
| Isolation default OFF | Standard study makes no response attempt | All 17 capture flags false; six incident responses not attempted | PASS-E for study |
| Clock skew | Reject skew; retain invalid evidence | Prior SVM batch: 19 invalid. Current 17 captures valid/zero skew | PASS-E current checks; cause unresolved |
| Broad template preview | Flag unsafe corpus match rate | 201: 3/36; 202: 8/36; not submitted; no actual refusal calls | PASS-E preview; submission unrun |
| Later benign windows | No learned-rule hits in new windows | Admin/config/curl: 0/3 hit windows, 0/3 incident windows; repeated workload families | PASS-E, limited sample |
| Experimental response | Eligible SVM/Falco isolation + recoverable resume | Incident 190, saved JSON + paused-state console; acceptance doc | PASS-H, SVM-only functional case |

Evidence index: [measured results](monitor_measured_results_20261011.md),
[acceptance](reliability_acceptance_20261013.md), [protocol](academic_study.md),
[reviewed study](academic_results_20261015.md).
Mark actual FAIL, INVALID or NOT RUN where appropriate after execution; preserve IDs,
artifact paths, exclusions and configuration hashes. Never infer a pass from a proposed command.

**Out of scope:** universal/zero-day coverage; production CWPP/fleets/Kubernetes/
multi-tenancy; autonomous rule deployment; model self-retraining; ML-only pattern
invention; representative production FPR; unrun independent live ablations;
complete stage/containment latency; exhaustive failure/soak validation. Backtesting
estimates corpus matches, not safety; templates can lose original context.
