# Designed-case coverage matrix

> Current status: [21 October academic handoff](academic_handoff_20261021.md). It records the latest rule workflow, benign false positive and clock recurrence. Historical entries below retain their original scope.


SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

15 October 2026. **PASS-E**: supplied study artifacts checked offline; **PASS-H**:
earlier reported live pass; **TEST**: source test; **RE-RUN**: evidence still needed.
PASS-E does not mean the reviewer independently operated the VM.
The 15 October study exercised Falco-backed process metadata. The 16 October
extension supports proposals with a retained literal syscall witness; aggregate-only
anomalies remain unsupported. The new anomaly-only live chain remains unverified.

| Case | Expected behavior | Evidence / next artifact | Pass–Fail |
|---|---|---|---|
| Falco-only high priority | Persist alert without invented agreement | Binary incidents 200/204: Critical stock alert, IF ~0.143 nonqualifying, responses off | PASS-E |
| No baseline / learning | Falco incident, explicit unavailable ML | Incident 178; shell probe `reliability-shell-20261012T174808Z.json` | PASS-H |
| Both layers agree | Falco + qualifying default IF assessment | Seven frozen attack windows; IF incident 177 | PASS-H; refresh current case |
| Confirm → candidate | Persist confirmation; template; nonempty backtest; pending queue | 209 confirmed by guna; candidates 21 and 22; 0/65 corpus matches | Operator-supplied current functional pass |
| Anomaly-only synthesis | Retain qualifying same-container/window literal witness; refuse aggregate-only input; require backtest and human approval | Benign incident 211: IF 0.821809; no security alert; literal file witness | Detection/witness observed; synthesis/deployment/re-fire unverified |
| Reject → undeployed | Reviewer saved; exact candidate absent; reason audited | Rule 21 rejected, reason/reviewer retained in audit 949; absent at check | Operator-supplied current functional pass |
| Approve → reload → re-fire | Human decision + active native rule | Rule 22 approved/deployed, audits 951–953; native match linked 210 via 954 | Operator-supplied current functional pass; refreshed timeline confirmed |
| Monitor restart | Resume durable work without duplicate/timeline loss | [Reviewed graceful restart during DB outage](live_restart_results_20261021.md): pending key retained, incident 208, unchanged timeline, one row in bounded duplicate query | PASS-E for this case; crash/other fault extensions NOT RUN |
| Backend/DB restart recovery | Queue drains to one incident after recovery | Incident 179 PostgreSQL outage in `monitor_final_review.md` | PASS-H for recorded outage |
| Isolation default OFF | Standard study makes no response attempt | All 17 capture flags false; six incident responses not attempted | PASS-E for study |
| Clock skew | Reject skew; retain invalid evidence | One reboot/resume check passed; later ~67.5s and ~16437.6s skew recurred | Clock guard observed; permanent correction OPEN |
| Broad template preview | Flag unsafe corpus match rate | 201: 3/36; 202: 8/36; not submitted; no actual refusal calls | PASS-E preview; submission unrun |
| Later benign windows | No learned-rule hits in new windows | Historical 0/3 learned-rule hit windows separate; current pilot has incident 211 in 1/6 benign windows | Pilot complete; representative longer validation OPEN |
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
