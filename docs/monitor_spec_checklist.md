# Continuous monitor acceptance evidence

Current reviewed status, 12 October 2026 IST. Original pending claims are superseded
by the concrete checks below. Final polish verification and a source commit remain
release steps; scope limitations remain explicit.

| # | Criterion | Evidence / boundary |
|---|---|---|
| 1 | Continuous execution | Live full run, restart and outage; no production soak |
| 2 | Checkpointed ingestion | Live Falco/incident path and restart dedup; rotation loss boundary documented |
| 3 | Gate bypass discovery | Direct start audit and gate registration live checks |
| 4 | Learning/readiness | 20-sample ready baseline; per-container no-baseline check |
| 5 | Falco during learning | Incident 178 live fallback; all six assertions pass |
| 6 | Valid models only | Five invalid/degenerate/review-required regression cases; no live baseline corruption |
| 7 | Correlation evidence | 200 labeled trials; only qualifying ML gets agreement |
| 8 | Persisted automatic incidents | Incident 179 live PostgreSQL outage/recovery; exactly one row |
| 9 | Eligible auto-confirm | 5/100 attacks and 0/100 benign auto-confirmed in frozen batch |
| 10 | Confirmation source | selfsentry-auto records and policy evidence inspected |
| 11 | Policy-controlled isolation | Incident 40 live isolation/resume; protected Docker integration name/short/full ID |
| 12 | Partial/failed responses | Automated checks; exhaustive native failure injection not run |
| 13 | Candidate generation | Reviewed benign corpus and live pending candidates; human review retained |
| 14 | Rule approval/deployment | Rule 5 native validate/load/re-fire; no automatic approval |
| 15 | No destructive replay | Persistent intent and automated interrupted-attempt checks; no forced live mid-response kill |
| 16 | Recovery | Live PostgreSQL and earlier backend interruption/restart checks; exhaustive disk faults not run |
| 17 | Advisory AI | 50 ready/63 rate-limited in full run; bounded retry tests; incident 177 HTTP 200 |
| 18 | Major paths tested | 406 Python tests; four frontend severity tests in final polish |
| 19 | Existing behavior retained | Original tests remain; detection thresholds/baseline unchanged by polish |
| 20 | Measured evaluation | 200 full trials plus verified retrospective layers; independent live variants/timings unmeasured |

Features M1–M4 are delivered. M5 implements operating/testing/evaluation deliverables
and reports actual controlled measurements. The four independent live variants from
the initial plan were not run; retrospective comparison is the delivered alternative.
No production-readiness or added attack-coverage claim is made. See monitor_final_review.md.
