# SelfSentry academic roadmap

Updated 15 October 2026. [TODO.md](TODO.md) tracks actions; the
[academic evidence pack](docs/academic_evidence_pack.md) defines the current thesis,
protocol and evidence boundaries. Production platform expansion is outside scope.

| Priority | Deliverable | Current state / next evidence |
|---|---|---|
| P0 | Supported adaptive-loop mini-study | Reviewed 17 captures: one approved re-fire chain, two preview failures, explicit rejection; no extra coverage |
| P0 | Designed-case matrix | Study-artifact passes distinguished from historical tests; live restart/fault extensions remain unrun |
| P0 | Clear demo proof | Updated 6:40 talk track; isolation OFF; C2 rehearsal/recording explicitly deferred |
| P1 | Evaluation interpretation | Historical 200-trial denominators, timing endpoints, retrospective layers and threats documented |
| P1 | Narrative/report/viva | Thesis-aligned architecture, limitations script, examiner answers and report outline ready |
| P2 | Hybrid contribution analysis | Report Falco-only/ML-only/both/unscored separately; no demonstrated extra attack coverage |
| Reliability | Timestamp skew | Clock validation detects skew; restart is temporary recovery, root cause unresolved |
| Model research | Representative baseline/validation | Default IF preserved; small baseline and experimental SVM false positives remain documented |

Completed implementation/release: image/policy checks; runtime ingestion; per-container
model lifecycle; correlation/persistence; direct isolation/resume and one experimental
SVM automatic response; default-shell mapping; observed timeline; human rule review;
dashboard screenshots; source commits through f465de1. These are bounded functional
results, not production or unseen-workload guarantees.

## Next sequence

1. Apply/review this documentation and research helper; preserve all runtime evidence.
2. Freeze default-IF/manual-study configuration and verify fresh event timestamps.
3. Retain the reviewed mini-study artifacts and publish its measured results with
   hashes/IDs, preview failures, calibration false positive and unperformed cases.
4. Extend only as needed: actual failed submissions, other after-runs or broader
   comparisons require new evidence; one workflow success is not new attack coverage.
5. Resume C2 only when requested; link a real checked recording after it exists.

Future academic research: more representative baselines; independent live comparisons;
richer supported extraction for anomaly-only evidence; measured stage timings and
controlled fault recovery. No automatic generated-rule deployment is proposed.
