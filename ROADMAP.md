# SelfSentry roadmap

Reconciled 13 October 2026. [TODO.md](TODO.md) is the actionable release checklist;
[monitor_final_review.md](docs/monitor_final_review.md) records previous VM evidence.

| Phase | Current status | Remaining acceptance |
|---|---|---|
| 1 Image scanning | Implemented; real Trivy validation recorded | Demo preparation |
| 2 Deployment policy | Implemented and unit tested | A1 VM probe passed; retain report |
| 3 Falco/eBPF | Live events recorded; monitor/parser implemented | A2 VM probe and dashboard confirmed |
| 4 Behavioral detection | Per-container baseline and model lifecycle implemented | Forest saturation reproduced; opt-in SVM needs independent benign validation |
| 5 Correlation | Windowed scoring, durable inbox/outbox, fallback paths implemented | Controlled SVM response passed; demo recording remains |
| 6 Rule synthesis | Templates, backtest, review/deploy and re-fire recorded | Always retain human approval; review broad legacy rules |
| 7 Advisory analysis | Optional AI summary implemented | LLM narrative timeline integration; live 429 recovery evidence |
| 8 API/database | Incident, confirmation, evidence and workflow persistence implemented | Current release PostgreSQL smoke checks |
| 9 Dashboard | Upgraded at e781e02; observed timeline added | VM screenshots and recording |
| 10 Evaluation/release | 200-trial full run and retrospective comparison delivered | A1/A2 and SVM automatic response passed; release commit/push remains |

## Next release sequence

1. Apply source changes with backend/monitor stopped; preserve runtime state.
2. Run offline release verification, then restart the services.
3. Retain passing A1/A2 probe reports and the operator-confirmed dashboard timeline.
4. Retain SVM incident 190 isolation/resume evidence; leave automatic actions off
   during ordinary observation. Independent benign candidate evaluation remains open.
5. Capture three screens, rehearse the 5–7 minute script and record the demo.
6. Review/stage source changes, commit and push; retain runtime evidence separately.

## Future work

Independent live Falco-only/hybrid/response runs; separate layer/containment timings;
long-duration fault/soak testing; baseline drift/retraining; RBAC and retention;
Kubernetes admission/runtime integration. These are outside demonstrated acceptance.
