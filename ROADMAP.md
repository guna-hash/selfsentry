# Roadmap

Phase-by-phase build order (see `docs/` for per-phase detail as each is completed).

| # | Phase | Est. duration (solo, part-time) | Status |
|---|-------|----------------------------------|--------|
| 0 | Foundations (Linux, Docker, Python, Git) | 1–2 wks | ✅ self-verified by user |
| 1 | Image Scanner (Trivy) | 3–5 days | ✅ complete (real Trivy validated, pushed to GitHub) |
| 2 | Deployment Policy Checker | 2–3 days | 🔶 code complete (25/25 tests), manual `docker inspect` validation pending |
| 3 | Falco + eBPF (rule-based layer) | 1.5–2 wks | ⬜ not started (biggest risk phase) |
| 4 | Behavioral baseline + anomaly detection | 2–2.5 wks | ⬜ not started |
| 5 | Correlation Engine | 4–6 days | ⬜ not started |
| 6 | Rule Synthesis Engine (core novelty) | 2–2.5 wks | ⬜ not started |
| 7 | AI Analysis Layer (LLM) | 3–5 days | ⬜ not started |
| 8 | Backend + Database | ~1 wk (spread throughout) | ⬜ not started |
| 9 | Frontend Dashboard + Rule Review Queue | 1.5–2 wks | ⬜ not started |
| 10 | Testing, backtesting validation, evaluation writeup | 1–1.5 wks | ⬜ not started |

**Total estimate:** ~10–14 weeks solo part-time / 5–7 weeks solo full-time / 6–8 weeks small team.

## Non-negotiable constraints preserved throughout
- Auto-generated Falco rules must pass backtesting AND get human approval before deployment (Phase 6).
- Rule generation is template-based (Jinja2), never LLM-freehand (Phase 6).
- The LLM layer is advisory-only — never the detection source of truth (Phase 7).
- Reference/citation work must be verified via live search, never recalled from memory.

## Future scope (explicitly not in current build)
- Full Kubernetes integration (admission controllers, OPA/Gatekeeper)
- SHAP explainability, attack-graph/lateral-movement detection, honeytokens, business-context risk scoring, attack-simulation module
