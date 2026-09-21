# Roadmap

Phase-by-phase build order (see `docs/` for per-phase detail as each is completed).

_Last reconciled: after merging Phase 7/8/9 (teammate) + Phase 4 (this session) into main._

| # | Phase | Est. duration (solo, part-time) | Status |
|---|-------|----------------------------------|--------|
| 0 | Foundations (Linux, Docker, Python, Git) | 1–2 wks | ✅ self-verified |
| 1 | Image Scanner (Trivy) | 3–5 days | ✅ complete, real Trivy validated, pushed |
| 2 | Deployment Policy Checker | 2–3 days | 🔶 code complete (25/25 tests), manual `docker inspect` validation unconfirmed |
| 3 | Falco + eBPF (rule-based layer) | 1.5–2 wks | 🔶 real Falco running + confirmed events, default-ruleset alert path not explicitly re-verified |
| 4 | Behavioral baseline + anomaly detection | 2–2.5 wks | ✅ complete — validated on real Falco/Docker data |
| 5 | Correlation Engine | 4–6 days | ✅ done (Stage 5 live validation deferred to Phase 6) |
| 6 | Rule Synthesis Engine (core novelty) | 2–2.5 wks | ⬜ not started |
| 7 | AI Analysis Layer (LLM) | 3–5 days | ✅ complete (teammate, merged PR #1) |
| 8 | Backend + Database | ~1 wk (spread throughout) | ✅ complete (teammate, merged) — verified end-to-end per commit |
| 9 | Frontend Dashboard + Rule Review Queue | 1.5–2 wks | ✅ complete (teammate, merged PR #3, redesigned) |
| 10 | Testing, backtesting validation, evaluation writeup | 1–1.5 wks | ⬜ not started — blocked on Phases 5 & 6 |

**Real remaining work:** Phase 5 (Correlation Engine — the glue between your detection layers and the backend/dashboard your teammate already built), Phase 6 (Rule Synthesis Engine — the project's core novelty claim, still untouched), and Phase 10 (final integration + writeup).

## Non-negotiable constraints preserved throughout
- Auto-generated Falco rules must pass backtesting AND get human approval before deployment (Phase 6).
- Rule generation is template-based (Jinja2), never LLM-freehand (Phase 6).
- The LLM layer is advisory-only — never the detection source of truth (Phase 7 — confirm this held true in teammate's implementation).
- Reference/citation work must be verified via live search, never recalled from memory.

## Future scope (explicitly not in current build)
- Full Kubernetes integration (admission controllers, OPA/Gatekeeper)
- SHAP explainability, attack-graph/lateral-movement detection, honeytokens, business-context risk scoring, attack-simulation module

## Outstanding housekeeping
- Grayscale `ContainerGuard_AI_Summary.pdf` conversion with highlighted Novelty section (deferred)
- Confirm `docs/interfaces.md` (shared data contracts) is current against what Phase 7/8/9 actually implemented, before building Phase 5 against it
