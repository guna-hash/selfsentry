# TODO

_Last reconciled: after merging Phase 7/8/9 (teammate) + Phase 4 (this session) into main._

## Phase 1 — Image Scanner
- [x] Design `ScanResult` / `Vulnerability` / `Secret` / `Misconfiguration` data model
- [x] Implement `trivy_wrapper.py`
- [x] Unit tests (16/16 passing, mocked)
- [x] CLI entry point
- [x] Docs (`docs/phase1_image_scanner.md`)
- [x] Real Trivy scan validated on Linux/Docker machine
- [x] **Phase 1 fully closed, pushed to GitHub**

## Phase 2 — Deployment Policy Checker
- [x] Default policy rules (root user, privileged, capabilities, writable rootfs)
- [x] Implement `deploy_policy_validator.py`
- [x] Wire in Phase 1's `image_scan_has_blocking_findings` (decoupled, no direct import)
- [x] Unit tests (25/25 passing, mocked)
- [x] Docs (`docs/phase2_deployment_policy_checker.md`)
- [ ] **Run real `docker inspect` validation** (privileged container caught + clean container passes) — status unconfirmed as of this conversation, see docs/phase2_deployment_policy_checker.md
- [ ] Mark Phase 2 fully closed once confirmed

## Phase 3 — Falco Rule Engine + eBPF
- [x] Real Falco install (`falco-modern-bpf.service`), confirmed running
- [x] Implement `falco_integration.py` (alert parsing, shape #1) — 18/18 tests passing
- [x] Implement `ebpf_collector.py` as a facade over Falco's stream (scope decision: no separate raw eBPF collector built — documented, acceptable for capstone scope)
- [x] Real Falco events confirmed flowing on VM (used extensively during Phase 4 validation)
- [ ] Explicit confirmation of a real *default-ruleset* security alert (e.g. "Terminal shell in container") parsed end-to-end through `falco_integration.py`'s real shape #1 output — not directly demonstrated in this conversation (Phase 4 used the separate baseline-capture rules, not the default security rules, for its live tests)
- [ ] Mark Phase 3 fully closed once the above is confirmed

## Phase 4 — Behavioral Baseline + Anomaly Detection
- [x] `feature_extractor.py`, `baseline_builder.py`, `anomaly_model.py` — 34/34 tests passing
- [x] `falco-rules/baseline-capture-rules.yaml` (real baseline event capture)
- [x] `baseline_collector.py`, `collect_baseline.py`, `validate_live.py`
- [x] Real learning-window capture (20 samples, test-container)
- [x] Real live validation: normal=0.2595, docker-exec-triggered=0.9977 (ANOMALY)
- [x] Documented known limitation: `proc.name` race on first exec'd process
- [x] Lint clean (flake8), committed, pushed
- [x] **Phase 4 fully closed**

## Phase 5 — Correlation Engine
- [x] Implement `risk_scorer.py` (corrected against real backend schema)
- [x] Implement `event_router.py` (confidence-weighted routing, real-world SOC-style)
- [x] Unit tests: 33/33 passing (`test_risk_scorer.py` + `test_event_router.py`)
- [x] Real Groq `ai_summary` integration confirmed working (fixed `GROQ_API_KEY` env var bug)
- [x] `validate_pipeline.py`: local simulation + real backend POST integration confirmed (4/4 scenarios, ids 4-7 persisted with real ai_summary)
- [x] `docs/phase5_correlation_engine.md` written
- [ ] Stage 5 manual validation: live Falco + live anomaly model (no simulated data) — deferred to Phase 6's live loop demo


## Phase 6 — Rule Synthesis Engine (CORE NOVELTY) — ✅ DONE 2026-10-01
- [x] confirmation_manager.py — verified against real backend
- [x] pattern_extractor.py — verified against real incident
- [x] rule_template_generator.py + template — verified, Falco schema validated
- [x] rule_backtester.py — verified, real 1.91% FP rate on 1,784 events
- [x] rule_deployer.py — verified, live-deployed to real Falco
- [x] rule_lifecycle_manager.py — verified, real TP/FP tracked in Postgres
- [ ] Phase 10: resolve backend /confirm persistence gap
- [ ] Phase 10: investigate deployed-rule re-fire gap

## Phase 7 — AI Threat Analysis ✅ (teammate, merged)
- [x] `root_cause_summarizer.py`, `attack_timeline_builder.py` implemented for real
- [x] Merged via PR #1 (`c6c5957`)
- [ ] Not yet verified by this side of the team — worth a joint sync per your `MyGuide_TrackA.md`'s weekly-sync process

## Phase 8 — Backend + Database ✅ (teammate, merged)
- [x] SQLAlchemy models, `incidents.py`, `rules.py`, `main.py`
- [x] Per commit message: "Verified end-to-end: incident creation -> automatic AI summary -> persisted in PostgreSQL"
- [x] Merged (`ad49251`)

## Phase 9 — Frontend Dashboard ✅ (teammate, merged)
- [x] React app, `Alerts.jsx`, `RuleReviewQueue.jsx`, dark security-ops theme redesign
- [x] Merged via PR #3 (`8b68bfa`)

## Phase 10 — Joint Integration & Evaluation — IN PROGRESS
- [x] auto_isolate.py implemented and unit-verified
- [x] backend /confirm endpoint fixed to persist confirmed_incidents
- [x] event_router.py hardened against isolation failures
- [x] rule_performance schema fix (UNIQUE constraint)
- [ ] auto_isolate.py tested against a real live container (not just the not-found case)
- [ ] Full end-to-end demo recorded
- [ ] Evaluation writeup (real FP rate, detection latency, limitations)
- [ ] Auto-rule firing gap root-caused (optional, time permitting)
- [ ] Final README/CHANGELOG/ROADMAP pass

## Outstanding from design phase (deferred, not urgent)
- [ ] Grayscale `ContainerGuard_AI_Summary.pdf` conversion with highlighted Novelty section (deferred, revisit only if asked)

## Housekeeping
- [ ] `ROADMAP.md` had leftover raw git-diff text accidentally pasted in — cleaned up in this pass, see commit
- [ ] Confirm with teammate whether `docs/interfaces.md` (the 4 shared data contracts) was kept up to date as Phase 7/8/9 were built — this file is critical for Phase 5's risk_scorer.py to stay compatible with what the backend actually expects
