# TODO

## Phase 1 — Image Scanner
- [x] Design `ScanResult` / `Vulnerability` / `Secret` / `Misconfiguration` data model
- [x] Implement `trivy_wrapper.py` (invocation, error handling, JSON parsing)
- [x] Write unit tests (16/16 passing, mocked — no Trivy binary needed)
- [x] CLI entry point (`python3 trivy_wrapper.py <image>`)
- [x] Document manual validation steps (`docs/phase1_image_scanner.md`)
- [x] Run real Trivy scan manually on your Linux/Docker machine to confirm end-to-end
- [x] Mark Phase 1 fully closed once manual validation passes — **Phase 1 complete, pushed to GitHub**

## Phase 2 — Deployment Policy Checker
- [x] Define default policy rules (no root user, no privileged mode, no excess capabilities, no writable root FS)
- [x] Implement `deploy_policy_validator.py`
- [x] Wire in Phase 1's image-scan verdict via `image_scan_has_blocking_findings` (kept decoupled from image-scanner/ — no direct import)
- [x] Unit tests (25/25 passing, mocked — no Docker daemon needed)
- [x] Docs (`docs/phase2_deployment_policy_checker.md`)
- [ ] **Run real `docker inspect` validation on your Linux/Docker machine** (privileged container caught + clean container passes) — blocked on your local environment, see docs/phase2_deployment_policy_checker.md
- [ ] Mark Phase 2 fully closed once manual validation passes

## Backlog (later phases — not started)
- [ ] Phase 3 — Falco + eBPF integration (next up once Phase 2 manual validation is done)
- [ ] Phase 4 — Behavioral baseline + anomaly detection
- [ ] Phase 5 — Correlation Engine
- [ ] Phase 6 — Rule Synthesis Engine (core novelty)
- [ ] Phase 7 — AI Analysis Layer
- [ ] Phase 8 — Backend + Database
- [ ] Phase 9 — Frontend Dashboard
- [ ] Phase 10 — Testing / backtesting validation / evaluation writeup

## Outstanding from design phase (deferred, not urgent)
- [ ] Grayscale `ContainerGuard_AI_Summary.pdf` conversion with highlighted Novelty section (deferred at user's request — revisit only if asked)
