# TODO

## Phase 1 — Image Scanner
- [x] Design `ScanResult` / `Vulnerability` / `Secret` / `Misconfiguration` data model
- [x] Implement `trivy_wrapper.py` (invocation, error handling, JSON parsing)
- [x] Write unit tests (16/16 passing, mocked — no Trivy binary needed)
- [x] CLI entry point (`python3 trivy_wrapper.py <image>`)
- [x] Document manual validation steps (`docs/phase1_image_scanner.md`)
- [ ] **Run real Trivy scan manually on your Linux/Docker machine** to confirm end-to-end (blocked on your local environment — see docs/phase1_image_scanner.md)
- [ ] Mark Phase 1 fully closed once manual validation passes

## Phase 2 — Deployment Policy Checker (next up)
- [ ] Define default policy rules (no root user, no privileged mode, no excess capabilities, no writable root FS)
- [ ] Implement `deploy_policy_validator.py`
- [ ] Wire in `ScanResult.has_blocking_findings` from Phase 1
- [ ] Unit tests
- [ ] Docs

## Backlog (later phases — not started)
- [ ] Phase 3 — Falco + eBPF integration
- [ ] Phase 4 — Behavioral baseline + anomaly detection
- [ ] Phase 5 — Correlation Engine
- [ ] Phase 6 — Rule Synthesis Engine (core novelty)
- [ ] Phase 7 — AI Analysis Layer
- [ ] Phase 8 — Backend + Database
- [ ] Phase 9 — Frontend Dashboard
- [ ] Phase 10 — Testing / backtesting validation / evaluation writeup

## Outstanding from design phase (deferred, not urgent)
- [ ] Grayscale `ContainerGuard_AI_Summary.pdf` conversion with highlighted Novelty section (deferred at user's request — revisit only if asked)
