# Phase 6 — Rule Synthesis Engine (Core Novelty)

**Status:** code-complete, all 6 sub-modules verified against real infrastructure (Falco, Postgres, backend-api). Two findings documented in `docs/known_limitations.md`, not hidden.

## What this phase delivers
A pipeline that converts a confirmed incident into a new, backtested, deployed Falco detection rule — with mandatory human approval and no LLM involved in writing rule syntax.

Flow: confirm → extract pattern → generate rule (Jinja2) → backtest against real benign history → deploy to live Falco (after approval) → track TP/FP outcomes.

## Sub-modules and what was verified

### 1. `confirmation_manager.py`
Calls the real backend endpoint `POST /incidents/{id}/confirm?confirmed_by=<name>`.
**Verified:** confirmed real incident 8 against the live backend-api; got back `{'status': 'confirmed', 'incident_id': 8, 'confirmed_by': 'guna'}`, visible as a `200 OK` in the backend's own logs.

### 2. `pattern_extractor.py`
Parses a confirmed incident's `falco_alert.output` free text into a structured `{container_id, rule_name, proc_name, parent_proc, action}` pattern. Deliberately narrow/literal, per project design constraint.
**Verified:** extracted a real pattern from incident 8 (`rule_name: "Terminal shell in container"`). Documented scope limitation: anomaly-only incidents (no `falco_alert`) are not supported for extraction in v1 — raises `PatternExtractionError` explicitly rather than guessing.

### 3. `rule_template_generator.py` + `templates/falco_rule_template.yaml.j2`
Renders a pattern dict into valid Falco YAML via Jinja2 — **never LLM-freehand**, per the project's non-negotiable safety constraint.
**Verified:** generated `Auto_Generated_ls_from_sh_8`, confirmed valid by Falco's own schema validator on load.

### 4. `rule_backtester.py`
Replays the candidate rule's actual rendered condition against real historical benign events (sourced from this project's own Phase 4 baseline-capture Falco rule, `Baseline Process Spawn` — not synthetic data).
**Verified:** backtested `Auto_Generated_ls_from_sh_8` against 1,784 real historical events; matched 34; false-positive rate 1.91%, under the 5% threshold; verdict `pass`.

### 5. `rule_deployer.py`
Appends an approved rule to `falco-rules/auto-generated-rules.yaml` (never `base-rules.yaml`) and triggers Falco's hot-reload via `systemctl reload falco-modern-bpf`.
**Verified end-to-end on live Falco:** rule written, validated as YAML, Falco reloaded, confirmed via `journalctl` showing `auto-generated-rules.yaml | schema validation: ok`.
**Known finding (documented in known_limitations.md):** a manual re-trigger of the exact matching behavior (`ls` spawned by `sh`) did not visibly re-fire the deployed rule in the same test session. The deployment mechanism itself (write/validate/reload) is proven; the live re-fire has not yet been reproduced and is flagged for follow-up, not claimed as fully working.

### 6. `rule_lifecycle_manager.py`
Records true/false-positive outcomes to the real `rule_performance` Postgres table and flags rules for retirement review above a 50% FP ratio.
**Verified:** recorded 1 TP + 1 FP against a real `generated_rules` row; `rule_performance` table correctly showed `true_positives=1, false_positives=1`; retirement check correctly returned `True` (50% ratio ≥ 0.5 threshold).
**Schema fix applied:** added a missing `UNIQUE` constraint on `rule_performance.rule_id` (required for the upsert logic) — this was not present in the original Phase 8 schema.

## Integration findings for Phase 10 (joint)
- The backend's `POST /incidents/{id}/confirm` returns a success response but does **not** persist a row to `confirmed_incidents`, and `incidents` has no status column either. The `confirmed_incidents → generated_rules` chain currently has to be populated manually. This is backend-api (Phase 8) scope — flagged for the joint Phase 10 integration pass, not fixed here.
- `rule_deployer.py` writes directly to the Falco rules file; it does not currently read from or write to `generated_rules`/`rule_performance` itself for the deploy step — only `rule_lifecycle_manager.py` touches `rule_performance`. Phase 10 should decide whether `rule_deployer.py` should also update `generated_rules.status` to `'deployed'` after a successful write.

## What's original vs. off-the-shelf
Off-the-shelf: Jinja2 (templating library), Falco (rule engine), PostgreSQL.
Original: the entire confirm → extract → generate → backtest → deploy → track pipeline, the pattern-extraction logic, the backtesting methodology against real historical data, and the safety gates (template-only generation, FP-rate threshold, human approval before any write to the live rules file).

## Design constraints preserved
- Rule generation is template-based (Jinja2), never LLM-freehand. ✅
- Backtesting is mandatory before a rule is considered ready. ✅
- `auto-generated-rules.yaml` stays separate from `base-rules.yaml`. ✅
- No auto-confirmation heuristics built — confirmation remains a manual, human-driven CLI action. ✅
