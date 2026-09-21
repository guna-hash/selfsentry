# Phase 5 — Correlation Engine

## What this phase delivers
Two modules that turn raw Falco alerts + anomaly-model events into
actionable, routed incidents:

- **`correlation-engine/risk_scorer.py`** — merges Falco alerts (shape #1)
  and anomaly events (shape #2) by `container_id` + a 60-second time
  window into a unified `risk_score` (0-100) and a 3-tier `confidence`
  label (`high` / `medium` / `low`). Output matches the REAL backend's
  `POST /incidents/` request body exactly (see "Design correction" below).
- **`correlation-engine/event_router.py`** — decides what happens next for
  an already-scored incident, using an `effective_score` (risk_score
  adjusted by confidence) rather than raw risk_score alone, so a single
  noisy signal can never trigger the same response as a dual-layer-
  confirmed one.

## Design correction: shape #3 vs. the original speculative design
`docs/interfaces.md`'s original shape #3 (`incident_id`, boolean
`dual_layer_agreement`, `status`) was written before the real backend
existed. Once `backend-api`'s actual `POST /incidents/` route and
`db_models.py` were available, `risk_scorer.py` was corrected to match
reality:
- No `incident_id` — the database auto-assigns `Incident.id` on insert.
- `confidence` (string: `high`/`medium`/`low`) replaces the boolean
  `dual_layer_agreement` — matches `db_models.py`'s `confidence` column.
- No `status` field — confirmation state lives in a separate
  `ConfirmedIncident` table, not on the incident payload itself.

`docs/interfaces.md` has been updated to reflect this corrected shape.

## Routing model (event_router.py)
Real-world SOC-style routing, not a single flat threshold. Confidence
adjusts the effective score before any tier is chosen:

| Confidence | Adjustment |
|---|---|
| high   | 0 (full trust) |
| medium | -10 |
| low    | -20 |

| Effective score | Actions |
|---|---|
| < 40 | `log` |
| 40–69 | `log`, `ai_analysis_noted` |
| 70–89 | `log`, `ai_analysis_noted`, `analyst_alert` |
| ≥ 90 | `log`, `ai_analysis_noted`, `analyst_alert`, `auto_isolate` |

This makes `auto_isolate` mathematically very hard to reach on `low`
confidence alone — even a perfect `risk_score=100` at `low` confidence
only reaches `effective_score=80`, below the isolation threshold.
Isolating a container is disruptive; this is a deliberate design choice
to avoid triggering it off a single noisy signal, consistent with the
project's stated non-negotiable: automation must not be irresponsible.

`dispatch_incident()` performs (or safely stubs) each routed action.
`auto_isolate` calls `response-engine/auto_isolate.py`'s
`isolate_container()` defensively — if that function doesn't exist yet
(Phase 10 stub), it logs what *would* have happened instead of crashing.

## Open item — flagged to Phase 8 owner
`backend-api`'s real `POST /incidents/` calls Groq (`ai_summary`)
unconditionally on every incident, regardless of `risk_score` — confirmed
via curl testing on 2026-09-18 (incidents at risk_score 78, 87.5, and 100
all triggered summarization). This means `event_router.py`'s
`ai_analysis_noted` action is currently a routing *label* for our own
audit trail, not a real gate on the Groq call — the call has already
happened by the time `event_router.py` runs (it operates on
already-persisted incident data). If we want to skip AI summarization for
low-value incidents later (to save API cost/rate limit), that gate needs
to move into the backend's incident-creation route, not here. Raised at
next sync.

## Automated tests
- `tests/test_risk_scorer.py` — 16 unit tests: matching logic, scoring
  math, confidence tiering, and the never-drop-unmatched guarantee
  (every unmatched Falco alert AND unmatched anomaly event still becomes
  its own incident — critical, since anomaly-only detections are exactly
  what this project's hybrid design exists to catch).
- `tests/test_event_router.py` — 17 unit tests: effective-score math for
  all three confidence tiers, all four routing tiers, confidence-gated
  isolation (same `risk_score=90` isolates at `high` confidence but not
  at `medium`/`low`), and `dispatch_incident()` safely handling the
  unimplemented `auto_isolate.py` stub without crashing.

Run with:
```bash
python3 -m unittest tests.test_risk_scorer tests.test_event_router -v
```
**Result as of this phase: 33/33 passed.**

## Manual validation

### Stage 1–4: local simulation + real backend integration (completed 2026-09-21)
`correlation-engine/validate_pipeline.py` runs four realistic scenarios —
shaped exactly like the real output of `falco_integration.py`'s
`FalcoAlert.to_dict()` and `anomaly_model.py`'s
`AnomalyResult.to_event_dict()` — through the real `risk_scorer.py` and
`event_router.py`, with an optional `--post-to-backend` flag to submit
each result to the live `POST /incidents/` endpoint.

Scenarios and results:
| Scenario | risk_score | confidence | effective_score | Routed actions |
|---|---|---|---|---|
| Dual-layer agreement | 100 | high | 100.0 | log, ai_analysis_noted, analyst_alert, auto_isolate |
| Falco-only, ERROR priority | 70 | low | 50.0 | log, ai_analysis_noted |
| Anomaly-only, no matching rule | 34 | medium | 24.0 | log |
| Low-signal noise (NOTICE) | 20 | low | 0.0 | log |

All four incidents were confirmed to persist correctly to the real
PostgreSQL database via `POST /incidents/` (ids 4–7), each with a real,
populated `ai_summary` from Groq.

**Most important result:** the anomaly-only scenario (no matching Falco
rule) was correctly scored, correctly kept a `medium` confidence tier
(anomaly_score 0.86 ≥ 0.8 threshold), and was **never dropped** — this is
the exact case the hybrid rule+behavior design exists to catch, and it
flows through the pipeline correctly end-to-end.

**Observation for defense prep:** the Groq-generated `ai_summary` text
occasionally editorializes beyond what the underlying data supports (e.g.
describing a NOTICE-level alert in dramatic terms). The deterministic
`risk_score`/`confidence`/routing decision was unaffected by this and
routed correctly regardless — direct, real evidence for why the project's
"LLM is advisory-only, never the detection source of truth" design
constraint matters in practice, not just in theory.

### Stage 5: live end-to-end with real Falco + real anomaly model (not yet done)
Requires a running container with a fresh baseline (the Phase 4 baseline
container was removed since training). Deferred to be captured naturally
during Phase 6's own live end-to-end loop demo, rather than duplicating
container/baseline setup twice.

## Known limitations at this stage
- `ai_analysis_noted` is a routing label only — the real Groq call is not
  actually gated by this module (see "Open item" above).
- `analyst_alert` and `auto_isolate` are currently log-based placeholders
  — no real paging channel, and `auto_isolate` depends on Phase 10's
  `response-engine/auto_isolate.py`, which is still an unimplemented stub.
- Stage 5 (live Falco + live anomaly model, no simulated data) has not
  yet been run for Phase 5 specifically — see above.
