# ContainerGuard AI — Shared Data Contracts (`docs/interfaces.md`)

This is the canonical copy of the 4 shapes referenced in
`ContainerGuard_AI_MyGuide_TrackA.md`. Both of you should work against this
file — if a shape needs to change, update it here first and raise it in the
weekly sync before changing code, since a silent field rename on one side
breaks the other's code with no warning.

Status legend: ✅ = confirmed, produced by real (tested) code · 🔜 = planned,
not yet produced by real code.

---

## 1. Falco alert — produced by `runtime-monitor/falco_integration.py` — ✅ CONFIRMED (Phase 3)

```json
{
  "container_id": "abc123def456",
  "timestamp": "2026-08-09T10:15:00.123456789Z",
  "rule": "Terminal shell in container",
  "priority": "WARNING",
  "output": "A shell was spawned in a container (user=root container=abc123)"
}
```

Field notes:
- `container_id`: string, or `null` for host-level events not tied to any
  container (these are filtered out entirely by default — see
  `container_only` in `stream_falco_alerts()` / `read_falco_alerts_from_file()`).
- `timestamp`: ISO 8601 string, exactly as Falco emits it (nanosecond
  precision) when `time_format_iso_8601: true` is set in `falco.yaml`.
- `rule`: exact Falco rule name as a string (e.g. `"Terminal shell in container"`).
- `priority`: one of `EMERGENCY | ALERT | CRITICAL | ERROR | WARNING | NOTICE | INFO | DEBUG`
  (normalized upper-case; Falco's own JSON uses Title-case strings like
  `"Warning"`, and spells the 6th level out as `"Informational"`, which this
  project normalizes to `"INFO"`).
- `output`: Falco's full human-readable alert string, unmodified.

Producer function: `falco_integration.parse_falco_alert(raw_line) -> FalcoAlert`,
`.to_dict()` returns exactly this shape. Batch/backtest callers use
`read_falco_alerts_from_file()`; live callers use `stream_falco_alerts()`.
`ebpf_collector.stream_raw_events()` yields the identical shape (thin facade
— see that module's docstring for why).

---

## 2. Anomaly-model event — produced by `behavioral-engine/anomaly_model.py` — 🔜 PLANNED (Phase 4)

```json
{
  "container_id": "abc123",
  "timestamp": "2026-08-09T10:15:02Z",
  "anomaly_score": 0.87,
  "features": { "proc_name": "curl", "parent_proc": "nginx" }
}
```

---

## 3. Correlated incident — produced by `correlation-engine/risk_scorer.py` — 🔜 PLANNED (Phase 5)

This is what the AI layer, backend DB, and dashboard all consume.

```json
{
  "incident_id": "inc_001",
  "container_id": "abc123",
  "risk_score": 78,
  "falco_alert": { "...": "shape #1 above, nullable" },
  "anomaly_event": { "...": "shape #2 above, nullable" },
  "dual_layer_agreement": true,
  "status": "open"
}
```

---

## 4. Candidate generated rule — produced by `rule-synthesis-engine/` — 🔜 PLANNED (Phase 6)

Consumed by the `/rules/*` API routes and the Rule Review Queue page.

```json
{
  "rule_id": "rule_004821",
  "source_incident_id": "inc_001",
  "rule_yaml": "- rule: Auto_Generated_Suspicious_Curl_From_Nginx_4821\n  desc: ...\n  condition: ...",
  "pattern": { "proc_name": "curl", "parent_proc": "nginx", "action": "spawned_process" },
  "backtest_false_positive_rate": 0.02,
  "backtest_events_tested": 500,
  "status": "pending_review",
  "created_at": "2026-08-09T10:20:00Z",
  "reviewed_by": null
}
```

---

## Change discipline

Don't rename, remove, or retype a field in a ✅ CONFIRMED shape unilaterally.
If Phase 4/5/6 work reveals a real need to change shape #1 (e.g. an
additional field the Correlation Engine needs), update this file in the
same PR as the code change and flag it in the weekly sync.
