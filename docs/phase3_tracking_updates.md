# Phase 3 — Tracking File Updates

Your `TODO.md` / `CHANGELOG.md` / `ROADMAP.md` have presumably been updated
since Phase 2 in ways this session can't see, so rather than overwrite them,
here's exactly what to change in each — find the matching section and
apply the edit.

---

## TODO.md

Replace the `## Backlog` line `- [ ] Phase 3 — Falco + eBPF integration`
with this expanded section (insert it right after your Phase 2 section,
before the remaining backlog items):

```markdown
## Phase 3 — Falco + eBPF (rule-based layer)
- [x] Implement `falco_integration.py` (parse_falco_alert, read_falco_alerts_from_file, stream_falco_alerts)
- [x] Implement `ebpf_collector.py` as a documented facade — scope decision: no separate custom eBPF collector (see module docstring)
- [x] Write unit tests (20/20 passing, mocked — no live Falco binary needed)
- [x] CLI entry point (`python3 falco_integration.py <log_path> --mode tail|batch`)
- [x] Document install/config/manual validation steps (`docs/phase3_falco_integration.md`)
- [x] Confirm shape #1 (Falco alert) in `docs/interfaces.md`
- [ ] **Install real Falco on your Linux VM, trigger a real alert (`docker exec -it <container> sh`), confirm `falco_integration.py` parses it end-to-end** (blocked on your local environment — see docs/phase3_falco_integration.md)
- [ ] Mark Phase 3 fully closed once manual validation passes
```

Remove the now-redundant `- [ ] Phase 3 — Falco + eBPF integration` line
from `## Backlog` (it's superseded by the section above).

---

## CHANGELOG.md

Add this under `## [Unreleased]` (above or below your Phase 2 entry,
whichever order you've been using):

```markdown
### Added — Phase 3: Falco + eBPF Integration
- `runtime-monitor/falco_integration.py`: Falco JSON alert parser and normalizer (`parse_falco_alert`, `read_falco_alerts_from_file`, `stream_falco_alerts`), producing shape #1 (`container_id`, `timestamp`, `rule`, `priority`, `output`) for the Correlation Engine and everything downstream.
- `runtime-monitor/ebpf_collector.py`: documented facade over Falco's own eBPF-derived stream — scope decision to not build a second, independent eBPF collector (justified in the module docstring and `docs/phase3_falco_integration.md`).
- `tests/test_falco_integration.py`: 20 unit tests (all mocked/fixture-based, no live Falco/network dependency), covering parsing, priority normalization, host-vs-container filtering, malformed-input handling, and the ebpf_collector facade's delegation.
- `docs/phase3_falco_integration.md`: install/config steps (verified against current Falco docs), manual validation checklist, test coverage rationale, known limitations.
- `docs/interfaces.md`: canonical copy of the 4 shared data-contract shapes, with shape #1 now marked confirmed.
```

---

## ROADMAP.md

In the phase table, change the Phase 3 row from:

```
| 3 | Falco + eBPF (rule-based layer) | 1.5–2 wks | ⬜ not started (biggest risk phase) |
```

to:

```
| 3 | Falco + eBPF (rule-based layer) | 1.5–2 wks | 🔶 code complete, manual validation pending |
```

(matching exactly how Phase 1's row reads while in the same state).

---

## README.md (optional but recommended)

Update the modules list to show Phase 3 in progress, and the "Status" line,
e.g.:
```markdown
## Status
🚧 **In active implementation.** Currently on **Phase 3 of 11** (Falco Rule Engine). See `ROADMAP.md` for the full phase plan and `TODO.md` for current task status.
```
and in the modules list:
```markdown
3. Falco Rule Engine — 🔶 code complete, manual validation pending
```
