# Falco `rule_matching` requirement

## Summary
SelfSentry requires Falco to run with `rule_matching: all` in `/etc/falco/falco.yaml`.
With Falco's default (`first`), the catch-all baseline rule shadows every auto-generated rule.

## Symptom
A deployed auto-generated rule (`Auto_Generated_ls_from_sh_<id>`) compiled, loaded
(`schema validation: ok`) and showed `enabled: true` in `falco -L`, but never fired,
while `Baseline Process Spawn` fired for the same event.

## Root cause
- Falco 0.45.0 ships with `rule_matching: first` (per the comments in falco.yaml): Falco
  stops checking rules for an event at the first match.
- `Baseline Process Spawn` (`spawned_process and container`) matches every container
  process spawn and is loaded before `auto-generated-rules.yaml` (see `rules_files`).
- So the auto-generated rules were never evaluated for those events.

## Evidence (same action: `docker exec selfsentry-test sh -c 'ls /'`)
| Time (UTC) | rule_matching | Rules that fired |
|---|---|---|
| 2026-10-08 07:31:43 | first | BASELINE_PROCESS_SPAWN only |
| 2026-10-08 07:32:47 | all | BASELINE_PROCESS_SPAWN + Auto-generated rule matched (x2) + DEBUG_MATCH |
| 2026-10-08 07:35:10 | all (debug rule removed) | Baseline Process Spawn + Auto_Generated_ls_from_sh_8 (same timestamp, .023417764) |

## Fix
```bash
sudo cp /etc/falco/falco.yaml /etc/falco/falco.yaml.bak
sudo sed -i 's/^rule_matching: first$/rule_matching: all/' /etc/falco/falco.yaml
grep -n "^rule_matching" /etc/falco/falco.yaml     # expect: rule_matching: all
sudo systemctl restart falco-modern-bpf
sudo chmod 644 /var/log/falco/alerts.json           # perms reset to 600 on restart
```

## Trade-off
Falco's own comments in falco.yaml say `all` may carry a performance penalty and should
be tested before production use. Not measured for SelfSentry yet.
