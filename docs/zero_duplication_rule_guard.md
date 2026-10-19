# Zero-Duplication Rule Guard

The guard sits in `rule-synthesis-engine/rule_deduplicator.py`. It protects the
submission API, the synthesis client's preflight, human approval, and the final
Falco file write. Template rendering and authoritative benign backtesting remain
unchanged. AI has no role in comparison or enforcement.

## Inventory and permanent protection

Each decision verifies the running systemd Falco service's PID and command line,
checks that `FALCO_CONFIG_PATH` identifies its configuration, and reads the ordered
`rules_files` / legacy `rules_file` inventory. Includes, directories, symlinks,
config merge strategies, default rules, administrator rules, lists and macros are
included. Untracked `-r` or inventory-changing `-o` overrides block the decision.
Sources that are missing, malformed, changing during a read, or unsupported do not
become an empty inventory: submission/approval fails closed.

Observed definitions are stored once per rule/version in the permanent SQLite
registry at `state/rule-guard/registry.sqlite3` (override with
`RULE_GUARD_STATE_DIR`). Each record retains its expanded condition AST and SHA-256
semantic fingerprint. Historical ASTs keep the macro/list meaning at observation;
candidates use the current environment. Deleted, disabled and replaced observed
rules remain protected. Backend pending/approved/deployed candidates, retirement
history and successful deployment audits provide additional protection across
incidents. A rule persisted before a failed reload also remains protected.

All workers and the deployer must share this directory. Back it up along with the
main database. There is no reset or bypass option. The main database requires no
schema migration: terminal `rejected_duplicate` status uses the existing status
column, and the rejection reason and matched name are stored in `audit_events`.
`/rules/history` projects `rejection_reason` into the dashboard response.

## Normalization and comparison

- Tokenize quoted literals without removing significant whitespace, case, or path
  characters. Reject ambiguous duplicate YAML keys and unsupported escapes.
- Expand macros and nested lists, including append/replace definitions. Reject
  cycles, unsupported syntax and excessive complexity.
- Normalize `=`, `==`, singleton membership, set ordering, parentheses and `!=` /
  `not`. Literal globs and simple anchored literal regexes reduce to equality.
  File/process/network fields retain their actual identities: do not guess that a
  basename, executable path, client/server IP or different case means the same thing.
- Build a reduced ordered Boolean DAG with memoized operations; canonical hashes
  recognize reordered conditions, duplicate terms, distribution, absorption and
  De Morgan equivalence. Known scalar fields also use mutually exclusive equality
  values. Cache compiled inventories and index permanent fingerprints.
- Reject existing names, exact conditions and equivalent hashes. Also reject
  same-process conditions with atom Jaccard similarity at least 0.75. The threshold
  is fixed in code and cannot be weakened with a request parameter.
- For overlapping cross-operator predicates over the same event dimensions, reject
  conservatively when equivalence cannot be excluded. Necessary conflicting scalar
  values can prove the event families distinct. Unrelated event dimensions remain
  distinct. Arbitrary Falco/plugin semantics are **not** claimed to be completely
  decidable; unsupported syntax blocks synthesis, and ambiguous supported matches
  can reject genuinely new rules. This favors protection over candidate volume.

Duplicate attempts receive `Rejected – Duplicate`, a specific matched rule/reason,
and a `RULE_DUPLICATE_REJECTED` audit event. No backtest, pending-review insertion
or deployment follows a detected duplicate. Repeated identical rejected submissions
reuse the rejected record. The dashboard shows rejected duplicates in their own
section with reasons, separate from the default actionable list; review controls
are disabled for terminal statuses.

## Concurrency and deployment

A host file lock spans inventory/check/write. PostgreSQL advisory transaction locks
also serialize API candidate creation across workers; checks are not scoped only
to the source incident. Inventory is revalidated after backtesting and immediately
before appending. The deployment lock covers append, durable registry write and
reload. Byte-identical owner-bound receipts permit reload-only recovery after a
failed reload. A name-only match never authorizes a retry, and a newly observed
manual equivalent blocks a retry.

The service remains a single-host Falco integration. Root administrators can edit
files without taking this lock; no application lock can make those external edits
atomic. Administrative updates must be coordinated with the guard lock and Falco
reload. The running daemon does not expose its complete compiled condition AST
through this implementation: the inventory is its verified configured rules plus
observed history, not an independent in-memory rules dump. Initialize against a
successful reload of the complete configuration. Rules removed before the guard
was installed or before any observation require their archived definitions to be
seeded; their previous conditions cannot be recovered from names alone.

## Activate on the Falco host

1. Apply the patch, restart the backend/monitor processes, and rebuild or restart
   the dashboard. Keep the existing `rule_matching: all` configuration.
2. Ensure `FALCO_SERVICE` (default `falco-modern-bpf`) and `FALCO_CONFIG_PATH`
   (default `/etc/falco/falco.yaml`) identify the running service. Backend and
   deployer need read access to every configured source and the same permanent
   registry directory. This implementation requires host systemd and `/proc`
   access; an isolated backend container without that access blocks safely.
3. During a coordinated configuration change, use the same
   `RULE_GUARD_STATE_DIR/guard.lock` with `flock` while editing and reloading Falco.
   After a successful reload, seed the registry before accepting proposals:

   ```bash
   cd ~/selfsentry
   source .venv/bin/activate
   python - <<'PY'
   from dotenv import load_dotenv
   import runpy
   load_dotenv('.env')
   runpy.run_path('rule-synthesis-engine/rule_deduplicator.py', run_name='__main__')
   PY
   ```

   Expected: `{"status": "ready", "protected_definitions": ...}`. A failure must
   be corrected at its source; do not substitute only the repository's generated
   rules file or clear the registry. Include all manual and default sources in the
   running configuration. Run this seed after each manual reload as well; every
   synthesis/approval/deployment decision also refreshes it automatically.
4. Submit an incident matching an existing rule. Confirm the terminal history and
   audit reason, its absence from `/rules/pending`, and an approval HTTP 409.
   A genuinely new supported template still needs a passing authoritative backtest
   and explicit human approval.

## Verification

Unit/integration coverage includes exact, near and Boolean-equivalent rejection;
unique acceptance; manual rules before and after removal; macro/list expansion and
changed macro meaning; cross-incident candidates; retirement; concurrent writers;
late administrator additions; failed reload ownership; unavailable inventories;
runtime config/CLI override mismatch; malformed YAML and protocol failures.

The upstream default rules corpus was also parsed/indexed as a compatibility check,
and a unique template was accepted against it. This is not a substitute for checking
the operator VM's actual rules/configuration. Live VM activation was not performed
in the implementation environment.

Falco reference behavior:
[configuration and merge strategies](https://falco.org/docs/configuration/),
[ordered rule overrides](https://falco.org/docs/concepts/rules/overriding/).
