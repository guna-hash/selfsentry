# Repository audit — current status and evidence history

## Acceptance follow-up — 29 October 2026

The recorded review/deployment crash cases have now been exercised.
Controlled approval-process termination before and after a private adapter
effect passed. A separate native Falco test passed termination after the
deployer returned but before final deployed-status commit, competing review
exclusion, preserved approval, explicit retry without duplicate append, and
restoration with positive/negative native witnesses.

Controlled stalled-worker verification passed CLI timeout/PID retention,
continued ownership, competing-monitor refusal, orderly shutdown after
release and private restart. This does not impose a completion deadline on
a permanently stalled production worker or reproduce a hung external call.

The first four-hour soak attempt did not complete. Its last resource sample
was at 300.862 seconds; the runner detected host-clock discontinuity and
approximately 17,826 seconds of native event/receipt skew. The owned
container was removed. The monitor was unhealthy immediately afterward
and recovered in a subsequent operator status check. Preserve this failed
attempt; it is not four-hour performance acceptance.

Evidence directories under ~/selfsentry-private-evidence:
- native-deployment-crash-20261029T041642Z
- stalled-worker-20261029T043133Z
- soak-20261029T044301Z

Remaining work includes the deferred uninterrupted soak, clock-fault
investigation, broader independent model validation and scoped provenance
review. Licensing remains an owner decision. Historical failures and
limitations remain intact; no model or automatic-response setting changes.


Authoritative ten-criterion review: [acceptance review](acceptance-review-20261028.md).
Earlier dated assessments below are historical evidence, not current blanket blockers.

## Current acceptance reconciliation — 28 October 2026

This section supersedes older current-status lists within the scopes below.
Historical results, failed attempts and their limitations remain intact.

Completed and recorded:
- Independent fresh Ubuntu installation passed within the scope in
  docs/repository-audit/clean-install-20261028.md, including operator
  browser checks. Broader production acceptance remains unclaimed.
- Genuine PostgreSQL wire-level COMMIT-reply loss passed for the keyed
  audit endpoint, including uncertain-write reporting and retry deduplication.
- Latest operator release passed 1,278 Python tests plus 104 subtests,
  168 frontend tests, lint, scoped types, build and whitespace checks.
- Native disposable isolation/resume and interrupted resume recovery passed.
  The interruption test required explicit retry; continuous containment
  across a crash was not established.
- Controlled gate start/create/remove interruption tests passed within
  their recorded acknowledgement and persistence boundaries.
- Separate native Falco capture/checkpoint/log-replacement checks passed.
- A 30-minute synthetic workload measurement completed, with resource,
  queue, journal-growth and native drop-counter observations recorded.
  Completion was not performance acceptance; adverse findings remain.
- Prospective LOF evaluation used 24 training and six calibration windows.
  With calibration frozen before validation, LOF flagged 0/6 routine,
  2/2 structural-deviation and 2/2 volume-deviation windows. The unchanged
  Isolation Forest comparison qualified 5/6 routine and all four deviation
  windows at 0.8. These are small synthetic results, not production accuracy.
- After restart and bridged-network configuration, an owned fresh-event
  probe passed: 150 events, maximum absolute receipt lag 0.0742 seconds.
  The probe was removed. This is current timestamp evidence, not a
  permanent fix for the recurring clock fault.

Still open:
- Broader independent model validation, including legitimate behavior
  changes; no experimental candidate has replaced the live model.
- Remaining explicitly untested review/deployment fault interleavings
  and stalled-worker shutdown completion bounds.
- Representative capacity, storage-retention and longer-duration behavior.
- Recurring Falco event-clock fault root cause and durable remediation.
- Owner license decision and any outstanding artifact/OS provenance review.
- Final reconciliation against the original master-prompt criteria.

Automatic isolation remains disabled. Proposed file removals, live archival
and demo recording remain deferred; they are not silently marked complete.


## Historical consolidated acceptance status — 26 October 2026

This section supersedes older current-status statements only within the
evidence scopes below. Historical results and failed attempts remain intact.
Source and verification summaries have been integrated into main through
27a97d2; raw operational evidence remains outside Git.

Verified:
- Latest operator release: 1,272 Python tests plus 104 subtests, 168 frontend
  tests, lint, scoped types, production build and whitespace checks passed.
- Default Isolation Forest anomaly-only file-write and process rule loops
  passed human review, native deployment and linked re-fire verification.
  Both temporary rules were subsequently verified unloaded.
- Scoped PostgreSQL, audit replay, monitor replay and full-monitor Docker
  connection recovery passed. HTTP response loss is not PostgreSQL
  COMMIT-acknowledgement loss.
- Separate bounded native Falco captures verified checkpoint reopening and
  private-log replacement; this does not prove lossless engine downtime.
- Controlled gate start/create/remove interruption boundaries preserved
  uncertain intent and required explicit current-state reconciliation.
  Missing creation identity was correctly left unresolved.
- Existing separate-host recovery and post-reboot checks passed; these are
  not clean-installation evidence.
- Operator reported mobile/theme/keyboard and sample-mode checks passed.
  This is bounded operator evidence, not exhaustive browser accessibility.
- pip check passed; npm audit and the declared Python lock audit reported
  no known vulnerabilities at execution time.

Remaining:
- Independent clean supported-Linux installation.
- Current native response/isolation interruption acceptance in an explicitly
  named disposable environment.
- Remaining review/deployment fault interleavings and genuine PostgreSQL
  COMMIT-acknowledgement-loss testing.
- Representative independent benign/attack evaluation and sustained
  resource, queue, disk, dropped-event and shutdown measurements.
- Recurring Falco clock-skew root-cause investigation.
- Owner license decision and any required artifact/OS provenance review.
- Final documentation and ten-criterion reconciliation after remaining work.

Four proposed file removals remain retained; no deletion is required merely
to complete a checklist. Live archival needs a specific approved cutoff.
Demo recording remains deferred. Multi-user deployment and production
certification are not claimed. Automatic isolation remains disabled.
Full master-prompt completion is not yet established.

---


**Source follow-up implemented and locally checked; the full 24-phase prompt remains open.**
This checkout is `followup/remaining-work-20261023`, from integration commit
`a25fca0cc22974cda692a4dd8410de99b06fc37e`. Remote refs were checked before editing:
integration matched that commit and main matched `18c40d228de66ce3b75c03b23a569b69e28a1b45`.
No commit, push, main merge, deployment, live pruning, service restart or real isolation
was performed by this agent. A final remote recheck found main at
`16ac05bdf145b5b31914b281a9589949374a5d9c`: PR #6 has merged the original audit branch.
Its source tree exactly matches integration `a25fca0`, so that original release-integration
step is now credited as complete. This new follow-up is still uncommitted and unmerged. Default Isolation Forest, human rule approval and response safety gates remain.

## Historical changes and evidence hierarchy — 23 October 2026

- Recovered the original PostgreSQL backup/migration, PostgreSQL concurrency, bounded workload
  and journal export/archive packages. `recovered-runners.json` preserves package/source hashes
  and historical source manifests. Repository imports, JSON report typing and source manifest
  locations were adapted; source pins now identify this reviewed checkout, not a historical run.
- Integrated manual closed-baseline archival and archive-aware replay/telemetry/export from the
  recovered retention patch. Publication/readback precedes the SQLite transaction's removal of
  live payloads. Replay keys, alerts, rejected evidence, workflow/action history and closed-window
  markers remain. Disk/publication/commit/restore faults are tested on disposable SQLite.
  No live cutoff was chosen and no live payload was moved. This is relocation with retained
  identity, not deletion of evidence, a total storage bound or whole-application recovery.
- Added an explicit local operator reconciliation ledger. A full known container ID and original
  attempt hash bind the review. Successful Docker inventory/inspection supplies current evidence;
  transport errors never prove absence. A real ownership lock blocks review even after its
  deadline expires. Concurrent reviews retain one original decision. The original command outcome,
  deployment registration and degraded-health counts are unchanged. This does not guess the
  outcome of an unknown create, retry Docker, or promise a global Docker/SQLite transaction.
- Added offline holdout evaluation using the unchanged default Isolation Forest and fixed 0.5
  model flag. Frozen training must precede nonoverlapping validation windows. Corpus hashes,
  class-specific scored denominators, missing/unscored windows and invalid runs remain explicit.
  This evaluates the model flag, not the monitor's entire confirmation/response policy. Test
  fixtures verify accounting only; no representative detection measurements were manufactured.
- Reconciled the ten missing inventory paths, including the legitimate unique-performance
  migration, late-alert recovery and regressions. Proposed removal of `-c` and the three backup
  files is recorded in `deletion-manifest.json`, with exact recoverable Git blobs. None was removed.
- Refreshed declared-lock SPDX inventory (219 entries), scanner evidence and documentation without
  changing either dependency lock or claiming installed-artifact/OS/license provenance.

Evidence levels are deliberately separate:

| Evidence | Current assessment |
| --- | --- |
| Source and local disposable tests/build | Independently executed in this checkout; final results in validation.json |
| Original runner packages | Source recovered and reviewed; local safety/orchestration tests executed |
| VM gate, incident 216, ready 20-sample model, PostgreSQL restore/migrations/concurrency, workload, journal export | **Recorded in committed VM note; raw evidence not inspected** |
| Prior browser smoke, reboot and operator-reported suspend/resume | Retained bounded historical evidence; not reset to failures or promoted to permanent correctness |
| Current native failure/isolation/browser/fresh-host/detection acceptance | NOT VERIFIED here; original VM/private data not accessible |
| Public production readiness | Not established; host-local/shared-token academic boundary retained |

The unmodified integration branch independently passed 1,013 Python tests + 104 subtests,
165 frontend tests, lint, types (81 source files) and build. It is a new local checkpoint,
not a replacement for the older committed VM count. Final follow-up counts/commands/failures
are in `validation.json`. Raw local logs are preserved in the handoff, separate from private
VM exports. No meaningful React warnings appeared in this run; none were suppressed.
The chart chunk remains 512.67 kB / 151.77 kB gzip. Loading impact was not measured, so it was
not optimized based only on the warning.

## Prior follow-up validation — before the native retirement continuation

| Check | Result | Scope |
| --- | --- | --- |
| Full release verifier | PASS, all five checks | `final-checks-20261023T144655Z`: 1,120 Python tests + 104 subtests in 31.81 s; 165 frontend tests; lint; types; build |
| Root `python -m pytest -q` without provider keys, isolation false | PASS | 1,120 tests + 104 subtests in 30.72 s; actual SQLite/locks/processes/model tests and mocks, no native services |
| Types | PASS | 93 source files, untyped bodies checked; no type-check suppression added |
| Dependency checks | PASS within declared scope | Locked clean installs, pip check, npm/pip-audit results; no lock changes |
| Static/current metadata | PASS within declared scope | Current-path inventory/tree, AST/JSON parsing, limited no-value secret scan, diff whitespace and package byte checks |

The initial follow-up release failed lint after Python passed. Recovered runner JSON reports
needed explicit dynamic typing; no checks were disabled. A direct CLI launch exposed a missing
import path masked by test setup; a subprocess regression now covers the documented command.
An intermediate duplicate copy of recovered exporter tests was omitted from final source;
all original repository tests and historical evidence remain. Earlier failed logs and
successful checkpoints are retained. That checkpoint received subsequent static/hash/package verification. The native-retirement
continuation below introduces additional source changes and its own fresh verification.

## Current security review

Time-specific `npm audit --json` and `pip-audit -r requirements.lock --no-deps --disable-pip`
reported zero known advisories in the declared lock entries. `pip check` passed. The Python
scanner warned that locks lack distribution hashes; lock reproducibility is not artifact
integrity. Security tools ran in a separate ignored environment and changed neither app lock.
Bandit scanned backend/monitor/gate/response/rule/evaluation/scripts and reported 115 findings after the retirement continuation:
102 low, 10 medium, three high. The nine additional low flags arise from the expanded
source/subprocess scope; new subprocess argv remains fixed or taken from the verified service. This broader scope is not comparable to the old 24-finding scan.

The three high flags remain the two persisted SHA-1 identity/checkpoint uses and Jinja YAML
without HTML autoescaping. These are compatibility identifiers, not authentication, and literal
YAML output has its own escaping/validation. Replacing them blindly would break replay or rules.
Medium SQL flags use fixed whitelisted table identifiers or quoted introspected identifiers
with bound values; no arbitrary table selector is accepted by reconciliation. The YAML loader
is the existing SafeLoader subclass. Native acceptance runners' `/tmp` use is a working
directory for explicit administrator commands, not a predictable output file. Subprocess flags
remain relevant to trusted PATH, local Docker privileges and review of argv; commands use argument
lists, and the new observer performs read-only Docker operations with ten-second deadlines.
No blanket suppression, dependency upgrade or security certification was introduced.
Shared-token actor labels remain unverified identities, and local ledger files are not signed
or tamper-proof against their owner. Private dumps/corpora are not included in this handoff.

## Current feature and phase closure

| Phases | Source/evidence now available | Remaining closure work |
| --- | --- | --- |
| 1–4 inventory/correctness/refactor | Complete current-path CSV/tree, original history retained, focused source changes/regressions | Maintainer review of exact apply manifest; approval before proposed removals |
| 5–8 security/cleanup/architecture/dependencies | Current scans, triaged flags, concrete deletion proposal, unchanged locks, explicit state ownership | Native least-privilege/grant validation; owner license decision; full artifact provenance |
| 9–11 tests/docs/UI | Release/root tests and build recorded; current docs reconciled; prior UI passes retained | Live desktop/mobile/theme/form/error/action/backend-state coverage; keyboard focus/return |
| 12–14 feature flow/final handoff | Recovered runners and reviewable source patch; native VM records reconciled | Current full native chain, final maintainer integration into main |
| 15–17 reality/contracts | Honest model/unavailable/sample states; no fabricated native or quality claims | Anomaly-only witness → authoritative backtest → human approval → load/refire/linked incident; process/parent and file templates |
| 18–20 recovery/state/concurrency | Archive publication/crash/readback tests; explicit action reconciliation ledger; recovered PG runners | Native DB disconnect/established-socket/uncertain-commit and pending-work hard-kill; daemon/log restart/rotation faults; full review/deploy races; grants/sequences/whole-app restore |
| 21–22 setup/supply chain | Clean locked Python/npm installation, 219-entry declared-lock SPDX, native setup instructions and runner provenance | Fresh supported Linux host proof with PostgreSQL/Falco/Docker/Trivy; artifact/OS provenance |
| 23–24 performance/ownership | Recovered bounded workload driver, holdout evaluator, updated developer guide | Representative sustained/model/queue/disk/drop measurements; unknown-create/native retirement acceptance; measured shutdown bounds |

## Native retirement continuation — current source change

Added an explicitly enabled, human-confirmed native retirement route, full-ID/hash-bound
source review, ordered Falco prevalidation, retained original/validation files, durable
pending state and generation-based reload receipts. The original DB-only endpoint is
preserved. Ambiguous outcomes block ordinary review and require reconciliation; a verified
receipt can finish an uncertain DB result without repeating the native command. Explicit
rollback is guarded, revalidated, audited and refuses unrelated edits. The permanent duplicate
registry/history is retained. The dashboard distinguishes recorded unloads and unresolved
native outcomes. New audits keep authoritative integer rule IDs.

The protocol was inspected in original Falco 0.45.0 source at commit
`05d5b3e363d5196c68c8ccea842ca57a2ef05562`; code was not copied into this project. Local tests
cover actual API/SQLite/files/locks, a hard-killed worker with pending work and explicit
recovery, duplicate/concurrent reviews, rejected/ambiguous reloads, publication/result-store
failures and replay without native repetition. HTTP responses are controlled, not Falco.
Three optional real-Unix-peer tests are skipped because this host blocks AF_UNIX creation.
Their initial PermissionError failures are retained. Real native acceptance remains open.

The flag defaults false in `.env.example`; no running configuration, service, rule file or
container was changed by this continuation. Exact request/state/precondition details are in
the developer guide's native retirement section. This closes the source-implementation gap
for A11, not the native acceptance, production-readiness or full master-prompt gap.

### Latest verified continuation checks

| Check | Result | Scope |
| --- | --- | --- |
| Full release verifier | PASS, all five checks | `final-checks-20261023T162816Z`: 1,159 Python tests + 104 subtests, 3 explicit AF_UNIX skips; 168 frontend tests; lint; 94 typed source files; build |
| Root discovery without provider keys, isolation false | PASS | 1,159 tests + 104 subtests, 3 AF_UNIX skips in 34.85 s |
| New workflow boundaries | Locally exercised | Actual file/SQLite/lock/API/worker-kill behavior; controlled native commands and HTTP responses |
| Native Falco | NOT VERIFIED | No native binary/service/socket/re-fire acceptance on this host |

The initial socket tests failed with PermissionError because AF_UNIX creation is forbidden
here. Three explicitly scoped fixture skips retain that boundary; they are not successful
native tests. Controlled transport tests still exercise HTTP framing, peer validation,
closure, rejection/instance changes/timeouts and the single-POST rule. Test harness and lint
failures from intermediate iterations remain retained. No test, type or security warning
was broadly suppressed, and no real native or isolation action was executed.

## Historical ten-criterion acceptance — 23 October 2026

Each result applies to its explicit evidence, not to production approval.

| Criterion | Result | Evidence and remaining boundary |
| --- | --- | --- |
| 1. Complete inventory | PASS | All current nonignored source paths, including ten omitted additions, reconciled; hashes except documented metadata self-reference exclusions |
| 2. Justified removals | PASS | Four concrete proposed removals with recoverable blobs; zero actual deletions; approval still needed before removal |
| 3. Critical feature flow traced/exercised | NOT VERIFIED | Source/local paths exercised and bounded native VM records retained; current complete native rule/detection/recovery chain still open |
| 4. Tests executed | PASS | New baseline and final release/root/focused logs, commands and boundaries in validation.json; historical failures preserved |
| 5. Build | PASS | Current Vite production build; chart warning retained without performance claims |
| 6. Security findings resolved/documented | PASS | Current advisory/static results triaged above; privilege, identity, native recovery risks still documented |
| 7. Reproducible setup | NOT VERIFIED | Locked install/build and versioned runners available; no fresh complete supported native host proof |
| 8. Accurate current docs | PASS | Current assessment supersedes dated tables below; native records distinguished from independently inspected results |
| 9. Reviewed final diff | PASS | Source/contract/diff/whitespace and installer applicability reviewed; uncommitted for maintainer review |
| 10. Documented limitations | PASS | Individually scoped blockers below and known_limitations.md; no overall completion claim |

## Historical access and owner blockers — 23 October 2026

1. **Disposable VM/host access and private evidence:** provide an authorized local environment or
   run the documented tracked runners there. Inspect original raw logs before independently
   accepting the recorded results. Existing configured-VM passes do not prove fresh installation.
   Do not rerun disruptive historical tests just because this checkout lacks their private logs.
2. **Native rule retirement source is now implemented, with native acceptance still NOT VERIFIED:** current deprecate is audited DB retirement.
   Official Falco setup documents automatic file watching and reload status in 0.45; removing a
   rule file section can trigger native changes before a manual reload. The implemented workflow now includes exact inventory/hash checks, ordered native prevalidation,
   durable intent, generation-completion verification and reviewed rollback/recovery. These still
   need disposable Falco acceptance; shell exit success alone is insufficient. The new route is
   disabled by default and no real native unload was performed here.
3. **Real response authorization:** name an isolated target environment and explicitly authorize
   pause/disconnect/resume before testing changed current response paths. General completion does
   not waive the prompt's restriction. Isolation remains disabled.
4. **Native failure/full restore:** use disposable PostgreSQL, Docker/Falco/state and coordinated
   stopped-state backups; preserve failed trials and original timelines/keys. PostgreSQL restore
   alone excludes SQLite journals/archives, checkpoints, models, response records and rule registry.
   Unknown create identities remain unresolved; an accepted present-state observation does not
   prove the original command or clear the monitor's unresolved-action count.
5. **Retention and governance:** approval of a specific live cutoff/relocation/deletion is still
   needed before runtime archival; deletion automation remains absent. Licensing belongs to owner.
   Keep host-local scope; per-person identity/RBAC and gateway/TLS require an actual multi-user
   deployment request. Do not broaden deployment to make the checklist appear complete.
6. **Study/UI/load inputs:** representative independently labeled frozen data, approved disposable
   workloads and a live browser/backend are needed for detection, clock-lifecycle and UI/performance
   acceptance. The default IF, experimental SVM status and failed/invalid trials stay intact.

Falco reference reviewed: https://falco.org/docs/setup/tarball/ (hot reload section),
23 October 2026. This source informs the retirement blocker; it does not verify the VM config.

---

# Historical audit checkpoint — preserved below

The following is the original dated audit/handoff record. Its branch, counts, inventory,
blanket assessment and remaining-work wording describe that checkpoint. The individually
scoped current assessment above supersedes those statements; no historical pass/failure
has been rewritten into new evidence.

# Repository audit and implementation batch — 23 October 2026

**Readiness: audit handoff finalized; full project acceptance remains incomplete.**
Changes are uncommitted on `audit/repository-review-20261021`, based on
`18c40d228de66ce3b75c03b23a569b69e28a1b45` from
`https://github.com/guna-hash/selfsentry.git`. No commit, push, history rewrite,
original-file removal, production database operation or real isolation was performed.

## Final handoff and completion boundary

The review package contains actual source changes and a cumulative patch, as well as reports.
It is a review handoff, not a change already installed on the developer's VM. All original
files remain, and no commit/push or deployment was performed. Full master-prompt completion
is **not claimed**: the ten acceptance criteria below contain eight scoped PASS results and
two NOT VERIFIED results, and documented engineering decisions remain open.

### Requested deliverables

| Deliverable | Location in the package |
| --- | --- |
| Repository audit and severity/component findings | This report: Findings and security review; batch evidence above historical sections |
| File cleanup report and deletion manifest | This report: Cleanup manifest and refactoring report; `file_inventory.csv` for every source path; deletion manifest is empty |
| Refactoring report | This report: focused implementation batches and cleanup/refactoring rationale |
| Security review | This report: Findings and security review; `../known_limitations.md`; raw scanner evidence under `evidence/` |
| Testing results and commands | Latest Batch 25 table, final root run below, `validation.json` and preserved raw logs |
| Architecture overview | Feature reality and architecture; `developer-guide.md`: Follow one container / State ownership |
| Remaining limitations | This report: Remaining master-prompt work; `../known_limitations.md` |
| Developer understanding guide | `developer-guide.md`, including data flow, failure modes and interview/viva questions |
| Final directory tree | `final-tree.txt`; all 336 paths cross-checked against inventory and source manifest |
| Final readiness assessment | This report: Final acceptance gate, feature matrix and completion boundary |

The original numbered deliverables are consolidated into existing documents rather than
creating ten overlapping reports. `changes.patch` applies to the recorded base only; the
package's applied-source byte/mode checks verify that baseline. It still needs integration
review against any newer VM/GitHub changes. Do not layer earlier cumulative packages or
overwrite an active installation, `.env`, runtime state or native rules.

### Final executed checks

The latest full release is `final-checks-20261022T191830Z`: all five checks passed
(939 Python tests + 104 subtests, 165 frontend tests/34 files, Python lint,
full-body scoped types/79 files and Vite build). Root-level `python -m pytest -q` also passed
**939 tests + 104 subtests in 34.27 s**, in
`state/evaluation/audit-batch25/root-tests.log`. Earlier checkpoint evidence remains preserved.
Python checks used retained installed-package PYTHONPATH with AUTO_ISOLATION_ENABLED=false.
Finalized documents/inventory received static and cumulative-package checks; application source
was unchanged after release. Overlapping runs are not performance benchmarks.

The executable probe in `audit-final/environment.json` records unavailable Docker, Falco,
Trivy, PostgreSQL and native browser executables. No native environment was installed,
production service disrupted or real isolation performed. Unit/mocked, real disposable storage
and controlled route/client evidence remain distinct from native integration acceptance.
Historical academic evidence remains preserved and was not independently rerun.

### What prevents full closure

- A disposable Linux environment with Docker, Falco, Trivy, PostgreSQL and a browser is needed
  for fresh setup, end-to-end, native migration/concurrency/restore, UI and workload validation.
  Existing VM history is not substituted for a new run of the modified source.
- Real isolation/recovery requires explicit authorization in an isolated environment under the
  original task's safety restriction; it remains disabled here.
- Native rule retirement, consistent operator reconciliation, retention/export and shutdown
  bounds still require design/operational evidence. No destructive retention policy or unverified
  rule unload was introduced to make the checklist appear complete.
- Host-local versus multi-user identity/permissions, licensing and rollout are owner decisions;
  dependency removal/provenance also needs native use evidence. These remain documented rather
  than guessed. The detailed remaining-work table below records each prerequisite.

## Scope and inventory

All **312 original tracked files** were inspected: 300 text files and 12 historical
screenshots. The CSV inventories **336 final files**, recording purpose, reference
candidates, dependencies, findings, action and review depth. Application/test source,
configuration, scripts and active documentation were read; historical transcripts,
measurements, structured data and screenshots received evidence-specific review.
This does not reproduce historical experiments, inspect transitive package source or
constitute fresh browser/native service acceptance. Literal references are candidates,
not proof of execution. No original untracked source existed in the fresh clone.

## Batch 25 — backend keyed audit content validation

- **A45, medium / backend false duplicate success, corrected:** a reused key previously returned
  HTTP 200 duplicate success even for changed content. The disposable route reproduction stored
  FIRST, then acknowledged CHANGED under the same key. It now returns generic 409 and retains
  FIRST. Both the initial lookup and unique-insert rollback branch compare event type, severity,
  source, container ID/name, image name and detail through the same helper. New rows and matching
  replies retain the existing 201/false and 200/true contract; no schema migration occurs.
- Detail comparison uses finite sorted JSON, ignoring mapping order but distinguishing booleans
  from integers. Historical null detail equals the API's empty-object default; malformed stored
  detail does not produce success. Nonfinite request detail receives generic 422 before query/
  insertion/duplicate acknowledgement, avoiding raw-value echo and unreplayable new rows.
- **Timestamp decision:** occurred_at/created_at are first-write metadata, excluded from backend
  identity. Later request time alone neither changes stored time nor conflicts. This preserves
  caller retries that regenerate a default clock value. Separate occurrences require separate
  keys. The local pending durable check remains stricter for explicitly changed timestamps;
  this difference is intentional and tested, not a complete all-field content binding claim.
- Both clients now demonstrate retention of a changed request after local delivery/deletion:
  the actual route returns 409, the client keeps it pending, and the original backend row remains
  unchanged. Controlled competing insert checks cover matching and conflicting winning rows.
  This uses real SQLite/ORM with controlled fault scheduling, not native PostgreSQL concurrency.
- **Limits:** keyless direct/historical events, timestamp-only reuse, producer key selection,
  response authenticity, native races/crashes and ordered backlog resolution remain open.
  A conflict can block ordered replay until review; no automatic replacement, removal, new key
  assignment, immediate retry loop, response action or history migration was introduced.
  Batch 24's backend key-only limitation is superseded for the compared fields, with prior
  checkpoint evidence retained.

### Batch 25 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T191830Z`: 939 Python tests + 104 subtests in 35.74 s; 165 frontend tests/34 files; lint; types/79 files; build |
| Root `python -m pytest -q` | PASS | 939 tests + 104 subtests in 34.27 s; `audit-batch25/root-tests.log` |
| Focused audit/API/database/completion checks | PASS | 184 tests + 26 subtests in 17.63 s; actual disposable route/storage and controlled delivery |
| Before/after backend probe | Confirmed correction | Changed content previously received 200/duplicate; now 409, one unchanged original row |
| Identity/error cases | PASS within local scope | Seven changed fields; mapping order/type differences; first timestamps; controlled race; nonfinite new/historical detail; both clients after local delivery |
| Static/package verification | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; local Markdown targets/selected secret patterns; cumulative patch bytes/executable bits |

Focused tests and lint passed initially. Full and root results overlap and their elapsed times
are not performance measurements. All Python runs used AUTO_ISOLATION_ENABLED=false. Finalized
documents/inventory received static checks. No dependency update, original-file removal,
production database operation, native failure injection, historical record rewrite or real isolation.

## Batch 24 — pending audit payload integrity

- **A44, medium / silent pending audit conflict, corrected:** durable enqueue used
  INSERT OR IGNORE without comparing the retained payload. A disposable reproduction queued
  FIRST then CHANGED under the same key; the second call returned normally while only FIRST
  remained. It now raises `AuditEventConflict` for changed data while preserving the original.
  Insert/read/comparison share one SQLite write transaction; no HTTP or schema migration occurs.
- Identical retries remain valid independent of nested mapping order. If occurred_at is omitted
  (or the existing empty-string default is used), comparison keeps the original pending time.
  Explicitly changed timestamps and other fields conflict. Malformed originals instead raise
  `AuditJournalError`; finite JSON serialization refuses new NaN/Infinity before insertion.
  Error messages omit keys/payload values, and incoming conflicts are not silently quarantined.
- Tests cover seven changed fields, a later generated timestamp with nested mapping reorder,
  four corrupt stored shapes, nonfinite input and two real concurrent SQLite writers. Exactly
  one conflicting writer queues; the other receives an explicit conflict. Original content stays
  intact. Existing caller sites in watcher, behavioral and incident workflows were reviewed;
  stable event keys remain unchanged and no approval/isolation gate is weakened.
- **Limits:** this protects pending durable rows, not a permanent identity ledger. After local
  acknowledgement deletion, backend key-only dedup still applies. Legacy JSONL and direct API
  content binding remain unchanged; native PostgreSQL, separate-process crash recovery and
  uncertain commit validation remain open. Operator/caller investigation is required on conflict.

### Batch 24 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T185434Z`: 931 Python tests + 86 subtests in 45.19 s; 165 frontend tests/34 files; lint; types/79 files; build |
| Root `python -m pytest -q` | PASS | 931 tests + 86 subtests in 57.33 s; `audit-batch24/root-tests.log` |
| Focused audit/monitor/workflow/behavior checks | PASS | 213 tests in 10.33 s; disposable SQLite and controlled collaborators |
| Before/after conflict probe | Confirmed correction | Changed enqueue previously returned normally; now explicit AuditEventConflict, one unchanged original row |
| Static/package verification | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; local Markdown targets/selected secret patterns; cumulative patch bytes/executable bits |

All focused tests passed initially; one continuation indent was corrected after focused lint
before full release. Full/root checks overlapped and elapsed times are not performance evidence.
All Python runs used `AUTO_ISOLATION_ENABLED=false`. Final documentation/inventory updates received
static checks. No dependency change, original-file removal, historical record migration,
production database operation, native failure injection or real isolation occurred.

## Batch 23 — stable identity for new audit replay

- **A43, medium / legacy audit replay identity, corrected for new emissions:** the legacy client
  previously sent None when callers omitted a key. A real audit-route/disposable SQLite test
  committed the request, injected loss of its reply, then replayed after client reconstruction:
  both requests had null keys and produced two backend rows. New emissions now generate one
  key before HTTP and retain it in the spooled payload. The corrected same-path probe sends the
  same generated key twice and stores one row. Durable new emissions retain the same behavior
  through the shared key-selection helper, now with explicit supplied-key validation.
- Provided keys remain unchanged; non-string, empty and overlength keys fail before new HTTP or
  insertion instead of silently substituting identity. Both clients have route/restart tests;
  separate unkeyed emissions remain distinct even with identical content. Existing make_event_key
  hashes, stored keys and backend request/response schemas remain unchanged. Historical keyless
  spool entries are replayed unchanged rather than assigned an invented identity.
- **Limits:** callers retrying the same logical operation through another emit call must provide
  a stable key. This is queued-payload replay identity, not exactly-once processing. Historical
  keyless events/direct API calls, the legacy HTTP-first crash gap, uncertain local commits,
  reused-key/content conflicts and native PostgreSQL/network/power-loss recovery remain open.
  Batch 21's keyless-client limitation is superseded for new emits only; its historical test
  checkpoint and evidence are retained. Filenames below use actual UTC; this report date is
  the client date in Asia/Kolkata.

### Batch 23 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Final `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T183340Z`: 917 Python tests + 86 subtests in 35.61 s; 165 frontend tests/34 files; lint; types/79 files; frontend build |
| Focused audit/API/completion suite | PASS | 144 tests + 8 subtests in 8.04 s; actual disposable route/storage and controlled transport |
| Before/after legacy lost-reply probe | Confirmed correction | Two null keys/two rows before; same generated key/one row after client reconstruction |
| Key behavior | PASS within local scope | New distinct emits remain distinct; explicit keys unchanged; invalid keys fail early; historical keyless payload unchanged |
| Static/package checks | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; local Markdown targets/selected secret patterns; cumulative patch bytes and executable bits |

Focused tests passed on the first run. One overlength test signature was wrapped after focused
lint, before the full release. Root discovery was last run in Batch 19; this release includes
all new `tests/` cases. All Python runs used `AUTO_ISOLATION_ENABLED=false`; finalized documents
received static checks. No dependency change, original-file removal, production data operation,
historical record migration, native failure injection or real isolation.

## Batch 22 — corrupt audit evidence and monitoring continuity

- **A42, medium / audit corruption handling, corrected:** legacy spool size reads appended each
  invalid JSON line to dead letters while leaving its source unchanged. A three-read disposable
  reproduction reported sizes `[0,0,0]` and created three duplicate rejection lines. Reads now
  perform no quarantine writes: invalid text, non-object or nonfinite JSON raises a sanitized
  `AuditJournalError`, retaining both the spool and existing dead letters. The corrected probe
  reports three explicit errors, zero new dead-letter lines and unchanged original input.
- The monitor handles this declared corruption error during status collection: depth becomes
  null, component `audit_spool` is degraded, and status persistence/independent ingestion continue.
  Real temporary Falco JSONL/tailer tests advance checkpoints across two input iterations with
  a corrupt legacy audit spool; no corrupt data reaches HTTP. A readable count is labeled as
  depth readability, not proof that every stored SQLite payload is valid.
- Durable replay preflights the selected batch (up to 50 rows) for finite JSON object shape and
  exact nonempty key/body association before HTTP. Invalid selected rows retain the whole batch
  and raise a sanitized error. This is structural/key validation, not the backend's full schema.
  Controlled repair tests preserve original disposable input in a backup, then verify legacy
  ordering before SQLite delivery and restored telemetry. No production repair was performed.
- **Limits/tradeoff:** affected replay stops until reviewed repair; the existing control-worker
  error boundary can delay subsequent deployment delivery stages. New durable enqueue can still
  work if SQLite is writable, and main ingestion/status continue. This does not automatically
  quarantine, delete, reconstruct or replay corrupt events. Full database/I/O failure behavior,
  native crash/power-loss recovery, consistent cross-process repair, legacy file memory bounds
  and retention remain unresolved. Blank legacy lines remain ignored.

### Batch 22 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Final `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T182149Z`: 895 Python tests + 86 subtests in 35.72 s; 165 frontend tests/34 files; lint; types/79 files; frontend build |
| Final focused audit/monitor/reliability/completion suite | PASS | 144 tests in 3.90 s; actual disposable files and controlled collaborators/HTTP |
| Before/after repeated-read probe | Confirmed correction | Three reads previously created three duplicate dead-letter lines and reported zero; now explicit errors, no new dead letters, original unchanged |
| Corrupt spool integration | PASS within local scope | Actual tailer/checkpoint and persisted status continue with unknown depth/degraded component; reviewed disposable repair restores depth |
| Static/package checks | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; local Markdown targets/selected secret patterns; cumulative patch byte/mode application |

Initial focused checks passed 126 tests; focused lint found two continuation indents, corrected
before the final focused and full releases. Root discovery was last run in Batch 19; final
release includes every new `tests/` case. All Python runs used `AUTO_ISOLATION_ENABLED=false`.
Finalized documentation received static checks. No dependency change, original-file removal,
production repair/database operation, native service failure injection or real isolation.

## Batch 21 — audit delivery acknowledgements and connection ownership

- **A40, high / audit delivery contract, corrected:** any HTTP 200/201 previously acknowledged
  and removed pending audit data, even with an empty JSON body. A disposable SQLite reproduction
  returned reported-sent=1 and pending=0 for HTTP 200 with `{}`. Both clients now require the
  actual API reply shape: positive integer ID and boolean duplicate matching 201/false or
  200/true. Malformed/contradictory acknowledgements retain the original pending event.
  Authentication/authorization, throttling and other ambiguous statuses remain retryable;
  explicit 400/422 payload rejections are preserved in dead letters. Existing flush cadence/order
  remains; no immediate retry loop or automatic response action is introduced.
- **A41, medium / resource ownership and transport logging, corrected:** the durable client used
  SQLite transaction contexts without explicit connection closure. Under retained test references,
  the pre-fix probe found five still-open handles; this is an ownership reproduction, not a
  production descriptor/memory leak measurement. Each short-lived handle now closes after
  commit/rollback, including error paths. Selection closes before HTTP delivery. Raw transport
  exception messages, which can contain connection details, are replaced by exception class logs.
- Controlled route/client integration commits through the real audit endpoint on disposable
  SQLite, discards the first reply via injected ConnectionError, then receives a duplicate
  acknowledgement for the same key with one backend row. Tests cover both legacy and durable
  clients, actual buffered response parsing, invalid shapes/statuses, auth/throttling recovery,
  retained rejections and connection closure on initialization/enqueue/count/select/delete faults.
  Existing successful-response fixtures now model the real API contract rather than status alone.
- **Limits:** acknowledgements lack an event-key binding; existing key dedup does not compare all
  content, and the legacy client permits keyless calls. This does not establish cryptographic
  response authenticity, native PostgreSQL/network/power-loss recovery or blanket idempotency.
  Prolonged failures can grow the backlog; retention, legacy spool repair and overall request
  deadlines remain open. The earlier absolute no-loss docstring claim was removed.

### Batch 21 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Final `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T181022Z`: 874 Python tests + 86 subtests in 63.06 s; 165 frontend tests/34 files; lint; types/79 files; frontend build |
| Focused audit/API/completion checks | PASS | 102 tests + 8 subtests in 6.00 s; disposable SQLite, real route and controlled/mocked delivery |
| Before/after acknowledgement probe | Confirmed correction | Invalid HTTP 200 body previously cleared event; now reported-sent=0, pending=1 |
| Owned-connection probe | PASS | Corrected probe: zero explicitly unclosed handles with retained test references; not a production leak benchmark |
| Static/package checks | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; local Markdown targets/selected secret patterns; cumulative patch bytes and executable bits |

Evidence: `state/evaluation/audit-batch21/`. The initial focused run had two failures from an
unimported test mock name (100 passed plus 8 subtests); corrected to the existing MagicMock.
One overlength test line was wrapped after focused lint. All five final release checks then
passed. Root discovery was last run in Batch 19; final release includes all new `tests/` cases.
All Python runs used `AUTO_ISOLATION_ENABLED=false`; finalized documentation received static checks.
No dependency change, original-file removal, production database operation or real isolation.

## Batch 20 — read-only deployment attempt evidence

- **A32 continuation / operator visibility, improved:** aggregate failure/unfinished counts did
  not expose individual attempt keys or known container IDs. The gate now supports
  `bin/selfsentry-run --inspect-journal --limit 50 --offset 0`, returning creation/action metadata
  and counts from one SQLite read transaction. It opens an existing journal with `mode=ro`
  and query-only behavior; it does not invoke the writer/schema initializer. Missing, corrupt,
  incompatible or invalid-metadata journals fail with sanitized errors, without repair.
- Fixed SQL columns omit decision/rejection payloads, override reasons and Docker arguments.
  Bound numeric pagination caps output to 200 records; invalid bounds are refused before opening.
  Connections close on success/failure. Snapshot tests use a real concurrent WAL writer between
  reads, and a SQL authorizer rejects writes/DDL. A separate actual CLI process returns bounded
  metadata and leaves the disposable main database hash unchanged. This is not proof that all
  SQLite sidecar files remain unchanged: read-only WAL access may use shared-memory sidecars.
- The command performs no Docker action, backend delivery, acknowledgement, retry or outcome edit.
  Recorded success is a CLI outcome, not current container state or complete gate approval.
  Unfinished may mean running, interrupted or timed out; a missing create ID remains unknown.
  Pagination across invocations is not a frozen export. Protect operational IDs/keys/timestamps.
  Reviewed reconciliation records, retention and native crash/remediation acceptance remain open.

### Batch 20 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Final `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T180125Z`: 829 Python tests + 86 subtests in 40.08 s; 165 frontend tests/34 files; lint; types/79 files; frontend build |
| Final focused gate/journal checks | PASS | 87 tests + 11 subtests in 2.34 s; real disposable SQLite and controlled mocks |
| Actual inspection subprocess | PASS | `audit-batch20/cli-process.json`: one-record page, accurate counts, main DB hash unchanged; no native Docker/backend |
| Static/package verification | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; local Markdown targets/selected secret patterns; cumulative patch byte/mode application check |

The first focused run failed one new fixture because it supplied an already-keyed event where
`begin_action` requires a new event (82 passed plus 11 subtests); the fixture was corrected to
respect that existing protection. A long test parametrization line was wrapped after a focused
lint finding. An earlier full release passed before final bounds/metadata refinements and is
superseded by the release above. Root discovery was last run in Batch 19; this batch's complete
`tests/` release includes all new tests, and root diagnostic files are unchanged. All Python
runs used `AUTO_ISOLATION_ENABLED=false`; documentation finalized afterward received static checks.
No dependency update, original-file removal, production database operation or real isolation.

## Batch 19 — operational database HTTP failures and uncertain writes

- **A39, medium / request failure contract, corrected:** the actual API previously returned
  generic HTTP 500 for an injected SQLAlchemy OperationalError. Narrow application exception
  handlers now return sanitized 503 JSON for OperationalError and pool checkout TimeoutError.
  Logs contain exception class and HTTP method, without driver messages or SQL parameters.
  Allowed-origin CORS headers remain readable. Authentication still rejects unauthorized writes
  before reaching SQL. ProgrammingError/IntegrityError and startup failures retain existing handling.
- Read responses report unavailable operations. Mutation responses explicitly say a write may have
  completed and advise reviewing recorded state before retrying. No Retry-After or automatic SQL,
  commit or Docker replay is introduced. This is not blanket idempotency or a database diagnosis.
- Actual backend TestClient tests exercise disposable SQLite sessions and a real exhausted
  single-connection QueuePool, verifying sanitized responses, connection return and successful
  requests after faults are removed. A failure before INSERT leaves no row; a controlled error
  after real DBAPI commit retains one committed row. Reusing its identical audit event key returns
  duplicate success without a second row. A driver trace records BEGIN/COMMIT before the injected
  acknowledgement error. This does not establish disk durability or native network recovery.
- **Experiment correction:** the initial commit-event test incorrectly assumed rollback and failed
  (1 failed, 31 passed). A visible row on a reused connection did not establish transaction state.
  An exploratory trace assertion using a guessed explanation also failed and is not evidence.
  Final tests inject the two phases explicitly; no unsupported SQLite root-cause claim is retained.

### Batch 19 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Final `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T171555Z`: 813 Python tests + 86 subtests in 35.7 s; 165 frontend tests/34 files; lint; types/79 files; frontend build |
| Root `python -m pytest -q` | PASS | 813 tests + 86 subtests in 40.34 s; before final read-message refinement, covered by final full release |
| Corrected focused database/monitor checks | PASS | 33 tests in 10.19 s; final database-only refinement: 18 tests in 8.22 s |
| Prior API behavior | Failure reproduced | Actual app with controlled OperationalError returned 500 before correction |
| Transaction trace | PASS within controlled scope | Real disposable SQLite COMMIT then injected error; HTTP 503, one committed row; no native PostgreSQL/durability claim |
| Static/package checks | PASS within scope when packaged | 336 inventory paths, 145 Python/six JSON parses; local Markdown targets and selected secret patterns checked; cumulative patch byte/mode verification |

Evidence: `state/evaluation/audit-batch19/` and the final release directory. Initial failed
experiments are retained/documented rather than counted as passes. All Python runs used
`AUTO_ISOLATION_ENABLED=false`. Documentation finalized afterward received static checks.
Native PostgreSQL outages, established-socket loss, actual commit acknowledgement uncertainty,
full SQL/lock/request deadlines and the native end-to-end acceptance remain NOT VERIFIED or
unresolved. No dependency change, original-file removal, production operation or real isolation.

## Batch 18 — declared PostgreSQL driver and connection-phase limits

- **A38, high / fresh-install reproducibility, corrected:** the locked SQLAlchemy 2.1.6 selects
  psycopg 3 for plain PostgreSQL URLs, while this project declares psycopg2. A connection-free
  engine-construction probe reproduced ModuleNotFoundError for psycopg. `create_database_engine`
  now selects `postgresql+psycopg2` internally for unqualified URLs, matching the existing lock.
  It does not rewrite the environment URL used by other consumers. Explicit driver selection,
  SSL/application-name/other query options and SQLite test/development behavior are preserved.
- The psycopg2 branch supplies a five-second connection timeout by default, accepting a single
  positive whole-number URL override. Invalid/nonpositive/duplicate values fail before engine
  construction without echoing raw values. Pool checkout wait is five seconds (previously the
  SQLAlchemy default, not an infinite pool wait); pre-ping checks stale handles before application
  transactions. These defaults also reach Alembic/schema tools through the shared engine.
  No dependency was upgraded or added, and engine construction alone does not modify a schema.
- Real psycopg2/libpq against an owned silent loopback listener timed out at 5.01 seconds for
  the default and 2.00 seconds for a two-second override in focused checks. Engine/URL checks
  and disposable SQLite transaction/migration checks pass. Listener lifetime is fixture-owned
  so engine-construction failures also release it. This is a real client/network failure probe,
  not a PostgreSQL server, SQL transaction, authentication or native recovery integration.
- **Limits:** SQL execution, row/DDL locks, established-socket failures, DNS/multi-host behavior,
  complete request duration, actual PostgreSQL pool pressure/restart and unknown commit outcomes
  remain unbounded or unverified. Pre-ping does not replay application SQL/commits/Docker actions.
  No statement/lock timeout or automatic mutation retry was silently added. Existing route error
  handling remains; not every database error becomes HTTP 503. Explicit alternate drivers do
  not receive these psycopg2-specific defaults. This does not close fresh-host/native acceptance.

### Batch 18 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Final full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T150534Z`: 806 Python tests + 86 subtests in 44.08 s; 165 frontend tests/34 files; lint; full-body types/79 files; build |
| Fresh root `python -m pytest -q` | PASS | 806 tests + 86 subtests in 40.45 s; `audit-batch18/root-final.log` |
| Focused engine/migration checks | PASS | 15 tests in 7.98 s; real engine/libpq, owned TCP peer and disposable SQLite |
| Prior engine construction | Failure reproduced without connecting | Plain URL selected psycopg; missing undeclared module prevented construction |
| Timeout observation | PASS within narrow scope | Default 5.01 s and explicit two-second override 2.00 s; not a latency benchmark or PostgreSQL integration |
| Static/final package | PASS within scope when packaged | 336 paths, 145 Python/six JSON parses; no broken local Markdown file targets or selected secret-pattern candidates; cumulative patch byte/mode check |

All Python checks used retained installed-package `PYTHONPATH` with
`AUTO_ISOLATION_ENABLED=false`. A focused lint blank-line issue was corrected before release.
The original root log lacks a completion summary and is not counted as a pass; a new root run
completed with the results above. An earlier release passed before improving the owned-listener
fixture cleanup; the final release includes it. Documentation finalized afterward received static
checks. Overlapping checks/elapsed times are not comparable performance measurements. npm
proxy-configuration and Vite chunk-size notices remain. No original file removal, native server,
production database, migration, deployment or real isolation operation occurred.

## Batch 17 — completed control progress and shared health interpretation

- **A37, medium / progress and status consistency, corrected:** `control_updated_at` was
  published before incident/delivery work, while a separate main loop could keep the status file
  fresh. The API ignored this age, and CLI status accepted even future heartbeat timestamps.
  Prior probes reproduce fresh/API healthy with control timestamp zero and CLI exit 0 with a
  2099 timestamp. Control progress and `control=ok` now publish only after all iteration stages
  return; failed/interrupted work does not refresh successful progress.
- `monitor_status.describe_status` now owns API/CLI snapshot interpretation, replacing duplicate
  freshness/health code. It requires completed control progress under the same 30-second horizon
  as the main heartbeat and exposes `control_progress_fresh`/`control_status_age_seconds`.
  Missing, invalid, stale or future progress degrades control. The API adds an actual database
  count result before interpretation; CLI uses local reports and does not independently probe
  PostgreSQL. No known repository consumers referenced the removed CLI-local stale constant;
  the single limit now lives with the shared status interpretation.
- Monitor displays actual control-cycle age. A real blocked-thread test proves a separate status
  board write can refresh the heartbeat without publishing cycle completion, then completion
  appears after release. Ordering and failed-cycle tests verify incident/audit/deployment work
  precedes progress. External collaborators are fake; JSON files/threading are real and local.
- The shared reader rejects nonfinite JSON telemetry and malformed snapshot shapes rather than
  forwarding NaN/Infinity to strict HTTP serialization. Very large invalid epoch integers degrade
  progress without numeric conversion crashes. Source status files are retained, not repaired.
- **Limits:** the freshness horizon is diagnostic. A legitimate long cycle can exceed 30 seconds
  and report degraded; stale progress cannot distinguish busy work from a dead worker. No
  automatic watchdog/restart/kill/replay/isolation action is introduced. Old monitors publish
  the same timestamp before completion, so restart the updated monitor when integrating. Other
  per-component progress, native transport/outage/termination and end-to-end monitoring still
  require isolated acceptance. This does not bound shutdown or prove continuous detection.

### Batch 17 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T144959Z`: 795 Python tests + 86 subtests in 34.68 s; 165 frontend tests/34 files; lint; full-body types/79 files; build |
| Root `python -m pytest -q` | PASS | 795 tests + 86 subtests in 36.52 s; `audit-batch17/root.log`; before final numeric type-narrowing/test-format corrections, which final release covers |
| Focused control/API/service/shutdown | PASS | 120 tests; local blocked thread, fake remote services and disposable JSON/SQLite |
| Standalone types after narrowing fix | PASS | All 79 source files; persistent cache disabled |
| Prior-source reproduction | Two faults confirmed | Stale control timestamp with healthy API; future timestamp accepted by CLI; source copies/proof JSON retained |
| Frontend age contract | PASS in final release | Existing DOM test now verifies actual `control_status_age_seconds=42` rendering |
| Static/final package | PASS within scope when packaged | 335 paths; 144 Python/six JSON parses; no broken local Markdown file targets or selected secret-pattern candidates; cumulative patch byte/mode validation |

All Python checks used retained installed-package `PYTHONPATH` with
`AUTO_ISOLATION_ENABLED=false`. Intermediate lint failures and the type-narrowing error are
retained; no failed check is counted as passed. Final release includes corrected source and
frontend age assertion. Documentation finalized afterward received static checks. Root/release
elapsed times overlap and are not benchmarks. npm proxy-configuration and Vite chunk-size
notices remain. No dependencies, original files, native services or production data were removed
or operated. Native busy-cycle/outage/forced-stop/browser acceptance remains NOT VERIFIED.

## Batch 16 — snapshot health contract and malformed status resilience

- **A36, medium / health interpretation and availability, corrected:** the API's documented
  `healthy` field previously meant only fresh/running heartbeat and could be true with Docker
  unavailable. The frontend already separately degraded component failures; this was an API
  semantic gap, not a claim that every dashboard label ignored them. The API now separates
  `heartbeat_fresh` and aggregate `healthy`, with `degraded_components` and `health_reason`.
  Aggregate health requires running state, a timestamp less than 30 seconds old/nonfuture,
  required Docker/Falco/control/backend reports in `ok`/`connected`, successful API database
  count and no reported component failures. Optional disabled components are allowed; disabled
  core components are not. Missing components are named, never fabricated as observed rows.
- Missing/malformed status now returns `status_available=false`, nullable `running`, false
  health and an explicit unknown-process reason. A non-object JSON root is rejected by the
  shared reader. Bad component maps previously caused API TypeError; individual invalid entries
  now become explicit unknown while other recorded data is retained. A null component previously
  crashed frontend `monitorState`; malformed shapes now degrade safely. UI helper also requires
  boolean running/healthy data and distinguishes unknown availability from observed Stopped.
- The Monitor page/global warning display escaped aggregate health reasons. Existing healthy
  fixtures were made realistic by supplying required component observations; separate missing-
  component tests prove the API does not infer health from absent services. No safety setting,
  response action, authentication or rule approval behavior changed.
- **Contract change:** the healthy meaning is deliberately tighter; callers interested only
  in freshness must use `heartbeat_fresh`/`status_age_seconds`. Deploy backend/frontend together.
  Legacy clients may mislabel nullable running as Stopped. The database component denotes the
  API's database query; it does not prove monitor-local SQLite health.
- **Limit:** this is reported snapshot health. Fresh global heartbeats can coexist with old
  per-component reports; thread progress, actual daemon availability and end-to-end event
  detection remain independently unverified. Tests do not establish native monitoring continuity,
  outages, fresh browser accessibility or deployment readiness.

### Batch 16 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T142512Z`: 781 Python tests + 86 subtests in 32.27 s; 165 frontend tests/34 files; whole-tree lint; full-body types/79 files; build |
| Root `python -m pytest -q` | PASS | 781 tests + 86 subtests in 31.72 s; `audit-batch16/root.log` |
| Focused API/status/container tests | PASS | 102 tests + 2 subtests; temporary real JSON/TestClient/SQLite |
| Initial focused frontend subset | PASS | 24 tests/3 files, before adding two banner tests; final release includes all 165 |
| Prior-source reproduction | Confirmed | API healthy=true with unavailable Docker; component map None raised TypeError; frontend null item also TypeError |
| Failure and contract regressions | PASS locally | Missing/disabled core vs disabled optional; malformed roots/maps/items; naive/future/invalid timestamps; injected SQLAlchemy query failure; unknown process labels; escaped aggregate reason |
| Static/final package | PASS within scope when packaged | 335 source paths; 144 Python/six JSON parses; no broken local Markdown file targets or selected secret-pattern candidates; cumulative patch applies with byte/mode match |

All Python checks used retained installed-package `PYTHONPATH` with
`AUTO_ISOLATION_ENABLED=false`. Initial reproduction import lacked DATABASE_URL and failed
before execution; it was rerun with disposable sqlite://. A wrong-working-directory edit changed
nothing and was corrected. Focused lint found two 101-character lines, corrected before the
complete release. These are recorded as unsuccessful attempts. Runtime source was unchanged
after final release; later documentation received static checks. Overlapping root/release times
are not benchmarks. npm proxy-configuration and Vite chunk-size notices remain. No dependency,
production database, native service or original-file deletion operations occurred.

## Batch 15 — durable creation intent and trustworthy returned identity

- **A32 continuation / creation evidence gap, locally improved:** a local creation attempt now
  commits before even `docker create`. Failed intent prevents any Docker command. Success
  persists its returned full ID before inspection/scanning; an outcome-write failure prints the
  known ID for operator review and stops further inspection/start/removal. The separate additive
  `creation_attempts` table retains keys, nullable IDs, timestamps and CLI outcomes, never raw
  Docker arguments that may contain secrets. Existing decision/action history remains intact.
- **A35, medium / creation response contract, corrected:** empty Docker create output previously
  caused an uncaught IndexError; arbitrary last-line text could become an action target. The gate
  now requires one full 64-character lowercase hexadecimal ID. Empty, short, named, malformed or
  multi-ID output becomes `DockerOutcomeUnknown` with exit 2. It retains unfinished creation
  intent and never guesses a removal target. The fake Docker fixture now returns a full ID to
  match the actual creation contract; existing decision assertions remain unchanged.
- A nonzero CLI exit records `command_failed`; timeout/interruption or an unrecorded outcome
  stays `outcome_not_recorded`. This describes CLI observations, not guaranteed host state.
  Creation success cannot enqueue a deployment decision or register a container. Conditional
  completion refuses identity replacement; real two-thread SQLite contention verifies only one
  conflicting completion succeeds. Actual failed/unfinished creation counts join existing action
  health keys, including currently running attempts. No automatic replay or orphan removal exists.
- **Validation tooling:** the initial full release passed Python/lint, then mypy crashed reading
  a corrupt generated SQLite plugin snapshot even with `--no-incremental`. The traceback is
  retained. `verify_types.py` now also sends cache storage to `os.devnull`; standalone and final
  full type checks pass without persistent cache. The damaged generated cache was not deleted,
  and no check was skipped, downgraded or labeled successful after its crash.
- **Remaining boundary:** lost creation responses or persistence failure can still leave unknown
  unstarted orphans. No label/cidfile is injected and timestamps are not identity proof. A saved
  successful creation ID can precede an interrupted scan/policy run; it is not gate completion.
  Native daemon/host crash reconciliation, retention and an operator resolution workflow remain
  unverified. The host action and SQLite are not atomic. No live container was operated.

### Batch 15 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T141314Z`: 754 Python tests + 86 subtests in 27.63 s; 155 frontend tests/34 files; lint; full-body types/79 files; build |
| Root `python -m pytest -q` | PASS | 754 tests + 86 subtests in 34.46 s; `audit-batch15/root.log`; before the type-runner cache argument change, runtime source unchanged afterward |
| Focused gate/outbox/control | PASS | 84 tests + 11 subtests; real disposable SQLite and fake Docker/scanner/backend |
| Prior-source reproduction | Three observations confirmed | Missing creation intent/health after timeout; empty output IndexError; arbitrary text returned as ID; prior gate retained in evidence |
| Cache failure recovery | PASS after explicit failure | Original traceback retained; standalone no-cache type check and final release pass; existing corrupt cache retained |
| Inventory/static/package | PASS within scope when packaged | 335 paths; 144 Python/six JSON parses; current top-level Python symbols refreshed; no broken local Markdown file targets or selected secret-pattern candidates; cumulative patch byte/mode match |

Python checks used the retained installed-package `PYTHONPATH` and
`AUTO_ISOLATION_ENABLED=false`. The initial focused lint found one continuation-indent issue;
corrected before release. The first release's type-tool failure is preserved, not counted as a
pass. Final checks include the no-cache runner. Documentation finalized after runtime checks
received static validation. Root/release timings overlap and are not performance comparisons.
npm proxy-configuration and Vite chunk-size notices remain. No dependencies or original files
were removed. No native crash, daemon identity recovery or fresh-host acceptance was performed.

## Batch 14 — response transport failures and recovery containment

- **A34, high / response failure-path gap, locally corrected:** isolation/recovery only caught
  Docker `APIError`; requests timeouts/connection errors could escape before pause or failed-state
  persistence. Prior-source probes reproduce a disconnect timeout leaving the fake workload
  running with `isolating`, and reconnect timeout leaving it running with `resuming`.
- Selected Docker SDK and requests operational exceptions now enter explicit failure paths.
  Disconnect failures are retained per network while remaining disconnects/pause are attempted.
  Pause/inspection failures cannot yield successful isolation. During recovery, unpause/connect/
  inspection errors enter best-effort re-pause and persist `resume_failed` with original network
  evidence. The engine reloads before pausing; if that read fails, it still attempts pause because
  the lost unpause response may hide a running workload. It verifies again and records any
  re-pause/inspection failure. These are containment attempts, not guaranteed native outcomes.
- Pre-action requests transport errors now produce audited 503 responses on action routes,
  and listing returns 503 while closing its client. Engine-reported incomplete actions retain
  audited 409 behavior. A real TestClient/SQLite audit path with fake Docker verifies failed
  recovery and absence of a success audit. No policy, approval gate or enable flag changed.
- A real local flock test proves name/full-ID requests use one inode and the second operation
  waits while the first is active. It covers a successful first isolation and one failing on
  pause; recovery then retains original attachment evidence. Docker is faked and JSON state is
  disposable. This does not prove cross-process/native daemon or forced-termination behavior.
- **Remaining risk:** an unavailable daemon can prevent re-pause. Recovery still unpauses before
  restoring networks; hard termination can leave a running workload. Host operations and local
  records are not atomic. Native outage/restart/crash acceptance and recovery endpoint options
  remain open; static IPs and all endpoint settings are not restored. Automatic isolation was
  disabled throughout testing, and no real container was isolated or recovered.

### Batch 14 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T135900Z`: 741 Python tests + 81 subtests in 31.27 s; 155 frontend tests/34 files; lint; full-body types/79 files; build |
| Root `python -m pytest -q` | PASS | 741 tests + 81 subtests in 34.32 s; `audit-batch14/root-final.log` |
| Focused response/API/reliability checks | PASS | Initial 54+13; API follow-up 57+15; concurrency follow-up 58+17; all fake Docker and disposable records/SQLite |
| Concurrency | PASS within local scope | Two real threads/Linux flock; same full-ID inode, blocked second action, recovery after success/failure |
| Prior-source reproduction | Two faults confirmed | ReadTimeout escaped disconnect/reconnect before failed-state/pause handling; prior source retained in evidence |
| Static/final package | PASS within scope when packaged | 335 source paths; 144 Python/six JSON parses; no broken local Markdown file targets or selected secret-pattern candidates; cumulative patch applies with byte/mode match |

All Python checks used retained installed-package `PYTHONPATH` and
`AUTO_ISOLATION_ENABLED=false`. A release/root run passed before adding the concurrency
regression; the final release/root reruns include it. The concurrency test initially introduced
one 101-character line, detected by focused lint and corrected before the final release.
Documentation finalized afterward received static checks. Runtime source was unchanged after
final release. Root/release elapsed times overlap and are not performance benchmarks. npm
proxy-configuration and Vite chunk-size notices remain. No dependency changes or original
removals occurred. Live containment/recovery, native transport faults and hard-kill acceptance
remain NOT VERIFIED.

## Batch 13 — gate Docker command deadlines

- **A33, medium / unbounded gate commands, locally corrected:** Docker create/inspect/start/
  removal previously used `subprocess.run` with no timeout. A stuck daemon could leave the
  operator waiting indefinitely. Gate commands now supply explicit per-command limits:
  create 300 seconds, inspect 30, start/removal 60. Trivy retains its separate 300-second
  limit. These are per-command waits, not a measured complete-workflow/shutdown SLA.
- A distinct `DockerCommandTimeout` escapes the returned-nonzero start cleanup branch.
  Start/removal timeout retains `outcome_not_recorded`, never delivers completed policy
  evidence and never retries the Docker action or automatically removes after uncertain
  start. Main reports exit 2. Timeout messages omit full arguments/output, which can contain
  secrets. This does not sanitize all unrelated Docker failure paths.
- Create timeout can leave a daemon-created container without a returned ID; no guessed
  container is removed. Slow pulls may exceed the limit and require operator reconciliation.
  Inspect timeout may attempt separately journaled cleanup of the known unstarted container.
  Killing the CLI cannot establish/cancel the daemon outcome. Native transport, Docker helper
  process trees and forced-shutdown acceptance remain NOT VERIFIED.

### Batch 13 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T134334Z`: 731 Python tests + 77 subtests in 47.39 s; 155 frontend tests/34 files; lint; 79-file full-body types; build |
| Root `python -m pytest -q` | PASS | 731 tests + 77 subtests in 45.16 s; `audit-batch13/root.log` |
| Focused gate/outbox tests | PASS | 58 tests + 6 subtests; real disposable SQLite, mocked Docker/scanner/backend |
| Local child deadline | PASS | Real sleeping Python process substituted for CLI; 0.5-second timeout killed/reaped that child; not Docker daemon cancellation |
| Prior source reproduction | Missing deadline confirmed | Mocked subprocess saw no timeout keyword; prior gate source retained in evidence |
| Static checks and final patch | PASS within scope when packaged | 335 inventory paths; 144 Python/six JSON parses; no broken local Markdown file targets or selected secret-pattern candidates; cumulative patch byte/mode verification |

Python checks use the retained installed-package `PYTHONPATH` with
`AUTO_ISOLATION_ENABLED=false`. A focused lint check initially found one 101-character test
line; corrected before the complete release. Source runtime/tests were unchanged after that
release; documentation finalized afterward received static checks. Root/release checks overlap,
so elapsed times are not performance comparisons. npm proxy and Vite chunk-size notices remain.
No dependencies changed, no native service was operated and no original file was removed.

## Batch 12 — durable intent before deployment actions

- **A32, high / action-to-journal boundary, locally corrected with remaining native limits:**
  the gate now commits intent before start/removal, including cleanup. Intent contains the full
  returned container ID, action, timestamp and available policy/scan/override evidence. Journal
  failure refuses the action; a created container may remain unstarted for operator review.
- Successful CLI outcome and completed-decision enqueue commit in one SQLite transaction.
  Nonzero commands have explicit local failure outcomes. Unexpected interruption or outcome-write
  failure leaves `outcome_not_recorded`; restart/HTTP flush never executes these actions. Failed
  or unfinished actions never become completed backend deployment/registration rows.
- Blocked-container removal previously ignored a nonzero return and reported a completed block.
  It now raises an error. Start failure and cleanup have separate intent/outcomes. The gate CLI
  reports Docker/storage errors with exit 2. Earlier local decisions remain compatible; the new
  local action table is additive and no existing database was migrated destructively.
- Monitor health uses real failed/unfinished action counts, separately from delivery health.
  Unfinished may mean currently running. Historical failed rows remain visible. No automatic
  resolution, data deletion, native reconciliation, individual action-history dashboard or action
  replay is introduced. Operator guidance requires backup and authoritative full-ID review.
- **Remaining boundary:** Docker creation/inspection/scanning precede intent and can leave an
  unstarted orphan on interruption. SQLite cannot transact Docker itself; zero CLI status does
  not prove continuing runtime health. Failed/unfinished override attempts remain local history
  with aggregate monitor health. Native crash/power-loss/reconciliation and a reviewed retention/
  resolution workflow remain required. This batch does not close native acceptance.

### Batch 12 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Full release `python scripts/verify_final_checks.py` | PASS, all five checks | `final-checks-20261022T133700Z`: 725 Python tests + 73 subtests in 27.52 s; 155 frontend tests/34 files; whole-tree lint; full-body types/79 files; frontend build |
| Root `python -m pytest -q` | PASS | 725 tests + 73 subtests in 26.21 s; `audit-batch12/root.log` |
| Focused gate/outbox/control pytest | PASS | 65 tests + 2 subtests; real disposable SQLite, fake Docker/scanner/HTTP |
| Prior-package reproduction | Two faults confirmed | No intent at start; failed removal still returned blocked; preserved prior gate with current journal dependency and mocked collaborators |
| Transaction/error regressions | PASS within local scope | Intent visible before command, disk failure refuses action, completion/enqueue rollback, retained uncertainty, no restart replay, failure health and retained acknowledged history |
| Static follow-up | PASS within scope | 144 Python and six JSON parses; no broken local Markdown file targets or selected secret-pattern candidates |
| Final patch verification | PASS when packaged | Whitespace check, cumulative patch applies to original HEAD archive, source bytes/executable modes match |

All Python checks used the retained installed-package `PYTHONPATH` and
`AUTO_ISOLATION_ENABLED=false`. The first full release passed Python but failed three test
formatting findings; corrected before final release. An initial reproduction probe omitted
`PYTHONPATH` and could not import requests; the corrected probe passed. Logs retain these
limits/failures. Documentation was finalized after runtime checks and received static link and
syntax validation. Root/release checks overlapped; elapsed times are not performance benchmarks.
No dependency changes or native service actions occurred. Existing Vite chunk-size and npm
proxy-configuration notices remain. No claim of fresh browser/live acceptance is made.

## Batch 11 — deployment delivery acknowledgement and replay binding

- **A31, high / delivery integrity, corrected:** gate/monitor accepted any HTTP 201 as delivery
  and deleted its journal without checking an acknowledgement body. Both now require a
  positive integer ID and matching decision. Ambiguous or invalid JSON responses remain
  queued. Success fixtures now model the actual response, with separate negative tests;
  this strengthens the contract rather than weakening assertions.
- Local `INSERT OR IGNORE` previously discarded a different request under the same key.
  Canonical payload comparison now refuses that conflict without replacing original data.
  Two real threads against disposable SQLite prove one conflicting writer succeeds and
  the other receives an explicit conflict. Setup failures close the acquired connection.
- Backend replay previously returned an audit-linked ID for a different container/report.
  New events retain a versioned request fingerprint. Replays also verify actual deployment,
  scan and persisted material fields; changed requests, cross-operation keys and orphan or
  inconsistent state return 409. Legacy records compare persisted data, with explicit limits
  for extra metadata never stored. No fabricated historical fingerprints are backfilled.
- Permanent 400/409/422 or malformed journal input now produce rejection markers with raw
  copies while leaving original pending rows untouched. Later valid deliveries continue;
  active transient failures preserve FIFO. Monitor delivery health uses real pending/rejected
  counts. An explicit identical `record_decision` retry can recover after valid backend acceptance
  while preserving the rejection copy (simulated HTTP test). There is no automatic
  deletion/requeue UI: reviewed resolution and
  native recovery remain open. Authentication, rate-limit and server failures are not quarantined.
- A real SQLite journal through actual FastAPI/TestClient/ORM code verifies conflict retention
  and next-record delivery. HTTP transport is simulated, and no Docker/Trivy/PostgreSQL service
  is involved. Preserved prior-package probes reproduce four original faults independently.
- **A32 at the Batch 11 checkpoint (superseded by Batch 12):** Docker start/removal preceded enqueue in `run_gate`.
  Crash/disk failure there can leave an unrecorded action. This batch fixes delivery after
  enqueue; it does not make host actions and journals atomic. A reviewed pre-action intent/
  outcome design plus native validation remains required. No real deployment was operated.

### Batch 11 executed validation

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Release script with audit Python path and isolation disabled | PASS: all five checks | `final-checks-20261022T132111Z`; 715 Python tests + 71 subtests in 37.26 s; 155 frontend tests/34 files, lint, types (79 files), build |
| Root `python -m pytest -q` with same environment | PASS | 715 tests + 71 subtests in 49.1 s; `audit-batch11/root-final.log` |
| Initial focused journal/API/gate/control follow-up | PASS | 102 tests + 23 subtests before further recovery/concurrency tests; simulated services |
| Preserved prior-package reproduction | Four faults confirmed | Invalid 201 acknowledgement erased evidence, conflicting enqueue ignored, rejection blocked next work, changed backend payload returned old ID |
| Attribution/template follow-up | PASS | Upstream Alembic notice preserved; added source comments render identically and generated Python parses; no project license selected |
| Static follow-up | PASS within scope | 144 Python/six JSON parses, no broken local Markdown file targets or selected secret-pattern candidates |
| Patch packaging | PASS when packaged | Diff whitespace plus cumulative application/byte-mode verification against original HEAD archive |

Failed initial collection (a missing test bootstrap path) and an intermediate line-length
failure are retained in logs. The source/template attribution comments and README notice were
added after the release run; direct template-render equivalence and AST verification passed.
No runtime dependencies changed. Test elapsed times are evidence, not comparable benchmarks;
root/release checks ran concurrently. Native services, actual rejection repair and action/audit
crash recovery remain NOT VERIFIED.

## Batch 10 — incident mutation and report-write integrity

- **A29, medium, corrected in source:** concurrent metadata writers could overwrite benign
  disposition or response state because they merged cached JSON without a common lock.
  Workflow updates, dismissals and confirmations now lock the parent incident first;
  metadata/parent reads refresh stale identity-map values. Real SQLite stale-session
  regressions reproduce both lost-update orders. PostgreSQL SQL compilation verifies
  `FOR UPDATE` on the first parent read; native PostgreSQL concurrency remains NOT VERIFIED.
- Empty confirmation actors were persisted. Whitespace around `selfsentry-auto` dispatched
  through the human-label branch. Normalize/check the actor before policy dispatch and
  enforce the storage length. This is dispatch consistency, not a fix for per-person
  authentication: shared-token callers can still supply their own human labels.
- Workflow patch fields must be objects. Benign dismissal writes UTC timestamp and audit
  atomically, with repeat calls producing no new audit and individual actor explicitly
  unknown. Historical benign rows receive no invented audit backfill. This does not undo
  isolation or synchronously cancel an already in-flight Docker response; that external
  cancellation boundary still needs an explicit design/native acceptance.
- **A30, medium, corrected:** incomplete scan summaries could be stored with missing counts
  defaulted to clean zeros. Nonempty summaries now require all five bounded integer counts;
  no coercion of missing, bool, negative, fractional, string or oversized values. Empty
  summaries remain unavailable with no scan row. Findings/violations must be object lists.
  SQL field-length limits and nonempty supplied event keys now fail at request validation.
- Gate production callers already supply complete summaries. Manual/legacy clients with
  invalid requests can now receive 422; deployment FIFO outboxes retain rejected entries,
  so operator inspection may be needed. No queued or database evidence was edited/deleted.
  Backend recording still trusts privileged gate claims; shape checks are not scan attestation.
- Eighteen new cases failed before implementation (18 original monitor API tests passed).
  Those same cases pass after correction. Additional bounds/audit/SQL contract tests were
  added; no assertions were weakened. Initial focused API follow-up passed 61 tests plus
  25 subtests before the final dismissal-audit test was added.

### Batch 10 executed validation

| Command/check | Result | Evidence / boundary |
| --- | --- | --- |
| Release script under audit Python path, real isolation false | PASS: all five checks | `final-checks-20261022T124117Z`; 683 Python tests + 65 subtests in 37.17 s; 155 frontend tests/34 files; lint, types (79 files), build |
| Root `python -m pytest -q` under same environment | PASS | 683 tests + 65 subtests in 33.93 s; `audit-batch10/root-tests.log` |
| Pre-change new regressions | 18 FAIL, 18 original tests PASS | Lost metadata, invalid workflow fields, empty/whitespace actors; `before.log` |
| Request/SQL follow-ups | PASS within scope | Real SQLite/TestClient validation plus PostgreSQL statement compilation; no native database contention test |
| Static follow-up | PASS within scope | 143 Python / six JSON parses; zero broken local Markdown file targets or selected secret-pattern candidates |
| Git diff / package | PASS when packaged | Whitespace checked and cumulative patch applied/byte-mode verified against original HEAD archive |

The chart bundle-size warning remains. No dependency versions, native service settings,
production data or academic measurements changed. API input rejections and the external
cancellation boundary are explicitly documented above; no production-ready claim follows.

## Batch 9 — Falco checkpoint and record-boundary integrity

- **A28, high, corrected:** invalid checkpoints previously became a fresh tail at EOF,
  silently skipping unread events. Validation now rejects malformed/negative/bool/string
  positions, invalid hashes and invalid discard state. The original remains intact,
  ingestion is unavailable, other monitor work proceeds and a repaired checkpoint can
  recover without a restart. Deleting the bad file is not an automatic reset.
- Failed checkpoint writes previously logged an error while advancing in-memory offset
  and deduplication state. Private atomic replacements now sync file and directory; failures
  restore the prior in-memory acknowledgement and mark ingestion unavailable. Replays require
  existing sink idempotency. A directory-sync failure after replacement can leave a valid
  newer on-disk checkpoint covering already-handled data; no exactly-once/power-loss claim.
- The log position now uses `fstat` of the opened descriptor, closing the pathname rotation
  race. Unread bytes on an old rotated descriptor are still not drained; native rotation,
  filesystem faults and hostile mount/inode reuse remain NOT VERIFIED.
- Oversized records were discarded one chunk at a time, allowing a trailing fragment to be
  interpreted as a new event. Discard-through-newline state now survives checkpoint/restart
  and resets on observed rotation/truncation. The optional field defaults false for older
  checkpoint files. Oversized source evidence remains in the source log; no retention or
  automatic operator repair was introduced.
- Post-change probes against the preserved pre-batch module reproduced all four prior
  faults using temporary files: corrupt checkpoint skipped history, failed write advanced
  position, oversized input emitted `IJKLM` as a record, and rotation emitted `t` instead of
  `first`. This isolated historical probe is not a native Falco experiment. The old test
  asserting silent corruption fallback was replaced to match this justified safety correction.

| Batch 9 command/check | Result | Scope / evidence |
| --- | --- | --- |
| `PYTHONPATH="$PWD/.venv/lib/python3.12/site-packages" AUTO_ISOLATION_ENABLED=false python scripts/verify_final_checks.py` | PASS: all five checks | `final-checks-20261022T122831Z`; 657 Python tests + 40 subtests in 25.53 s; 155 frontend tests/34 files, lint, types (79 files), build |
| Root `python -m pytest -q` under the same environment | PASS | 657 tests + 40 subtests in 35.19 s; `audit-batch9/root-tests.log` |
| Initial focused ingestion/service/reliability suite | PASS | 54 tests + 7 subtests; three additional sync/symlink/service-repair tests included in final suite |
| Pre-batch isolated reproductions | Four faults reproduced | `before-reproductions.json`; preserved source, synthetic disk/sync failures, no native service |
| Native deployment, isolation, real disk failure/power loss | NOT VERIFIED | None executed; source changes remain uncommitted |

## Batch 8 — migrations, full-body type checks and invalid-state handling

- Added an opt-in Alembic initial revision frozen independently of live ORM metadata.
  It refuses an existing unversioned database and guards destructive downgrade behind an
  explicit operator flag. Existing startup behavior is preserved; no user database was
  migrated, stamped, restarted or rewritten. Future revisions and native PostgreSQL
  adoption/backup/restore still require review and testing.
- Added `scripts/verify_schema.py`: read-only PostgreSQL/SQLite schema comparison with
  credential-safe availability errors. Disposable SQLite tests cover upgrade, repeat
  upgrade with row retention, refusal to adopt existing tables, guarded downgrade/upgrade,
  and detecting a missing table without repairing it. PostgreSQL offline SQL compiles;
  this is not execution against PostgreSQL.
- Replaced legacy untyped ORM declarations with SQLAlchemy typed mappings. A before/after
  comparison verifies identical table/column names, SQL types, nullability, primary/unique/
  foreign keys and client/server defaults. No schema/data change is required by this refactor.
- Added a repeatable type runner mapping service directories to real import roots, including
  routes/models/migrations. It checks untyped bodies too. Initial attempts exposed 23 errors
  and then 31 nested-route errors; the full-body pass exposed 95 further errors, many caused
  by inferred heterogeneous dictionaries or optional values. Logs preserve these failures.
  The final scoped check covers 79 files; dependency implementations, tests, root manual
  diagnostics and missing stubs remain outside that guarantee. No blanket type-error
  suppressions were introduced.
- BDD duplicate checking now stores only nonterminal branch nodes. Terminal IDs, allocation
  order and the complexity cap are unchanged; semantic/deduplication regressions pass.
  JSON/status payloads have explicit dynamic types rather than misleading inferred types.
- Empty provider content now produces an explicit error after closing the client. Workflow
  explanation payloads reject invalid shapes before persistence and return conflict for
  orphan metadata. A journal baseline record that no longer parses is retained and marks
  its window degraded, never turned into a fabricated zero-event learning sample.
- Fixed a remaining evaluation SQLite connection lifetime and ignored mypy's generated cache.
  Updated setup, migration/adoption and developer instructions. Native isolation remains off.

### Batch 8 executed validation

| Check | Result | Scope / evidence |
| --- | --- | --- |
| Release script with `AUTO_ISOLATION_ENABLED=false` and audit package path | PASS: all five checks | `final-checks-20261022T121810Z/results.json`; 645 Python tests + 33 subtests in 25.71 s; 155 frontend tests / 34 files; full-tree lint, scoped types and Vite build |
| Root `python -m pytest -q` under same environment | PASS | 645 tests + 33 subtests in 34.69 s; `audit-batch8/root-tests.log` |
| Type runner including `--check-untyped-defs` by default | PASS | 79 application/script/migration files; missing stubs tolerated; dynamic values still limit proof |
| Disposable migration tests | PASS: four cases | SQLite only; actual PostgreSQL execution/adoption/recovery NOT VERIFIED |
| PostgreSQL `alembic upgrade head --sql` | PASS | SQL generation only; dummy unreachable endpoint; no native DB connection |
| Typed ORM metadata equivalence | PASS | Before/after snapshot of every table/column type, nullability, key and default |
| Static follow-up | PASS within scope | 143 Python and six JSON files parse; no broken local Markdown file targets or limited secret-pattern candidates |
| Patch application | PASS when packaged | Cumulative patch checked/applied against original HEAD archive; all 333 source files and executable modes verified by packaging helper |

No dependency versions changed in this batch. Fresh dependency installation was not repeated;
earlier locked-install evidence remains in the package. Failed intermediate lint/type runs
are preserved. The chart bundle warning remains; no performance benefit is claimed.

## Batch 7 — final file review, scan trust boundary and diagnostic correctness

- **A25, high, corrected:** syntactically valid but malformed Trivy JSON could normalize
  into a clean result. Production scanning now requires schema 2 container-image metadata,
  a valid immutable image identity, matching requested digest and valid finding shapes/
  severities. Invalid responses fail closed; valid reports may omit Results for empty
  artifacts. CLI option separation prevents image arguments becoming options. Scanner
  configuration/ignore rules still determine coverage; native Trivy interoperability is
  NOT VERIFIED. Contract reference: [official reporting schema](https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/reporting.md).
- **A26, medium, corrected:** standalone capture/validation discarded partial records and
  future-window events and validation defaulted to a different window size. They now retry
  partial lines, retain future events, close elapsed windows and refuse mismatched baseline
  timing. Eleven synthetic regression cases cover these paths. Existing baselines were
  not rewritten. These legacy diagnostics still require the exact Falco container ID and
  do not provide production checkpoint/rotation, late-delivery or clock-jump recovery.
- Replaced a vacuous generator-existence assertion with a deterministic EOF-following
  assertion. Moved direct unittest entry points after all classes. Removed unused imports,
  corrected narrow bootstrap annotations and resolved all whole-tree Python lint findings.
  The release script now checks the entire source tree rather than a selected allowlist.
- Reviewed all remaining historical reports, transcripts, frozen evidence and dependency
  lock metadata. Frozen snapshot hashes agree with the cited source evidence. Historical
  terminal demos include synthetic/manual steps and are not native end-to-end proof.
  All twelve retained screenshots were visually inspected; none establishes current
  backend truth or fresh accessibility/mobile acceptance. No historical measurements changed.
- Corrected active operations/deployment/permissions/locking documentation. Phase documents
  now identify historical scope; no historical result was erased. No files were proposed
  for deletion because no defensible redundant-file case was established.

Final executed commands/results are recorded in `validation.json` and the packaged
`evidence/batch7` logs. Earlier batch sections below preserve checkpoint results rather
than overriding the final checkpoint. Dependency advisories/Bandit results dated 21 October
are historical scan results, not a claim of a fresh 22 October vulnerability database scan.

## Historical executed validation — Batch 7

| Check | Result | Evidence / scope |
| --- | --- | --- |
| `PYTHONPATH="$PWD/.venv/lib/python3.12/site-packages" AUTO_ISOLATION_ENABLED=false python scripts/verify_final_checks.py` | PASS | `final-checks-20261022T115742Z/results.json`; Python 630 tests + 33 subtests in 26.66 s, frontend 155 tests / 34 files, whole-tree lint and Vite build |
| `PYTHONPATH="$PWD/.venv/lib/python3.12/site-packages" AUTO_ISOLATION_ENABLED=false python -m pytest -q` | PASS | Root discovery: 630 tests + 33 subtests in 25.25 s; no live provider calls |
| Final whole-tree flake8 after help-text wrap | PASS | Zero findings; command and log in validation/evidence |
| AST / JSON / local Markdown links | PASS within scope | 138 Python and six JSON files parse; no broken local targets; limited secret-pattern scan has zero candidates |
| Native host / fresh browser / representative load | NOT VERIFIED | Required services/corpus absent; build warns about chart chunk size |

Earlier failed lint attempts are retained in the evidence directory. No tests were removed
or weakened to obtain these results. Existing installed packages were used for this final
run; earlier fresh locked-venv installation evidence is preserved separately. The final
help-text-only edit was linted after the release run; it changes no execution logic.

## Batch 6 — bounded work, truthful runtime settings and evaluation safety

- **A20 (high, corrected): runtime settings were misreported.** `/monitor/status` used the
  backend process's environment for the monitor's safety flags. The monitor now publishes
  its actual immutable configuration. The API preserves it and exposes its own settings
  separately as `backend_configuration`. Older status files return unknown configuration,
  never an invented disabled flag. Regression tests deliberately give the two processes
  conflicting settings. Restart the monitor after installing this change.
- Evaluation preflights, coverage probes, full/scheduled trials, academic capture,
  no-baseline/protection and database-recovery runners now refuse healthy-but-unknown or
  enabled isolation settings before triggering work. Tests still use disposable state and
  mocked host operations. This is a precondition, not a lock against a concurrent operator
  restart/configuration change. Live destructive checks were not run.
- **A12 (partially corrected):** each Docker forwarding queue is bounded to 1,000 entries.
  The main loop retains one pending event when the control queue is full, preserving FIFO
  and continuing Falco ingestion. The pump already uses stop-aware backpressure. Model
  training admits at most two concurrent jobs; deferred baselines remain on disk in
  `BASELINE_READY`. Actual queue depths reach the Monitor page. Counts do not bound event
  byte size, retained database history, tracked-container maps or total model memory.
  Docker queues are not durable; daemon backlog/restart delivery still needs native testing.
- **A21 (medium, corrected):** malformed baseline fields could raise undeclared exceptions
  and abort batch readers. Shape/time conversion errors now become `BaselineParseError`,
  so later valid records are retained. `umount2`, emitted by the shipped Falco capture rule,
  now contributes to the sensitive-syscall feature. Existing persisted vectors are not
  rewritten: review/recollect a baseline before comparing models across this feature fix.
- **A22 (medium, corrected):** an invalid JSON confirmation response previously looked like
  success. It now reports an unknown outcome requiring state inspection. Registry SQLite
  handles close after successful or exceptional use; evaluation read-only SQLite handles
  also close explicitly.
- **A23 (low, corrected):** evaluation fingerprints now hash the configured baseline path.
  Fingerprints still exclude source content/kernel changes; matching hashes alone cannot
  establish comparability across different code revisions or runtime configurations.
- **A24 (low, corrected):** README editing had broken the screenshot capture anchor. A tested
  anchor restores the contract. The source exporter now includes extensionless launchers,
  lockfiles and the CSV inventory. Historical rules, datasets, screenshots and results remain.

| Batch 6 check | Result | Evidence and boundary |
| --- | --- | --- |
| Locked dependency installation | PASS in a newly created Python 3.12 venv | `requirements.lock`; no fresh Linux/security-service provisioning |
| `AUTO_ISOLATION_ENABLED=false /tmp/selfsentry-final-venv/bin/python scripts/verify_final_checks.py` | 617 Python tests + 22 subtests; 155 frontend tests; selected lint and build PASS | `final-checks-20261022T011958Z`; 34 frontend test files |
| Prior attempts | Preserved | One lint failure caught a missing import; eight recovery tests caught missing runtime-setting fixture fields, corrected without weakening recovery assertions |
| `python -m pip check` | PASS | No broken requirements found |
| Root test collection (`PYTHONPATH=.venv/lib/python3.12/site-packages AUTO_ISOLATION_ENABLED=false python -m pytest -q`) | PASS: 617 tests + 22 subtests in 20.00 s | Existing installed packages; no live provider calls during collection |
| Static all-file follow-up | PASS within scope | 137 Python AST parses, six JSON parses, zero broken local Markdown targets or selected secret-pattern candidates; not an exhaustive secret scan |
| Whole-tree flake8 | FAIL: 45 findings | Mostly inherited style/import/test-fixture issues; selected-module lint is not whole-tree lint |
| `git diff --check` and cumulative patch application | PASS after packaging validation | No final commit or push |
| Native tools | NOT VERIFIED | Docker, Falco, Trivy, PostgreSQL client and Chromium absent; no native disruptions, isolation or browser session |

The successful full check is the final source checkpoint for this batch. No latency,
throughput, memory reduction or detection-accuracy improvement is claimed from unit tests.

## Batch 5 — shutdown ownership and Docker stream cancellation

Five regressions failed before correction: early lock release while control work remained,
missing cleanup after a thread-start failure, stopping an unstarted worker, returning before
model training finished, and not waiting for AI executor work. A separate failing regression
showed that a competing lock attempt erased the current owner's PID before acquiring flock.

- The instance lock now encloses construction, startup and cleanup. Startup is inside the
  cleanup boundary. Shutdown requests both workers to stop before waiting, cancels the SDK
  event stream, joins event/control threads without a timeout, and waits for running model/AI
  jobs while cancelling queued executor work. The lock is released after cleanup returns.
- Stream ownership is synchronized so stop/reconnect cleanup takes each stream once. A stream
  created after a stop request is closed without consumption. Queue puts check for stop while
  waiting; the reconnect timestamp advances only after a successful enqueue. At this batch checkpoint, queues
  were unbounded and non-durable; batch 6 above bounds their entry counts.
- Status distinguishes `shutdown=stopping` from completed cleanup. The ingestion-loop log no
  longer claims that every worker has stopped. Failed baseline resets also close their pipeline.
- Lock files are opened without truncation; PID contents change only after successful flock.
  No lock file was removed to bypass an active owner.

| Batch 5 check | Observed result | Boundary |
| --- | --- | --- |
| Before fixes | 5 shutdown regressions failed; separate lock-PID regression failed | Original failures preserved in evidence |
| Focused shutdown/control/Docker/monitor/completion tests | 72 passed at checkpoint | Later PID/reset/ordering cases included in full run |
| `AUTO_ISOLATION_ENABLED=false .venv/bin/python scripts/verify_final_checks.py` | 596 Python tests + 22 subtests, 154 frontend tests, release lint/build PASS | `final-checks-20261021T182155Z`; chart chunk-size warning remains |
| `AUTO_ISOLATION_ENABLED=false /tmp/selfsentry-audit-repro/bin/python -m pytest -q` | 596 passed + 22 subtests in 13.28 s | Existing locked venv; no fresh VM installation |
| SDK stream cancellation | PASS over a blocked local socket pair | Real installed `CancellableStream.close`; fake Docker client, no daemon |
| Shutdown lock ownership | PASS with real threads and flock | Controlled blocked worker; old timed join shortened in regression harness |

Waiting for completion is deliberate: shutdown has **no guaranteed maximum duration**.
Unsupported cancellation (the installed SDK rejects SSH-stream cancellation), blocked client
creation, stuck control calls or training can keep the process and lock alive. The lifecycle
CLI's existing 15-second stop wait reports failure and retains PID records; it does not
force-kill or proceed with restart. That CLI contract was inspected, not exercised on a VM.
Native Docker/Falco/AI transport failures, forced process termination, queue capacity and
crash recovery remain NOT VERIFIED or unresolved. No real isolation was performed.

## Batch 4 — monitor scheduling and cooperative shutdown

Five new regressions failed before correction: unlimited Docker draining, a reconciliation
request lost during active reconciliation, SQLite leaked on pipeline initialization failure,
and new work started after shutdown was requested during an event or incident delivery.
These are deterministic ordering tests with fake service collaborators, not native failures.

- Each ingestion cycle forwards at most `MONITOR_MAX_BATCH_LINES` Docker events, reusing the
  existing positive batch limit. The FIFO remainder stays queued for later cycles, allowing
  Falco reads and behavior-window processing to continue between bursts. No overflow dropping
  or durable Docker queue was introduced.
- Control reconciliation consumes its request before work, preserves a new request arriving
  during work, and restores the request on failure. This avoids waiting for the periodic
  reconciliation to recover a lost wakeup.
- Control tasks check the stop event between stages and before dequeuing another event.
  Already-running calls are not interrupted; pending in-memory events are not crash durable.
- SQLite is closed after setup or pipeline initialization failure and even when executor
  cleanup raises. No database contents, isolation gates or rule approval gates were changed.

| Batch 4 check | Observed result | Boundary |
| --- | --- | --- |
| Before fixes, focused regression run | 5 failed, 14 passed | Actual baseline failures retained |
| Focused monitor/reliability/completion run | 72 passed | Before two additional cleanup cases; all included below |
| First release attempt | 582 passed + 22 subtests; lint FAIL on one changed line length | Corrected; frontend checks were not reached in that attempt |
| Final release with `AUTO_ISOLATION_ENABLED=false` | 584 Python tests + 22 subtests; 154 frontend tests; release lint and build PASS | `final-checks-20261021T181240Z`; mock services, temporary SQLite/files |
| Separate locked environment, root pytest | 584 passed + 22 subtests in 15.53 s | Existing fresh venv reused; no fresh host provisioning |
| Diff/patch handoff | Whitespace and application against the exact base checked | Uncommitted review branch; no deployment |

At the end of batch 4, queue capacity, outage backlog, retention, unbounded model scheduling,
Docker stream interruption and the timed-join/instance-lock boundary remained unresolved.
Batch 5 above supersedes the stream cancellation and normal shutdown ownership findings.
Checks between stages are cooperative, not atomic cancellation: a stop request can race with
a task beginning. This batch makes no bound on shutdown latency or representative load claim.

## Batch 3 — isolation recovery record integrity

The first batch identified A13: corrupt recovery state could be interpreted as missing,
allowing a retry to replace original network context. A second regression confirmed that
same-path state naming a different container could be consumed by resume. Both failed before
the correction. This batch does not enable real isolation or operate any workload.

- Record reads distinguish missing files from unreadable/invalid data. Validation requires
  matching full Docker ID, a supported lifecycle state, a network map and correctly typed
  optional aliases/network IDs. Invalid state is preserved and raises an error common to
  isolation and resume. Older valid records without a network-ID field remain supported.
- State filenames require a full hexadecimal Docker ID. Writes use unique private temporary
  files, fsync the contents, atomically replace the record and fsync its containing directory.
  Failed file sync preserves the previous record; failed directory sync surfaces the failure
  before Docker actions and retains the attempted record's original network context.
- Inventory survives a bad per-container record and reports `record_unavailable`, `isolated=null`
  and an explicit repair error. It does not assert that containment is verified or absent.
  Both dashboard buttons and the action helper refuse further actions for that state; backend
  actions independently re-read state, return 409 and audit failure without reporting success.
- No bad record was automatically repaired, removed, migrated or silently replaced. Operators
  must retain damaged evidence and restore only verified original network context. The two old
  UI fixtures were updated to include the ownership field actual record writers already emit.

| Batch 3 check | Observed result | Boundary |
| --- | --- | --- |
| Full release script, real isolation false | 576 Python tests + 22 subtests, 154 frontend tests; release lint/build PASS | `final-checks-20261021T180358Z`; mocked Docker, isolated SQLite/temp files |
| Fresh locked environment, root pytest without AI keys | 576 passed + 22 subtests in 13.69 s | Same Linux/Python platform; not a host deployment |
| Focused state/API tests at first checkpoint | 84 passed + 13 subtests; later API/directory-sync cases in full suite | Includes corrupted records, ownership mismatch, missing/invalid shapes, read denial, sync failures and private-file mode |
| Focused frontend operations/dialog tests | 19 passed | DOM/unit checks; no native browser certification |
| Whole-tree lint | FAIL: 45 existing findings | Changed files pass expanded release lint |
| Current Bandit scan | 23 findings: 17 low, 3 medium, 3 high | Static flags remain for review; no secure-system conclusion |

File/directory sync ordering does not prove power-loss recovery across every filesystem,
parent-directory creation or storage device. Real Docker containment/recovery, process crashes
between Docker actions, and transport failures during partial network restoration still need
native isolated-host checks. Other journals/atomically replaced files retain their earlier
durability limitations. State-directory ownership and trusted host administration remain assumptions.

## Batch 2 — rule review and counter integrity

This continuation implements code changes, not reading-only recommendations. It preserves the
first batch and its evidence. No VM deployment, database migration, native rule removal, commit
or push was performed.

- Approval/rejection/retirement now share one per-rule lock. PostgreSQL pins a connection and
  holds a session advisory lock across approval commits and native deployment; SQLite/local
  tests use a nonblocking file lock. A second reviewer gets HTTP 409 and must refresh.
  Ambiguous database lock errors discard the connection instead of returning it locked to a pool.
- Outcome recording locks the existing parent rule, then inserts/updates its counter row.
  It does not require a missing unique index or alter existing tables. Existing duplicate rows
  cause an explicit error without deleting/merging evidence. Connections close after success
  and rollback. Writers bypassing this function are outside its serialization guarantee.
- Retirement requires an explicit human reviewer and records `RULE_RETIRED`. Repeated retirement
  preserves the first review. The response reports `native_rule_unloaded: false`, the UI labels
  native state unverified, and later native matches remain recorded for retired database rows.
  Native rule unloading is still NOT IMPLEMENTED.

The regression for concurrent rejection failed before correction (HTTP 200 instead of 409).
The SQL-adapter regressions failed against the original missing-index `ON CONFLICT` statement.
The retired-native-match regression also failed before evidence handling was extended.

| Batch 2 check | Observed result | Boundary |
| --- | --- | --- |
| `AUTO_ISOLATION_ENABLED=false .venv/bin/python scripts/verify_final_checks.py` | PASS: 566 Python tests + 9 subtests; 152 frontend tests; expanded release lint and build | Actual release log under `final-checks-20261021T174353Z`; Docker/Falco mocked |
| Fresh locked venv, no AI keys, root `pytest -q` | 566 passed + 9 subtests in 12.50 s | Current source; same Linux/Python platform |
| Focused review/counter/lock tests | 43 passed at the focused checkpoint; later retirement/rollback tests included in full suite | Real SQLite transactions plus PostgreSQL connection-protocol mocks |
| Focused frontend rule tests | 12 passed | DOM/unit behavior; native browser unverified |
| Whole-repository flake8 | FAIL: 45 remaining findings | Same count as prior batch; changed files pass release lint |
| Updated Bandit scan | 23 findings: 17 low, 3 medium, 3 high | Fixed-choice SQL interpolation removed; scanner counts are not security scores |
| Native PostgreSQL locks/counter concurrency | NOT VERIFIED | No PostgreSQL server; package setup failed under execution-host user-switch restrictions |

All reviewing backend workers must run the updated code. These tests do not prove native
PostgreSQL lock lifetime, process-crash recovery, or the atomicity of the database/Falco-file
boundary. Direct database edits and direct Falco-file edits remain privileged external actions.

## Findings and security review

| ID | Severity / component | Root cause and consequence | Resolution / evidence |
| --- | --- | --- | --- |
| A01 | High / response | Diagnostic `dispatch_incident` directly called Docker isolation from a score tier, bypassing opt-in, dual-layer policy and durable attempt/audit coordination. `validate_pipeline.py` and the router smoke demo call it. | Diagnostic dispatch now logs suggestions and reports isolation not attempted. The durable monitor remains the automatic response owner. A regression reproduced the disabled-policy bypass before correction; response-engine/monitor tests remain intact. |
| A02 | High / gate | `evaluate` scanned `Config.Image`, a mutable tag that could point to bytes different from the already-created container. | Scan the inspected immutable `Image` ID; missing/invalid ID follows the existing scan-failure block/explicit-override path. Display retains the requested name. Two regressions cover ID choice and missing-ID fail-closed behavior. Native Trivy acceptance of the complete gate is NOT VERIFIED here. |
| A03 | Medium / audit | Read-before-insert deduplication did not handle a concurrent unique-key insert. Replays could produce an HTTP 500 even though the winning event existed. | Roll back the constraint error, acknowledge the matching committed key and preserve unrelated errors. A deterministic competing insert uses a real SQLite constraint; real PostgreSQL concurrency remains NOT VERIFIED. |
| A04 | Medium / incident API | Dismissing a legacy incident without monitor metadata returned success without persisting any disposition. | Return HTTP 409 with an explicit inability to record the action. Monitor-backed dismissal remains persistent. The new test failed before correction and passes afterward. |
| A05 | Medium / resources | Docker inventory clients and event reconnect clients/streams were never explicitly closed. | Close clients on successful/failed polling and close event streams/pools before retry. Tests cover polling success/failure and reconnect cleanup. This does not prove termination of an indefinitely blocked stream. |
| A06 | Medium / testability and AI | Root diagnostic scripts called live AI on import; timeline narration constructed a provider client at import and had no explicit request budget. Root pytest collection failed without credentials. | Direct-execution guards, lazy client construction, 15-second timeout/no SDK retry, context-managed provider clients. Root collection and full root tests succeed without provider keys. Narration now explicitly distinguishes observed evidence from inferred intent. |
| A07 | Medium / frontend | Blocked `sessionStorage` caused live API calls to throw before fetching data. | Credential lookup tolerates storage denial; requests carry no invented token. A browser-storage regression failed before and passes after. Backend write authentication remains authoritative. |
| A08 | Low / scoring contract | Falco normalization emits `INFO`; the scorer only recognized `INFORMATIONAL`, assigning default 30 instead of informational 10. | Recognize both spellings; regression failed before and passes after. |
| A09 | High / rule review concurrency | Original review could accept a rejection during an in-progress deployment. | Corrected in batch 2 with a pinned PostgreSQL session lock / SQLite file lock shared by review endpoints across commits and deployment. Reproduced interleaving and lock protocol tests pass. Native PostgreSQL concurrency remains NOT VERIFIED. |
| A10 | High / rule outcomes and schema | Original counter upsert assumed a rule_id unique constraint absent from the declared schema; connections were not explicitly closed. | Corrected in batch 2: parent-row-serialized insert/update, explicit duplicate refusal, and closing transaction contexts. Existing schema/data untouched. SQLite SQL-adapter tests pass; native PostgreSQL locking remains NOT VERIFIED and arbitrary direct writers are not covered. |
| A11 | Medium / retirement | Database retirement was displayed as disabled without native removal, reviewer validation or retirement audit. | Batch 2 validates/audits retirement and labels native state unverified; later native matches remain recorded. Native unloading is still NOT IMPLEMENTED. |
| A12 | Medium / resilience and scale | Original queues and model scheduling were unbounded; retained events/windows/actions still have no retention bound. Original Docker drain could monopolize ingestion. Original shutdown released ownership after timed joins. | PARTIALLY FIXED: batch 4 bounds per-cycle drain; batch 5 cancels event streams and waits under the lock. Batch 6 bounds queue entry counts and training jobs. Retention, total model/container memory and bounded shutdown latency remain unresolved; no native/soak/forced-stop guarantee. |
| A13 | Medium / state integrity | Original isolation reads treated corruption as absence, and replacement writes were not fsynced. | Isolation-state handling corrected in batch 3: full-ID/shape validation, explicit failure, original-evidence retention, private synced replacement, and unknown-containment UI/API semantics. Other journal durability, real Docker recovery and power-loss behavior remain NOT VERIFIED. |
| A14 | Medium / deployment boundary | Reads are unauthenticated; all writers share one bearer credential. Reviewer/actor names are supplied labels. Docker access is root-equivalent; reload requires scoped host privilege. | Documented host-local design limitation. No per-person RBAC, TLS gateway, production supervision or permission-hardening deployment was validated. Keep services bound to localhost. |
| A15 | Medium / reproducibility and docs | Python lower bounds resolve differently over time. README contained obsolete stepwise UI status; interface docs still described implemented features as planned and gave the wrong candidate shape. SQL draft differs from ORM. | Added a tested Python resolution, condensed README and rewrote active interface guidance. Marked the SQL draft as historical/non-installation input. Existing historical reports are retained; documentation/link review completed in Batch 7. |
| A16 | Low / repository quality | Whole-tree lint had 51 findings; selected release lint did not cover several changed critical modules. Mypy cannot start in package directories containing hyphens. | Expanded release lint to cover this batch. Batch 7 resolves whole-tree lint findings; Batch 8 resolves type-check packaging and checks untyped function bodies. No broad suppressions or cosmetic mass rewrite were applied. |
| A17 | Governance / licensing | No license is selected, despite public repository availability. | Unresolved ownership decision; no license or authorship history was invented. |
| A18 | Medium / monitor recovery | A reconciliation request arriving during work was cleared afterward; initialization errors could leak SQLite and executor cleanup could skip connection closure. | Batch 4 consumes requests before work, restores failed requests, and closes connections through setup and cleanup failures. Deterministic regressions pass; native failure recovery remains NOT VERIFIED. |
| A19 | Medium / monitor ownership | Timed joins and non-waiting executors allowed cleanup/lock release before work ended; startup failures missed cleanup. Failed competing lock attempts truncated the owner's PID. | Batch 5 waits for normal shutdown under the instance lock, cancels the event stream and pending executor jobs, cleans up after startup failure, and writes PID only after flock. Native transports and forced termination remain unverified; shutdown may wait indefinitely. |

### Findings added in follow-up batches

| ID | Severity / component | Result and remaining boundary |
| --- | --- | --- |
| A20 | High / runtime configuration | Correct monitor-owned flags and fail-closed evaluation preflights; concurrent operator reconfiguration remains outside that check |
| A21 | Medium / baseline parsing and features | Declared errors for invalid fields; umount2 included; old vectors retained and recollection guidance documented |
| A22 | Medium / confirmation and resources | Invalid JSON is unknown outcome; short-lived SQLite connections close explicitly |
| A23 | Low / evaluation reproducibility | Correct configured baseline fingerprint and preserve exporter launchers/lock/inventory |
| A24 | Low / documentation contract | Restore/test screenshot gallery marker contract; no new native browser acceptance |
| A25 | High / scanner trust boundary | Reject malformed/wrong-identity reports; actual Trivy interoperability remains unverified |
| A26 | Medium / manual windows | Partial/future records retained and timing validated; standalone tools still lack production recovery guarantees |
| A27 | Medium / invalid runtime state | Empty provider content, malformed workflow explanations and unrecognized journal baselines fail explicitly; types/migration baseline added in Batch 8 |
| A28 | High / Falco checkpoint integrity | Preserve corruption, sync commit state, report failures, use opened-file identity and retain discard boundaries; native durability/rotation limits remain |
| A29 | Medium / incident mutation | Common parent lock/refresh, normalized actor, atomic dismissal audit; native PostgreSQL contention and Docker cancellation unverified |
| A30 | Medium / recorded scan data | Complete bounded counts, object lists and SQL lengths validated; backend still trusts privileged report provenance |
| A31 | High / deployment delivery | Validate acknowledgement, bind replay identity, retain rejected evidence and continue valid work; operator/native recovery still scoped |
| A32 | High / action-to-journal gap | Start/removal and creation intent/outcome history plus Batch 20 read-only individual inspection implemented locally; unknown orphan identity, native crash/reconciliation and operator resolution remain open |
| A33 | Medium / gate command hangs | Explicit per-command CLI deadlines and uncertainty handling; native daemon/helper cancellation remains unverified |
| A34 | High / response transport error paths | Local SDK/requests failure handling, failed-state persistence and best-effort re-pause corrected; native outage/crash and cross-process recovery remain unverified |
| A35 | Medium / gate creation identity | Require one full hexadecimal Docker create ID; unknown/malformed results fail without guessed cleanup; native lost-response reconciliation remains unverified |
| A36 | Medium / reported health and malformed snapshots | Separate freshness/aggregate reported health, unknown process state, resilient component shapes and UI reasons; native health/continuity/browser acceptance remains unverified |
| A37 | Medium / completed worker progress and CLI/API divergence | Publish completed-cycle progress; shared snapshot interpretation flags stale/future/invalid progress. Busy-vs-stalled distinction and native watchdog/recovery remain unverified; no watchdog action added |
| A38 | High / locked PostgreSQL driver mismatch | Select installed psycopg2 for plain URLs; real engine and client handshake checks pass. Native PostgreSQL setup/SQL/pool/restart/restore acceptance remains unverified |
| A39 | Medium / database request failure contract | Narrow sanitized 503 handlers, unknown-write warning, real HTTP/SQLite pool and controlled commit tests; native PostgreSQL outage/recovery unverified |
| A40 | High / audit delivery acknowledgement | Validate insert/dedup reply shapes; retain transient and ambiguous failures; real route/SQLite controlled lost-response check. Native recovery and event-key/content binding remain limited |
| A41 | Medium / audit SQLite ownership and transport logs | Explicit close after transaction contexts and failure paths; omit raw transport exception messages. Retained-handle tests pass; no production leak measurement |
| A42 | Medium / audit corruption read side effects and payload integrity | Nonmutating reads, sanitized errors, null depth/degraded spool with continued ingestion; preflight SQLite batch. Affected replay blocks for reviewed repair; native storage recovery remains unverified |
| A43 | Medium / new legacy audit replay identity | Generate and retain one key per new emit; actual route/lost-reply/restart test deduplicates. Historical keyless data, caller retries and unpersisted crash gaps remain limited |
| A44 | Medium / silent pending durable audit conflict | Atomic insert/compare refuses changed payloads and preserves original time for omitted-time retries; two-thread SQLite proof. Delivered/backend and native crash limits remain |
| A45 | Medium / backend keyed audit false success | Compare event fields/detail in both duplicate paths; generic 409/finite-detail 422 preserve evidence. First-write timestamps are excluded; keyless and native race limits remain |

### Automated security checks and interpretation

`npm audit --json` reported zero known vulnerabilities for the installed lockfile.
The first `pip-audit` reported 12 advisory entries, six distinct IDs, all for the venv's
bootstrap `pip 25.0.1`; these are not 12 independent application dependency defects.
After updating only this audit environment's installer to `pip 26.2.1`, `pip-audit` reported
no known vulnerabilities. README pins that installer bootstrap; the Python application
lock retains the originally tested dependency resolution. Scans are time-specific and
cannot establish absence of vulnerabilities. Other platforms/installers were not assessed.

Bandit produced 24 findings: 17 low, four medium and three high. Reviewed high/medium flags
include SHA-1 event/dedup keys (not authentication/signatures), a SafeLoader subclass that
Bandit cannot recognize, literal-restricted YAML Jinja output intentionally without HTML
escaping, fixed-choice SQL column interpolation, and URL-opening code. The SQL interpolation
uses one of two fixed identifiers with bound values; the real issue in that function is
the original A10 missing-index upsert (corrected in batch 2). These scanner flags are not accepted wholesale as exploit proofs;
raw output is included for follow-up. Persisted hashes were not changed casually because
that would affect replay compatibility. URL and subprocess flags still require per-path review.

A limited current-tree and full-history blob scan found no matches for four patterns:
private key headers, GitHub token prefixes, AWS access-key IDs and long OpenAI-style tokens.
It inspected 600 historical blobs. It is not entropy scanning, a complete secret detector,
or proof that all credentials/log disclosures are absent. No secret values were printed.

## Cleanup manifest and refactoring report

**Proposed deletion manifest: empty. No removals authorized or performed in this batch.**
No baseline, evidence, tests, screenshot, generated native rule or local credential was deleted.
Changing the README does not delete its prior Git history. Uncertain legacy helpers remain.

| File / group | Action | Reason | Validation |
| --- | --- | --- | --- |
| `correlation-engine/event_router.py` | REFACTOR | Eliminate alternate unsafe automatic-response execution; retain diagnostic result contract | Dedicated bypass regression and monitor/response suite |
| `deployment-gate/deployment_gate.py` | REFACTOR | Bind scan to created image bytes | Gate tests with real policy, mocked Docker/Trivy |
| `backend-api/routes/audit.py`, `incidents.py` | REFACTOR | Recover concurrent dedup and reject false dismissal success | SQLite route/transaction tests |
| Docker watcher/pump and AI modules | REFACTOR | Release owned resources; prevent import/network side effects | Focused mock/resource tests and root discovery |
| `frontend-dashboard/src/api.js` | REFACTOR | Keep reads available with blocked browser storage | Vitest; no native browser claim |
| `correlation-engine/risk_scorer.py` | REFACTOR | Match the parser's informational priority contract | Scorer regression |
| README, interfaces, environment example, SQL draft header | REFACTOR | Active instructions match verified source and disclose stale-schema limits | Manual source comparison; host provisioning not verified |
| `requirements.lock` | KEEP (new) | Preserve this tested Python resolution without speculative dependency removal | Separate venv install, `pip check`, Python suite |
| Audit inventory/report/guide/tree and new regressions | KEEP (new) | Required review handoff and meaningful failure coverage | Source/log inspection |
| Historical measurements, screenshots, native generated-rule file | KEEP | Reproducibility/provenance not proven redundant | Frozen measurements/screenshots/rules preserved; evaluation safety and active methodology documentation changes are recorded above |
| Unreferenced and ambiguous helpers | KEEP | Dynamic/CLI/manual use cannot be disproved by imports | Inventory explicitly records uncertainty |

`.gitignore` already excludes `.env`, state, baselines, venvs, caches, Node installations
and build output. These exclusions were checked; no unrelated ignore rule was needed.
Potentially unused Python dependencies were retained because native startup and every
legacy command have not been verified. Frontend npm lockfile was preserved unchanged.
No CI workflow, Dockerfile or Compose deployment is tracked; a versioned migration baseline is now provided.
this is a host-managed application, not an independently verified container deployment.

## Initial batch tests and evidence

The table below records the first batch; the newest batch table above gives current results.
Complete logs and machine-readable outputs accompany the handoff. Commands run from the
repository root unless a frontend directory is stated. A failed pre-fix regression is
expected evidence, not the final state. Passing tests do not replace live verification.

| Check / actual command | Baseline | Final observed result |
| --- | --- | --- |
| `python3 -m pytest tests/ -q` before installing project dependencies | Failed: pytest unavailable | Dependencies installed in isolated venv |
| `.venv/bin/python -m pytest tests/ -q` | 538 passed, 7 subtests in 12.46 s | 550 passed, 9 subtests in 16.18 s |
| `npm test -- --run` in frontend | 150 passed, 34 files | 151 passed, 34 files |
| `npm run build` in frontend | PASS | PASS; chart chunk 512.67 kB, gzip 151.77 kB |
| `AUTO_ISOLATION_ENABLED=false .venv/bin/python scripts/verify_final_checks.py` | Earlier historical reports not reused as fresh evidence | All four release checks PASS; scope includes newly changed critical Python modules |
| `.venv/bin/python -m flake8 --exclude=.venv,node_modules --max-line-length=100` | FAIL: 51 findings | FAIL: 45 findings; raw paths retained |
| `env -u GROQ_API_KEY -u OPENAI_API_KEY ... pytest --collect-only -q` | FAIL: two live-AI import errors | PASS after direct-execution guards; full root run recorded separately |
| Separate venv `pip install -r requirements.lock`, `pip check`, `pytest tests/ -q` | Not present | Install/check PASS; first fresh-env suite 548 passed, 9 subtests before the last two API/scorer regressions |
| Final fresh-env root `pytest -q`, no AI keys, isolation false | Not present | 550 passed, 9 subtests in 13.49 s |
| `python -m mypy --ignore-missing-imports monitor-service backend-api behavioral-engine correlation-engine response-engine rule-synthesis-engine` | No configured type baseline | BLOCKED: hyphenated package name rejected; not a passed type check |
| `npm audit --json`; `python -m pip_audit --format json`; `python -m bandit -r ... -f json` | See scanner interpretation above | Tool outputs preserved; no 'secure' conclusion inferred |
| `git diff --check` | Clean initial checkout | PASS; final diff examined, no commit created |

The removed direct-dispatch isolation tests asserted the unsafe legacy behavior. They were
replaced by disabled/enabled diagnostic-no-Docker checks; actual isolation success/failure
coverage remains in `test_incident_pipeline.py` and `test_auto_isolate.py`. Counts are therefore
not evidence of coverage percentage. No production detection benchmark, throughput, CPU/RAM,
API latency or accuracy improvement was measured. Existing lab results were not recomputed.

## Feature reality and architecture

See `developer-guide.md` for subsystem data flow, functions, state ownership and maintenance.
The intended architecture is retained; the only authority consolidation in this batch makes
the diagnostic router defer automatic response to the existing durable monitor.

| Capability | Source path / dependencies | Available checks | Status in this audit |
| --- | --- | --- | --- |
| Scan → policy → container start/override → registration | Gate, scanner, policy, deployment API/outbox; Docker + Trivy + PostgreSQL | Gate/policy/API tests, simulated replay | PARTIALLY VERIFIED; complete real gate NOT VERIFIED |
| Falco normalize → journal → checkpoint/replay | Runtime parser, classifier, tailer, behavior pipeline; real JSON log | Parsing, rotation/truncation, restart and durable failure tests | PARTIALLY VERIFIED; native ingestion/kernel drop behavior NOT VERIFIED |
| Per-container learning / Isolation Forest / unavailable fallback | Feature extractor, baseline store, anomaly model, behavior pipeline; scikit-learn | Actual model fitting/unit data plus lifecycle/failure regressions | PARTIALLY VERIFIED; representative benign/attack performance NOT VERIFIED |
| Correlation → incident persistence → timeline/dashboard contract | Scorer, monitor outbox, backend, hooks; SQLite/PostgreSQL + HTTP | Unit/SQLite TestClient and frontend DOM integration | PARTIALLY VERIFIED; real PostgreSQL restart/E2E NOT VERIFIED |
| Automatic isolation and operator recovery | Policy, incident pipeline, response engine, container routes; privileged Docker API | Mocked safety, retry, partial recovery, identity/protection tests | PARTIALLY VERIFIED; no real isolation/resume executed |
| Candidate → authoritative backtest → human review → native re-fire | Pattern/templates/backtester, registry, API, deployer; benign corpus + Falco + reload rights | Literal/duplicate/backtest/review tests | PARTIALLY VERIFIED; native acceptance NOT VERIFIED; native PostgreSQL concurrency for A09 unverified |
| Continuous monitoring and failure recovery | Service, control worker, journals, lifecycle CLI | Mocked slow services, outages, restarts and process checks | PARTIALLY VERIFIED; hard-stop, sustained load, power loss NOT VERIFIED |
| Rule outcome counters | Lifecycle manager + PostgreSQL parent-row locking | Real SQLite SQL-adapter/rollback/duplicate checks and connection tests | PARTIALLY VERIFIED after batch 2; native PostgreSQL concurrency NOT VERIFIED |
| Native retirement | Deprecate route records reviewed/audited database status only | Retirement audit/identity/idempotency and retired-refire checks | NOT IMPLEMENTED as native unloading; UI now explicitly says native state unverified |
| AI narration | Optional SDK calls, bounded request clients | Provider mocks/import tests | PARTIALLY VERIFIED; real provider NOT VERIFIED; no detection authority |
| Dashboard and sample separation | React routes/hooks/adapters, backend | 165 Vitest tests/build; fixtures explicitly marked | PARTIALLY VERIFIED; no new browser visual/accessibility or live actions validated |
| Academic evidence | Evaluation scripts, reports, JSON, screenshots | Retained unchanged; evidence sync tests | Retained historical evidence; measurements NOT independently rerun |

`docker`, `falco`, `trivy`, `psql`, `postgres`, `chromium` and `google-chrome` are absent on
this execution host. No database credentials, benign corpus or live baseline was supplied.
The fresh Python venv proves dependency/test reproducibility on this Linux/Python environment,
not a fresh host deployment. Do not interrupt the user's existing VM to close these gaps.

## Remaining work by requested phase

| Phases | Completed work | Outstanding evidence/work |
| --- | --- | --- |
| 1–4 discovery/correctness/refactor | Whole-tree inventory, completed original-file inspection and focused fixes with regressions | Native integration remains unverified |
| 5–8 security/cleanup/architecture/dependencies | Critical-path review, limited secret/history and dependency scans; empty deletion manifest; authority consolidation; Python lock | Native verification for A09/A10/A13; unresolved A12/A14; dependency-use and privilege review |
| 9–11 tests/docs/UI | Baseline and final checks; active README/contracts; storage failure fix | Fresh native UI checks; whole-tree lint and scoped type checking now pass |
| 12–14 functional trace/final handoff | Source feature matrix, diff review, reports/guide/tree | Real integrations and final acceptance remain open |
| 15–17 reality/placeholders/contracts | Found diagnostic safety bypass and false-success dismissal; corrected priority/schema docs | Native UI/evaluation verification; native schema/adoption comparison; a frozen migration baseline is now available |
| 18–20 recovery/state/concurrency | Existing regression suites plus resource cleanup; explicit unresolved hazards | Disposable PostgreSQL concurrency/migrations/backup restore, power-loss and blocked-thread tests |
| 21–22 fresh setup/supply chain | npm clean install; locked Python fresh venv; scanner outputs | Fresh Linux/Falco/Docker/PostgreSQL installation; lockfile package SBOM now generated; full source/artifact provenance unverified |
| 23–24 performance/ownership | Actual build-size observations; developer/viva guide | Representative workload measurements; source review is complete |

## Final acceptance gate

PASS here means evidence for the stated criterion, not overall release approval.

| Criterion | Result | Evidence / limit |
| --- | --- | --- |
| 1. All source files inventoried | PASS | CSV covers all original tracked paths and added artifacts; semantic-review depth explicitly varies |
| 2. All removals justified | PASS | Empty deletion manifest; zero original files removed |
| 3. Critical features traced end-to-end | NOT VERIFIED | Source flow traced, but no complete native host run; rule outcomes/retirement have gaps |
| 4. Tests executed and recorded | PASS | Fresh baseline/final logs, including failures and mocked/SQLite boundaries |
| 5. Build completes | PASS | Actual Vite production build; chart-size warning retained |
| 6. Critical security findings resolved or documented | PASS | Findings and unresolved high-risk items recorded; not a security certification |
| 7. Reproducible setup/configuration | NOT VERIFIED | Fresh Python/npm checks pass; complete host provisioning absent |
| 8. Documentation matches behavior | PASS | Active instructions/contracts corrected; historical claims explicitly scoped and preserved; live behavior remains unverified |
| 9. Final Git diff reviewed | PASS | Source diff and whitespace checked; still uncommitted for maintainer review |
| 10. Remaining limitations documented | PASS | Findings, coverage checklist, feature matrix and missing tools above |

Maintainability has improved through fewer response authorities, bounded AI resource use,
recoverable audit idempotency and clearer active documentation. Correctness has regression
support for the changes, and every original file has been inspected; this cannot exclude undiscovered defects. Security and
deployment readiness remain limited by the documented lifecycle, state, privilege and live
verification gaps. No arbitrary quality score or 'production ready' label is warranted.

## Remaining master-prompt work

The original-file source review and current handoff are complete, but the full master prompt is not closed. Batches 1–25 contain the implemented changes; the items below remain open. Eight of
the ten acceptance criteria pass within their stated scope; native end-to-end behavior
and fresh-host setup remain NOT VERIFIED. Passing criterion 6 means unresolved security
findings are documented, not that every risk is repaired.

| Track | Remaining item | Closure evidence / prerequisite |
| --- | --- | --- |
| Repository engineering | A11: native rule retirement | Safe reviewed removal/reload/rollback design and native Falco acceptance; current DB retirement is deliberately labeled |
| Repository engineering | A12/A19: retention, total memory and bounded shutdown | Retention/export policy that preserves academic/audit evidence; representative load and blocked-dependency measurements before optimization |
| Repository engineering | A14: identity and deployment permissions | Decide host-local versus multi-user deployment; validate reviewer identity, scoped privileges, service supervision and gateway/TLS if required |
| Repository engineering | A15/A16: native schema adoption | Batch 8 supplies a frozen baseline, read-only comparison and working type checks. Disposable PostgreSQL migration/adoption/restore remains unverified; do not run historical schema.sql on existing data |
| Repository engineering | Dependency cleanup/provenance | Prove candidate removals across native startup/evaluation; review remaining scan flags; select license as owner; artifact/OS provenance remains open |
| Repository engineering | A32 operator action reconciliation | Intent/outcome and read-only individual inspection are implemented locally; reviewed reconciliation/retention and native crash acceptance remain open; no auto-repeat of uncertain Docker actions |
| Native acceptance | Gate through monitoring and dashboard | Real immutable image scan, allowed/blocked/override cases, registration, Falco ingestion, incident persistence and visible live state |
| Native acceptance | Model and rule behavior | Representative per-container baselines, unavailable/learning states, meaningful benign/attack cases, authoritative backtest, human approval and native re-fire; no claimed added coverage without evidence |
| Native acceptance | Isolation/recovery | Mocked paths already tested; real pause/disconnect/recovery requires explicit authorization in an isolated test environment; otherwise leave NOT VERIFIED |
| Native acceptance | Recovery and database integrity | Isolated service failures, duplicate/delayed delivery, restart/checkpoint continuity, PostgreSQL concurrent updates, backup/restore and transaction tests; no disruption of active deployment |
| Native acceptance | Browser, setup and performance | Fresh browser desktop/mobile/accessibility checks against live data, fresh Linux host provisioning, latency/CPU/memory/queue/model measurements under documented workloads |
| Final integration | Apply and review current VM changes | Compare the exact patch base with current VM branch; reconcile any newer UI/code, rerun checks and inspect diff before any commit |

Existing runners include `scripts/verify_live_reliability.py`,
`evaluation/verify_no_baseline.py`, `evaluation/verify_protected_container.py` and
`evaluation/verify_postgres_recovery.py`. They are not a single blanket safe command:
read their preconditions and use disposable services; database recovery can restart services.
No runner was executed against the user's VM from this environment.

The supply-chain follow-up generated `evidence/batch7/additional-checks/lockfile-sbom.spdx.json`
in the review package. It lists declared Python/npm lock entries, including development
and platform-optional packages. Input hashes, entry counts and structural assertions are
in `sbom-summary.json`. This does not verify installed artifacts, licenses, complete dependency
edges, OS/container packages or current vulnerabilities. That supply-chain-only follow-up changed no application code. Later batch tables supersede its test checkpoint.

## Closure review — 23 October 2026

The request to complete everything does not supply a native environment or waive the explicit
restriction on real isolation. The remaining items above are required work, not optional
reading. The delivered source and cumulative patch implement batches 1–25; the reports explain
those changes and provide their evidence. They do not apply changes to an existing installation.

Complete the remaining work in this order, retaining evidence at each boundary:

1. **Integration:** compare the recorded base and cumulative patch with the current project in
   a separate checkout. Preserve local configuration/state, resolve differences, review the diff
   and rerun the release checks. No commit is created by this handoff.
2. **Disposable host:** provision Docker, Falco, Trivy, PostgreSQL and a browser using the README
   prerequisites. Use separate credentials, database and runtime directories. Confirm automatic
   isolation is disabled before starting any monitoring or acceptance workload.
3. **Native state and feature checks:** validate migration/schema comparison and backup/restore
   on the disposable database; then exercise scan/policy/override/registration, real Falco
   ingestion and checkpoint recovery, model states, incidents, audit delivery and dashboard data.
   Record actual IDs, timestamps, commands, outputs and failure cases. Existing probe scripts
   cover portions of this flow, not full acceptance.
4. **Review and measurement:** verify desktop/mobile accessibility with the live backend;
   measure representative latency, CPU, memory, queue growth and model cost. Preserve benign
   and attack evaluation methodology and historical evidence. Use measured results to choose
   retention, resource and shutdown limits rather than inventing thresholds.
5. **Remaining engineering:** resolve reviewed native rule unload/reload/rollback, uncertain
   operator-action reconciliation, retention/export and deployment identity/permissions. Test
   these changes before changing their feature status. The current host-local boundary must
   not be treated as verified multi-user security.
6. **Authorized isolation only:** real disconnect/pause/recovery tests require explicit approval
   naming an isolated environment. General completion instructions do not establish that
   environment. Keep these checks NOT VERIFIED until actually executed; preserve human rule
   approval throughout native rule testing.
7. **Final acceptance:** repeat affected tests/builds, examine the integration diff and fresh
   evidence, and update each acceptance result individually. Only then assess deployment
   readiness. Review precedes any final commit or rollout.

No new application change was justified by this closure pass. The latest 939 Python tests,
104 subtests, 165 frontend tests, scoped types, lint and build results remain the Batch 25
results; they were not rerun or relabeled as native verification. The stale deliverables-table
reference to Batch 23 was corrected to Batch 25. Closure metadata and package integrity were
checked separately. Missing native executables were rechecked without installing software,
starting services, accessing production state or performing response actions.

## Historical acceptance update — 26 October 2026

The following supersedes older current-status wording only. Dated historical results,
failed trials and scope boundaries remain unchanged. Evidence was inspected from supplied
operator terminal output; private database/journal files remain outside the repository.

| Evidence | Current result and boundary |
| --- | --- |
| Release checks | Operator VM: 1,268 Python tests plus 104 subtests, 168 frontend tests in 34 files, lint, scoped types over 99 files, production build and whitespace check passed. Evidence directory: `state/evaluation/final-checks-20261026T064610Z`. Chart bundle warning remains non-blocking. |
| Audit durability | Seven disposable PostgreSQL/API checks passed: producer/backend SIGKILL, pending replay, unreachable backend, lost HTTP response after commit, database stop/start and retained changed-content conflict. HTTP acknowledgement loss is not PostgreSQL COMMIT acknowledgement loss. |
| Monitor replay | Five additional checks passed with real separate monitor/API processes and disposable PostgreSQL: pending incident survives SIGKILL during outage, exact-once recovery with original timeline, checkpoint reopening, private-log inode replacement and partial-line completion. Telemetry was explicitly synthetic; native Falco lifecycle was not exercised. |
| Test cleanup | Owned API/monitor stopped and owned database container removed; live monitor healthy with incident outbox zero afterward. Disposable final status had an outbox depth of one, so this run does not establish every disposable workflow drained before shutdown. |
| Rule loops | Default Isolation Forest anomaly-only sources 220 and 224 produced reviewed rules 24 and 25 and linked native re-fire incidents 223 and 226. File-write and process/parent verifier results passed. Each backtest had 36 usable matching-type benign events, zero false positives; no representative accuracy claim. |
| Native cleanup | Rules 24 and 25 retired with `native_rule_unloaded=true`; temporary reload socket override removed, environment settings restored, test container stopped. Earlier blocked retirement attempts were retained. |
| Separate host recovery | Existing separate VM restored and verified database tables/sequences, state/checkpoint/model readback and live ingestion; post-reboot health/UTC and operator browser checks recorded. This is not clean installation proof. |
| Idle health | Authenticated database readiness probe fixes backend-unknown health on an idle monitor. Its 17 targeted regressions and the current full release passed. |

Private replay evidence directory: `~/selfsentry-private-evidence/monitor-replay-20261026T064051Z`.
The terminal report is inspected evidence, not an independent execution on the operator VM.
No credentials, original logs, baselines or database exports are included here.

### Historical ten-criterion assessment — 26 October 2026

| Criterion | Result | Evidence / remaining boundary |
| --- | --- | --- |
| 1. Complete inventory | PASS within scope | Uploaded VM inventory covers all 387 source paths; no missing/extra rows or final hash mismatches. Semantic review depth remains as recorded. |
| 2. Justified removals | PASS within scope | No original files deleted; four concrete removal proposals remain retained pending owner approval. |
| 3. Critical feature flow | PARTIAL | Native gate/Falco and two supervised anomaly-only rule loops recorded; current full response and remaining fault interleavings unverified. |
| 4. Executed tests | PASS | Current operator release and 12 scoped replay checks above. |
| 5. Build | PASS | Current production build; chart-size warning preserved. |
| 6. Security findings resolved or documented | PARTIAL | Controls and known risks documented; current advisory refresh and remaining native action checks outstanding. |
| 7. Reproducible setup | NOT VERIFIED | Locked dependencies exist; existing-host recovery is not clean Linux provisioning. |
| 8. Accurate docs | PARTIAL | Current acceptance updated here; final inventory and all feature wording still require reconciliation. |
| 9. Final Git diff reviewed | PASS within scope | Exact uploaded tracked patch and five new files reconstructed at base 229c236; 30 changed files compared, focused source review and 123 regressions passed. No new actionable defect established in this diff; not proof of defect absence. |
| 10. Limitations documented | PASS | Explicit synthetic/native, accuracy, recovery and deployment boundaries retained. |

### Remaining closure work by master-prompt phases

- Phases 1–4, 9–14: inventory and uploaded diff reviewed; remaining live
  mobile/theme/keyboard/loading/error/operator-action walkthrough and final documentation consistency.
- Phases 5–8, 21–22: clean supported Linux provisioning with locked dependencies;
  current advisory/package-use/permissions review and owner license decision.
- Phases 15–20: Docker unavailability, native Falco engine restart/log lifecycle,
  remaining gate/action interruption and review/deployment interleavings, database
  COMMIT acknowledgement uncertainty. Keep uncertain actions explicit and never auto-repeat.
- Phases 23–24: representative sustained measurements and independent benign/attack
  validation with declared denominators; investigate recurring clock skew root cause.
- File deletion, live pruning and real isolation remain separately controlled owner actions.
  A general completion request does not authorize real isolation on existing workloads.

Historical tables above retain their original dates and evidence. This assessment supersedes
older blanket pass counts; it is not release approval or a production-readiness claim.

### Uploaded final diff review — 26 October 2026

The operator package reconstructed cleanly at `229c236d325013e9249069affdf8b4c38e83e923`.
All 30 changed files matched the previously reviewed source except the two expected
VM-regenerated inventory files. Inventory rows, final tree and source path set each
cover 387 paths; every populated final SHA-256 matched the reconstructed bytes.
Historical inventory counts in older validation sections retain their original scope.

Focused checks independently executed on the reconstruction: 123 passed across database
configuration, idle readiness, duplicate guard, holdout accounting and both new verification
runners. These are unit/component regressions, not a repeated native PostgreSQL/Falco run.
Whitespace checking passed. The supplied native/full-release evidence remains separately
attributed above. No new actionable application defect was established during this review.

This documentation update changes inventory/report hashes; regenerate inventory after
applying it. No new files, runtime changes, deletions, commits or pushes are required.

## Docker event-stream EOF follow-up — 26 October 2026

Unexpected Docker event-stream EOF now reports unavailable during reconnect
backoff. Backoff resets after an accepted event rather than an empty stream.

Verification: 12 event-pump tests passed; full release passed 1,272 Python
tests plus 104 subtests, 168 frontend tests, lint, scoped types and build.
Release evidence: state/evaluation/final-checks-20261026T092428Z.

Four native component checks passed through a private faulting connection:
outage reporting, reconnection, explicit recovery enumeration and subsequent
real event delivery. Owned probe cleanup succeeded; live health and empty
outbox verified after application restart.

Private evidence remains outside Git:
~/selfsentry-private-evidence/docker-outage-fixed-20261026T092311Z/results.json.
Earlier failed attempts are retained. This does not establish full-monitor
reconciliation, Docker daemon restart or native Falco lifecycle acceptance.

## Full-monitor Docker connection recovery — 26 October 2026

Operator execution on commit 628ae21 passed seven prerequisite audit checks
and five separate full-monitor checks. Docker degradation retained fresh
heartbeat/control progress; synthetic incident delivery continued during
the outage. Automatic reconciliation recovered a container whose start
event was deliberately excluded from replay. Post-recovery events arrived,
incident identity/timeline remained unchanged, and incident/audit queues
drained. Owned probes, database, API, monitor and proxy were cleaned up.
The original live monitor remained healthy.

Private evidence: ~/selfsentry-private-evidence/full-monitor-docker-20261026T094026Z.
Scope: private Docker connection failure, not daemon restart. Falco input
was explicitly synthetic; native Falco lifecycle, model accuracy and real
isolation were not tested. Raw evidence remains outside Git.

## Private native Falco lifecycle — 26 October 2026

Operator execution on commit 9a5498d passed four checks using two separate,
bounded modern-eBPF Falco captures and a private literal host-printf rule.
Both captures produced fresh native events. The real FalcoTailer reopened
committed checkpoints without replay and recovered after private-log inode
replacement. Both capture processes exited; live Falco PID 4366 and monitor
health were preserved.

Private evidence: ~/selfsentry-private-evidence/native-falco-lifecycle-20261026T094817Z.
No live service restart, live-log rotation, full-monitor incident flow,
lossless downtime capture or permanent clock-skew repair is established.

## Interrupted gate-action verification — 26 October 2026

Operator execution on commit b0560dc passed controlled SIGKILL before
Docker start and after acknowledged start before durable outcome storage.
Production action helpers, leases and a private SQLite journal were used.
Original intents remained unchanged; unfinished actions were not queued
as completed decisions. Active ownership blocked reconciliation.
Explicit full-ID observations recorded stopped/running state without
rewriting uncertain outcomes; duplicate reconciliation was refused.
Unknown creation identity remained unresolved. Owned probe cleanup and
live monitor health with empty incident outbox were verified.

Private evidence: ~/selfsentry-private-evidence/interrupted-gate-20261026T095550Z.
This does not establish complete scan/policy/create/remove crash acceptance
or automatic response/isolation recovery. The runner import-path failure
was retained; the successful run supplied monitor-service via PYTHONPATH.

## Interrupted gate-create verification — 26 October 2026

A controlled interruption after Docker acknowledged creation but before
the gate persisted the container identity retained the unfinished intent.
Reconciliation refused to guess the missing identity. The owned disposable
container was removed; subsequent live monitor health and an empty incident
outbox were verified.

Private evidence remains outside Git:
~/selfsentry-private-evidence/gate-create-85c8666d4cbe/results.json.

Scope: create acknowledgement before identity persistence. This does not
establish scan/policy acceptance, removal interruption recovery, or recovery
from a lost Docker acknowledgement.

## Interrupted gate-remove verification — 26 October 2026

Operator execution on commit 764cc0d interrupted the production removal
helper after Docker acknowledged removal but before durable outcome storage.
The original unfinished intent remained unchanged. Explicit reconciliation
verified the full-ID container's current absence without rewriting the
original uncertain outcome. The disposable container was absent afterward;
live monitor health and an empty incident outbox were verified.

Private evidence remains outside Git:
~/selfsentry-private-evidence/gate-remove-cdbccd12b7e6/results.json.

Scope: acknowledged removal before outcome persistence. This does not
establish recovery from a lost Docker acknowledgement or automatic-response
interruption.

## Native disposable response verification — 26 October 2026

Operator execution on commit b2e1cbf exercised production isolation/resume
functions against one explicitly authorized disposable container on a new
internal Docker network, using private response state.

Native pause and complete network disconnection passed. Repeated isolation
preserved the original record. Resume restored running/unpaused state and
the exact original network identity. Both owned resources were removed;
live monitor health and an empty incident outbox were verified.

Private evidence: ~/selfsentry-private-evidence/response-19dd96f1c0a5/results.json.
Scope: direct response functions, not automatic policy, API audit delivery,
transport failure or process-interruption acceptance. Ordinary automatic
isolation remained disabled.

## Native response interruption verification — 26 October 2026

A controlled SIGKILL after acknowledged unpause and before network
restoration preserved the private durable resuming record and original
network identity. Independent inspection found the disposable container
running, unpaused and disconnected. An explicit production-function retry
restored the exact original network and persisted resumed state.

Both owned resources were removed. Live monitor health and an empty
incident outbox were verified. Ordinary automatic isolation remained off.

Private evidence:
~/selfsentry-private-evidence/response-kill-3ac509862ace/results.json.

Scope: one controlled resume interruption boundary and explicit recovery.
This does not establish continuous paused containment, automatic crash
recovery, every response interruption boundary or API audit acceptance.

## Sustained workload measurement and false positives — 26 October 2026

A 30-minute single-container synthetic routine workload completed on commit
468d20b. Of 181 status samples, 180 succeeded and one connection reset;
the failed request is unavailable evidence, not a reported unhealthy state.
Successful-request latency was p95 72.4 ms, maximum 163.2 ms.
All sampled delivery/control queues were zero.

One Falco instance reported 3,104,885 additional kernel events with zero
kernel and output-queue counter drops over approximately 1,800 seconds.
This does not prove end-to-end losslessness. Managed monitor root-process
RSS increased from 92.5 to 218.2 MiB; the main journal grew approximately
102 MiB. Initialization and later incident/AI activity coincided with
memory increases; their causal contributions and leak absence are unproven.
The temporary Falco metrics override was removed and service activity verified.

The unchanged routine workload generated anomaly-only incidents 228–231
during full steady-operation windows. Incident 232 overlaps cleanup and
is assessed separately. Offline production-model replay reproduced all five
raw and normalized scores exactly; sklearn also predicted anomaly.
The frozen 20-sample baseline contained six unique vectors.
This establishes false positives for this controlled workload, not a
representative false-positive rate. No baseline or threshold was changed.

Private evidence:
~/selfsentry-private-evidence/sustained-e13584e27565/

Remaining: explain the connection reset, assess memory/storage behavior
under longer representative workloads, and validate any model improvement
with independent benign and deviation cases. No blanket performance or
detection-quality acceptance is claimed.

## New baseline observation boundary — 26 October 2026

New container lifecycles persist learn_after at discovery. Training accepts
only buckets beginning at or after that boundary, excluding the partially
observed discovery bucket. Existing saved baselines remain unchanged.

Regression checks cover exclusion across restart, subsequent full-window
admission and security-alert delivery from the excluded bucket. Existing
replay, late-alert invalidation and readiness assertions were retained with
fixtures explicitly discovered at the window boundary.

Operator release passed 1,274 Python tests plus 104 subtests, 168 frontend
tests, lint, scoped types, build and whitespace checks.
Evidence: state/evaluation/final-checks-20261026T154456Z.

This improves training admission. It does not establish observation
continuity during later outages or resolve the recorded routine-workload
false positives; independent model-quality validation remains open.

## Varied routine workload and recurring event-clock fault — 27 October 2026

A new cyclic routine workload trained the unchanged Isolation Forest on
20 admitted windows. Training was frozen before validation, SHA-256:
8d477dc0a4befa93c66c093cbb6d0108943abaf880fd9c74d1a9feec2d6e7b9d.

Eight subsequent full benign windows passed capture clock/freshness guards,
with no missing windows. All eight triggered the model flag at 0.5;
three qualified at the configured monitor threshold of 0.8. Validation
feature ranges lay within training ranges. This is a controlled benign
quality failure, not a representative production false-positive rate.
No threshold, model or saved baseline was changed to suppress the result.

Earlier captures were incomplete or timestamp-invalid and remain retained.
Fresh appended events showed approximately 60,224 seconds of timestamp skew.
Falco restart temporarily restored 21–77 ms receipt differences. A later
controlled-deviation attempt aborted on approximately 793 seconds of skew.
Deviation detection and recall remain unmeasured. The owned study container
was explicitly stopped; its filesystem and private evidence were retained.

Host BOOTTIME-minus-MONOTONIC did not explain the earlier skew. Subsequent
NTP status showed an approximately 76 ms offset; queried time-sync/kernel
logs supplied no matching clock-step evidence. Permanent cause is unresolved.
A healthy monitor heartbeat does not attest event timestamp correctness.

Private evidence:
~/selfsentry-private-evidence/model-study-55306e8084b8/

This study does not establish a false-positive improvement from varied
training or the discovery-window admission change.

## Event timestamp observation — 27 October 2026

Monitor status exposes event_time_observation after a successfully processed
container event: event_timestamp, received_at, signed
receipt_minus_event_seconds, warning, interpretation and scope.

warning is true when the absolute receipt/event difference exceeds 30 seconds.
A positive difference may reflect historical replay, backlog, delivery delay
or clock skew; it does not diagnose the cause. A negative difference indicates
an event timestamp ahead of receipt. The observation describes the latest
processed container event and remains unchanged while no new event arrives.
It does not alter aggregate health, discard evidence, change checkpoints,
repair timestamps or add a dashboard banner.

Four regressions cover fresh/delayed/future events, warning replacement,
status persistence and checkpoint replay. Operator release passed 1,278 Python
tests plus 104 subtests, 168 frontend tests, lint, types, build and whitespace.
Evidence: state/evaluation/final-checks-20261027T104226Z.

## Completed controlled holdout study — 27 October 2026

Frozen 20-window training was evaluated against eight subsequent benign
windows and four later controlled-deviation windows, without overlap,
missing windows or threshold tuning.

At the model flag threshold of 0.5, all eight benign and all four deviation
windows flagged. At the configured monitor threshold of 0.8, three of eight
benign windows and three of four deviation windows qualified. This is an
adverse quality finding, not a production accuracy or attack-recall claim.
The evaluator's positive label denotes added uname activity and /dev/null
opens, not malicious attacks. Each deviation window contained 59–60 uname
records. Qualification is an offline assessment, not proof of API incident
delivery for every window.

The complete deviation capture retained one Falco instance, zero kernel
and output-queue drop-counter deltas, maximum matching-event gap 1.11 s,
and maximum receipt/event difference 134 ms. These bounded observations
do not prove end-to-end losslessness. Earlier invalid attempts remain
preserved and excluded.

The owned study container was stopped. Metrics were preserved privately,
the temporary study-metrics override was removed, and Falco was active
after restart. The baseline, default model and thresholds remain unchanged.

Private evidence:
~/selfsentry-private-evidence/model-study-55306e8084b8/
deviation-instrumented-1793118060645859744/combined-evaluation.json

The controlled study is complete; representative model-quality validation
and a separately evaluated improvement remain open.

## Candidate model rejection — 27 October 2026

A fixed scaled LOF candidate flagged zero of eight routine development
windows but only two of four controlled-deviation windows. Adding a signal
for changes to constant training features produced zero/eight benign flags
and four/four deviation flags on already-inspected development data.

The candidate policy was then frozen before two new windows of explicitly
approved date activity. LOF flagged one/two benign windows; the combined
rule flagged both. The combined rule is rejected as a replacement incident
classifier. Structural novelty does not establish maliciousness.

Aggregate process/file counts do not preserve the identity or approval
context needed to distinguish these legitimate changes from the controlled
deviation. Any future candidate needs representative approved activity,
separate calibration and untouched validation. No live algorithm, baseline
or response threshold was changed.

Private evidence:
~/selfsentry-private-evidence/model-study-55306e8084b8/
fresh-legitimate-1793122011168844726/candidate-evaluation.json

The owned study container remains stopped. Development results and this
negative fresh validation remain retained.

## Prospective calibrated LOF study — 27 October 2026

A new synthetic native workload supplied 24 training windows and six
separate calibration windows. The LOF decision boundary was frozen at
0.47411045071039704 before validation collection.

On subsequent validation windows, calibrated LOF flagged zero of six
approved routine windows, two of two structural-deviation windows and
two of two volume-deviation windows. The unchanged Isolation Forest
comparison, trained on the same study training data and evaluated at
0.8, qualified five of six benign windows and all four deviation windows.

All five capture stages passed their guards. Maximum reported receipt
skew was below 0.136 seconds. Each stage stopped the owned container
and reported a healthy live monitor with empty incident and audit queues.
The disposable study container remains stopped.

These small synthetic results support further independent evaluation.
They do not establish production accuracy, malicious-attack recall,
zero native drops or a reliable false-positive rate. Structural novelty
was reported separately. The live model and configuration were unchanged.

Private evidence: ~/selfsentry-private-evidence/workload-study-v2

## Normal managed shutdown — 28 October 2026

On commit 840f00e, one normal managed stop completed successfully in
0.393 seconds. Managed startup then recovered a healthy monitor with
empty incident and audit delivery queues; automatic isolation remained
disabled. The 49 targeted shutdown/control/monitor tests also passed.

The CLI sends SIGTERM, waits up to 15 seconds and retains PID records
when a managed process remains alive. Monitor cleanup waits for running
background work while retaining its instance lock.

This verifies one normal stop/start cycle. It does not establish a
graceful completion deadline for stalled external calls or running jobs.

Private evidence:
~/selfsentry-private-evidence/normal-shutdown-4a5811a3f103

## Managed stop timeout verification — 28 October 2026

On commit 8d34839, the production CLI stop function was exercised against
one private process configured to ignore SIGTERM. It returned an explicit
failure after 15.024 seconds, retained the original PID records unchanged
and did not force-kill the process or claim successful shutdown.

The test harness subsequently killed and reaped its owned process.
The live monitor remained healthy. This verifies CLI timeout reporting
and record retention, not bounded completion of stalled monitor workers.

Private evidence:
~/selfsentry-private-evidence/shutdown-timeout-11cba6c49416

## Native PostgreSQL COMMIT reply loss — 28 October 2026

On commit 4d0ca6a, five checks passed using the production FastAPI audit
path in-process and one disposable PostgreSQL 18 container.

A protocol proxy forwarded COMMIT and withheld PostgreSQL's actual
COMMIT CommandComplete reply. Independent inspection verified the row
was committed while the application request still awaited its outcome.
Closing the connection produced HTTP 503 with explicit write uncertainty.
An identical keyed retry acknowledged the original row without duplication;
changed-content replay returned HTTP 409.

All five proxy unit tests also passed. The owned database container was
removed, and the live monitor was subsequently verified healthy with
automatic isolation disabled.

This closes the recorded wire-level COMMIT-reply-loss gap for the keyed
audit endpoint. It does not establish blanket endpoint idempotency,
host power-loss recovery or WAL/storage-device durability.

Private evidence:
~/selfsentry-private-evidence/commit-ack-20261028T074216Z

## Rule-review process crash verification — 28 October 2026

On commit c33dab8, production review routes were exercised against a
disposable real PostgreSQL database with a separate request process killed
by SIGKILL at two controlled boundaries: before and after a private
deployment-adapter file effect.

All six acceptance checks passed. Competing approval/rejection requests
were blocked while the review lock was held. After each process death,
the lock could be reacquired and the committed approval remained intact,
without a deployed status or deployment audit claim. Seven helper tests
also passed. The owned database container was removed; the live monitor
was subsequently checked healthy with automatic actions disabled.

Backtest, duplicate-registry and deployment behavior used controlled
adapters. This does not establish native Falco publication/reload recovery,
host power-loss durability, or safe automatic deployment retry. The native
effect-before-final-database-status crash boundary remains open.

Private evidence: review-crash-20261028T104551Z/results.json.

## Native deployment-before-status crash verification — 29 October 2026

On commit 1e7976c, the production approval route, backtester, duplicate
guard and deployer were exercised with real PostgreSQL and native Falco.
A separate approval process was killed after the native deployer returned
and before the final deployed-status database commit.

All six acceptance checks and ten helper tests passed. Competing reviews
were blocked. After SIGKILL, committed approval remained and the review
lock was released. Seven native rule matches were observed while the
database still recorded approved. One explicit approval retry committed
deployed status and one deployment audit without appending duplicate
rule bytes; five further native matches were observed.

Cleanup restored the original generated-rule bytes and reloaded Falco.
Eleven subsequent target-write witnesses produced zero test-rule matches.
Owned containers were removed without cleanup errors. The live monitor
was healthy with empty incident and audit queues. Maximum observed
absolute event/receipt lag was 0.072 seconds.

This closes the tested request-owner crash boundary, not host power-loss,
WAL/device failure or all deployment failure cases. The candidate row and
database were disposable, the guard registry was private, and the benign
backtest contained only eleven usable native events. No representative
false-positive rate or zero-drop guarantee is claimed. Live monitoring
may retain probe evidence; cleanup was not a production retirement test.

Private evidence: native-deployment-crash-20261029T041642Z/results.json.

## Controlled stalled-worker shutdown — 29 October 2026

On commit e29c71e, a separate private monitor process exercised production
main, signal handling, shutdown, instance locking, ControlWorker.stop and
CLI stop with deliberately stalled control work.

All six acceptance checks and six helper tests passed. The CLI returned
an explicit timeout after 15.006 seconds, retaining PID records and the
active owner's lock. Shutdown remained stopping without premature sink
closure. A separate competing monitor was refused without changing the
owner's lock contents.

Releasing the controlled worker allowed orderly shutdown in 0.268 seconds.
Private PID-record cleanup and a fresh private monitor iteration succeeded.
All owned processes were reaped. The live monitor retained PID 5012,
remained healthy and reported empty incident and audit queues.

ControlWorker.run, ingestion/pump wiring and the sink used controlled
adapters. This verifies the tested stall/release recovery behavior, not an
actual hung network/model/LLM request or a completion deadline for permanently
blocked workers. No live monitor was signalled, and Docker, PostgreSQL and
Falco were not changed by this check.

Private evidence: stalled-worker-20261029T043133Z/results.json.

## Installed package review — 29 October 2026

On source commit a2b3e99, eight selected system packages were installed:
Falco, Trivy, Docker Engine/CLI, containerd, PostgreSQL 16, Python 3.12
and the running kernel package. Installed versions matched candidates
in the locally cached APT metadata.

Root-level dpkg verification reported only the Falcoctl configuration
difference. The kernel entry from the unprivileged check disappeared
with root access; its file permissions were root:root 0600.

Comparison with the downloaded installed-version Falco package showed
YAML formatting/order changes and falcoVersions renamed to falcoversions,
with the displayed values unchanged. Behavioral equivalence of these
key spellings was not established. Falcoctl reported version 0.14.2;
falcoctl-artifact-follow.service was inactive at inspection.

No package, configuration or service was changed by this review.
Evidence: ~/selfsentry-private-evidence/package-provenance-20261029T100002Z,
supplemented by operator-supplied root verification and package diff.

This completes the selected-package inventory/local integrity inspection.
It does not independently verify repository signing-key provenance,
installation-media authenticity, all installed files, Node/npm/Python
dependencies, or absence of vulnerabilities. Cached APT candidates are
not a claim about the latest available upstream releases.

## Frozen candidate cross-VM validation — 30 October 2026

The corrected external runner used /usr/bin/uptime and preserved the
earlier failed attempt. Original training, calibration and LOF cutoff
0.47411045071039704 remained unchanged.

All four stages supplied six complete windows. LOF flagged 0/6 routine
benign, 6/6 approved uptime, 6/6 controlled process-deviation and 6/6
controlled volume-deviation windows. The offline Isolation Forest
comparison qualified all six windows in every stage at 0.8.

The candidate is not accepted for live promotion: approved new activity
still produced six false positives. Controlled deviations are not malicious
attacks. This synthetic cross-VM study does not establish production
accuracy or lossless capture; native drop counters were not collected.
All captures passed their guards, retained the owned container stopped,
and reported a healthy monitor with empty delivery queues afterward.
Live model and response configuration were unchanged.
