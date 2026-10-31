# Monitor journal archives

Archiving is manual and disabled until an operator runs `scripts/archive_journal.py
--apply`. There is no default age cutoff, scheduled purge, automatic vacuum or
archive deletion. The monitor creates two empty metadata tables on first startup
with this version. Existing event bodies are unchanged by startup.

## Preserved records

Only baseline payloads in closed windows ending at or before an explicit cutoff
are eligible. The live journal keeps their original key, container, bucket, kind,
body checksum and archive reference. Replay checks consult live and archived keys
before changing counters, lifecycle or emitting late-event evidence. Window
markers remain live, preserving the distinction between old and new windows.

Alerts, rejected evidence, lifecycle, model/review files, windows, outbox and
response-action history are not archived by this command. Late security evidence
continues entering the live journal. Baseline review still reads all alerts live.

Academic telemetry export and SVM evaluation use `journal_archive.event_rows` to
read both stores. Consumers that issue SQL against `events` directly now see only
live payloads; use that helper for complete historical telemetry. Archive files
are verified against their file checksum and every retained row identity/body
checksum. Missing or changed evidence raises an error instead of returning an
apparently complete export. The monitor's ordinary status response does not
continuously scan archive files; successful monitor health alone does not attest
to archive integrity.

## Plan and apply

Choose a cutoff suitable for the study and inspect a plan while monitoring runs:

```bash
.venv/bin/python scripts/archive_journal.py \
  --before '<ISO-8601 timestamp with timezone>' --limit 1000
```

The cutoff refers to the closed window's end, not arrival time. A batch has at
most 5,000 rows, 32 MiB of original JSON payloads and a 64 MiB archive file.
Reduce `--limit` if a batch exceeds a limit. The command processes one batch and
does not loop until all history has moved. There is no hard runtime deadline.

After backup/export verification and reviewing the selected cutoff, stop the
monitor before using the same command with `--apply`. The exclusive monitor lock
and SQLite write transaction prevent ingestion from racing the move. A failed
lock acquisition leaves the owner's PID untouched. Do not use older monitor code
after archiving: it would not consult retained replay identities or archive reads.

The archive is created under the configured monitor state directory at
`journal-archives/<random-id>.sqlite`. It is closed, fsynced, published without
replacement and its directory synced before the live transaction references it.
That transaction inserts retained identities and removes exactly the matching
baseline rows. It commits with SQLite FULL synchronous durability. Readback of
the published file precedes removal. Readers hold a single live read snapshot
across the union of both stores.

If publication or commit fails, the live transaction rolls back. A process death
before commit leaves original live rows; after commit, the published archive and
retained keys are authoritative. An interrupted run can leave an unreferenced
`.partial` or `.sqlite` file. Keep it for review; no automatic orphan cleanup or
uncertain-operation retry is performed. A later run processes remaining live
rows and never overwrites existing archive files. These checks do not simulate
power loss, faulty storage hardware or every filesystem's durability behavior.

## Export and recovery

Use the current archive-aware exporter after installing this version:

```bash
.venv/bin/python scripts/export_monitor_journal.py
```

The earlier standalone `selfsentry-journal-export/export_journal.py` only copies
one SQLite file. It remains valid for the pre-archive snapshot already verified
on 2026-10-23, but must not be used as a complete journal export after archiving.
The current exporter pins one live snapshot, copies its referenced archive files,
then checks all row identities and payloads from the copied set. By default it limits exports
to 100 archives, 512 MiB of archive files, a 512 MiB live journal and 100,000
rows per table. Larger stores require explicit bounded options; no rows or
archives are silently omitted. See the larger-export procedure below.

Keep exports private. Copying or restoring `pipeline.sqlite` alone after archiving
is insufficient: keep its referenced `journal-archives` files beside it. Restore
only while the monitor is stopped and with compatible source. Do not merge a
snapshot's metadata with another journal or remove archived keys/window markers.
A journal export excludes PostgreSQL, models, other journals, Falco checkpoints,
configuration and service state; it is not a coordinated whole-app rollback.

## Storage limits still open

Moving payloads makes live pages reusable; it does not immediately shrink the
SQLite file, compress evidence or reduce total disk usage. Publication temporarily
needs space for both copies. Full-disk/write failures must not remove live rows;
there is no policy that acknowledges an event without durable storage. Private
unreferenced files from failures can consume disk and need operator review.

Retained identities, windows, alerts, workflow history, models and cold archives
still grow. Owner-selected hot/cold budgets, archive lifetime, archive health
reporting, coordinated log rotation, long-running load and disk-exhaustion
acceptance remain open. This change preserves replay and historical reads during
manual baseline archival; it does not close the whole A12/A19 scale finding.


## Explicit larger exports

For the measured test journal (592 MiB, 280,669 live events), use explicit
limits without changing the conservative defaults:

    .venv/bin/python scripts/export_monitor_journal.py \
      --max-database-mib 1024 --max-table-rows 500000 --deadline-seconds 600

The byte limit applies separately to the live database and the combined
referenced archives. Overrides are capped at 2048 MiB, 1,000,000 rows per
table and 900 seconds per export snapshot. The 4 MiB SQLite cell limit,
100-archive cap, exclusive publication, source read-only transaction,
free-space checks, typed row fingerprints, duplicate accounting, integrity
check and health/PID checks remain in force. Each manifest records its limits.
Overrides are scoped to one operation; later default runs retain original limits.

Row fingerprints retain one SHA-256 digest per row before sorting. This bounds
rather than eliminates memory growth; larger exports consume more memory, I/O
and WAL retention while the source snapshot remains open. The snapshot deadline
is not a hard whole-process deadline: final file hashing/fsync and service calls
have their existing boundaries. Do not overlap an export with a timed study.

After a successful export, test archival only on its disposable copy:

    .venv/bin/python evaluation/verify_archive_copy.py \
      --snapshot /absolute/path/to/verified/export-directory \
      --max-database-mib 1024 --max-table-rows 500000 --deadline-seconds 600

The verifier records these limits and applies them to row fingerprints and its
archive-aware re-export. Its deadline option governs that re-export snapshot,
not the complete verification process. Live event rows and the source export
are preserved. Exporting and disposable-copy validation do not authorize live
archival or deletion, shrink files, choose an age cutoff or close total-disk
retention bounds. Keep the source export and manifest private and intact.
