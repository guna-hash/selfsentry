"""Export only target telemetry for an existing schedule; source database is read-only."""

from contextlib import closing

import json
import sqlite3
import tarfile
import sys
from pathlib import Path
from dotenv import dotenv_values

root = Path.cwd()
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
from journal_archive import event_rows  # noqa: E402

trial_path = root / "state/evaluation/full-20261011-only.jsonl"
trials = [json.loads(line) for line in trial_path.read_text().splitlines() if line.strip()]
if len(trials) != 200 or len({row["container_id"] for row in trials}) != 1:
    raise SystemExit("Expected one target and 200 trials; no export made.")
schedule = root / "state/evaluation/schedules/full-20261011.jsonl"
entries = [json.loads(line) for line in schedule.read_text().splitlines() if line.strip()]
buckets = {int(entry["boundary_epoch"]) for entry in entries}
cid = trials[0]["container_id"]
values = dotenv_values(root / ".env")
state = Path(values.get("MONITOR_STATE_DIR") or root / "state/monitor")
db_path = (state / "pipeline.sqlite").resolve()
if not db_path.is_file():
    raise SystemExit("Monitor state database missing; no export made.")
out = root / "state/evaluation/full-20261011-telemetry.jsonl"
if out.exists():
    raise SystemExit("Telemetry export already exists; preserve it or use another filename.")
counts: dict[str, int] = {}
with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)) as db:
    selected = sorted(event_rows(db, cid, min(buckets), max(buckets)),
                      key=lambda row: (row[1], row[0]))
with out.open("x") as stream:
    for key, bucket, kind, body in selected:
        if bucket in buckets:
            stream.write(
                json.dumps(
                    {"event_key": key, "bucket": bucket, "kind": kind, "event": json.loads(body)}
                )
                + "\n"
            )
            counts[kind] = counts.get(kind, 0) + 1
archive = Path.home() / "Downloads/selfsentry-layer-telemetry.tar.gz"
archive.parent.mkdir(parents=True, exist_ok=True)
if archive.exists():
    raise SystemExit(f"Archive already exists; telemetry saved at {out}")
with tarfile.open(archive, "w:gz") as bundle:
    bundle.add(out, arcname=out.name)
print("Exported event counts:", counts)
print("Upload:", archive)
print("No baseline, monitor settings, services, or source evidence were changed.")
