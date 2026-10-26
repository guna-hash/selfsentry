"""Plan a baseline archive, or publish one batch with the monitor stopped."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import sqlite3
import sys

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "monitor-service"))
from journal_archive import archive_batch, candidates, read_snapshot  # noqa: E402
from monitor_config import load_config  # noqa: E402


def cutoff(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise argparse.ArgumentTypeError("Cutoff must include a timezone")
    epoch = result.timestamp()
    if not math.isfinite(epoch) or epoch > datetime.now(timezone.utc).timestamp():
        raise argparse.ArgumentTypeError("Cutoff must be a finite past timestamp")
    return int(epoch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=cutoff,
                        help="Closed window end cutoff, ISO 8601 with timezone")
    parser.add_argument("--limit", type=int, default=1000, help="Batch rows, 1 to 5000")
    parser.add_argument("--apply", action="store_true", help="Requires stopped monitor")
    args = parser.parse_args()
    os.chdir(ROOT)
    load_dotenv(ROOT / ".env")
    config = load_config()
    state = config.state_dir.resolve()
    path = state / "pipeline.sqlite"
    if not path.is_file() or path.is_symlink():
        raise SystemExit("Existing regular pipeline.sqlite is required")
    if not args.apply:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            with read_snapshot(db):
                rows = candidates(db, args.before, config.window_seconds, args.limit)
        print(json.dumps({"mode": "plan", "candidate_rows": len(rows),
                          "payload_bytes": sum(len(row[4].encode()) for row in rows),
                          "before_epoch": args.before, "changes_applied": False}, indent=2))
        return
    # Match monitor ownership without truncating its PID or taking its identity.
    with (state / "monitor.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit("Stop the monitor before applying a journal archive")
        with closing(sqlite3.connect(path)) as db:
            report = archive_batch(db, args.before, config.window_seconds, args.limit)
        print(json.dumps(report, indent=2))
    print("No vacuum, service start, PostgreSQL change or archive deletion performed.")


if __name__ == "__main__":
    main()
