"""Export a verified journal snapshot and every referenced baseline archive."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import time
import uuid

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
from journal_archive import has_archives, verified_archive, sync_directory  # noqa: E402

MAX_DATABASE_BYTES = 512 * 2**20
MAX_TABLE_ROWS = 100000
MAX_CELL_BYTES = 4 * 2**20
DEADLINE_SECONDS = 120


class ExportFailed(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ExportFailed(message)


def cell(value):
    # Preserve SQLite value types, including duplicate rows and float/int differences.
    if value is None:
        return ["null"]
    if type(value) is int:
        return ["integer", str(value)]
    if type(value) is float:
        return ["real", value.hex()]
    if isinstance(value, str):
        return ["text", value]
    if isinstance(value, bytes):
        return ["blob", value.hex()]
    raise ExportFailed("Unsupported SQLite value type")


def digest_rows(rows, deadline=None):
    hashes: list[bytes] = []
    for row in rows:
        require(deadline is None or time.monotonic() <= deadline,
                "Row verification exceeded its export deadline")
        require(len(hashes) < MAX_TABLE_ROWS, "A table exceeds the reviewed export row limit")
        encoded = json.dumps([cell(value) for value in row], ensure_ascii=True,
                             separators=(",", ":")).encode()
        hashes.append(hashlib.sha256(encoded).digest())
    digest = hashlib.sha256()
    for value in sorted(hashes):
        digest.update(value)
    return {"rows": len(hashes), "sha256": digest.hexdigest()}


def fingerprint(connection, deadline=None):
    schema = digest_rows(connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ), deadline)
    tables = {}
    for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall():
        # SQLite internal tables, if present, are part of this exact snapshot too.
        quoted = '"' + name.replace('"', '""') + '"'
        cursor = connection.execute("SELECT * FROM " + quoted)
        columns = [column[0] for column in cursor.description]
        tables[name] = {**digest_rows(cursor, deadline), "columns": columns}
    return {"schema": schema, "tables": tables,
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "application_id": connection.execute("PRAGMA application_id").fetchone()[0]}


def readonly(path, deadline, *, immutable=False):
    # Immutable mode is only for the completed private export, never the live source.
    uri = path.resolve().as_uri() + "?mode=ro" + ("&immutable=1" if immutable else "")
    connection = sqlite3.connect(uri, uri=True, timeout=2)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_CELL_BYTES)
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        return connection
    except BaseException:
        connection.close()
        raise


def copy_snapshot(source, destination, deadline):
    """Source must already hold the read transaction used for its fingerprint."""
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(fd)

    def progress(_status, _remaining, _total):
        require(time.monotonic() <= deadline, "SQLite snapshot exceeded its export deadline")

    with closing(sqlite3.connect(destination, timeout=2)) as exported:
        source.backup(exported, pages=128, progress=progress, sleep=0.05)


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot(source_path, destination):
    require(source_path.resolve() != destination.resolve(), "Source cannot be its export target")
    require(source_path.is_file(), "Source journal does not exist")
    require(not destination.exists() and not destination.is_symlink(), "Export target exists")
    deadline = time.monotonic() + DEADLINE_SECONDS
    with closing(readonly(source_path, deadline)) as source:
        source.execute("BEGIN")
        try:
            page_size = source.execute("PRAGMA page_size").fetchone()[0]
            pages = source.execute("PRAGMA page_count").fetchone()[0]
            logical_bytes = page_size * pages
            require(logical_bytes <= MAX_DATABASE_BYTES, "Journal exceeds the reviewed size limit")
            require(shutil.disk_usage(destination.parent).free > logical_bytes * 3 + 50 * 2**20,
                    "Insufficient free space for a verified journal export")
            print("Fingerprinting the held read-only journal snapshot...", flush=True)
            expected = fingerprint(source, deadline)
            classifications = {}
            for table, column in (("outbox", "stage"), ("actions", "phase"), ("events", "kind")):
                if table in expected["tables"] and column in expected["tables"][table]["columns"]:
                    classifications[table] = source.execute(
                        f'SELECT "{column}",count(*) FROM "{table}" GROUP BY "{column}"'
                    ).fetchall()
            print("Exporting that same SQLite snapshot...", flush=True)
            copy_snapshot(source, destination, deadline)
            archives = copy_archives(source, destination.parent, deadline)
        finally:
            source.rollback()
    print("Checking exported integrity and reading back every table...", flush=True)
    with closing(readonly(destination, deadline, immutable=True)) as exported:
        integrity = exported.execute("PRAGMA integrity_check").fetchall()
        require(integrity == [("ok",)], "Exported database integrity check failed")
        actual = fingerprint(exported, deadline)
        for name in archives:
            verified_archive(exported, name)
    require(actual == expected, "Exported schema or typed row fingerprints differ")
    require(time.monotonic() <= deadline, "Journal verification exceeded its export deadline")
    # The destination connection is closed before hashing/fsyncing the completed file.
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())
    return {"data_verified": True, "source_logical_bytes": logical_bytes,
            "export_bytes": destination.stat().st_size, "export_sha256": file_sha(destination),
            "integrity_check": "ok", "readback_matches": True,
            "single_file_readback_matches": not bool(archives),
            "archives": archives, "archive_readback_matches": True,
            "fingerprints": actual, "classifications": classifications}


def copy_archives(source, folder, deadline):
    if not has_archives(source):
        return {}
    names = source.execute("SELECT name FROM event_archives ORDER BY name").fetchall()
    require(len(names) <= 100, "Export exceeds the reviewed limit of 100 archives")
    archives = {}
    total = 0
    for (name,) in names:
        verified_archive(source, name)
        live = source_path_for_archive(source, name)
        total += live.stat().st_size
        require(total <= MAX_DATABASE_BYTES, "Referenced archives exceed 512 MiB")
        require(shutil.disk_usage(folder).free > live.stat().st_size * 3 + 50 * 2**20,
                "Insufficient free space for archived journal evidence")
        directory = folder / "journal-archives"
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / name
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with live.open("rb") as incoming, os.fdopen(fd, "wb") as outgoing:
            for block in iter(lambda: incoming.read(1024 * 1024), b""):
                require(time.monotonic() <= deadline, "Archive copy exceeded export deadline")
                outgoing.write(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        archives[name] = {"bytes": target.stat().st_size, "sha256": file_sha(target)}
        sync_directory(directory)
    return archives


def source_path_for_archive(source, name):
    return Path(source.execute("PRAGMA database_list").fetchone()[2]).parent / (
        "journal-archives"
    ) / name


def monitor_status():
    response = requests.get("http://127.0.0.1:8000/monitor/status", timeout=5)
    response.raise_for_status()
    return response.json()


def run(root, output_root):
    require(output_root != root and not output_root.is_relative_to(root),
            "Choose an export directory outside the project")
    require((root / "monitor-service/monitor_config.py").is_file(), "SelfSentry checkout required")
    load_dotenv(root / ".env")
    sys.path.insert(0, str(root / "monitor-service"))
    from monitor_config import load_config

    config = load_config()
    state_dir = config.state_dir.expanduser()
    if not state_dir.is_absolute():
        state_dir = root / state_dir
    source_path = state_dir / "pipeline.sqlite"
    require(not output_root.is_relative_to(state_dir.resolve()),
            "Choose an export directory outside the monitor state directory")
    before = monitor_status()
    require(before.get("healthy") is True and type(before.get("pid")) is int,
            "A healthy monitor is required before exporting")
    require((state_dir / "monitor.lock").read_text().strip() == str(before["pid"]),
            "Configured state directory does not identify the running monitor")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    folder = output_root / (stamp + "-" + uuid.uuid4().hex[:8])
    folder.mkdir(mode=0o700)
    report = {"passed": False, "data_verified": False, "started_at": stamp,
              "source": str(source_path.resolve()), "errors": [],
              "monitor_pid_before": before["pid"],
              "scope": "journal and referenced archives; no application-wide restore claim",
              "limits": {"database_bytes": MAX_DATABASE_BYTES, "table_rows": MAX_TABLE_ROWS,
                         "cell_bytes": MAX_CELL_BYTES, "deadline_seconds": DEADLINE_SECONDS}}
    try:
        report.update(snapshot(source_path, folder / "pipeline.sqlite"))
        after = monitor_status()
        report["monitor_healthy_after"] = after.get("healthy") is True
        report["monitor_not_restarted"] = after.get("pid") == before.get("pid")
        report["delivery_depths_after"] = {
            key: after.get(key) for key in ("incident_outbox_size", "audit_spool_size")
        }
        require(report["monitor_healthy_after"] and report["monitor_not_restarted"],
                "Post-export monitor health/PID changed; review before using this export")
        report["passed"] = True
    except Exception as exc:
        report["errors"].append(str(exc) if isinstance(exc, ExportFailed) else type(exc).__name__)
    except KeyboardInterrupt:
        report["errors"].append("Interrupted; incomplete export retained for review")
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = folder / "manifest.json"
        manifest_fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(manifest_fd, "w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        brief = {key: report.get(key) for key in (
            "passed", "data_verified", "integrity_check", "readback_matches", "export_bytes",
            "single_file_readback_matches",
            "export_sha256", "monitor_healthy_after", "monitor_not_restarted", "errors")}
        brief["row_counts"] = {name: item["rows"] for name, item
                               in report.get("fingerprints", {}).get("tables", {}).items()}
        brief["archive_files"] = len(report.get("archives", {}))
        brief["archive_readback_matches"] = report.get("archive_readback_matches")
        print(json.dumps(brief, indent=2))
        print("Private export:", folder)
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "selfsentry")
    parser.add_argument("--output-root", type=Path,
                        default=Path.home() / "selfsentry-journal-exports")
    args = parser.parse_args()
    previous_umask = os.umask(0o077)
    try:
        return run(args.repo.expanduser().resolve(), args.output_root.expanduser().resolve())
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("Stopped:", str(exc) if isinstance(exc, ExportFailed) else type(exc).__name__,
              file=sys.stderr)
        raise SystemExit(2)
