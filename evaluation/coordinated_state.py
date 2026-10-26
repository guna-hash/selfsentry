"""Private durable-state snapshots and bounded disposable readback checks.

Capture requires quiescent application writers. No .env file is copied, no live
paths are restored, and process/lock/status files are explicitly not recovery inputs.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

MAX_FILE_BYTES = 2 * 1024**3
VOLATILE = {'status.json', 'control-status.json', 'control_status.json'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular_files(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'Regular source directory required')
    files = []
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'Symlink in recovery state requires operator review')
        if path.is_file():
            require(path.stat().st_nlink == 1, 'Hard-linked recovery state requires review')
            require(path.stat().st_size <= MAX_FILE_BYTES, 'Recovery source exceeds file budget')
            if path.name.endswith(('.lock', '-wal', '-shm')) or path.name in VOLATILE:
                continue
            files.append(path)
    require(len(files) <= 10000, 'Recovery state exceeds file-count budget')
    return files


def sqlite_snapshot(source, target):
    # Existing bounded typed fingerprints are shared with the verified journal exporter.
    from export_monitor_journal import readonly, fingerprint, copy_snapshot
    deadline = time.monotonic() + 90
    with closing(readonly(source, deadline)) as db:
        db.execute('BEGIN')
        expected = fingerprint(db, deadline)
        copy_snapshot(db, target, deadline)
        db.rollback()
    with closing(readonly(target, deadline, immutable=True)) as db:
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                'Copied SQLite integrity check failed')
        require(fingerprint(db, deadline) == expected, 'Copied SQLite rows/schema differ')
    os.chmod(target, 0o600)
    return expected


def copy_tree(source, target):
    require(not target.exists(), 'Recovery capture destination must be new')
    target.mkdir(parents=True, mode=0o700)
    result = {}
    for path in regular_files(source):
        relative = path.relative_to(source)
        dest = target / relative
        dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with path.open('rb') as stream:
            is_sqlite = stream.read(16) == b'SQLite format 3\x00'
        if is_sqlite:
            logical = sqlite_snapshot(path, dest)
        else:
            before = sha(path)
            shutil.copyfile(path, dest)
            os.chmod(dest, 0o600)
            require(sha(dest) == before == sha(path), 'Source changed while copying private state')
            logical = None
        result[str(relative)] = {'sha256': sha(dest), 'bytes': dest.stat().st_size,
                                 'sqlite_fingerprint': logical}
    require(set(result) == {str(p.relative_to(source)) for p in regular_files(source)},
            'Source file membership changed during capture')
    return result


def check_source(source, records):
    from export_monitor_journal import readonly, fingerprint
    require(set(records) == {str(p.relative_to(source)) for p in regular_files(source)},
            'Source state membership changed across capture')
    for name, item in records.items():
        if item['sqlite_fingerprint'] is None:
            require(sha(source / name) == item['sha256'], 'Source bytes changed across capture')
        else:
            with closing(readonly(source / name, time.monotonic() + 90)) as db:
                require(fingerprint(db) == item['sqlite_fingerprint'],
                        'Source SQLite rows changed across coordinated capture')


def check_copy(directory, records):
    for name, item in records.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,
                'Invalid recovery manifest path')
        path = directory / relative
        require(not path.is_symlink() and sha(path) == item['sha256'],
                'Copied recovery artifact checksum differs')


def capture_log(source, target, checkpoint):
    """Copy a finite prefix and bind the saved checkpoint to that same inode."""
    cp = json.loads(checkpoint.read_text())
    with source.open('rb') as stream:
        info = os.fstat(stream.fileno())
        require(info.st_size <= MAX_FILE_BYTES, 'Falco log exceeds reviewed recovery budget')
        require(type(cp.get('inode')) is int and cp['inode'] == info.st_ino,
                'Checkpoint/log rotation mismatch; original log generation is required')
        require(type(cp.get('offset')) is int and 0 <= cp['offset'] <= info.st_size,
                'Checkpoint offset is outside the captured log')
        remaining = info.st_size
        with target.open('xb') as out:
            while remaining:
                chunk = stream.read(min(1024**2, remaining))
                require(chunk, 'Falco log truncated during prefix capture')
                out.write(chunk)
                remaining -= len(chunk)
            out.flush()
            os.fsync(out.fileno())
        after = source.stat()
        require((info.st_dev, info.st_ino) == (after.st_dev, after.st_ino)
                and after.st_size >= info.st_size, 'Falco log rotated during capture')
    os.chmod(target, 0o600)
    return {'sha256': sha(target), 'bytes': info.st_size,
            'checkpoint_offset': cp['offset'], 'original_inode': info.st_ino}


def check_checkpoint_on_copy(log, checkpoint):
    """Exercise a cloned tailer with explicit inode rebinding; never edit original checkpoints."""
    from falco_ingest import FalcoTailer
    cp = json.loads(checkpoint.read_text())
    require(type(cp.get('offset')) is int and 0 <= cp['offset'] <= log.stat().st_size,
            'Restored checkpoint exceeds log prefix')
    # Inodes are host filesystem identities. This mapping applies only to the verified log copy.
    cp['inode'] = log.stat().st_ino
    checkpoint.write_text(json.dumps(cp) + '\n')
    tailer = FalcoTailer(log, checkpoint)
    require(tailer.offset == cp['offset'], 'Restored tailer did not accept the saved cursor')
    batch = tailer.read_batch()
    tailer.commit(batch)
    reopened = FalcoTailer(log, checkpoint)
    require(reopened.offset == batch.end_offset, 'Copied checkpoint did not survive reopen')
    return {'cursor_loaded': True, 'cursor_commit_reopened': True,
            'read_lines': len(batch.lines), 'skipped_duplicates': batch.skipped_duplicates}
