"""Explicit larger exports remain bounded and do not change later defaults."""
from contextlib import closing
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import export_monitor_journal as e  # noqa: E402


def selected(mib=1024, rows=500000, seconds=600):
    return e.ExportLimits(mib * 2**20, rows, seconds)


def test_real_table_over_default_limit_requires_explicit_override(tmp_path):
    source = tmp_path / 'source.sqlite'
    with closing(sqlite3.connect(source)) as db, db:
        db.execute('CREATE TABLE evidence(id INTEGER PRIMARY KEY, value TEXT)')
        db.executemany('INSERT INTO evidence VALUES (?,?)',
                       ((i, 'preserved') for i in range(100001)))
    refused = tmp_path / 'refused.sqlite'
    with pytest.raises(e.ExportFailed, match='row limit'):
        e.snapshot(source, refused)
    assert not refused.exists()
    with e.export_limits(selected()):
        result = e.snapshot(source, tmp_path / 'verified.sqlite')
    assert result['data_verified'] and result['readback_matches']
    assert result['fingerprints']['tables']['evidence']['rows'] == 100001
    with pytest.raises(e.ExportFailed, match='row limit'):
        e.digest_rows((i,) for i in range(100001))


def test_byte_override_and_failed_nested_scope_restore_defaults(tmp_path, monkeypatch):
    source = tmp_path / 'source.sqlite'
    with closing(sqlite3.connect(source)) as db, db:
        db.execute('CREATE TABLE evidence(value)')
        db.execute('INSERT INTO evidence VALUES (1)')
    monkeypatch.setattr(e, 'MAX_DATABASE_BYTES', 1)
    with pytest.raises(e.ExportFailed, match='size limit'):
        e.snapshot(source, tmp_path / 'refused.sqlite')
    with e.export_limits(selected()):
        e.snapshot(source, tmp_path / 'verified.sqlite')
        with pytest.raises(RuntimeError):
            with e.export_limits(selected(rows=10)):
                raise RuntimeError('interrupted inner operation')
        assert e.current_limits().table_rows == 500000
    assert e.current_limits().database_bytes == 1


@pytest.mark.parametrize('limits', [
    (0, 1, 1), (2049 * 2**20, 1, 1), (1, 1000001, 1),
    (1, 1, 901), (1, True, 1), (1, 1, float('inf')),
])
def test_invalid_or_excessive_limits_refused(limits):
    with pytest.raises(e.ExportFailed):
        e.ExportLimits(*limits)


def test_cli_override_is_recorded_and_does_not_leak(monkeypatch, tmp_path):
    original = e.limit_record()
    seen = []
    monkeypatch.setattr(sys, 'argv', [
        'export', '--repo', str(tmp_path), '--max-database-mib', '1024',
        '--max-table-rows', '500000', '--deadline-seconds', '600',
    ])

    def run(*_):
        seen.append(e.limit_record())
        return 0
    monkeypatch.setattr(e, 'run', run)
    assert e.main() == 0
    assert seen == [{'database_bytes': 1024 * 2**20, 'table_rows': 500000,
                     'cell_bytes': 4 * 2**20, 'deadline_seconds': 600}]
    assert e.limit_record() == original


def test_invalid_cli_limits_refused_before_run(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['export', '--max-table-rows', '0'])
    monkeypatch.setattr(e, 'run', lambda *_: pytest.fail('invalid request reached run'))
    with pytest.raises(e.ExportFailed):
        e.main()
