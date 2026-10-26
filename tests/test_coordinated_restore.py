"""Real SQLite/files/model recovery; PostgreSQL/Falco acceptance requires the VM."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / directory) for directory in
                ('evaluation', 'scripts', 'monitor-service', 'behavioral-engine')]
import coordinated_state as state  # noqa: E402
import verify_coordinated_restore as runner  # noqa: E402


def test_sqlite_backup_includes_wal_and_typed_rows_without_altering_source(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    path = source / 'pipeline.sqlite'
    with closing(sqlite3.connect(path)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE rows(value)')
        db.executemany('INSERT INTO rows VALUES (?)', [(1,), (1.0,), ('1',), (b'1',), (None,)])
        db.commit()
        (source / 'status.json').write_text('{"pid":123}')
        (source / 'monitor.lock').touch()
        records = state.copy_tree(source, tmp_path / 'capture')
        assert set(records) == {'pipeline.sqlite'}
        state.check_source(source, records)
        state.check_copy(tmp_path / 'capture', records)
        with closing(sqlite3.connect(tmp_path / 'capture/pipeline.sqlite')) as restored:
            assert restored.execute('SELECT typeof(value) FROM rows').fetchall() == [
                ('integer',), ('real',), ('text',), ('blob',), ('null',)]
        db.execute('INSERT INTO rows VALUES (2)')
        db.commit()
        with pytest.raises(RuntimeError, match='changed across'):
            state.check_source(source, records)


def test_raw_copy_corruption_and_new_source_file_are_detected(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'baseline.json').write_text('{"kept":true}')
    records = state.copy_tree(source, tmp_path / 'capture')
    (tmp_path / 'capture/baseline.json').write_text('changed')
    with pytest.raises(RuntimeError, match='checksum'):
        state.check_copy(tmp_path / 'capture', records)
    (source / 'new.json').write_text('{}')
    with pytest.raises(RuntimeError, match='membership'):
        state.check_source(source, records)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'size'])
def test_ambiguous_or_over_budget_sources_refuse(tmp_path, monkeypatch, kind):
    source = tmp_path / 'source'
    source.mkdir()
    target = source / 'data'
    target.write_bytes(b'original data')
    if kind == 'symlink':
        (source / 'linked').symlink_to(target)
    elif kind == 'hardlink':
        os.link(target, source / 'linked')
    else:
        monkeypatch.setattr(state, 'MAX_FILE_BYTES', 1)
    with pytest.raises(RuntimeError):
        state.copy_tree(source, tmp_path / 'capture')
    assert target.read_bytes() == b'original data'


def test_checkpoint_is_rebound_only_on_clone_and_survives_reopen(tmp_path):
    log = tmp_path / 'live.json'
    log.write_text('first\nsecond\n')
    checkpoint = tmp_path / 'checkpoint.json'
    checkpoint.write_text(json.dumps({'inode': log.stat().st_ino, 'offset': 6,
                                     'recent_keys': [], 'discarding_line': False}))
    original_checkpoint = checkpoint.read_bytes()
    copied_log = tmp_path / 'copied.json'
    manifest = state.capture_log(log, copied_log, checkpoint)
    assert manifest['checkpoint_offset'] == 6
    copied_checkpoint = tmp_path / 'copied-checkpoint.json'
    copied_checkpoint.write_bytes(original_checkpoint)
    result = state.check_checkpoint_on_copy(copied_log, copied_checkpoint)
    assert result['cursor_commit_reopened'] is True and result['read_lines'] == 1
    assert checkpoint.read_bytes() == original_checkpoint
    assert log.read_text() == 'first\nsecond\n'


@pytest.mark.parametrize('inode,offset', [(0, 0), (None, 100), ('current', 1000)])
def test_rotation_or_invalid_cursor_refuses_capture(tmp_path, inode, offset):
    log = tmp_path / 'live.json'
    log.write_text('one\n')
    if inode == 'current':
        inode = log.stat().st_ino
    checkpoint = tmp_path / 'checkpoint.json'
    checkpoint.write_text(json.dumps({'inode': inode, 'offset': offset}))
    with pytest.raises(RuntimeError):
        state.capture_log(log, tmp_path / 'copy.json', checkpoint)
    assert not (tmp_path / 'copy.json').exists()


def test_actual_ownership_lock_blocks_even_without_a_deadline(tmp_path):
    lock = tmp_path / 'monitor.lock'
    lock.write_text('{}')
    with lock.open('r') as owner:
        fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            with runner.held_lock(lock):
                pytest.fail('entered owned lock')
    with runner.held_lock(lock):
        pass
    assert lock.read_text() == '{}'


def test_original_app_resume_does_not_depend_on_evidence_disk_space(tmp_path, monkeypatch):
    calls = []

    def start(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b'started')

    monkeypatch.setattr(runner.subprocess, 'run', start)
    monkeypatch.setattr(Path, 'write_bytes', lambda *a, **kw: (_ for _ in ()).throw(
        OSError('disk full')))
    report = {'errors': [], 'checks': {}}
    runner.resume_managed(tmp_path, {}, report, tmp_path, status_getter=lambda: {'healthy': True})
    assert len(calls) == 1 and calls[0][-1] == 'start'
    assert report['checks']['original_app_healthy_after_capture'] is True
    assert report['errors'] == ['Resume log could not be saved; inspect original app status']


def test_no_pause_without_explicit_confirmation(tmp_path):
    with pytest.raises(RuntimeError, match='approval'):
        runner.run(tmp_path, tmp_path / 'output', False)
    assert not list(tmp_path.iterdir())


def test_real_model_can_be_rebuilt_from_copied_baseline_json(tmp_path):
    from baseline_builder import BaselineStore
    from feature_extractor import FeatureVector
    from monitor_config import MonitorConfig
    from behavior_pipeline import BehaviorPipeline
    from types import SimpleNamespace
    from dataclasses import replace

    source = tmp_path / 'source'
    baselines = tmp_path / 'baselines'
    cfg = replace(MonitorConfig(), state_dir=source, baseline_dir=baselines,
                  auto_confirm_enabled=False, rule_candidates_enabled=False)
    store = BaselineStore(baselines)
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    cid = 'a' * 12
    for i in range(20):
        store.append(FeatureVector(cid, start + timedelta(seconds=60 * i),
                                   start + timedelta(seconds=60 * (i + 1)),
                                   distinct_process_count=i % 3 + 1, total_event_count=i + 1))
    pipe = BehaviorPipeline(cfg, SimpleNamespace(), SimpleNamespace(emit=lambda **kw: None))
    pipe.discover(cid)
    assert pipe.lifecycle[cid]['state'] == 'MODEL_READY'
    pipe.db.close()
    state.copy_tree(source, tmp_path / 'restored-monitor')
    state.copy_tree(baselines, tmp_path / 'restored-baselines')
    assert runner.rebuild_models(cfg, tmp_path / 'restored-monitor',
                                 tmp_path / 'restored-baselines', [cid])[cid] == {
                                     'state': 'MODEL_READY', 'samples': 20}


def test_all_required_acceptance_checks_are_explicit_not_a_passing_count():
    report = {'errors': [], 'checks': dict.fromkeys(runner.REQUIRED_CHECKS, True)}
    assert runner.acceptance_passed(report)
    for key in runner.REQUIRED_CHECKS:
        incomplete = {'errors': [], 'checks': {
            k: v for k, v in report['checks'].items() if k != key}}
        incomplete['checks'].update({f'unrelated_{i}': True for i in range(100)})
        assert not runner.acceptance_passed(incomplete)
    report['errors'].append('a failed command was retained')
    assert not runner.acceptance_passed(report)
