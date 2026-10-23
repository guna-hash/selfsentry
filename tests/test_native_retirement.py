"""Actual temporary files, SQLite and inventory locks; native Falco calls controlled."""

from contextlib import closing
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'rule-synthesis-engine'))
import native_retirement as nr  # noqa: E402
from tests.rule_guard_support import inventory  # noqa: E402

RULE = '''- rule: Auto_Generated_Retirement
  desc: reviewed test
  condition: spawned_process and proc.name = bash
  output: test
  priority: WARNING
'''
REAL_VALIDATE = nr.validate

KEEP = '''- rule: Other_Generated_Rule
  condition: spawned_process and proc.name = curl
  output: retained
  priority: WARNING
'''


def status(generation=1, instance='test', ready=True, rejected=0):
    return {'instance_id': instance, 'started_generation': generation,
            'applied_generation': generation, 'rejected_generation': rejected, 'ready': ready}


@pytest.fixture
def host(tmp_path, monkeypatch):
    config, _ = inventory(tmp_path)
    path = tmp_path / 'auto.yaml'
    path.write_text('# preserved header\n' + RULE + KEEP)
    settings = yaml.safe_load(config.read_text())
    settings['rules_files'].append(str(path))
    config.write_text(yaml.safe_dump(settings))
    monkeypatch.setenv('RULE_GUARD_STATE_DIR', str(tmp_path / 'guard'))
    monkeypatch.setattr('rule_deduplicator._runtime_arguments',
                        lambda: ['falco', '-c', str(config)])
    monkeypatch.setattr(nr, 'validate', lambda *args: None)
    journal = nr.RetirementJournal(tmp_path / 'retirements')
    client = Mock()
    client.status.return_value = status()
    client.reload.return_value = status(2)
    intent, complete = Mock(), Mock()
    return path, config, journal, client, intent, complete


def execute(host, **kwargs):
    path, config, journal, client, intent, complete = host
    original_hash = kwargs.pop('expected_file_hash', nr.digest(path.read_bytes()))
    return nr.execute('7', RULE, original_hash, 'alice', 'Reviewed false positives',
                      journal, client, path, config, intent, complete, **kwargs)


def test_retirement_removes_only_exact_rule_after_durable_intent(host):
    path, _, journal, client, intent, complete = host
    original = path.read_bytes()
    intent.side_effect = lambda record: (
        path.read_bytes() == original or pytest.fail('File changed before DB intent'))
    result = execute(host)
    assert yaml.safe_load(path.read_text()) == yaml.safe_load(KEEP)
    assert (journal.directory / (result['operation_id'] + '.original')).read_bytes() == original
    assert result['phase'] == 'applied'
    complete.assert_called_once_with(result, True)
    client.reload.assert_called_once()
    with closing(journal.connect()) as db:
        phases = [json.loads(row[0])['phase'] for row in db.execute('SELECT body FROM history')]
    assert phases == ['prepared', 'publication_pending', 'published', 'applied']


def test_completed_receipt_recovers_db_result_without_repeating_reload(host):
    path, _, _, client, _, complete = host
    original_hash = nr.digest(path.read_bytes())
    execute(host)
    client.status.return_value = status(2)
    execute(host, expected_file_hash=original_hash)
    assert client.reload.call_count == 1 and complete.call_count == 2
    client.status.return_value = status(2, instance='replacement-process')
    with pytest.raises(nr.RetirementError):
        execute(host, expected_file_hash=original_hash)
    assert client.reload.call_count == 1


def test_validation_failure_keeps_original_and_preserves_failed_intent(host, monkeypatch):
    path, _, journal, client, intent, _ = host
    original = path.read_bytes()

    def invalid(*_args):
        raise nr.RetirementError('native validation failed')

    monkeypatch.setattr(nr, 'validate', invalid)
    with pytest.raises(nr.RetirementError):
        execute(host)
    assert path.read_bytes() == original
    assert journal.get('7')['phase'] == 'validation_failed'
    intent.assert_not_called()
    client.reload.assert_not_called()


def test_ambiguous_reload_never_retries_or_invents_success(host):
    path, _, journal, client, _, complete = host
    client.reload.side_effect = nr.RetirementError('acknowledgement lost')
    with pytest.raises(nr.RetirementError):
        execute(host)
    assert journal.get('7')['phase'] == 'published'
    assert yaml.safe_load(path.read_text()) == yaml.safe_load(KEEP)
    complete.assert_not_called()
    with pytest.raises(nr.RetirementError, match='explicit rollback'):
        execute(host)
    assert client.reload.call_count == 1
    client.reload.side_effect = None
    client.reload.return_value = status(3)
    result = execute(host, rollback=True)
    assert result['phase'] == 'rolled_back'
    assert RULE in path.read_text() and KEEP in path.read_text()
    complete.assert_called_once_with(result, False)


def test_known_rejection_restores_original_and_verifies_rollback_reload(host):
    path, _, journal, client, _, complete = host
    original = path.read_bytes()
    client.reload.side_effect = [nr.ReloadRejected('rejected'), status(3)]
    with pytest.raises(nr.ReloadRejected):
        execute(host)
    assert path.read_bytes() == original
    assert journal.get('7')['phase'] == 'rolled_back'
    assert client.reload.call_count == 2
    assert complete.call_args.args[1] is False


def test_failed_rollback_preserves_pending_state_and_original(host):
    path, _, journal, client, _, complete = host
    original = path.read_bytes()
    client.reload.side_effect = [nr.ReloadRejected('rejected'), nr.RetirementError('offline')]
    with pytest.raises(nr.RetirementError):
        execute(host)
    assert path.read_bytes() == original
    assert journal.get('7')['phase'] == 'rollback_pending'
    complete.assert_not_called()


@pytest.mark.parametrize('fault', ['duplicate', 'changed', 'stale', 'symlink'])
def test_ambiguous_rule_or_file_identity_blocks_all_native_writes(host, fault):
    path, _, _, client, intent, complete = host
    expected = nr.digest(path.read_bytes())
    if fault == 'duplicate':
        path.write_text(path.read_text() + RULE)
    elif fault == 'changed':
        path.write_text(path.read_text().replace('name = bash', 'name = sh'))
    elif fault == 'stale':
        expected = '0' * 64
    else:
        copy = path.with_name('target.yaml')
        path.rename(copy)
        path.symlink_to(copy)
    with pytest.raises(nr.RetirementError):
        execute(host, expected_file_hash=expected)
    intent.assert_not_called()
    complete.assert_not_called()
    client.reload.assert_not_called()


def test_db_intent_failure_precedes_any_live_file_write(host):
    path, _, journal, client, intent, _ = host
    original = path.read_bytes()
    intent.side_effect = RuntimeError('database outcome unknown')
    with pytest.raises(RuntimeError):
        execute(host)
    assert path.read_bytes() == original and journal.get('7')['phase'] == 'prepared'
    client.reload.assert_not_called()


def test_unrelated_post_failure_edits_cannot_be_overwritten_by_recovery(host):
    path, _, _, client, _, _ = host
    client.reload.side_effect = nr.RetirementError('offline')
    with pytest.raises(nr.RetirementError):
        execute(host)
    path.write_text(path.read_text() + '# operator addition\n')
    with pytest.raises(nr.RetirementError, match='refuse overwriting'):
        execute(host, rollback=True)
    assert path.read_text().endswith('# operator addition\n')


def test_journal_save_failure_before_publication_prevents_file_write(host, monkeypatch):
    path, _, journal, client, _, _ = host
    original, save = path.read_bytes(), journal.save

    def failed(record, phase, **changes):
        if phase == 'publication_pending':
            raise OSError('disk unavailable')
        return save(record, phase, **changes)

    monkeypatch.setattr(journal, 'save', failed)
    with pytest.raises(nr.RetirementError):
        execute(host)
    assert path.read_bytes() == original
    client.reload.assert_not_called()


def test_persisted_success_survives_unknown_database_completion(host):
    path, _, journal, client, _, complete = host
    original_hash = nr.digest(path.read_bytes())
    complete.side_effect = RuntimeError('DB commit acknowledgement lost')
    with pytest.raises(RuntimeError):
        execute(host)
    assert journal.get('7')['phase'] == 'applied'
    complete.side_effect = None
    client.status.return_value = status(2)
    execute(host, expected_file_hash=original_hash)
    assert client.reload.call_count == 1


def test_native_validation_uses_all_ordered_files_without_changing_runtime(host, monkeypatch):
    path, config, _, _, _, _ = host
    plan = nr.prepare(RULE, path, config)
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        candidate = Path(argv[-1])
        assert yaml.safe_load(candidate.read_text()) == yaml.safe_load(KEEP)
        return subprocess.CompletedProcess(argv, 0, b'verified', b'')

    monkeypatch.setattr(nr, '_runtime_arguments', lambda: ['falco'])
    monkeypatch.setattr(nr.subprocess, 'run', command)
    REAL_VALIDATE(plan, path, config)
    assert calls[0].count('-V') == 2
    assert plan['validation_output'] == b'verified\n'
    assert RULE in path.read_text()


@pytest.mark.parametrize('change', [
    {'ready': 'true'}, {'applied_generation': True}, {'instance_id': ''},
    {'rejected_generation': -1}, {'applied_generation': 5},
])
def test_invalid_reload_status_is_not_a_completion_receipt(change):
    with pytest.raises(nr.RetirementError):
        nr._status({**status(), **change})


def test_file_publication_then_fsync_error_remains_recoverable(host, monkeypatch):
    path, _, journal, client, _, complete = host
    replace = nr._replace

    def published_then_failed(target, body, mode):
        replace(target, body, mode)
        raise OSError('directory sync failed after publication')

    monkeypatch.setattr(nr, '_replace', published_then_failed)
    with pytest.raises(nr.RetirementError):
        execute(host)
    assert journal.get('7')['phase'] == 'publication_pending'
    assert RULE not in path.read_text()
    client.reload.assert_not_called()
    complete.assert_not_called()
    monkeypatch.setattr(nr, '_replace', replace)
    assert execute(host, rollback=True)['phase'] == 'rolled_back'


def test_success_receipt_disk_failure_does_not_complete_database_or_repost(host, monkeypatch):
    _, _, journal, client, _, complete = host
    save = journal.save

    def failed(record, phase, **changes):
        if phase == 'applied':
            raise OSError('result storage failed')
        return save(record, phase, **changes)

    monkeypatch.setattr(journal, 'save', failed)
    with pytest.raises(nr.RetirementError):
        execute(host)
    assert journal.get('7')['phase'] == 'published'
    complete.assert_not_called()
    with pytest.raises(nr.RetirementError, match='explicit rollback'):
        execute(host)
    assert client.reload.call_count == 1


def test_post_reload_external_edit_cannot_get_a_success_receipt(host):
    path, _, journal, client, _, complete = host

    def changed():
        path.write_text(path.read_text() + '# concurrent edit\n')
        return status(2)

    client.reload.side_effect = changed
    with pytest.raises(nr.RetirementError, match='Post-reload inventory'):
        execute(host)
    assert journal.get('7')['phase'] == 'published'
    complete.assert_not_called()


def test_explicit_rollback_records_db_intent_before_restoring_file(host):
    path, _, _, _, intent, _ = host
    execute(host)
    intent.reset_mock()
    intent.side_effect = lambda _record: (
        RULE not in path.read_text() or pytest.fail('Restored before recovery approval persisted'))
    assert execute(host, rollback=True)['phase'] == 'rolled_back'
    intent.assert_called_once()


def test_pending_database_without_local_original_cannot_create_a_new_retirement(host):
    path, _, _, client, _, _ = host
    original = path.read_bytes()
    with pytest.raises(nr.RetirementError, match='no retained native intent'):
        execute(host, previous_status='retirement_pending')
    assert path.read_bytes() == original
    client.reload.assert_not_called()


def test_hard_kill_retains_original_and_releases_lock_for_explicit_recovery(host):
    import select

    path, config, journal, client, _, _ = host
    original = path.read_bytes()
    script = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import native_retirement as nr
import rule_deduplicator as rd
rd._runtime_arguments = lambda: ['falco', '-c', sys.argv[3]]
nr.validate = lambda *args: None
class Client:
    def status(self):
        return dict(instance_id='child', started_generation=1, applied_generation=1,
                    rejected_generation=0, ready=True)
    def reload(self):
        print('published', flush=True)
        sys.stdin.read()
path = Path(sys.argv[2])
journal = nr.RetirementJournal(sys.argv[4])
nr.execute('7', path.read_text().split('- rule: Other_Generated_Rule')[0].split(
    '# preserved header\\n')[-1], nr.digest(path.read_bytes()), 'alice', 'crash test',
    journal, Client(), path, sys.argv[3], lambda r: None, lambda r, u: None)
'''
    child = subprocess.Popen([sys.executable, '-c', script,
                              str(ROOT / 'rule-synthesis-engine'), str(path), str(config),
                              str(journal.directory)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([child.stdout], [], [], 5)
        assert ready and child.stdout.readline().strip() == 'published'
        child.kill()
        child.wait(timeout=5)
        retained = journal.get('7')
        assert retained['phase'] == 'published'
        backup = journal.directory / (retained['operation_id'] + '.original')
        assert backup.read_bytes() == original
        client.reload.return_value = status(3)
        result = execute(host, rollback=True)
        assert result['phase'] == 'rolled_back' and path.read_bytes() == original
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)


def test_inventory_lock_serializes_duplicate_native_requests(host):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    import threading

    path, _, _, client, _, _ = host
    original_hash = nr.digest(path.read_bytes())
    entered, release = threading.Event(), threading.Event()

    def reload_once():
        entered.set()
        assert release.wait(5)
        client.status.return_value = status(2)
        return status(2)

    client.reload.side_effect = reload_once
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(execute, host, expected_file_hash=original_hash)
        assert entered.wait(5)
        second = pool.submit(execute, host, expected_file_hash=original_hash)
        try:
            with pytest.raises(TimeoutError):
                second.result(timeout=0.05)
        finally:
            release.set()
        assert first.result(timeout=5)['phase'] == second.result(timeout=5)['phase'] == 'applied'
    assert client.reload.call_count == 1


def test_changed_database_rule_cannot_use_an_old_recovery_receipt(host):
    path, config, journal, client, intent, complete = host
    execute(host)
    current = path.read_bytes()
    with pytest.raises(nr.RetirementError, match='Database rule differs'):
        nr.execute('7', RULE.replace('bash', 'sh'), nr.digest(current), 'bob', 'review',
                   journal, client, path, config, intent, complete, rollback=True)
    assert path.read_bytes() == current and client.reload.call_count == 1


def test_failed_recovery_prevalidation_retains_output_without_restoring_file(host, monkeypatch):
    path, _, journal, client, intent, _ = host
    execute(host)
    before = path.read_bytes()
    intent.reset_mock()

    def fail(plan, *_args):
        plan['validation_output'] = b'controlled recovery validation error'
        raise nr.RetirementError('restore configuration invalid')

    monkeypatch.setattr(nr, 'validate', fail)
    with pytest.raises(nr.RetirementError):
        execute(host, rollback=True)
    record = journal.get('7')
    assert record['phase'] == 'applied' and record['recovery_validation_failed'] is True
    assert (journal.directory / record['recovery_validation_artifact']).read_bytes() == (
        b'controlled recovery validation error')
    assert path.read_bytes() == before and client.reload.call_count == 1
    intent.assert_not_called()
