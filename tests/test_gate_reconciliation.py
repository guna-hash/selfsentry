"""Real SQLite/locks with controlled Docker observations; no native daemon mutations."""

from contextlib import closing
import json
import subprocess
from pathlib import Path
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'deployment-gate'), str(ROOT / 'monitor-service')]
import deployment_outbox as outbox  # noqa: E402
import reconcile_action as recon  # noqa: E402

CID = 'a' * 64


@pytest.fixture(autouse=True)
def state(tmp_path, monkeypatch):
    monkeypatch.setenv('SELFSENTRY_STATE_DIR', str(tmp_path))
    monkeypatch.setattr(recon, 'observe', lambda cid: {
        'container_id': cid, 'present': True, 'daemon_id': 'test', 'state': {'Running': True}})


def original(key):
    with closing(outbox.connect()) as db:
        return db.execute('SELECT * FROM deployment_actions WHERE key=?', (key,)).fetchone()


def test_review_retains_original_and_does_not_register_or_clear_health():
    key = outbox.begin_action(CID, 'start')
    before = original(key)
    proposal = recon.plan('action', key)
    record = recon.reconcile('action', key, proposal['original_sha256'],
                             'alice', 'inspected daemon')
    assert record['event_type'] == 'GATE_ACTION_RECONCILED'
    assert record['decision'] == 'accepted_current_observation'
    assert original(key) == before
    assert outbox.action_health()['outcome_not_recorded'] == 1
    with closing(outbox.connect()) as db:
        assert db.execute('SELECT count(*) FROM decisions').fetchone()[0] == 0
        stored = db.execute('SELECT body FROM action_reconciliations').fetchone()[0]
    assert json.loads(stored) == record
    with pytest.raises(ValueError, match='already exists'):
        recon.reconcile('action', key, proposal['original_sha256'], 'bob', 'different decision')


def test_live_owner_cannot_be_overridden_after_deadline(monkeypatch):
    monkeypatch.setattr(outbox.time, 'monotonic', lambda: 0)
    with outbox.operation_lease(1) as key:
        outbox.begin_action(CID, 'start', key=key)
        proposal = recon.plan('action', key)
        monkeypatch.setattr(outbox.time, 'monotonic', lambda: 1000)
        assert not outbox._operation_active(key)
        with pytest.raises(ValueError, match='still has an owner'):
            recon.reconcile('action', key, proposal['original_sha256'], 'alice', 'reason')


def test_unknown_creation_cannot_be_bound_to_a_guessed_id():
    key = outbox.begin_creation()
    with pytest.raises(ValueError, match='Known full container'):
        recon.plan('creation', key)


@pytest.mark.parametrize('actor,reason', [
    ('', 'why'), ('selfsentry-auto', 'why'), ('alice', ''), (None, 'why'),
])
def test_missing_human_review_does_not_write(actor, reason):
    key = outbox.begin_action(CID, 'remove')
    with pytest.raises(ValueError):
        recon.reconcile('action', key, recon.plan('action', key)['original_sha256'], actor, reason)


def test_stale_plan_or_docker_failure_never_changes_original(monkeypatch):
    key = outbox.begin_action(CID, 'start')
    before = original(key)
    with pytest.raises(ValueError, match='changed'):
        recon.reconcile('action', key, 'wrong', 'alice', 'why')

    def unavailable(_cid):
        raise RuntimeError('daemon offline')

    monkeypatch.setattr(recon, 'observe', unavailable)
    with pytest.raises(RuntimeError):
        recon.reconcile('action', key, 'irrelevant', 'alice', 'why')
    assert original(key) == before


def test_concurrent_decisions_keep_one_original_review():
    key = outbox.begin_action(CID, 'start')
    digest = recon.plan('action', key)['original_sha256']

    def review(actor):
        try:
            return recon.reconcile('action', key, digest, actor, 'checked')['reviewed_by']
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(review, ['alice', 'bob']))
    assert sum(item is not None for item in results) == 1
    with closing(outbox.connect()) as db:
        assert db.execute('SELECT count(*) FROM action_reconciliations').fetchone()[0] == 1


def test_native_observer_never_interprets_an_error_as_absence(monkeypatch):
    def unavailable(*args):
        raise RuntimeError('connection refused')

    monkeypatch.setattr(recon, 'observe', observe_original)
    monkeypatch.setattr(recon, '_docker', unavailable)
    with pytest.raises(RuntimeError):
        recon.observe(CID)


def test_successful_complete_inventory_can_record_absence(monkeypatch):
    calls = []

    def docker(*args):
        calls.append(args)
        return '"test-daemon"' if args[0] == 'info' else ''

    monkeypatch.setattr(recon, 'observe', observe_original)
    monkeypatch.setattr(recon, '_docker', docker)
    result = recon.observe(CID)
    assert result['present'] is False
    assert not any('inspect' in args for args in calls)
    assert all(args[0] in ('info', 'container') for args in calls)


observe_original = recon.observe


def test_documented_cli_runs_without_test_import_paths():
    result = subprocess.run(
        [sys.executable, str(ROOT / 'deployment-gate/reconcile_action.py'), '--help'],
        capture_output=True, text=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
    assert result.returncode == 0, result.stderr
    assert '--apply-original-sha256' in result.stdout
