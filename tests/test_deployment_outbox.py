"""Real disposable SQLite journals and fake HTTP; no Docker/backend daemon."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deployment-gate"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
import deployment_outbox as outbox  # noqa: E402
import deployment_gate as gate  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_journal(tmp_path, monkeypatch):
    monkeypatch.setenv("SELFSENTRY_STATE_DIR", str(tmp_path))


def decision(key="one"):
    return {"event_key": key, "decision": "blocked", "image_name": "test"}


def response(status=201, body=None):
    return SimpleNamespace(status_code=status, json=lambda: body)


def rows(table="decisions"):
    assert table in ("decisions", "decision_rejections")
    with closing(outbox.connect()) as db:
        return db.execute("SELECT * FROM " + table).fetchall()


def test_reused_key_preserves_original_and_refuses_changed_payload():
    item = decision()
    outbox.enqueue(item)
    outbox.enqueue(dict(reversed(list(item.items()))))
    with pytest.raises(outbox.OutboxConflict):
        outbox.enqueue({**item, "image_name": "different"})
    assert len(rows()) == 1
    assert json.loads(rows()[0][1]) == item


def test_concurrent_conflicting_writers_preserve_one_original_payload():
    with closing(outbox.connect()):
        pass  # Create the disposable schema before testing writer contention.
    barrier = threading.Barrier(2, timeout=5)

    def write(outcome):
        barrier.wait()
        try:
            outbox.enqueue({**decision(), "decision": outcome})
            return True
        except outbox.OutboxConflict:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write, value) for value in ("allowed", "blocked")]
        assert sorted(future.result(timeout=5) for future in futures) == [False, True]
    assert len(rows()) == 1
    assert json.loads(rows()[0][1])["decision"] in ("allowed", "blocked")


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        [],
        {"id": True, "decision": "blocked"},
        {"id": 0, "decision": "blocked"},
        {"id": 1, "decision": "allowed"},
    ],
)
def test_ambiguous_201_keeps_the_journal(monkeypatch, body):
    outbox.enqueue(decision())
    monkeypatch.setattr(outbox.requests, "post", lambda *a, **k: response(body=body))
    assert outbox.flush("http://test") == {"pending": 1, "rejected": 0}
    assert len(rows()) == 1


def test_invalid_json_ack_is_not_accepted_by_direct_gate_or_replay(monkeypatch):
    bad = Mock(status_code=201)
    bad.json.side_effect = ValueError("bad JSON")
    monkeypatch.setattr(outbox.requests, "post", lambda *a, **k: bad)
    assert gate.record_decision(decision(), "http://test") is False
    assert outbox.flush("http://test") == {"pending": 1, "rejected": 0}


def test_explicit_identical_retry_can_recover_without_deleting_rejection_history(monkeypatch):
    item = decision()
    outbox.enqueue(item)
    monkeypatch.setattr(outbox.requests, "post", lambda *a, **k: response(422))
    assert outbox.flush("http://test") == {"pending": 0, "rejected": 1}
    monkeypatch.setattr(outbox.requests, "post", lambda *a, **k: response(
        body={"id": 1, "decision": "blocked"}
    ))
    assert gate.record_decision(item, "http://test") is True
    assert outbox.flush("http://test") == {"pending": 0, "rejected": 0}
    assert len(rows("decision_rejections")) == 1
    assert json.loads(rows("decision_rejections")[0][1]) == item


@pytest.mark.parametrize("status", [400, 409, 422])
def test_permanent_rejection_keeps_evidence_and_allows_next_delivery(monkeypatch, status):
    outbox.enqueue(decision("bad"))
    outbox.enqueue(decision("good"))
    replies = iter([response(status), response(body={"id": 2, "decision": "blocked"})])
    post = Mock(side_effect=lambda *a, **k: next(replies))
    monkeypatch.setattr(outbox.requests, "post", post)
    assert outbox.flush("http://test") == {"pending": 0, "rejected": 1}
    assert [row[0] for row in rows()] == ["bad"]
    assert json.loads(rows("decision_rejections")[0][1]) == decision("bad")
    assert rows("decision_rejections")[0][2] == status
    outbox.flush("http://test")
    assert post.call_count == 2


@pytest.mark.parametrize("status", [401, 403, 404, 408, 429, 500, 503])
def test_temporary_or_ambiguous_failure_preserves_fifo(monkeypatch, status):
    outbox.enqueue(decision("first"))
    outbox.enqueue(decision("second"))
    post = Mock(return_value=response(status))
    monkeypatch.setattr(outbox.requests, "post", post)
    assert outbox.flush("http://test") == {"pending": 2, "rejected": 0}
    assert post.call_count == 1
    assert rows("decision_rejections") == []


@pytest.mark.parametrize("raw", ["invalid", "[]", '{"event_key":"wrong"}', None])
def test_corrupt_journal_record_is_retained_and_does_not_block_later_work(monkeypatch, raw):
    with closing(outbox.connect()) as db, db:
        db.execute("INSERT INTO decisions VALUES (?,?)", ("bad", raw))
    outbox.enqueue(decision("good"))
    monkeypatch.setattr(
        outbox.requests, "post", lambda *a, **k: response(body={"id": 1, "decision": "blocked"})
    )
    assert outbox.flush("http://test") == {"pending": 0, "rejected": 1}
    assert rows()[0][1] == raw
    assert rows("decision_rejections")[0][1] == raw


def test_connection_closes_when_initialization_fails(monkeypatch):
    db = Mock()
    db.execute.side_effect = sqlite3.OperationalError("busy")
    monkeypatch.setattr(outbox.sqlite3, "connect", lambda *a, **k: db)
    with pytest.raises(sqlite3.OperationalError):
        outbox.connect()
    db.close.assert_called_once()


def test_completed_action_enqueue_failure_rolls_back_outcome():
    record = {"decision": "allowed", "image_name": "test"}
    key = outbox.begin_action("a" * 64, "start", record)
    outbox.enqueue(record)  # Force a uniqueness failure inside the completion transaction.
    with pytest.raises(sqlite3.IntegrityError):
        outbox.finish_action(key, True)
    with closing(outbox.connect()) as db:
        assert db.execute("SELECT outcome FROM deployment_actions WHERE key=?",
                          (key,)).fetchone() == ("outcome_not_recorded",)


def test_completed_action_is_deliverable_once_and_keeps_history():
    record = {"decision": "blocked", "image_name": "test"}
    key = outbox.begin_action("a" * 64, "remove", record)
    assert rows() == []
    outbox.finish_action(key, True)
    assert len(rows()) == 1
    with pytest.raises(outbox.OutboxConflict):
        outbox.finish_action(key, True)
    outbox.acknowledge(key)
    assert rows() == []
    with closing(outbox.connect()) as db:
        assert db.execute("SELECT outcome FROM deployment_actions").fetchone() == (
            "command_succeeded",
        )
    assert outbox.action_health() == {"active": 0, "outcome_not_recorded": 0, "command_failed": 0}


def test_creation_completion_keeps_history_and_refuses_identity_replacement():
    key = outbox.begin_creation()
    assert outbox.action_health() == {"active": 0, "outcome_not_recorded": 1, "command_failed": 0}
    outbox.finish_creation(key, "a" * 64)
    with pytest.raises(outbox.OutboxConflict):
        outbox.finish_creation(key, "b" * 64)
    with pytest.raises(outbox.OutboxConflict):
        outbox.finish_creation("unknown", "b" * 64)
    with closing(outbox.connect()) as db:
        assert db.execute("SELECT container_id,outcome FROM creation_attempts").fetchall() == [
            ("a" * 64, "command_succeeded"),
        ]
    assert rows() == []  # Creation success is not a policy or registration decision.
    assert outbox.action_health() == {"active": 0, "outcome_not_recorded": 0, "command_failed": 0}


@pytest.mark.parametrize("invalid", ["", "short", "g" * 64, 42])
def test_creation_completion_rejects_invalid_identity_without_losing_intent(invalid):
    key = outbox.begin_creation()
    with pytest.raises(ValueError):
        outbox.finish_creation(key, invalid)
    assert outbox.action_health()["outcome_not_recorded"] == 1
    assert rows() == []


def test_concurrent_creation_completion_cannot_replace_original_identity():
    key = outbox.begin_creation()
    barrier = threading.Barrier(2, timeout=5)

    def finish(identifier):
        barrier.wait()
        try:
            outbox.finish_creation(key, identifier)
            return True
        except outbox.OutboxConflict:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(finish, identifier * 64) for identifier in ("a", "b")]
        assert sorted(f.result(timeout=5) for f in futures) == [False, True]
    with closing(outbox.connect()) as db:
        stored = db.execute("SELECT container_id,outcome FROM creation_attempts").fetchone()
    assert stored in [("a" * 64, "command_succeeded"), ("b" * 64, "command_succeeded")]


def test_additive_creation_schema_preserves_prior_journal(tmp_path):
    path = tmp_path / "deployments.sqlite"
    original = json.dumps(decision())
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE decisions (key TEXT PRIMARY KEY,body TEXT)")
        db.execute("INSERT INTO decisions VALUES (?,?)", ("one", original))
    with closing(outbox.connect()) as db:
        assert db.execute("SELECT key,body FROM decisions").fetchall() == [("one", original)]
        assert db.execute("SELECT count(*) FROM creation_attempts").fetchone() == (0,)


def test_inspection_returns_attempts_without_private_decision_payloads():
    creation = outbox.begin_creation()
    completed = outbox.begin_creation()
    outbox.finish_creation(completed, 'a' * 64)
    item = {**decision(), 'override_reason': 'private-reason', 'secret': 'private-token'}
    item.pop('event_key')
    action = outbox.begin_action('a' * 64, 'start', item)
    failed = outbox.begin_action('b' * 64, 'remove')
    outbox.finish_action(failed, False)
    outbox.enqueue({**decision('queued'), 'secret': 'private-body'})
    outbox._retain_rejection('rejected', 'private-rejection', 422, 'private-detail')
    result = outbox.inspect_actions()
    assert result['outcome_counts'] == {
        'outcome_not_recorded': 2, 'command_succeeded': 1, 'command_failed': 1}
    assert result['pending_decisions'] == result['retained_rejections'] == 1
    attempts = {row['key']: row for row in result['attempts']}
    assert attempts[creation]['container_id'] is None
    assert attempts[completed]['container_id'] == 'a' * 64
    assert attempts[action]['action'] == 'start'
    assert attempts[failed]['completed_at'] is not None
    assert result['has_more'] is False
    assert 'private-' not in json.dumps(result)


@pytest.mark.parametrize(
    'limit,offset', [(0, 0), (201, 0), (True, 0), (1, -1), (1, True), (1, 2**63)])
def test_invalid_inspection_bounds_do_not_initialize_journal(tmp_path, limit, offset):
    with pytest.raises(ValueError):
        outbox.inspect_actions(limit, offset)
    assert not (tmp_path / 'deployments.sqlite').exists()


def test_inspection_missing_path_is_not_created(tmp_path, monkeypatch):
    target = tmp_path / 'missing' / 'nested'
    monkeypatch.setenv('SELFSENTRY_STATE_DIR', str(target))
    with pytest.raises(sqlite3.OperationalError):
        outbox.inspect_actions()
    assert not target.exists()


def test_inspection_corrupt_and_legacy_journals_are_not_repaired(tmp_path, monkeypatch):
    path = tmp_path / 'deployments.sqlite'
    path.write_bytes(b'not a SQLite database')
    with pytest.raises(sqlite3.DatabaseError):
        outbox.inspect_actions()
    assert path.read_bytes() == b'not a SQLite database'
    # Use another disposable path rather than deleting evidence.
    legacy = tmp_path / 'legacy'
    legacy.mkdir()
    with sqlite3.connect(legacy / 'deployments.sqlite') as db:
        db.execute('CREATE TABLE decisions (key TEXT PRIMARY KEY, body TEXT)')
    monkeypatch.setenv('SELFSENTRY_STATE_DIR', str(legacy))
    with pytest.raises(sqlite3.OperationalError):
        outbox.inspect_actions()
    with sqlite3.connect(legacy / 'deployments.sqlite') as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
            ('decisions',)]


def test_inspection_paginates_stably_for_an_unchanged_journal():
    keys = {outbox.begin_creation() for _ in range(3)}
    pages = [outbox.inspect_actions(limit=1, offset=i) for i in range(3)]
    assert {p['attempts'][0]['key'] for p in pages} == keys
    assert [p['has_more'] for p in pages] == [True, True, False]
    assert outbox.inspect_actions(limit=1, offset=3)['attempts'] == []


def test_inspection_uses_read_only_connection_and_single_snapshot(monkeypatch):
    key = outbox.begin_creation()
    real_connect = sqlite3.connect
    calls, connections = [], []
    inserted = False

    def connect(*args, **kwargs):
        assert kwargs.get('uri') is True
        assert args[0].endswith('?mode=ro')
        db = real_connect(*args, **kwargs)
        connections.append(db)

        def trace(sql):
            nonlocal inserted
            calls.append(sql)
            if 'SELECT count(*) FROM decisions' in sql and not inserted:
                inserted = True
                # WAL permits a writer while the read transaction keeps its snapshot.
                with real_connect(args[0].split('?')[0].removeprefix('file:')) as writer:
                    writer.execute('INSERT INTO decisions VALUES (?,?)', ('later', '{}'))
                    writer.execute("UPDATE creation_attempts SET outcome='command_failed'")
        db.set_trace_callback(trace)
        db.set_authorizer(lambda code, *rest: sqlite3.SQLITE_DENY if code in (
            sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_DROP_TABLE) else sqlite3.SQLITE_OK)
        return db

    monkeypatch.setattr(outbox.sqlite3, 'connect', connect)
    result = outbox.inspect_actions()
    assert result['pending_decisions'] == 0
    assert result['outcome_counts'] == {'outcome_not_recorded': 1}
    assert result['attempts'][0]['key'] == key
    assert result['attempts'][0]['outcome'] == 'outcome_not_recorded'
    assert inserted and 'BEGIN' in calls
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        connections[0].execute('SELECT 1')
    monkeypatch.setattr(outbox.sqlite3, 'connect', real_connect)
    assert outbox.inspect_actions()['pending_decisions'] == 1


def test_inspection_cli_never_calls_docker_or_backend(monkeypatch, capsys):
    key = outbox.begin_creation()
    monkeypatch.setattr(gate, 'run_gate', Mock(side_effect=AssertionError('Docker gate called')))
    monkeypatch.setattr(outbox.requests, 'post', Mock(side_effect=AssertionError('HTTP called')))
    assert gate.main(['--inspect-journal', '--limit', '1']) == 0
    assert json.loads(capsys.readouterr().out)['attempts'][0]['key'] == key
    assert gate.main(['--inspect-journal', '--limit', '201']) == 2
    assert capsys.readouterr().err == 'Journal inspection unavailable (ValueError)\n'


def test_inspection_cli_errors_omit_database_details(tmp_path, capsys):
    (tmp_path / 'deployments.sqlite').write_bytes(b'private-corrupt-database')
    assert gate.main(['--inspect-journal']) == 2
    output = capsys.readouterr()
    assert output.out == ''
    assert output.err == 'Journal inspection unavailable (DatabaseError)\n'


def test_inspection_handles_uri_special_characters_in_state_path(tmp_path, monkeypatch):
    monkeypatch.setenv('SELFSENTRY_STATE_DIR', str(tmp_path / 'space # ?'))
    key = outbox.begin_creation()
    assert outbox.inspect_actions()['attempts'][0]['key'] == key


def test_inspection_flag_after_separator_still_reaches_docker_parser():
    _, docker_args = gate.parse_args(['--', '--inspect-journal'])
    assert docker_args == ['--inspect-journal']


def test_inspection_rejects_binary_metadata_without_echoing_it(capsys):
    key = outbox.begin_creation()
    with closing(outbox.connect()) as db:
        with db:
            db.execute('UPDATE creation_attempts SET container_id=? WHERE key=?',
                       (b'private-invalid-metadata', key))
    assert gate.main(['--inspect-journal']) == 2
    output = capsys.readouterr()
    assert output.out == ''
    assert output.err == 'Journal inspection unavailable (ValueError)\n'
