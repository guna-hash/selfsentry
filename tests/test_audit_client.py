"""Tests for monitor-service/audit_client.py (HTTP mocked, spool in a temp dir)."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import audit_client  # noqa: E402


def ok():
    return MagicMock(status_code=201, json=lambda: {"id": 1, "duplicate": False})


class AuditClientTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.spool = self.dir / "audit_spool.jsonl"
        patcher = patch.object(audit_client.requests, "post")
        self.post = patcher.start()
        self.addCleanup(patcher.stop)
        self.client = self.new_client()

    def new_client(self):
        return audit_client.AuditClient("http://backend", self.spool)

    def sent_keys(self):
        return [call.kwargs["json"]["event_key"] for call in self.post.call_args_list]


class TestEmit(AuditClientTestCase):
    def test_successful_delivery_posts_the_payload(self):
        self.post.return_value = ok()
        self.assertTrue(self.client.emit("TEST", container_id="abc", event_key="k1"))
        self.assertEqual(self.post.call_args.args[0], "http://backend/audit/")
        payload = self.post.call_args.kwargs["json"]
        self.assertEqual(payload["event_type"], "TEST")
        self.assertEqual(payload["event_key"], "k1")
        self.assertEqual(self.client.spool_size(), 0)
        self.assertEqual(self.client.last_outcome, "ok")

    def test_unreachable_backend_spools_the_event(self):
        self.post.side_effect = requests.ConnectionError("down")
        self.assertFalse(self.client.emit("TEST", event_key="k1"))
        self.assertEqual(self.client.spool_size(), 1)
        self.assertEqual(self.client.last_outcome, "retry")

    def test_server_error_spools_the_event(self):
        self.post.return_value = MagicMock(status_code=503)
        self.assertFalse(self.client.emit("TEST", event_key="k1"))
        self.assertEqual(self.client.spool_size(), 1)

    def test_rejected_event_goes_to_dead_letters_not_the_spool(self):
        self.post.return_value = MagicMock(status_code=422)
        self.assertFalse(self.client.emit("TEST", event_key="k1"))
        self.assertEqual(self.client.spool_size(), 0)
        rejected = (self.dir / "audit_rejected.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(rejected[0])["event_key"], "k1")
        self.assertEqual(self.client.last_outcome, "rejected")

    def test_spool_survives_a_restart(self):
        self.post.side_effect = requests.ConnectionError("down")
        self.client.emit("TEST", event_key="k1")
        self.assertEqual(self.new_client().spool_size(), 1)


class TestFlushAndOrdering(AuditClientTestCase):
    def spool_three(self):
        self.post.side_effect = requests.ConnectionError("down")
        for key in ("k1", "k2", "k3"):
            self.client.emit("TEST", event_key=key)
        self.post.reset_mock()

    def test_flush_stops_at_the_first_failure_and_keeps_order(self):
        self.spool_three()
        self.post.side_effect = [ok(), requests.ConnectionError("x")]
        self.assertEqual(self.client.flush_spool(), 1)
        self.assertEqual(self.client.spool_size(), 2)
        remaining = [json.loads(line)["event_key"] for line in self.spool.read_text().splitlines()]
        self.assertEqual(remaining, ["k2", "k3"])

    def test_flush_clears_the_spool_when_everything_is_delivered(self):
        self.spool_three()
        self.post.side_effect = None
        self.post.return_value = ok()
        self.assertEqual(self.client.flush_spool(), 3)
        self.assertEqual(self.client.spool_size(), 0)
        self.assertFalse(self.spool.exists())

    def test_a_new_event_is_sent_after_older_spooled_ones(self):
        self.post.side_effect = requests.ConnectionError("down")
        self.client.emit("TEST", event_key="k1")
        self.post.reset_mock()
        self.post.side_effect = None
        self.post.return_value = ok()
        self.assertTrue(self.client.emit("TEST", event_key="k2"))
        self.assertEqual(self.sent_keys(), ["k1", "k2"])


if __name__ == "__main__":
    unittest.main()


@pytest.fixture(params=[audit_client.AuditClient, audit_client.DurableAuditClient])
def delivery_client(request, tmp_path):
    return request.param("http://backend", tmp_path / "audit_spool.jsonl")


def acknowledgement(status=201, body=None):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    return response


@pytest.mark.parametrize("status,body", [
    (200, {}), (201, []), (201, {"id": True, "duplicate": False}),
    (201, {"id": 0, "duplicate": False}), (201, {"id": 1}),
    (201, {"id": 1, "duplicate": "false"}),
    (200, {"id": 1, "duplicate": False}), (201, {"id": 1, "duplicate": True}),
])
def test_ambiguous_acknowledgement_keeps_original_event(
    delivery_client, monkeypatch, status, body,
):
    monkeypatch.setattr(
        audit_client.requests, "post", lambda *a, **k: acknowledgement(status, body))
    delivery_client.emit("TEST", event_key="original")
    assert delivery_client.flush_spool() == 0
    assert delivery_client.spool_size() == 1
    assert delivery_client.last_outcome == "retry"
    assert not delivery_client._rejected_path.exists()
    delivered = []

    def accept(*args, **kwargs):
        delivered.append(kwargs["json"]["event_key"])
        return acknowledgement(201, {"id": 7, "duplicate": False})
    monkeypatch.setattr(audit_client.requests, "post", accept)
    assert delivery_client.flush_spool() == 1
    assert delivered == ["original"]
    assert delivery_client.spool_size() == 0


@pytest.mark.parametrize("status", [401, 403, 408, 409, 425, 429, 500, 503])
def test_retryable_http_failure_does_not_dead_letter(delivery_client, monkeypatch, status):
    monkeypatch.setattr(audit_client.requests, "post", lambda *a, **k: acknowledgement(status))
    delivery_client.emit("TEST", event_key="original")
    assert delivery_client.flush_spool() == 0
    assert delivery_client.spool_size() == 1
    assert not delivery_client._rejected_path.exists()
    monkeypatch.setattr(audit_client.requests, "post", lambda *a, **k: acknowledgement(
        200, {"id": 9, "duplicate": True}))
    assert delivery_client.flush_spool() == 1
    assert delivery_client.spool_size() == 0


@pytest.mark.parametrize("status", [400, 422])
def test_explicit_payload_rejection_is_retained(delivery_client, monkeypatch, status):
    monkeypatch.setattr(audit_client.requests, "post", lambda *a, **k: acknowledgement(status))
    delivery_client.emit("TEST", event_key="rejected")
    delivery_client.flush_spool()
    assert delivery_client.spool_size() == 0
    assert json.loads(delivery_client._rejected_path.read_text())["event_key"] == "rejected"


def test_invalid_json_ack_and_transport_error_are_sanitized(delivery_client, monkeypatch, caplog):
    response = acknowledgement()
    response._content = b"private-invalid-body"
    monkeypatch.setattr(audit_client.requests, "post", lambda *a, **k: response)
    delivery_client.emit("TEST", event_key="retained")
    assert delivery_client.flush_spool() == 0
    monkeypatch.setattr(audit_client.requests, "post", MagicMock(
        side_effect=requests.ConnectionError("private-token-in-url")))
    assert delivery_client.flush_spool() == 0
    assert delivery_client.spool_size() == 1
    assert "private-" not in caplog.text


@pytest.mark.parametrize("failure", [None, "init", "emit", "size", "read", "delete"])
def test_durable_sqlite_connections_close_on_success_and_failure(tmp_path, monkeypatch, failure):
    real_connect = sqlite3.connect
    handles = []
    failing_sql = {"init": "CREATE", "emit": "INSERT", "size": "SELECT count",
                   "read": "SELECT key", "delete": "DELETE"}.get(failure)

    class Connection(sqlite3.Connection):
        closed = False

        def execute(self, sql, *args, **kwargs):
            if failing_sql and sql.startswith(failing_sql):
                raise sqlite3.OperationalError("controlled fault")
            return super().execute(sql, *args, **kwargs)

        def close(self):
            self.closed = True
            return super().close()

    def connect(*args, **kwargs):
        db = real_connect(*args, **kwargs, factory=Connection)
        handles.append(db)
        return db
    monkeypatch.setattr(sqlite3, "connect", connect)
    path = tmp_path / "audit_spool.jsonl"
    try:
        if failure == "init":
            with pytest.raises(sqlite3.OperationalError):
                audit_client.DurableAuditClient("http://backend", path)
        else:
            client = audit_client.DurableAuditClient("http://backend", path)
            if failure == "emit":
                with pytest.raises(sqlite3.OperationalError):
                    client.emit("TEST", event_key="one")
            else:
                client.emit("TEST", event_key="one")
                if failure == "size":
                    with pytest.raises(sqlite3.OperationalError):
                        client.spool_size()
                else:
                    monkeypatch.setattr(client, "_post", lambda _: "ok")
                    if failure:
                        with pytest.raises(sqlite3.OperationalError):
                            client.flush_spool()
                    else:
                        assert client.spool_size() == 1
                        assert client.flush_spool() == 1
                        assert client.spool_size() == 0
        assert handles and all(db.closed for db in handles)
        for db in handles:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                db.execute("SELECT 1")
    finally:
        for db in handles:
            db.close()


def test_real_route_lost_ack_replays_as_duplicate(tmp_path, monkeypatch):
    from tests.test_backend_audit import AuditApiTestCase
    backend = AuditApiTestCase()
    backend.setUp()
    client = audit_client.DurableAuditClient("http://backend", tmp_path / "audit_spool.jsonl")
    replies = []

    def deliver(*args, **kwargs):
        response = backend.client.post("/audit/", json=kwargs["json"])
        replies.append((response.status_code, response.json()))
        if len(replies) == 1:
            raise requests.ConnectionError("controlled lost response after route committed")
        return response
    monkeypatch.setattr(audit_client.requests, "post", deliver)
    try:
        client.emit("TEST", event_key="stable-key")
        assert client.flush_spool() == 0
        assert client.spool_size() == 1
        assert len(backend.client.get("/audit/").json()) == 1
        assert client.flush_spool() == 1
        assert client.spool_size() == 0
        assert [reply[0] for reply in replies] == [201, 200]
        assert replies[1][1]["duplicate"] is True
        assert len(backend.client.get("/audit/").json()) == 1
    finally:
        backend.client.close()
        backend.doCleanups()


@pytest.mark.parametrize('raw', [b'{private-invalid\n', b'[]\n', b'null\n',
                                 b'{"detail": {"bad": NaN}}\n', b'\xffprivate-invalid\n'])
def test_legacy_corruption_reads_and_flushes_leave_evidence_unchanged(
    delivery_client, raw, monkeypatch, caplog,
):
    client = delivery_client
    client._spool_path.write_bytes(raw)
    client._rejected_path.write_bytes(b'previous-evidence\n')
    post = MagicMock(side_effect=AssertionError('HTTP must not receive corrupt journal data'))
    monkeypatch.setattr(audit_client.requests, 'post', post)
    for operation in (client.spool_size, client.spool_size, client.flush_spool):
        with pytest.raises(audit_client.AuditJournalError) as error:
            operation()
        assert 'private-' not in str(error.value)
        assert error.value.__suppress_context__
    assert not post.called
    assert client._spool_path.read_bytes() == raw
    assert client._rejected_path.read_bytes() == b'previous-evidence\n'
    assert 'private-' not in caplog.text


@pytest.mark.parametrize('body', [
    None, '{private-invalid', '[]', 'null',
    '{"event_key":"corrupt","detail":{"bad":NaN}}',
    '{"event_key":"different"}',
])
def test_invalid_sqlite_batch_is_retained_before_any_http(tmp_path, monkeypatch, body):
    client = audit_client.DurableAuditClient('http://unused', tmp_path / 'audit_spool.jsonl')
    client.emit('FIRST', event_key='first')
    with closing(sqlite3.connect(client._journal)) as db, db:
        db.execute('INSERT INTO audit_outbox VALUES (?,?)', ('corrupt', body))
    client.emit('LAST', event_key='last')
    post = MagicMock(side_effect=AssertionError('No HTTP before batch validation'))
    monkeypatch.setattr(audit_client.requests, 'post', post)
    for _ in range(2):
        with pytest.raises(audit_client.AuditJournalError) as error:
            client.flush_spool()
        assert 'private-' not in str(error.value)
        assert error.value.__suppress_context__
    assert not post.called
    assert client.spool_size() == 3
    with closing(sqlite3.connect(client._journal)) as db, db:
        assert db.execute('SELECT body FROM audit_outbox WHERE key=?',
                          ('corrupt',)).fetchone()[0] == body
    assert not client._rejected_path.exists()


def test_legacy_error_reports_line_without_body(delivery_client):
    delivery_client._spool_path.write_text('\n{"event_key":"good"}\nprivate-malformed\n')
    with pytest.raises(audit_client.AuditJournalError, match='line 3'):
        delivery_client.spool_size()


def test_operator_preserved_repair_resumes_legacy_before_sqlite(delivery_client, monkeypatch):
    client = delivery_client
    is_durable = isinstance(client, audit_client.DurableAuditClient)
    if is_durable:
        client.emit('NEW', event_key='new')
    valid = json.dumps({'event_type': 'OLD', 'event_key': 'old'}) + '\n'
    original = valid + 'private-malformed\n'
    client._spool_path.write_text(original)
    delivered = []

    def post(*args, **kwargs):
        delivered.append(kwargs['json']['event_key'])
        return acknowledgement(201, {'id': 1, 'duplicate': False})
    monkeypatch.setattr(audit_client.requests, 'post', post)
    with pytest.raises(audit_client.AuditJournalError):
        client.flush_spool()
    assert not delivered
    # Simulate explicit operator review on disposable data; preserve original evidence.
    backup = client._spool_path.with_suffix('.operator-backup')
    backup.write_text(original)
    client._spool_path.write_text(valid)
    assert client.flush_spool() == (2 if is_durable else 1)
    assert delivered == (['old', 'new'] if is_durable else ['old'])
    assert backup.read_text() == original
    assert client.spool_size() == 0


@pytest.mark.parametrize('value', ['', True, False, 0, 7, [], 'x' * 129])
def test_invalid_new_event_keys_fail_before_delivery_or_journaling(
    delivery_client, monkeypatch, value,
):
    post = MagicMock(side_effect=AssertionError('Invalid key must not reach HTTP'))
    monkeypatch.setattr(audit_client.requests, 'post', post)
    with pytest.raises(ValueError, match='event_key must contain'):
        delivery_client.emit('TEST', event_key=value)
    assert not post.called
    assert delivery_client.spool_size() == 0
    assert not delivery_client._rejected_path.exists()


def test_generated_key_survives_lost_reply_and_client_restart(delivery_client, monkeypatch):
    from tests.test_backend_audit import AuditApiTestCase
    backend = AuditApiTestCase()
    backend.setUp()
    keys = []

    def post(*args, **kwargs):
        keys.append(kwargs['json']['event_key'])
        response = backend.client.post('/audit/', json=kwargs['json'])
        if len(keys) == 1:
            raise requests.ConnectionError('Controlled loss after commit')
        return response
    monkeypatch.setattr(audit_client.requests, 'post', post)
    try:
        delivery_client.emit('TEST')
        if isinstance(delivery_client, audit_client.DurableAuditClient):
            assert delivery_client.flush_spool() == 0
        assert len(backend.client.get('/audit/').json()) == 1
        assert delivery_client.spool_size() == 1
        restarted = type(delivery_client)('http://backend', delivery_client._spool_path)
        assert restarted.flush_spool() == 1
        assert len(keys) == 2 and isinstance(keys[0], str) and keys[0]
        assert keys[0] == keys[1]
        assert restarted.spool_size() == 0
        assert len(backend.client.get('/audit/').json()) == 1
    finally:
        backend.client.close()
        backend.doCleanups()


def test_distinct_keyless_emissions_are_not_collapsed(delivery_client, monkeypatch):
    keys = []

    def post(*args, **kwargs):
        keys.append(kwargs['json']['event_key'])
        return acknowledgement(201, {'id': len(keys), 'duplicate': False})
    monkeypatch.setattr(audit_client.requests, 'post', post)
    delivery_client.emit('SAME_EVENT_CONTENT')
    delivery_client.emit('SAME_EVENT_CONTENT')
    delivery_client.flush_spool()
    assert len(keys) == 2 and all(isinstance(key, str) and key for key in keys)
    assert keys[0] != keys[1]


def test_explicit_valid_key_is_preserved(delivery_client, monkeypatch):
    keys = []

    def post(*args, **kwargs):
        keys.append(kwargs['json']['event_key'])
        return acknowledgement(201, {'id': 1, 'duplicate': False})
    monkeypatch.setattr(audit_client.requests, 'post', post)
    key = '  caller-key-' + 'x' * 100
    delivery_client.emit('TEST', event_key=key)
    delivery_client.flush_spool()
    assert keys == [key]


def test_historical_keyless_spool_is_not_assigned_an_invented_identity(
    delivery_client, monkeypatch,
):
    payload = {'event_type': 'HISTORICAL', 'event_key': None}
    delivery_client._spool_path.write_text(json.dumps(payload) + '\n')
    posted = []

    def post(*args, **kwargs):
        posted.append(kwargs['json'])
        return acknowledgement(201, {'id': 1, 'duplicate': False})
    monkeypatch.setattr(audit_client.requests, 'post', post)
    assert delivery_client.flush_spool() == 1
    assert posted == [payload]


@pytest.mark.parametrize('change', [
    {'event_type': 'PRIVATE_CHANGED'}, {'severity': 'critical'},
    {'container_id': 'b' * 64}, {'container_name': 'private-name'},
    {'image_name': 'private-image'}, {'detail': {'private': 'changed'}},
    {'occurred_at': '2026-10-22T00:00:01Z'},
])
def test_pending_key_conflict_is_explicit_and_preserves_original(tmp_path, monkeypatch, change):
    client = audit_client.DurableAuditClient('http://unused', tmp_path / 'audit_spool.jsonl')
    original = dict(event_type='ORIGINAL', event_key='same', detail={'count': 1},
                    occurred_at='2026-10-22T00:00:00Z')
    client.emit(**original)
    with closing(sqlite3.connect(client._journal)) as db:
        before = db.execute('SELECT body FROM audit_outbox WHERE key=?', ('same',)).fetchone()[0]
    post = MagicMock(side_effect=AssertionError('Enqueue must not call HTTP'))
    monkeypatch.setattr(audit_client.requests, 'post', post)
    with pytest.raises(audit_client.AuditEventConflict) as error:
        client.emit(**{**original, **change})
    assert 'private' not in str(error.value).lower()
    assert not post.called and client.spool_size() == 1
    with closing(sqlite3.connect(client._journal)) as db:
        assert db.execute('SELECT body FROM audit_outbox WHERE key=?',
                          ('same',)).fetchone()[0] == before


def test_identical_pending_retry_preserves_first_automatic_time(tmp_path, monkeypatch):
    client = audit_client.DurableAuditClient('http://unused', tmp_path / 'audit_spool.jsonl')
    times = iter(['2026-10-22T00:00:00Z', '2026-10-22T00:01:00Z'])
    monkeypatch.setattr(audit_client, '_utc_now', lambda: next(times))
    client.emit('TEST', event_key='same', detail={'a': 1, 'b': {'x': 2, 'y': 3}})
    restarted = audit_client.DurableAuditClient('http://unused', client._spool_path)
    restarted.emit('TEST', event_key='same', detail={'b': {'y': 3, 'x': 2}, 'a': 1})
    assert restarted.spool_size() == 1
    with closing(sqlite3.connect(client._journal)) as db:
        stored = json.loads(db.execute('SELECT body FROM audit_outbox').fetchone()[0])
    assert stored['occurred_at'] == '2026-10-22T00:00:00Z'
    delivered = []

    def post(*args, **kwargs):
        delivered.append(kwargs['json'])
        return acknowledgement(201, {'id': 1, 'duplicate': False})
    monkeypatch.setattr(audit_client.requests, 'post', post)
    assert restarted.flush_spool() == 1
    assert delivered == [stored]


@pytest.mark.parametrize('body', [
    None, 'private-invalid', '[]', '{"event_key":"different"}',
])
def test_existing_corruption_is_not_hidden_by_duplicate_enqueue(tmp_path, body):
    client = audit_client.DurableAuditClient('http://unused', tmp_path / 'audit_spool.jsonl')
    with closing(sqlite3.connect(client._journal)) as db, db:
        db.execute('INSERT INTO audit_outbox VALUES (?,?)', ('same', body))
    with pytest.raises(audit_client.AuditJournalError) as error:
        client.emit('TEST', event_key='same')
    assert 'private' not in str(error.value)
    with closing(sqlite3.connect(client._journal)) as db:
        assert db.execute('SELECT body FROM audit_outbox').fetchone()[0] == body


def test_conflicting_pending_writers_keep_one_original(tmp_path):
    path = tmp_path / 'audit_spool.jsonl'
    clients = [audit_client.DurableAuditClient('http://unused', path) for _ in range(2)]
    barrier = threading.Barrier(2, timeout=5)

    def emit(index):
        barrier.wait()
        try:
            clients[index].emit('TEST', event_key='same', detail={'writer': index})
            return 'queued'
        except audit_client.AuditEventConflict:
            return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(emit, i) for i in range(2)]
        outcomes = [future.result(timeout=5) for future in futures]
    assert sorted(outcomes) == ['conflict', 'queued']
    with closing(sqlite3.connect(clients[0]._journal)) as db:
        rows = db.execute('SELECT body FROM audit_outbox').fetchall()
    assert len(rows) == 1
    assert json.loads(rows[0][0])['detail']['writer'] == outcomes.index('queued')


def test_nonfinite_new_audit_is_refused_before_poisoning_journal(tmp_path):
    client = audit_client.DurableAuditClient('http://unused', tmp_path / 'audit_spool.jsonl')
    with pytest.raises(ValueError):
        client.emit('TEST', event_key='bad', detail={'value': float('nan')})
    assert client.spool_size() == 0
    client.emit('TEST', event_key='good')
    assert client.spool_size() == 1


def test_remote_conflict_after_local_delivery_keeps_changed_event_pending(
    delivery_client, monkeypatch,
):
    from tests.test_backend_audit import AuditApiTestCase
    backend = AuditApiTestCase()
    backend.setUp()
    statuses = []

    def post(*args, **kwargs):
        response = backend.client.post('/audit/', json=kwargs['json'])
        statuses.append(response.status_code)
        return response
    monkeypatch.setattr(audit_client.requests, 'post', post)
    try:
        delivery_client.emit('ORIGINAL', event_key='after-delivery')
        delivery_client.flush_spool()
        assert delivery_client.spool_size() == 0
        delivery_client.emit('CHANGED', event_key='after-delivery')
        assert delivery_client.flush_spool() == 0
        assert delivery_client.spool_size() == 1
        assert 409 in statuses
        rows = backend.client.get('/audit/').json()
        assert len(rows) == 1 and rows[0]['event_type'] == 'ORIGINAL'
        assert not delivery_client._rejected_path.exists()
    finally:
        backend.client.close()
        backend.doCleanups()
