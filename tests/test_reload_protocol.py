"""Real private Unix HTTP peer; tests protocol only, not a running Falco daemon."""

from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'rule-synthesis-engine'))
import native_retirement as nr  # noqa: E402


@pytest.fixture
def server(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.respond(200, {'instance_id': 'same-process',
                               'started_generation': self.server.generation,
                               'applied_generation': self.server.generation,
                               'rejected_generation': 0, 'ready': True})

        def do_POST(self):
            self.server.posts += 1
            before = self.server.generation
            self.server.generation += 1
            if self.server.lose_ack:
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.respond(202, {'instance_id': 'same-process', 'started_generation': before})

        def respond(self, code, body):
            assert self.path == '/reload'
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

    path = tmp_path / 'control.sock'
    try:
        host_socket = Server(str(path), Handler)
    except PermissionError:
        pytest.skip('Host policy blocks AF_UNIX; controlled transport tests still run')
    with host_socket as host:
        host.generation, host.posts, host.lose_ack = 1, 0, False
        thread = threading.Thread(target=host.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        monkeypatch.setattr(nr, '_runtime_arguments', lambda: ['falco'])
        monkeypatch.setattr(nr.subprocess, 'check_output', lambda *a, **kw: str(os.getpid()))
        try:
            yield host, nr.ReloadClient(str(path), timeout=0.2)
        finally:
            host.shutdown()
            thread.join(timeout=2)


def test_unix_peer_and_generation_complete_one_reload(server):
    host, client = server
    assert client.status()['applied_generation'] == 1
    assert client.reload()['applied_generation'] == 2
    assert host.posts == 1


def test_lost_ack_is_unknown_and_post_is_not_repeated(server):
    host, client = server
    host.lose_ack = True
    with pytest.raises(nr.RetirementError, match='outcome unavailable'):
        client.reload()
    assert host.posts == 1 and host.generation == 2
    assert client.status()['applied_generation'] == 2
    assert host.posts == 1


def test_other_process_socket_is_refused_before_mutation(server, monkeypatch):
    host, client = server
    monkeypatch.setattr(nr.subprocess, 'check_output', lambda *a, **kw: str(os.getpid() + 1000))
    with pytest.raises(nr.RetirementError, match='peer differs'):
        client.reload()
    assert host.posts == 0


@pytest.mark.parametrize('scenario', ['rejected', 'instance_changed', 'timeout'])
def test_reload_generation_failure_never_reposts(scenario):
    client = nr.ReloadClient(timeout=0.01)
    methods = []

    def request(method):
        methods.append(method)
        if method == 'POST':
            return {'instance_id': 'original', 'started_generation': 1}
        if scenario == 'rejected':
            return {'instance_id': 'original', 'started_generation': 2,
                    'applied_generation': 1, 'rejected_generation': 2, 'ready': False}
        if scenario == 'instance_changed':
            return {'instance_id': 'replacement', 'started_generation': 2,
                    'applied_generation': 2, 'rejected_generation': 0, 'ready': True}
        raise nr.RetirementError('temporarily disconnected')

    client.request = request
    with pytest.raises(nr.RetirementError):
        client.reload()
    assert methods.count('POST') == 1


def test_http_transport_validates_peer_sends_one_post_and_closes_handles(monkeypatch):
    from io import BytesIO
    import struct

    body = json.dumps({'instance_id': 'test-peer', 'started_generation': 9}).encode()
    wire = (b'HTTP/1.1 202 Accepted\r\nContent-Length: '
            + str(len(body)).encode() + b'\r\n\r\n' + body)

    class Peer:
        sent = []
        closed = 0

        def settimeout(self, _timeout):
            pass

        def connect(self, path):
            assert path == '/private/control.sock'

        def getsockopt(self, *_args):
            return struct.pack('3i', 123, 0, 0)

        def sendall(self, data):
            self.sent.append(data)

        def makefile(self, *_args):
            return BytesIO(wire)

        def close(self):
            self.closed += 1

    peer = Peer()
    monkeypatch.setattr(nr.socket, 'socket', lambda *_args: peer)
    monkeypatch.setattr(nr, '_runtime_arguments', lambda: ['falco'])
    monkeypatch.setattr(nr.subprocess, 'check_output', lambda *a, **kw: '123')
    result = nr.ReloadClient('/private/control.sock').request('POST')
    assert result['started_generation'] == 9
    assert b''.join(peer.sent).count(b'POST /reload HTTP/1.1') == 1
    assert peer.closed > 0
