"""Tests for monitor-service/docker_events.py with a fake Docker event stream."""

import queue
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import docker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import docker_events  # noqa: E402


class FakeStreamClient:
    def __init__(self, events):
        self._events = events
        self.calls = []

    def events(self, **kwargs):
        self.calls.append(kwargs)
        return iter(self._events)


def wait_until(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class TestDockerEventPump(unittest.TestCase):
    def test_stop_cancels_sdk_stream_blocked_on_local_socket(self):
        from docker.types.daemon import CancellableStream

        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        entered = threading.Event()

        def events():
            entered.set()
            if reader.recv(1):
                yield {"time": 42}

        raw = SimpleNamespace(
            closed=False, _fp=SimpleNamespace(fp=SimpleNamespace(raw=SimpleNamespace(_sock=reader)))
        )
        stream = CancellableStream(events(), SimpleNamespace(raw=raw))
        client = MagicMock()
        client.events.return_value = stream
        pump = self.make_pump(lambda: client)
        pump.start()
        try:
            self.assertTrue(entered.wait(1))
            pump.stop()
            pump.join(1)
            self.assertFalse(pump.is_alive())
            self.assertTrue(self.out.empty())
            client.close.assert_called_once()
        finally:
            writer.close()  # unblock the socket even if cancellation regresses

    def test_stream_created_after_stop_is_closed_without_consuming(self):
        entered, release = threading.Event(), threading.Event()
        client, stream = MagicMock(), MagicMock()

        def opening(**_):
            entered.set()
            release.wait(3)
            return stream

        client.events.side_effect = opening
        pump = self.make_pump(lambda: client)
        pump.start()
        try:
            self.assertTrue(entered.wait(1))
            pump.stop()
        finally:
            release.set()
            pump.join(3)
        self.assertFalse(pump.is_alive())
        stream.__iter__.assert_not_called()
        stream.close.assert_called_once()
        client.close.assert_called_once()

    def test_stop_during_client_creation_does_not_open_stream(self):
        entered, release = threading.Event(), threading.Event()
        client = MagicMock()

        def factory():
            entered.set()
            release.wait(3)
            return client

        pump = self.make_pump(factory)
        pump.start()
        try:
            self.assertTrue(entered.wait(1))
            pump.stop()
        finally:
            release.set()
            pump.join(3)
        self.assertFalse(pump.is_alive())
        client.events.assert_not_called()
        client.close.assert_called_once()

    def test_full_queue_can_stop_without_advancing_unaccepted_event_time(self):
        self.out = queue.Queue(maxsize=1)
        self.out.put({"already": "queued"})
        pump = self.make_pump(lambda: FakeStreamClient([{"time": 42}]))
        pump.start()
        self.assertTrue(pump.reconnected.wait(1))
        pump.stop()
        pump.join(1)
        self.assertFalse(pump.is_alive())
        self.assertIsNone(pump._last_time)
        self.assertEqual(self.out.get_nowait(), {"already": "queued"})

    def test_disconnected_stream_and_client_are_closed_before_retry(self):
        client = MagicMock()
        stream = MagicMock()
        stream.__iter__.side_effect = docker.errors.DockerException("lost stream")
        stream.close.side_effect = self.stop.set
        client.events.return_value = stream
        pump = self.make_pump(lambda: client)
        pump.start()
        pump.join(timeout=3)
        self.assertFalse(pump.is_alive())
        stream.close.assert_called_once()
        client.close.assert_called_once()

    def setUp(self):
        self.out = queue.Queue()
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)

    def make_pump(self, factory):
        pump = docker_events.DockerEventPump(factory, self.out, self.stop, 0.01, 0.02)

        def cleanup():
            pump.stop()
            pump.join(timeout=3)

        self.addCleanup(cleanup)
        return pump

    def test_events_are_queued_after_a_failed_first_connection(self):
        first, second = {"time": 5, "Action": "start"}, {"time": 6, "Action": "die"}
        calls = []

        def factory():
            calls.append(1)
            if len(calls) == 1:
                raise docker.errors.DockerException("down")
            return FakeStreamClient([first, second] if len(calls) == 2 else [])

        pump = self.make_pump(factory)
        pump.start()
        got = [self.out.get(timeout=3), self.out.get(timeout=3)]
        self.stop.set()
        self.assertEqual(got, [first, second])
        self.assertTrue(pump.reconnected.is_set())

    def test_reconnect_resumes_from_the_last_event_time(self):
        clients = [FakeStreamClient([{"time": 42, "Action": "start"}]), FakeStreamClient([])]

        def factory():
            return clients.pop(0) if len(clients) > 1 else clients[0]

        second = clients[1]
        pump = self.make_pump(factory)
        pump.start()
        self.assertTrue(wait_until(lambda: len(second.calls) > 0))
        self.stop.set()
        self.assertEqual(second.calls[0]["since"], 42)

    def test_state_reports_unavailable_with_the_error(self):
        def factory():
            raise docker.errors.DockerException("no daemon")

        pump = self.make_pump(factory)
        pump.start()
        self.assertTrue(wait_until(lambda: pump.state == "unavailable"))
        self.stop.set()
        self.assertIn("no daemon", pump.last_error)

    def test_normal_stream_eof_reports_unavailable_before_cleanup_and_backoff(self):
        observed = []
        client = MagicMock()
        client.events.return_value = iter([])
        pump = self.make_pump(lambda: client)

        def close():
            observed.append((pump.state, pump.last_error))
            self.stop.set()

        client.close.side_effect = close
        pump.start()
        pump.join(timeout=3)
        self.assertFalse(pump.is_alive())
        self.assertEqual(observed, [("unavailable", "Docker event stream ended; reconnecting")])

    def test_sdk_transport_error_converted_to_eof_remains_unavailable(self):
        from docker.types.daemon import CancellableStream

        def broken():
            raise OSError("controlled transport loss")
            yield  # pragma: no cover - force generator semantics

        stream = CancellableStream(broken(), SimpleNamespace(raw=SimpleNamespace(closed=True)))
        client = MagicMock()
        client.events.return_value = stream
        pump = self.make_pump(lambda: client)
        client.close.side_effect = self.stop.set
        pump.start()
        pump.join(timeout=3)
        self.assertFalse(pump.is_alive())
        self.assertEqual(pump.state, "unavailable")
        self.assertIn("stream ended", pump.last_error)

    def test_eof_during_requested_shutdown_is_not_reported_as_outage(self):
        def ending():
            self.stop.set()
            yield from ()

        pump = self.make_pump(lambda: FakeStreamClient(ending()))
        pump.start()
        pump.join(timeout=3)
        self.assertFalse(pump.is_alive())
        self.assertEqual(pump.state, "connected")
        self.assertIsNone(pump.last_error)

    def test_repeated_empty_streams_increase_backoff_until_an_event_is_accepted(self):
        waits = []
        stop = self.stop

        class Stop:
            def is_set(self):
                return stop.is_set()

            def wait(self, delay):
                waits.append(delay)
                return len(waits) == 3

        pump = docker_events.DockerEventPump(
            lambda: FakeStreamClient([]), self.out, Stop(), 0.1, 0.4
        )
        pump.run()
        self.assertEqual(waits, [0.1, 0.2, 0.4])
        self.assertEqual(pump.state, "unavailable")


if __name__ == "__main__":
    unittest.main()
