"""Tests for monitor-service/docker_events.py with a fake Docker event stream."""

import queue
import sys
import threading
import time
import unittest
from pathlib import Path

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
    def setUp(self):
        self.out = queue.Queue()
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)

    def make_pump(self, factory):
        pump = docker_events.DockerEventPump(factory, self.out, self.stop, 0.01, 0.02)
        self.addCleanup(lambda: pump.join(timeout=3))
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


if __name__ == "__main__":
    unittest.main()
