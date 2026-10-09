"""Tests for monitor-service/container_watcher.py with fake audit, lookup and Docker."""

import dataclasses
import sys
import unittest
from pathlib import Path

import docker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import container_watcher  # noqa: E402
from monitor_config import MonitorConfig  # noqa: E402

ID_A, SHORT_A = "a" * 64, "a" * 12
ID_B, SHORT_B = "b" * 64, "b" * 12
STARTED = "2026-10-09T10:00:00Z"


def docker_event(action, full_id, name="web", image="nginx:1.25", t=1, **attrs):
    return {
        "Type": "container",
        "Action": action,
        "Actor": {"ID": full_id, "Attributes": {"name": name, "image": image, **attrs}},
        "time": t,
        "timeNano": t * 10**9,
    }


class FakeAudit:
    def __init__(self):
        self.events = []

    def emit(self, **kwargs):
        self.events.append(kwargs)
        return True

    def types(self):
        return [event["event_type"] for event in self.events]


class FakeLookup:
    def __init__(self):
        self.registered = {}
        self.default = False

    def is_registered(self, short_id):
        return self.registered.get(short_id, self.default)


class FakeInspector:
    def __init__(self):
        self.containers = {ID_A: {"name": "web", "image": "nginx:1.25", "started_at": STARTED}}
        self.fail = False

    def inspect(self, full_id):
        if self.fail:
            raise docker.errors.DockerException("daemon busy")
        return self.containers.get(full_id)

    def list_running(self):
        return [{"id": full_id, **info} for full_id, info in self.containers.items()]


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class WatcherTestCase(unittest.TestCase):
    def setUp(self):
        self.audit = FakeAudit()
        self.lookup = FakeLookup()
        self.inspector = FakeInspector()
        self.clock = FakeClock()
        self.watcher = self.make_watcher()

    def make_watcher(self, audit=None, **overrides):
        config = dataclasses.replace(
            MonitorConfig(),
            registration_grace_seconds=15.0,
            registration_retry_seconds=5.0,
            **overrides,
        )
        return container_watcher.ContainerWatcher(
            config, audit or self.audit, self.lookup, self.inspector, clock=self.clock
        )

    def advance(self, seconds):
        self.clock.now += seconds
        return self.watcher.tick()

    def start(self, full_id=ID_A, **kwargs):
        self.watcher.handle_docker_event(docker_event("start", full_id, **kwargs))


class TestRegistration(WatcherTestCase):
    def test_gate_registered_container_is_started_not_unapproved(self):
        self.lookup.registered[SHORT_A] = True
        self.start()
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED"])
        self.assertEqual(self.audit.events[0]["detail"]["registration_status"], "registered")
        self.assertEqual(self.watcher.pending_count, 0)

    def test_unregistered_container_is_reported_only_after_the_grace_period(self):
        self.start()
        self.assertEqual(self.audit.types(), [])
        self.advance(14)
        self.assertEqual(self.audit.types(), [])
        self.advance(2)
        self.assertEqual(self.audit.types(), ["UNAPPROVED_CONTAINER_START"])
        event = self.audit.events[0]
        self.assertEqual(event["severity"], "warning")
        self.assertEqual(event["container_id"], SHORT_A)
        self.assertEqual(event["detail"]["detection_method"], "docker_event")
        self.assertEqual(event["detail"]["registration_status"], "unregistered")

    def test_registration_arriving_within_the_grace_period_prevents_a_false_alert(self):
        self.start()
        self.advance(6)
        self.lookup.registered[SHORT_A] = True
        self.advance(6)
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED"])
        self.advance(30)
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED"])

    def test_container_named_like_an_approved_one_is_still_unapproved(self):
        self.lookup.registered[SHORT_A] = True
        self.inspector.containers[ID_B] = {
            "name": "web", "image": "nginx:1.25", "started_at": STARTED,
        }
        self.start(ID_B)
        self.advance(16)
        self.assertEqual(self.audit.types(), ["UNAPPROVED_CONTAINER_START"])
        self.assertEqual(self.audit.events[0]["container_id"], SHORT_B)

    def test_lookup_failure_never_claims_the_container_is_unapproved(self):
        self.lookup.default = None
        self.start()
        self.advance(16)
        self.assertEqual(self.audit.types(), ["REGISTRATION_UNKNOWN"])

    def test_last_definitive_answer_is_used_when_the_lookup_fails_at_the_deadline(self):
        self.start()
        self.lookup.default = None
        self.advance(16)
        self.assertEqual(self.audit.types(), ["UNAPPROVED_CONTAINER_START"])

    def test_ignore_policy_records_a_normal_start_for_unregistered_containers(self):
        self.watcher = self.make_watcher(unapproved_start_policy="ignore")
        self.start()
        self.advance(16)
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED"])
        self.assertEqual(self.audit.events[0]["detail"]["registration_status"], "unregistered")

    def test_inspect_failure_falls_back_to_event_data(self):
        self.inspector.fail = True
        self.start()
        self.advance(16)
        self.assertEqual(self.audit.types(), ["UNAPPROVED_CONTAINER_START"])
        self.assertEqual(self.audit.events[0]["container_name"], "web")


class TestLifecycle(WatcherTestCase):
    def test_duplicate_start_event_is_ignored(self):
        self.lookup.registered[SHORT_A] = True
        self.start()
        self.start()
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED"])

    def test_restart_records_stop_and_a_new_start_with_distinct_keys(self):
        self.lookup.registered[SHORT_A] = True
        self.start()
        self.watcher.handle_docker_event(docker_event("die", ID_A, t=2, exitCode="137"))
        self.inspector.containers[ID_A]["started_at"] = "2026-10-09T10:05:00Z"
        self.start(t=3)
        self.assertEqual(
            self.audit.types(), ["CONTAINER_STARTED", "CONTAINER_STOPPED", "CONTAINER_STARTED"]
        )
        self.assertEqual(self.audit.events[1]["detail"]["exit_code"], "137")
        self.assertNotEqual(self.audit.events[0]["event_key"], self.audit.events[2]["event_key"])

    def test_removal_is_audited_and_stops_tracking(self):
        self.lookup.registered[SHORT_A] = True
        self.start()
        self.assertEqual(self.watcher.tracked_count, 1)
        self.watcher.handle_docker_event(docker_event("destroy", ID_A, t=2))
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED", "CONTAINER_REMOVED"])
        self.assertEqual(self.watcher.tracked_count, 0)

    def test_replacement_container_does_not_inherit_the_removed_ones_trust(self):
        self.lookup.registered[SHORT_A] = True
        self.start()
        self.watcher.handle_docker_event(docker_event("destroy", ID_A, t=2))
        self.inspector.containers[ID_B] = {
            "name": "web", "image": "nginx:1.25", "started_at": "2026-10-09T10:10:00Z",
        }
        self.start(ID_B, t=3)
        self.advance(16)
        self.assertEqual(self.audit.types()[-1], "UNAPPROVED_CONTAINER_START")
        self.assertEqual(self.audit.events[-1]["detail"]["name_previously_used_by"], SHORT_A)

    def test_unrelated_event_types_are_ignored(self):
        self.watcher.handle_docker_event(docker_event("exec_start: sh", ID_A))
        self.assertEqual(self.audit.types(), [])


class TestReconcile(WatcherTestCase):
    def setUp(self):
        super().setUp()
        self.inspector.containers[ID_B] = {
            "name": "stray", "image": "nginx:latest", "started_at": STARTED,
        }
        self.lookup.registered[SHORT_A] = True

    def test_existing_containers_are_registered_immediately(self):
        self.assertEqual(self.watcher.reconcile(), 2)
        self.assertEqual(self.audit.types(), ["CONTAINER_STARTED", "UNAPPROVED_CONTAINER_START"])
        self.assertEqual(self.audit.events[1]["detail"]["detection_method"], "startup_reconcile")

    def test_repeating_reconcile_is_idempotent_in_process(self):
        self.watcher.reconcile()
        self.assertEqual(self.watcher.reconcile(), 0)
        self.assertEqual(len(self.audit.events), 2)

    def test_a_restarted_monitor_produces_the_same_event_keys(self):
        self.watcher.reconcile()
        second_audit = FakeAudit()
        self.make_watcher(audit=second_audit).reconcile()
        first = [event["event_key"] for event in self.audit.events]
        second = [event["event_key"] for event in second_audit.events]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
