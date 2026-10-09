"""Tests for monitor-service/monitor_service.py with real files and fake collaborators."""

import dataclasses
import json
import queue
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import monitor_service  # noqa: E402
from falco_ingest import FalcoTailer  # noqa: E402
from monitor_config import MonitorConfig  # noqa: E402
from monitor_status import StatusBoard  # noqa: E402


def falco_line(rule="Terminal shell in container", container_id="12160024642b", second=0):
    stamp = f"2026-10-09T10:00:{second:02d}.123456789Z"
    fields = {"container.id": container_id, "container.name": "web", "proc.name": "sh"}
    return json.dumps(
        {
            "hostname": "vm",
            "output": f"{stamp}: Notice {rule} container_id={container_id}",
            "output_fields": fields,
            "priority": "Notice",
            "rule": rule,
            "source": "syscall",
            "tags": [],
            "time": stamp,
        }
    )


class RecordingSink:
    def __init__(self):
        self.alerts = []
        self.baseline = []
        self.fail_on = None
        self.on_alert = None

    def handle_alert(self, event):
        if self.fail_on and event["rule"] == self.fail_on:
            raise RuntimeError("sink failure")
        self.alerts.append(event)
        if self.on_alert:
            self.on_alert(event)

    def handle_baseline_event(self, event):
        self.baseline.append(event)


class FakeWatcher:
    tracked_count = 0
    pending_count = 0

    def __init__(self):
        self.events = []
        self.reconciles = 0
        self.ticks = 0
        self.fail_on_first_event = False

    def handle_docker_event(self, event):
        if self.fail_on_first_event and not self.events:
            self.events.append("failed")
            raise RuntimeError("watcher failure")
        self.events.append(event)

    def reconcile(self):
        self.reconciles += 1
        return 0

    def tick(self):
        self.ticks += 1
        return 0


class FakeAudit:
    last_outcome = "ok"

    def __init__(self):
        self.events = []

    def emit(self, **kwargs):
        self.events.append(kwargs)
        return True

    def flush_spool(self):
        return 0

    def spool_size(self):
        return 0

    def types(self):
        return [event["event_type"] for event in self.events]


class FakePump:
    def __init__(self):
        self.reconnected = threading.Event()
        self.state = "connected"
        self.last_error = None


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log = self.dir / "alerts.json"
        self.log.write_bytes(b"")
        self.sink = RecordingSink()
        self.watcher = FakeWatcher()
        self.audit = FakeAudit()
        self.status = StatusBoard(self.dir / "status.json")
        self.docker_queue = queue.Queue()
        self.pump = FakePump()
        self.service = self.make_service()

    def make_tailer(self):
        return FalcoTailer(self.log, self.dir / "checkpoint.json", start_from="beginning")

    def make_service(self, tailer=None):
        config = dataclasses.replace(
            MonitorConfig(), poll_interval_seconds=0.01,
            retry_base_seconds=0.01, retry_max_seconds=0.02,
        )
        return monitor_service.MonitorService(
            config, tailer or self.make_tailer(), self.watcher, self.audit,
            self.status, self.sink, self.docker_queue, self.pump,
        )

    def write_lines(self, *lines):
        with open(self.log, "ab") as handle:
            for line in lines:
                handle.write(line.encode() + b"\n")

    def counters(self):
        return self.status.snapshot()["counters"]


class TestFalcoProcessing(ServiceTestCase):
    def test_alerts_and_baseline_events_are_routed_separately(self):
        self.write_lines(falco_line(second=1), falco_line(rule="Baseline Process Spawn", second=2))
        self.assertEqual(self.service.run_once(), 2)
        self.assertEqual([a["rule"] for a in self.sink.alerts], ["Terminal shell in container"])
        self.assertEqual(len(self.sink.baseline), 1)

    def test_malformed_events_are_counted_and_do_not_stop_processing(self):
        self.write_lines("not json", json.dumps({"rule": "x"}), falco_line(second=3))
        self.service.run_once()
        self.assertEqual(len(self.sink.alerts), 1)
        self.assertEqual(self.counters()["malformed_events"], 2)

    def test_host_level_events_are_skipped(self):
        self.write_lines(falco_line(container_id="host", second=4))
        self.service.run_once()
        self.assertEqual(self.sink.alerts, [])
        self.assertEqual(self.counters()["host_events_skipped"], 1)

    def test_duplicate_events_are_processed_once(self):
        line = falco_line(second=5)
        self.write_lines(line, line)
        self.service.run_once()
        self.assertEqual(len(self.sink.alerts), 1)
        self.assertEqual(self.counters()["duplicates_skipped"], 1)

    def test_a_failing_event_does_not_block_the_next_one_and_is_counted(self):
        self.sink.fail_on = "Rule One"
        self.write_lines(
            falco_line(rule="Rule One", second=6), falco_line(rule="Rule Two", second=7)
        )
        self.service.run_once()
        self.assertEqual([a["rule"] for a in self.sink.alerts], ["Rule Two"])
        self.assertEqual(self.counters()["processing_errors"], 1)
        self.assertEqual(self.service.run_once(), 0)  # batch was committed, nothing replays

    def test_a_restarted_service_only_sees_new_lines(self):
        self.write_lines(falco_line(second=8), falco_line(second=9))
        self.service.run_once()
        self.write_lines(falco_line(second=10))
        restarted = RecordingSink()
        service = monitor_service.MonitorService(
            service_config(), self.make_tailer(), self.watcher, self.audit,
            self.status, restarted, self.docker_queue, self.pump,
        )
        service.run_once()
        self.assertEqual(len(restarted.alerts), 1)


def service_config():
    return dataclasses.replace(MonitorConfig(), poll_interval_seconds=0.01)


class TestIngestAvailability(ServiceTestCase):
    def test_outage_and_recovery_are_audited_once_each(self):
        self.log.unlink()
        self.assertEqual(self.service.run_once(), 0)
        self.service.run_once()
        self.assertEqual(self.audit.types(), ["FALCO_INGEST_UNAVAILABLE"])
        component = self.status.snapshot()["components"]["falco_ingest"]
        self.assertEqual(component["state"], "unavailable")

        self.write_lines(falco_line(second=11))
        self.assertEqual(self.service.run_once(), 1)
        self.assertEqual(
            self.audit.types(), ["FALCO_INGEST_UNAVAILABLE", "FALCO_INGEST_RECOVERED"]
        )
        self.assertEqual(self.status.snapshot()["components"]["falco_ingest"]["state"], "ok")
        self.assertEqual(len(self.sink.alerts), 1)


class TestDockerHandling(ServiceTestCase):
    def test_docker_events_are_forwarded_to_the_watcher(self):
        self.docker_queue.put({"Action": "start"})
        self.docker_queue.put({"Action": "die"})
        self.service.run_once()
        self.assertEqual(len(self.watcher.events), 2)

    def test_a_watcher_failure_is_counted_and_later_events_still_run(self):
        self.watcher.fail_on_first_event = True
        self.docker_queue.put({"Action": "start"})
        self.docker_queue.put({"Action": "die"})
        self.service.run_once()
        self.assertEqual(self.counters()["docker_event_errors"], 1)
        self.assertEqual(len(self.watcher.events), 2)

    def test_reconnect_triggers_one_reconcile(self):
        self.pump.reconnected.set()
        self.service.run_once()
        self.service.run_once()
        self.assertEqual(self.watcher.reconciles, 1)
        self.assertFalse(self.pump.reconnected.is_set())

    def test_registration_rechecks_run_every_iteration(self):
        self.service.run_once()
        self.service.run_once()
        self.assertEqual(self.watcher.ticks, 2)


class TestLifecycleAndStatus(ServiceTestCase):
    def test_graceful_shutdown_commits_the_checkpoint_and_marks_not_running(self):
        stop = threading.Event()
        self.sink.on_alert = lambda event: stop.set()
        self.write_lines(falco_line(second=12))
        self.service.run_forever(stop)
        self.assertTrue((self.dir / "checkpoint.json").exists())
        self.assertFalse(self.status.snapshot()["running"])
        written = json.loads((self.dir / "status.json").read_text())
        self.assertFalse(written["running"])

    def test_status_file_reports_components_counters_and_last_event(self):
        self.write_lines(falco_line(second=13))
        self.service.run_once()
        written = json.loads((self.dir / "status.json").read_text())
        for key in ("pid", "components", "counters", "last_event_at", "containers"):
            self.assertIn(key, written)
        self.assertEqual(written["counters"]["alerts_seen"] if "alerts_seen" in written["counters"]
                         else written["counters"]["falco_lines_processed"], 1)
        self.assertEqual(written["components"]["docker"]["state"], "connected")


if __name__ == "__main__":
    unittest.main()
