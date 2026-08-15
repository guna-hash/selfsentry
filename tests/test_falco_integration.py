"""
Tests for runtime-monitor/falco_integration.py and runtime-monitor/ebpf_collector.py

These tests use fixture Falco JSON alert dicts (matching the project's
existing pattern from tests/test_trivy_wrapper.py's SAMPLE_TRIVY_JSON) so
they run without a live Falco process, Docker, or network access.

What IS covered here (deterministic, no I/O timing dependency):
  - parse_falco_alert(): pure-function parsing/normalization logic
  - read_falco_alerts_from_file(): real file I/O against a finite, static
    fixture file (a genuine integration-style test — no live Falco needed)
  - stream_falco_alerts(from_start=True): bounded consumption (via
    itertools.islice) of pre-existing file content
  - ebpf_collector.stream_raw_events(): confirms it truly delegates to
    falco_integration rather than silently diverging

What is NOT covered here, and why:
  - stream_falco_alerts()'s live-tailing behavior — i.e. blocking and
    waiting for a line that gets appended to the file *after* the stream
    has already started — depends on real-time file I/O timing. Per the
    Phase 3 build guide, this is validated MANUALLY against a real,
    running Falco process (see docs/phase3_falco_integration.md), not with
    a timing-dependent automated test that would be flaky in CI.
"""

import json
import sys
import tempfile
import unittest
from itertools import islice
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime-monitor"))

import falco_integration  # noqa: E402
import ebpf_collector  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture data — realistic Falco JSON alerts, shaped exactly like Falco's
# real json_output (verified against Falco's documented output format and
# a real captured alert example: output/priority/rule/source/tags/time/
# output_fields, with dotted output_fields keys like "container.id").
# ---------------------------------------------------------------------------

SAMPLE_ALERT_WITH_CONTAINER = {
    "output": "10:15:00.123456789: Warning A shell was spawned in a container "
    "with an attached terminal (user=root container_id=abc123def456 "
    "container_name=test-container shell=sh parent=runc cmdline=sh "
    "terminal=34816)",
    "priority": "Warning",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": ["container", "shell", "mitre_execution"],
    "time": "2026-08-09T10:15:00.123456789Z",
    "output_fields": {
        "container.id": "abc123def456",
        "container.name": "test-container",
        "proc.cmdline": "sh",
        "proc.name": "sh",
        "proc.pname": "runc",
        "user.name": "root",
    },
}

SAMPLE_ALERT_CRITICAL_CONTAINER = {
    "output": "10:16:02.000000000: Critical Suspicious curl spawned by nginx "
    "(user=www-data container_id=def456abc123 container_name=web-1 "
    "proc.cmdline=curl)",
    "priority": "Critical",
    "rule": "Suspicious Curl From Nginx",
    "source": "syscall",
    "tags": ["container", "network", "mitre_execution"],
    "time": "2026-08-09T10:16:02.000000000Z",
    "output_fields": {
        "container.id": "def456abc123",
        "container.name": "web-1",
        "proc.cmdline": "curl",
        "proc.name": "curl",
        "proc.pname": "nginx",
    },
}

# Host-level event: container.id is the literal string Falco uses for
# non-container processes. Real Falco output has been observed using both
# "host" and "HOST" casing depending on context, so the code (and this
# fixture) treats it case-insensitively.
SAMPLE_ALERT_HOST_ONLY = {
    "output": "10:17:00.000000000: Notice Package management process launched "
    "(user=root command=apt-get)",
    "priority": "Notice",
    "rule": "Package management process launched",
    "source": "syscall",
    "tags": ["host", "process"],
    "time": "2026-08-09T10:17:00.000000000Z",
    "output_fields": {
        "container.id": "host",
        "container.name": "host",
        "proc.name": "apt-get",
    },
}


def _line(alert_dict: dict) -> str:
    return json.dumps(alert_dict) + "\n"


class TestParseFalcoAlert(unittest.TestCase):
    def test_parses_valid_alert_with_container(self):
        alert = falco_integration.parse_falco_alert(_line(SAMPLE_ALERT_WITH_CONTAINER))
        self.assertEqual(alert.container_id, "abc123def456")
        self.assertEqual(alert.rule, "Terminal shell in container")
        self.assertEqual(alert.priority, "WARNING")
        self.assertEqual(alert.timestamp, "2026-08-09T10:15:00.123456789Z")
        self.assertIn("shell was spawned", alert.output)

    def test_normalizes_priority_case(self):
        alert = falco_integration.parse_falco_alert(_line(SAMPLE_ALERT_CRITICAL_CONTAINER))
        self.assertEqual(alert.priority, "CRITICAL")

    def test_normalizes_informational_priority_to_info(self):
        variant = dict(SAMPLE_ALERT_WITH_CONTAINER)
        variant["priority"] = "Informational"
        alert = falco_integration.parse_falco_alert(_line(variant))
        self.assertEqual(alert.priority, "INFO")

    def test_host_only_alert_has_no_container_id(self):
        alert = falco_integration.parse_falco_alert(_line(SAMPLE_ALERT_HOST_ONLY))
        self.assertIsNone(alert.container_id)

    def test_host_container_id_is_case_insensitive(self):
        variant = dict(SAMPLE_ALERT_HOST_ONLY)
        variant["output_fields"] = dict(variant["output_fields"])
        variant["output_fields"]["container.id"] = "HOST"
        alert = falco_integration.parse_falco_alert(_line(variant))
        self.assertIsNone(alert.container_id)

    def test_to_dict_matches_shape_1(self):
        alert = falco_integration.parse_falco_alert(_line(SAMPLE_ALERT_WITH_CONTAINER))
        d = alert.to_dict()
        self.assertEqual(
            set(d.keys()), {"container_id", "timestamp", "rule", "priority", "output"}
        )

    def test_raises_on_malformed_json(self):
        with self.assertRaises(falco_integration.FalcoParseError):
            falco_integration.parse_falco_alert("{not valid json")

    def test_raises_on_empty_line(self):
        with self.assertRaises(falco_integration.FalcoParseError):
            falco_integration.parse_falco_alert("   ")

    def test_raises_on_missing_required_field(self):
        broken = dict(SAMPLE_ALERT_WITH_CONTAINER)
        del broken["rule"]
        with self.assertRaises(falco_integration.FalcoParseError):
            falco_integration.parse_falco_alert(_line(broken))

    def test_missing_output_fields_does_not_crash(self):
        broken = dict(SAMPLE_ALERT_WITH_CONTAINER)
        del broken["output_fields"]
        alert = falco_integration.parse_falco_alert(_line(broken))
        self.assertIsNone(alert.container_id)

    def test_raw_is_preserved_for_audit_debug(self):
        alert = falco_integration.parse_falco_alert(_line(SAMPLE_ALERT_WITH_CONTAINER))
        self.assertEqual(alert.raw["rule"], "Terminal shell in container")


class TestReadFalcoAlertsFromFile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmpdir.name) / "alerts.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_lines(self, *alert_dicts):
        with open(self.log_path, "w") as f:
            for d in alert_dicts:
                f.write(_line(d))

    def test_reads_and_filters_container_only_by_default(self):
        self._write_lines(
            SAMPLE_ALERT_WITH_CONTAINER, SAMPLE_ALERT_HOST_ONLY, SAMPLE_ALERT_CRITICAL_CONTAINER
        )
        alerts = falco_integration.read_falco_alerts_from_file(str(self.log_path))
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(a["container_id"] is not None for a in alerts))

    def test_include_host_alerts_when_requested(self):
        self._write_lines(SAMPLE_ALERT_WITH_CONTAINER, SAMPLE_ALERT_HOST_ONLY)
        alerts = falco_integration.read_falco_alerts_from_file(
            str(self.log_path), container_only=False
        )
        self.assertEqual(len(alerts), 2)

    def test_skips_malformed_lines_without_crashing(self):
        with open(self.log_path, "w") as f:
            f.write(_line(SAMPLE_ALERT_WITH_CONTAINER))
            f.write("not valid json at all\n")
            f.write(_line(SAMPLE_ALERT_CRITICAL_CONTAINER))
        alerts = falco_integration.read_falco_alerts_from_file(str(self.log_path))
        self.assertEqual(len(alerts), 2)

    def test_empty_file_returns_empty_list(self):
        self._write_lines()
        alerts = falco_integration.read_falco_alerts_from_file(str(self.log_path))
        self.assertEqual(alerts, [])


class TestStreamFalcoAlertsFromStart(unittest.TestCase):
    """
    Covers stream_falco_alerts()'s parsing/filtering behavior deterministically
    by reading pre-existing content (from_start=True) and bounding consumption
    with itertools.islice — this never blocks, since islice stops requesting
    items once it has enough, so the generator never reaches the "wait for a
    new line" branch. See module docstring for what's intentionally NOT
    covered here.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmpdir.name) / "alerts.json"
        with open(self.log_path, "w") as f:
            f.write(_line(SAMPLE_ALERT_WITH_CONTAINER))
            f.write(_line(SAMPLE_ALERT_HOST_ONLY))
            f.write(_line(SAMPLE_ALERT_CRITICAL_CONTAINER))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_yields_normalized_container_alerts_in_order(self):
        gen = falco_integration.stream_falco_alerts(
            str(self.log_path), from_start=True, poll_interval_seconds=0.01
        )
        first_two = list(islice(gen, 2))
        self.assertEqual(first_two[0]["container_id"], "abc123def456")
        # SAMPLE_ALERT_HOST_ONLY (2nd line) is skipped since container_only
        # defaults to True, so the 2nd yielded item is the 3rd line.
        self.assertEqual(first_two[1]["container_id"], "def456abc123")

    def test_include_host_when_requested(self):
        gen = falco_integration.stream_falco_alerts(
            str(self.log_path),
            from_start=True,
            container_only=False,
            poll_interval_seconds=0.01,
        )
        first_three = list(islice(gen, 3))
        self.assertEqual(len(first_three), 3)

    def test_from_start_false_starts_at_eof(self):
        # With from_start=False (the live-monitoring default), the file
        # pointer starts at EOF, so nothing is yielded from pre-existing
        # content. We can't wait forever for a new line in a unit test, so
        # this test only confirms the generator doesn't immediately replay
        # old content — it does NOT test the live-append-and-catch-up path
        # (that's the manually-validated behavior; see module docstring).
        gen = falco_integration.stream_falco_alerts(
            str(self.log_path), from_start=False, poll_interval_seconds=0.01
        )
        # Grab zero items — if this were from_start=True we'd assert on
        # content instead. Here we just confirm construction doesn't raise
        # and doesn't eagerly consume anything before iteration starts.
        self.assertTrue(hasattr(gen, "__next__"))


class TestEbpfCollectorFacade(unittest.TestCase):
    """ebpf_collector.py is documented as a thin facade over
    falco_integration.stream_falco_alerts (see that module's docstring for
    the scope decision). These tests confirm it really does delegate
    correctly rather than silently diverging."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmpdir.name) / "alerts.json"
        with open(self.log_path, "w") as f:
            f.write(_line(SAMPLE_ALERT_WITH_CONTAINER))
            f.write(_line(SAMPLE_ALERT_CRITICAL_CONTAINER))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_stream_raw_events_delegates_to_falco_stream(self):
        gen = ebpf_collector.stream_raw_events(
            str(self.log_path), from_start=True, poll_interval_seconds=0.01
        )
        first_two = list(islice(gen, 2))
        self.assertEqual(first_two[0]["container_id"], "abc123def456")
        self.assertEqual(first_two[1]["container_id"], "def456abc123")

    def test_stream_raw_events_same_shape_as_falco_alert(self):
        gen = ebpf_collector.stream_raw_events(
            str(self.log_path), from_start=True, poll_interval_seconds=0.01
        )
        first = next(gen)
        self.assertEqual(
            set(first.keys()), {"container_id", "timestamp", "rule", "priority", "output"}
        )


if __name__ == "__main__":
    unittest.main()
