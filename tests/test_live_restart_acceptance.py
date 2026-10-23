"""Offline recovery/failure tests. Docker, PostgreSQL and lifecycle actions are mocked."""

import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "ops"), str(ROOT / "monitor-service")]
import verify_postgres_recovery as check  # noqa: E402
import selfsentry_cli as lifecycle  # noqa: E402


class RestartEvidence(unittest.TestCase):
    def test_pending_payload_and_timeline_survive_real_sqlite_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "pipeline.sqlite"
            body = {"container_id": "a" * 12, "monitor_evidence": {
                "observed_timeline": [{"timestamp": "2026-10-20T00:00:00Z"}]}}
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE outbox(key,body,stage,incident_id,attempts)")
                db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)",
                           ("key", json.dumps(body), "pending", None, 2))
            item = check.queued(database, "a" * 12)[0]
            retained = check.assert_retained(item, check.queued(database, "a" * 12))
            self.assertEqual(retained["body"], body)
            with sqlite3.connect(database) as db:
                db.execute("UPDATE outbox SET body=?", (json.dumps({**body, "changed": True}),))
            with self.assertRaises(RuntimeError):
                check.assert_retained(item, check.queued(database, "a" * 12))

    def test_missing_or_advanced_pending_row_is_not_a_restart_pass(self):
        item = {"key": "one", "stage": "pending", "body": {"container_id": "a"}}
        for rows in ([], [{**item, "stage": "done"}], [{**item, "key": "other"}]):
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                check.assert_retained(item, rows)

    def test_changed_empty_or_duplicate_timeline_fails_acceptance(self):
        item = {"body": {"monitor_evidence": {"observed_timeline": [{"event": "original"}]}}}
        before = {"pid": 1}
        after = {"pid": 2, "healthy": True, "running": True}
        good = {"monitor_evidence": copy.deepcopy(item["body"]["monitor_evidence"])}
        self.assertTrue(all(check.restart_checks(before, after, item, [good]).values()))
        for matches in ([], [good, good], [{"monitor_evidence": {}}]):
            self.assertFalse(check.restart_checks(before, after, item, matches)[
                "original_nonempty_timeline_preserved"])
        self.assertFalse(check.restart_checks(before, {**after, "pid": 1}, item, [good])[
            "monitor_restarted_healthy"])
        self.assertFalse(check.restart_checks(before, after, {"body": {}}, [good])[
            "original_nonempty_timeline_preserved"])

    def test_preexisting_queue_or_unmanaged_processes_refuse_fault(self):
        records = {name: {"pid": index + 1} for index, name in enumerate(
            ("backend", "monitor", "frontend"))}
        with patch.object(lifecycle, "load_records", return_value=records), \
                patch.object(lifecycle, "alive", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "Existing pending"):
                check.restart_setup(ROOT, {"pid": 2, "incident_outbox_size": 1})
            with self.assertRaisesRegex(RuntimeError, "PID"):
                check.restart_setup(ROOT, {"pid": 999, "incident_outbox_size": 0})
        with patch.object(lifecycle, "load_records", return_value={}):
            with self.assertRaisesRegex(RuntimeError, "managed"):
                check.restart_setup(ROOT, {})

    def test_actual_runtime_flags_required_and_restart_retains_custom_state(self):
        records = {name: {"pid": index + 1} for index, name in enumerate(
            ("backend", "monitor", "frontend"))}
        env = {**check.STUDY_FLAGS, "MONITOR_STATE_DIR": "/tmp/custom-restart-state"}
        before = {"pid": 2, "incident_outbox_size": 0}
        with patch.object(lifecycle, "load_records", return_value=records), \
                patch.object(lifecycle, "alive", return_value=True), \
                patch.object(check, "dotenv_values", return_value={"MONITOR_STATE_DIR": "old"}):
            with patch.object(Path, "read_text", return_value="\0".join(
                f"{key}={value}" for key, value in env.items()
            )):
                config, launch_env = check.restart_setup(ROOT, before)
                self.assertEqual(config.state_dir, Path(env["MONITOR_STATE_DIR"]))
                self.assertEqual(launch_env["MONITOR_STATE_DIR"], env["MONITOR_STATE_DIR"])
            for key in check.STUDY_FLAGS:
                bad = {name: value for name, value in env.items() if name != key}
                with patch.object(Path, "read_text", return_value="\0".join(
                    f"{name}={value}" for name, value in bad.items()
                )), self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "frozen"):
                    check.restart_setup(ROOT, before)


class FaultRecovery(unittest.TestCase):
    def exercise(self, failure=None, clock_pass=True, restart=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "monitor-service").mkdir()
        (root / "monitor-service/monitor_service.py").touch()
        (root / "state/monitor").mkdir(parents=True)
        (root / "state/monitor/pipeline.sqlite").touch()
        (root / "falco-rules").mkdir()
        (root / "falco-rules/auto-generated-rules.yaml").write_text("unchanged\n")
        before = {"pid": 101, "healthy": True, "running": True,
                  "configuration": {"auto_isolation_enabled": False},
                  "components": {"database": {"state": "ok"}}}
        item = {"key": "one", "stage": "pending", "attempts": 1, "body": {
            "container_id": "a" * 12, "monitor_evidence": {
                "falco_alerts": [{"rule": "Terminal shell in container"}],
                "observed_timeline": [{"timestamp": "2026-10-20T00:00:00Z"}]}}}
        incident = {"id": 42, "event_key": "one",
                    "monitor_evidence": copy.deepcopy(item["body"]["monitor_evidence"]),
                    "monitor_workflow": {"response": {"status": "not_attempted"}}}
        state = {"database": True, "stack": True, "restarted": False}
        actions = []

        def command(*args):
            if args[:3] == ("sudo", "-n", "systemctl"):
                actions.append("db-" + args[3])
                if failure == "database-start" and actions.count("db-start") == 1:
                    raise RuntimeError("first database restore failed")
                state["database"] = args[3] == "start"
            if args[:2] == ("systemctl", "show"):
                return "301"
            if args[:2] == ("docker", "run"):
                return "a" * 64
            if args[:2] == ("docker", "rm"):
                actions.append("fixture-remove")
            return ""

        def stack_action(root, folder, action, env):
            actions.append("stack-" + action)
            if action == "stop":
                self.assertFalse(state["database"])
                state["stack"] = False
                if failure == "stop":
                    raise RuntimeError("stop failed")
            elif action == "start":
                self.assertTrue(state["database"])
                if failure == "start" and actions.count("stack-start") == 1:
                    raise RuntimeError("first start failed")
                state.update(stack=True, restarted=True)
            elif not state["stack"]:
                raise RuntimeError("stack unavailable")

        def queued(database, cid):
            if failure == "interrupt":
                raise KeyboardInterrupt()
            row = copy.deepcopy(item)
            if state["restarted"] or (not restart and state["database"]):
                row["stage"] = "done"
            if failure == "retention" and not state["stack"]:
                row["body"]["monitor_evidence"]["observed_timeline"] = []
            return [row]

        def get(path):
            if path == "/incidents/":
                return [incident] if state["database"] and state["stack"] else []
            return {**before, "pid": 202 if state["restarted"] else 101}

        config = SimpleNamespace(state_dir=root / "state/monitor", falco_log_path="mock-log")
        clock = SimpleNamespace(run_preflight=Mock(return_value={"passed": clock_pass}))
        with patch.object(Path, "cwd", return_value=root), \
                patch.object(check, "dotenv_values", return_value={
                    "MONITOR_STATE_DIR": str(root / "state/monitor")}), \
                patch.object(check, "command", side_effect=command), \
                patch.object(check, "active", side_effect=lambda: state["database"]), \
                patch.object(check, "get", side_effect=get), \
                patch.object(check, "restart_setup", return_value=(config, check.STUDY_FLAGS)), \
                patch.object(check, "stack_action", side_effect=stack_action), \
                patch.object(check.subprocess, "run"), \
                patch.object(check, "queued", side_effect=queued), \
                patch.object(check.time, "sleep"), \
                patch.dict(sys.modules, {"clock_guard": clock}):
            if failure or not clock_pass:
                with self.assertRaises(SystemExit):
                    check.main(["--restart-stack"] if restart else [])
            else:
                check.main(["--restart-stack"] if restart else [])
        reports = list(root.glob("state/evaluation/acceptance/*/evidence.json"))
        self.assertEqual(len(reports), 1)
        report = json.loads(reports[0].read_text())
        self.assertTrue(state["database"])
        self.assertTrue(state["stack"])
        self.assertTrue(report["container_removed"])
        return actions, report

    def test_pending_restart_delivers_once_with_timeline_and_frozen_rules(self):
        actions, report = self.exercise()
        self.assertEqual(actions[:4], ["db-stop", "stack-stop", "db-start", "stack-start"])
        self.assertTrue(report["passed"])
        self.assertTrue(all(report["checks"].values()))
        self.assertNotIn("monitor_kept_running", report["checks"])

    def test_original_database_only_mode_does_not_restart_applications(self):
        actions, report = self.exercise(restart=False)
        self.assertEqual(actions, ["db-stop", "db-start", "fixture-remove"])
        self.assertTrue(report["passed"])
        self.assertTrue(report["checks"]["monitor_kept_running"])
        self.assertNotIn("monitor_restarted_healthy", report["checks"])

    def test_partial_stop_restores_database_before_application_start(self):
        actions, report = self.exercise("stop")
        self.assertLess(actions.index("db-start"), actions.index("stack-start"))
        self.assertFalse(report["passed"])

    def test_failed_start_is_retried_during_cleanup_but_never_counts_as_pass(self):
        actions, report = self.exercise("start")
        self.assertEqual(actions.count("stack-start"), 2)
        self.assertFalse(report["passed"])

    def test_corrupted_retained_payload_recovers_services_and_fails(self):
        actions, report = self.exercise("retention")
        self.assertIn("stack-start", actions)
        self.assertFalse(report["passed"])

    def test_interrupt_restores_database_and_preserves_failed_report(self):
        actions, report = self.exercise("interrupt")
        self.assertEqual(actions[:2], ["db-stop", "db-start"])
        self.assertIn("KeyboardInterrupt", report["failure"])

    def test_invalid_clock_never_introduces_an_outage(self):
        actions, report = self.exercise(clock_pass=False)
        self.assertNotIn("db-stop", actions)
        self.assertNotIn("stack-stop", actions)
        self.assertFalse(report["passed"])

    def test_failed_database_start_is_retried_before_restoring_applications(self):
        actions, report = self.exercise("database-start")
        self.assertEqual(actions.count("db-start"), 2)
        self.assertLess(actions.index("db-start"), actions.index("stack-start"))
        self.assertFalse(report["passed"])


if __name__ == "__main__":
    unittest.main()
