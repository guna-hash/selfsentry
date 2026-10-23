"""Tests for response-engine/auto_isolate.py using a fake Docker client.

No real Docker daemon is touched; isolation records go to a temp directory.
"""

import os
import json
import sys
import tempfile
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import docker
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "response-engine"))

import auto_isolate  # noqa: E402

FULL_ID = "f" * 64
BRIDGE_ALIASES = ["web", "ffffffffffff"]


class FakeContainer:
    def __init__(self):
        self.id = FULL_ID
        self.name = "web"
        self.status = "running"
        self.connect_log = []
        self.attrs = {
            "NetworkSettings": {
                "Networks": {
                    "bridge": {"Aliases": list(BRIDGE_ALIASES)},
                    "appnet": {"Aliases": None},
                }
            }
        }

    def reload(self):
        pass

    def pause(self):
        self.status = "paused"

    def unpause(self):
        self.status = "running"

    @property
    def networks(self):
        return self.attrs["NetworkSettings"]["Networks"]


class FakeNetwork:
    def __init__(self, name, client):
        self.name = name
        self.client = client

    def disconnect(self, container, force=False):
        container.networks.pop(self.name, None)

    def connect(self, container, aliases=None):
        if self.name in self.client.fail_connect:
            raise docker.errors.APIError("boom")
        container.networks[self.name] = {"Aliases": aliases or []}
        container.connect_log.append((self.name, aliases))


class FakeClient:
    def __init__(self, container):
        self.container = container
        self.fail_connect = set()
        self.containers = SimpleNamespace(get=self._get_container)
        self.networks = SimpleNamespace(get=lambda name: FakeNetwork(name, self))

    def _get_container(self, identifier):
        known = (self.container.id, self.container.name, self.container.id[:12])
        if identifier not in known:
            raise docker.errors.NotFound(f"No such container: {identifier}")
        return self.container


class AutoIsolateTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {"SELFSENTRY_STATE_DIR": tmp.name})
        env.start()
        self.addCleanup(env.stop)

        self.container = FakeContainer()
        self.client = FakeClient(self.container)
        from_env = patch.object(auto_isolate.docker, "from_env", return_value=self.client)
        from_env.start()
        self.addCleanup(from_env.stop)

    def record(self):
        return auto_isolate.get_isolation_record(FULL_ID)


class TestIsolate(AutoIsolateTestCase):
    def test_corrupt_record_is_not_replaced_and_no_docker_action_runs(self):
        auto_isolate.isolate_container("web", "first")
        path = auto_isolate._record_path(FULL_ID)
        path.write_text('{"networks":')
        before = path.read_bytes()
        with patch.object(self.container, "pause") as pause, patch.object(
            self.client.networks, "get"
        ) as network:
            with self.assertRaises(auto_isolate.IsolationError):
                auto_isolate.isolate_container("web", "retry")
        pause.assert_not_called()
        network.assert_not_called()
        self.assertEqual(path.read_bytes(), before)

    def test_another_containers_record_is_not_used_for_recovery(self):
        auto_isolate.isolate_container("web", "first")
        path = auto_isolate._record_path(FULL_ID)
        record = json.loads(path.read_text())
        record["container_id"] = "a" * 64
        path.write_text(json.dumps(record))
        before = path.read_bytes()
        with patch.object(self.container, "unpause") as unpause:
            with self.assertRaises(auto_isolate.ResumeError):
                auto_isolate.resume_container("web", "alice")
        unpause.assert_not_called()
        self.assertEqual(path.read_bytes(), before)

    def test_isolate_saves_networks_cuts_them_and_pauses(self):
        auto_isolate.isolate_container("web", "test reason")
        self.assertEqual(self.container.status, "paused")
        self.assertEqual(self.container.networks, {})
        record = self.record()
        self.assertEqual(record["state"], "isolated")
        self.assertEqual(record["reason"], "test reason")
        self.assertEqual(sorted(record["networks"]), ["appnet", "bridge"])
        self.assertEqual(record["networks"]["bridge"]["aliases"], BRIDGE_ALIASES)

    def test_isolating_twice_keeps_the_original_record(self):
        auto_isolate.isolate_container("web", "first")
        auto_isolate.isolate_container("web", "second")
        record = self.record()
        self.assertEqual(record["reason"], "first")
        self.assertEqual(sorted(record["networks"]), ["appnet", "bridge"])

    def test_isolating_again_repauses_a_manually_unpaused_container(self):
        auto_isolate.isolate_container("web", "first")
        self.container.status = "running"
        auto_isolate.isolate_container("web", "second")
        self.assertEqual(self.container.status, "paused")
        self.assertEqual(sorted(self.record()["networks"]), ["appnet", "bridge"])

    def test_unknown_container_raises_not_found(self):
        with self.assertRaises(auto_isolate.ContainerNotFound):
            auto_isolate.isolate_container("nope", "x")

    def test_not_found_is_an_isolation_error_for_existing_callers(self):
        with self.assertRaises(auto_isolate.IsolationError):
            auto_isolate.isolate_container("nope", "x")


class TestResume(AutoIsolateTestCase):
    def test_resume_unpauses_and_restores_networks_with_aliases(self):
        auto_isolate.isolate_container("web", "test")
        outcome = auto_isolate.resume_container("web", "alice")
        self.assertEqual(self.container.status, "running")
        self.assertEqual(sorted(self.container.networks), ["appnet", "bridge"])
        self.assertEqual(self.container.networks["bridge"]["Aliases"], BRIDGE_ALIASES)
        self.assertEqual(sorted(outcome["networks"]), ["appnet", "bridge"])
        record = self.record()
        self.assertEqual(record["state"], "resumed")
        self.assertEqual(record["resumed_by"], "alice")
        self.assertFalse(auto_isolate.is_isolated(record))

    def test_resume_without_a_record_is_refused(self):
        with self.assertRaises(auto_isolate.ResumeError):
            auto_isolate.resume_container("web", "alice")
        self.assertEqual(self.container.status, "running")

    def test_resume_requires_a_name(self):
        auto_isolate.isolate_container("web", "test")
        with self.assertRaises(ValueError):
            auto_isolate.resume_container("web", "  ")
        self.assertEqual(self.container.status, "paused")

    def test_unknown_container_raises_not_found(self):
        with self.assertRaises(auto_isolate.ContainerNotFound):
            auto_isolate.resume_container("nope", "alice")

    def test_resume_skips_networks_that_are_already_attached(self):
        auto_isolate.isolate_container("web", "test")
        self.container.networks["bridge"] = {"Aliases": []}
        auto_isolate.resume_container("web", "alice")
        self.assertEqual([name for name, _ in self.container.connect_log], ["appnet"])

    def test_partial_failure_keeps_record_active_and_retry_finishes(self):
        auto_isolate.isolate_container("web", "test")
        self.client.fail_connect = {"appnet"}
        with self.assertRaises(auto_isolate.ResumeError):
            auto_isolate.resume_container("web", "alice")
        self.assertEqual(self.record()["state"], "resume_failed")
        self.assertEqual(self.container.status, "paused")

        self.client.fail_connect = set()
        auto_isolate.resume_container("web", "alice")
        self.assertEqual(self.record()["state"], "resumed")
        self.assertEqual(
            sorted(name for name, _ in self.container.connect_log), ["appnet", "bridge"]
        )


class TestTransportFailures(AutoIsolateTestCase):
    def test_disconnect_timeout_still_attempts_pause_and_records_failure(self):
        with patch.object(FakeNetwork, "disconnect", side_effect=requests.ReadTimeout("offline")):
            with self.assertRaises(auto_isolate.IsolationError):
                auto_isolate.isolate_container(FULL_ID, "test")
        self.assertEqual(self.container.status, "paused")
        record = self.record()
        self.assertEqual(record["state"], "isolation_failed")
        self.assertEqual(set(record["networks"]), {"bridge", "appnet"})
        self.assertIn("bridge", record["error"])
        self.assertFalse(auto_isolate.is_isolated(record))

    def test_pause_transport_failure_never_claims_isolated(self):
        with patch.object(self.container, "pause", side_effect=requests.ConnectionError("offline")):
            with self.assertRaises(auto_isolate.IsolationError):
                auto_isolate.isolate_container(FULL_ID, "test")
        self.assertEqual(self.record()["state"], "isolation_failed")
        self.assertIn("pause", self.record()["error"])
        self.assertEqual(self.container.status, "running")

    def test_reconnect_timeout_repauses_and_preserves_original_attachments(self):
        auto_isolate.isolate_container(FULL_ID, "test")
        original = self.record()["networks"]
        with patch.object(FakeNetwork, "connect", side_effect=requests.ReadTimeout("offline")):
            with self.assertRaises(auto_isolate.ResumeError):
                auto_isolate.resume_container(FULL_ID, "alice")
        self.assertEqual(self.container.status, "paused")
        self.assertEqual(self.record()["state"], "resume_failed")
        self.assertEqual(self.record()["networks"], original)
        self.assertEqual(self.record()["resumed_by"], "alice")
        auto_isolate.resume_container(FULL_ID, "alice")
        self.assertEqual(self.record()["state"], "resumed")

    def test_unpause_timeout_after_daemon_acceptance_rechecks_and_repauses(self):
        auto_isolate.isolate_container(FULL_ID, "test")

        def accepted_but_response_lost():
            self.container.status = "running"
            raise requests.ReadTimeout("response lost")

        with patch.object(self.container, "unpause", side_effect=accepted_but_response_lost):
            with self.assertRaises(auto_isolate.ResumeError):
                auto_isolate.resume_container(FULL_ID, "alice")
        self.assertEqual(self.container.status, "paused")
        self.assertEqual(self.record()["state"], "resume_failed")
        self.assertIn("docker", self.record()["error"])
        self.assertEqual(self.container.connect_log, [])

    def test_unknown_post_unpause_state_still_attempts_pause(self):
        auto_isolate.isolate_container(FULL_ID, "test")
        calls = []
        original_pause = self.container.pause
        original_unpause = self.container.unpause

        def reload():
            calls.append("reload")
            if len(calls) > 1:
                raise requests.ConnectionError("cannot inspect")

        with patch.object(self.container, "reload", side_effect=reload), patch.object(
            self.container, "unpause", side_effect=original_unpause
        ), patch.object(self.container, "pause", side_effect=original_pause) as pause:
            with self.assertRaises(auto_isolate.ResumeError):
                auto_isolate.resume_container(FULL_ID, "alice")
        pause.assert_called_once_with()
        self.assertEqual(self.record()["state"], "resume_failed")
        self.assertIn("repause_inspect", self.record()["error"])
        self.assertIn("repause_verification", self.record()["error"])

    def test_failed_repause_is_visible_without_false_recovery(self):
        auto_isolate.isolate_container(FULL_ID, "test")
        with patch.object(FakeNetwork, "connect", side_effect=requests.ReadTimeout("offline")), (
            patch.object(self.container, "pause", side_effect=requests.ConnectionError("offline"))
        ):
            with self.assertRaises(auto_isolate.ResumeError):
                auto_isolate.resume_container(FULL_ID, "alice")
        self.assertEqual(self.container.status, "running")
        record = self.record()
        self.assertEqual(record["state"], "resume_failed")
        self.assertIn("repause", record["error"])
        self.assertIn("repause_verification", record["error"])
        self.assertIsNone(record["resumed_at"])


class TestConcurrentResponse(AutoIsolateTestCase):
    def test_name_and_full_id_share_lock_and_preserve_recovery_after_success_or_failure(self):
        for first_fails in (False, True):
            with self.subTest(first_fails=first_fails):
                # Reset only the disposable fake/record between the two independent schedules.
                self.container = FakeContainer()
                self.client.container = self.container
                auto_isolate._record_path(FULL_ID).unlink(missing_ok=True)
                pause_entered = threading.Event()
                release_pause = threading.Event()
                second_lock_attempted = threading.Event()
                real_flock = auto_isolate.fcntl.flock
                original_pause = self.container.pause
                original_unpause = self.container.unpause
                lock_inodes = []
                unpaused = threading.Event()

                def flock(handle, operation):
                    lock_inodes.append(os.fstat(handle.fileno()).st_ino)
                    if pause_entered.is_set():
                        second_lock_attempted.set()
                    return real_flock(handle, operation)

                def pause():
                    pause_entered.set()
                    if not release_pause.wait(5):
                        raise RuntimeError("test did not release first action")
                    if first_fails:
                        raise docker.errors.APIError("pause rejected")
                    original_pause()

                def unpause():
                    unpaused.set()
                    original_unpause()

                with patch.object(auto_isolate.fcntl, "flock", side_effect=flock), patch.object(
                    self.container, "pause", side_effect=pause
                ), patch.object(self.container, "unpause", side_effect=unpause):
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        first = executor.submit(auto_isolate.isolate_container, "web", "first")
                        try:
                            self.assertTrue(pause_entered.wait(5))
                            second = executor.submit(
                                auto_isolate.resume_container, FULL_ID, "alice"
                            )
                            self.assertTrue(second_lock_attempted.wait(5))
                            self.assertFalse(unpaused.is_set())
                            self.assertFalse(second.done())
                            self.assertEqual(self.record()["state"], "isolating")
                        finally:
                            release_pause.set()
                        if first_fails:
                            with self.assertRaises(auto_isolate.IsolationError):
                                first.result(timeout=5)
                        else:
                            first.result(timeout=5)
                        outcome = second.result(timeout=5)
                self.assertEqual(len(lock_inodes), 2)
                self.assertEqual(len(set(lock_inodes)), 1)
                self.assertEqual(outcome["container_id"], FULL_ID)
                self.assertEqual(self.record()["state"], "resumed")
                self.assertEqual(set(self.record()["networks"]), {"bridge", "appnet"})
                self.assertEqual(self.container.status, "running")


class TestRecoveryRecords(AutoIsolateTestCase):
    def test_missing_record_is_distinct_from_unreadable_or_invalid_state(self):
        self.assertIsNone(self.record())
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            with self.assertRaises(auto_isolate.IsolationRecordError):
                self.record()

    def test_invalid_record_shapes_refuse_actions_and_preserve_evidence(self):
        path = auto_isolate._record_path(FULL_ID)
        path.parent.mkdir(parents=True, exist_ok=True)
        base = {"container_id": FULL_ID, "state": "isolated", "networks": {}}
        invalid = [
            None, [], {},
            dict(base, state="unknown"),
            dict(base, networks=[]),
            dict(base, networks={"bridge": None}),
            dict(base, networks={"bridge": {"aliases": "not-a-list"}}),
            dict(base, networks={"bridge": {"aliases": [42]}}),
            dict(base, networks={"bridge": {"id": 42}}),
            dict(base, networks={"": {}}),
        ]
        for record in invalid:
            with self.subTest(record=record):
                path.write_text(json.dumps(record))
                original = path.read_bytes()
                with patch.object(self.container, "pause") as pause, patch.object(
                    self.container, "unpause"
                ) as unpause, patch.object(self.client.networks, "get") as network:
                    with self.assertRaises(auto_isolate.IsolationError):
                        auto_isolate.isolate_container("web", "retry")
                    with self.assertRaises(auto_isolate.ResumeError):
                        auto_isolate.resume_container("web", "alice")
                pause.assert_not_called()
                unpause.assert_not_called()
                network.assert_not_called()
                self.assertEqual(path.read_bytes(), original)

    def test_failed_sync_preserves_existing_record_before_docker_is_touched(self):
        auto_isolate.isolate_container("web", "first")
        path = auto_isolate._record_path(FULL_ID)
        original = path.read_bytes()
        self.container.status = "running"
        with patch.object(auto_isolate.os, "fsync", side_effect=OSError("disk failure")):
            with patch.object(self.container, "pause") as pause:
                with self.assertRaises(auto_isolate.IsolationRecordError):
                    auto_isolate.isolate_container("web", "retry")
        pause.assert_not_called()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(list(path.parent.glob(f".{FULL_ID}.*")), [])

    def test_record_is_private_and_synced_before_network_disconnect(self):
        calls = []
        original = FakeNetwork.disconnect

        def disconnect(network, container, force=False):
            calls.append("disconnect")
            return original(network, container, force)

        with patch.object(auto_isolate.os, "fsync", side_effect=lambda _: calls.append("sync")):
            with patch.object(FakeNetwork, "disconnect", disconnect):
                auto_isolate.isolate_container("web", "test")
        self.assertEqual(calls[:2], ["sync", "sync"])
        self.assertIn("disconnect", calls[2:])
        self.assertEqual(auto_isolate._record_path(FULL_ID).stat().st_mode & 0o077, 0)

    def test_directory_sync_failure_stops_before_actions_and_retains_network_context(self):
        with patch.object(auto_isolate.os, "fsync", side_effect=[None, OSError("directory IO")]):
            with patch.object(self.container, "pause") as pause, patch.object(
                self.client.networks, "get"
            ) as network:
                with self.assertRaises(auto_isolate.IsolationRecordError):
                    auto_isolate.isolate_container("web", "test")
        pause.assert_not_called()
        network.assert_not_called()
        self.assertEqual(self.container.status, "running")
        self.assertEqual(set(self.record()["networks"]), {"appnet", "bridge"})
        self.assertEqual(self.record()["state"], "isolating")

    def test_short_or_traversal_ids_cannot_select_a_state_file(self):
        for identifier in (FULL_ID[:12], "../../outside", "g" * 64):
            with self.subTest(identifier=identifier):
                with self.assertRaises(auto_isolate.IsolationRecordError):
                    auto_isolate.get_isolation_record(identifier)


if __name__ == "__main__":
    unittest.main()
