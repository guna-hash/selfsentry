"""Tests for response-engine/auto_isolate.py using a fake Docker client.

No real Docker daemon is touched; isolation records go to a temp directory.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import docker

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
        self.assertTrue(auto_isolate.is_isolated(self.record()))
        self.assertEqual(self.container.status, "running")

        self.client.fail_connect = set()
        auto_isolate.resume_container("web", "alice")
        self.assertEqual(self.record()["state"], "resumed")
        self.assertEqual(
            sorted(name for name, _ in self.container.connect_log), ["appnet", "bridge"]
        )


if __name__ == "__main__":
    unittest.main()
