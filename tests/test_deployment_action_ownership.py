"""Real file locks and SQLite intents; no Docker command or backend service."""

from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "deployment-gate"), str(ROOT / "monitor-service")]
import deployment_outbox as outbox  # noqa: E402


@pytest.fixture(autouse=True)
def journal(tmp_path, monkeypatch):
    monkeypatch.setenv("SELFSENTRY_STATE_DIR", str(tmp_path))


def counts(active=0, unknown=0, failed=0):
    return {"active": active, "outcome_not_recorded": unknown, "command_failed": failed}


@pytest.mark.parametrize("kind", ["create", "start", "remove"])
def test_owned_work_is_active_until_its_outcome_is_recorded(kind):
    with outbox.operation_lease(60) as key:
        if kind == "create":
            outbox.begin_creation(key=key)
        else:
            outbox.begin_action("a" * 64, kind, key=key)
        path = outbox._ownership_path(key)
        assert path.exists() and path.stat().st_mode & 0o777 == 0o600
        assert outbox.action_health() == counts(active=1)
        if kind == "create":
            outbox.finish_creation(key, "a" * 64)
        else:
            outbox.finish_action(key, True)
        assert outbox.action_health() == counts()
    assert not path.exists()


def test_active_work_cannot_mask_an_unowned_intent_or_failed_command():
    outbox.begin_creation()
    failed = outbox.begin_action("b" * 64, "remove")
    outbox.finish_action(failed, False)
    with outbox.operation_lease(60) as key:
        outbox.begin_action("a" * 64, "start", key=key)
        assert outbox.action_health() == counts(active=1, unknown=1, failed=1)
    assert outbox.action_health() == counts(unknown=2, failed=1)


def test_exception_releases_ownership_and_preserves_the_unknown_intent():
    with pytest.raises(RuntimeError):
        with outbox.operation_lease(60) as key:
            outbox.begin_creation(key=key)
            raise RuntimeError("uncertain command outcome")
    assert outbox.action_health() == counts(unknown=1)
    with closing(outbox.connect()) as db:
        assert db.execute("SELECT outcome FROM creation_attempts").fetchall() == [
            ("outcome_not_recorded",),
        ]


def test_expired_ownership_does_not_hide_a_live_but_stalled_owner(monkeypatch):
    monkeypatch.setattr(outbox.time, "monotonic", lambda: 100.0)
    with outbox.operation_lease(60) as key:
        outbox.begin_creation(key=key)
        assert outbox.action_health() == counts(active=1)
        monkeypatch.setattr(outbox.time, "monotonic", lambda: 166.0)
        assert outbox.action_health() == counts(unknown=1)


def test_maximum_deadline_does_not_fail_due_to_float_subtraction_rounding(monkeypatch):
    started = 897.975828597
    assert (started + 300 + 5) - started > 305  # Reproduces the false-expiry boundary.
    monkeypatch.setattr(outbox.time, "monotonic", lambda: started)
    with outbox.operation_lease(300) as key:
        outbox.begin_creation(key=key)
        assert outbox.action_health() == counts(active=1)


@pytest.mark.parametrize("change", [
    {"deadline_monotonic": float("nan")}, {"deadline_monotonic": float("inf")},
    {"deadline_monotonic": True}, {"deadline_monotonic": 10**1000},
    {"started_monotonic": -1}, {"started_monotonic": 200},
    {"deadline_monotonic": 1000}, {"key": "different"},
])
def test_invalid_ownership_metadata_cannot_make_an_intent_active(monkeypatch, change):
    monkeypatch.setattr(outbox.time, "monotonic", lambda: 100.0)
    with outbox.operation_lease(60) as key:
        outbox.begin_creation(key=key)
        path = outbox._ownership_path(key)
        metadata = json.loads(path.read_text())
        metadata.update(change)
        path.write_text(json.dumps(metadata))
        assert outbox.action_health() == counts(unknown=1)


def test_a_file_without_a_held_lock_is_not_live_ownership():
    key = outbox.begin_creation()
    path = outbox._ownership_path(key)
    path.parent.mkdir(mode=0o700)
    path.write_text("{}")
    assert outbox.action_health() == counts(unknown=1)
    assert path.read_text() == "{}"  # A health read does not repair/delete evidence.


def test_old_intent_without_a_file_is_unknown_and_health_does_not_create_a_file():
    key = outbox.begin_creation()
    path = outbox._ownership_path(key)
    assert outbox.action_health() == counts(unknown=1)
    assert not path.parent.exists()


@pytest.mark.parametrize("key", [None, "legacy-key", "../escape"])
def test_corrupt_or_legacy_identity_stays_unknown_without_a_file_lookup(key, monkeypatch):
    with closing(outbox.connect()) as db, db:
        db.execute("INSERT INTO creation_attempts VALUES (?,NULL,?,?,NULL)",
                   (key, "outcome_not_recorded", "2026-10-23T00:00:00+00:00"))

    def no_lookup(_key):
        pytest.fail("Invalid journal identity was used for an ownership lookup")

    monkeypatch.setattr(outbox, "_operation_active", no_lookup)
    assert outbox.action_health() == counts(unknown=1)


@pytest.mark.parametrize("kind", ["create", "start"])
@pytest.mark.parametrize("succeeded", [True, False])
def test_completion_racing_the_ownership_check_does_not_create_a_false_orphan(
    monkeypatch, kind, succeeded
):
    with outbox.operation_lease(60) as key:
        if kind == "create":
            outbox.begin_creation(key=key)
        else:
            outbox.begin_action("a" * 64, "start", key=key)

        def completed(_key):
            if kind == "create":
                outbox.finish_creation(key, "a" * 64 if succeeded else None)
            else:
                outbox.finish_action(key, succeeded)
            return False

        monkeypatch.setattr(outbox, "_operation_active", completed)
        assert outbox.action_health() == counts(failed=int(not succeeded))


@pytest.mark.parametrize("value", [0, 301, True, 1.5, "60"])
def test_invalid_timeout_creates_no_ownership_file(value, tmp_path):
    with pytest.raises(ValueError):
        with outbox.operation_lease(value):
            pytest.fail("Invalid ownership budget was accepted")
    assert not list(tmp_path.iterdir())


@contextmanager
def child_owner():
    script = """
import sys
import deployment_outbox as outbox
with outbox.operation_lease(60) as key:
    outbox.begin_creation(key=key)
    print(key, flush=True)
    sys.stdin.buffer.read(1)
    outbox.finish_creation(key, 'a' * 64)
"""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        str(Path(path).resolve()) for path in sys.path if path))
    process = subprocess.Popen([sys.executable, "-c", script], env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([process.stdout], [], [], 10)
        assert ready, "Child did not establish ownership in time"
        key = process.stdout.readline().strip()
        assert len(key) == 32
        yield process, key
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


def test_independent_process_observes_live_ownership_and_normal_completion():
    with child_owner() as (process, key):
        assert outbox.action_health() == counts(active=1)
        process.communicate("x", timeout=5)
        assert process.returncode == 0
        assert outbox.action_health() == counts()
        assert not outbox._ownership_path(key).exists()


def test_process_death_leaves_unknown_intent_and_original_evidence():
    with child_owner() as (process, key):
        assert outbox.action_health() == counts(active=1)
        with closing(outbox.connect()) as db:
            before = db.execute("SELECT * FROM creation_attempts").fetchall()
        process.kill()
        process.wait(timeout=5)
        assert outbox.action_health() == counts(unknown=1)
        with closing(outbox.connect()) as db:
            assert db.execute("SELECT * FROM creation_attempts").fetchall() == before
        assert outbox._ownership_path(key).exists()  # A stale file never proves liveness.
