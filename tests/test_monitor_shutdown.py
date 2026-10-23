"""Shutdown ordering with real threads/flock and fake external services."""

import dataclasses
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
import monitor_service  # noqa: E402
from behavior_pipeline import BehaviorPipeline  # noqa: E402
from control_worker import ControlWorker  # noqa: E402
from monitor_config import MonitorConfig  # noqa: E402
from monitor_status import StatusBoard  # noqa: E402


def test_competing_lock_attempt_preserves_owner_pid(tmp_path):
    lock = monitor_service.acquire_lock(tmp_path)
    try:
        assert (tmp_path / "monitor.lock").read_text() == str(os.getpid())
        competing = monitor_service.acquire_lock(tmp_path)
        if competing is not None:
            competing.close()
        assert competing is None
        assert (tmp_path / "monitor.lock").read_text() == str(os.getpid())
    finally:
        lock.close()


@pytest.fixture
def wiring(tmp_path, monkeypatch):
    config = dataclasses.replace(MonitorConfig(), state_dir=tmp_path)
    monkeypatch.setattr(monitor_service, "load_config", lambda: config)
    monkeypatch.setattr(monitor_service, "setup_logging", lambda _: None)
    monkeypatch.setattr(monitor_service.signal, "signal", lambda *_: None)
    status = StatusBoard(tmp_path / "status.json")
    control = ControlWorker(config, Mock(), Mock(), status)
    sink = Mock()
    pump = Mock(ident=None)
    service = SimpleNamespace(
        _control_worker=control, _sink=sink, _status=status, run_once=Mock(),
    )
    stop = threading.Event()
    monkeypatch.setattr(monitor_service, "build_service", lambda _: (service, pump, stop))
    return config, service, pump, stop


def test_main_holds_lock_until_control_has_exited(wiring):
    config, service, _, _ = wiring
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    worker = service._control_worker
    worker.run = lambda: (entered.set(), release.wait(3))
    join = worker.thread.join
    # Compress the old 15-second timeout; an unbounded join still really waits.
    worker.thread.join = lambda timeout=None: join(None if timeout is None else 0.01)
    service.run_once.side_effect = lambda: entered.wait(1)
    errors = []

    def run():
        try:
            monitor_service.main(["--once"])
        except Exception as exc:
            errors.append(exc)
        finally:
            finished.set()

    owner = threading.Thread(target=run)
    owner.start()
    try:
        assert entered.wait(1)
        assert not finished.wait(0.1), "monitor returned while control work was still running"
        competing = monitor_service.acquire_lock(config.state_dir)
        if competing is not None:
            competing.close()
        assert competing is None, "another monitor acquired the active worker's lock"
        service._sink.close.assert_not_called()
    finally:
        release.set()
        owner.join(3)
        worker.thread.join(3)
    assert not owner.is_alive()
    assert not errors
    service._sink.close.assert_called_once_with()
    lock = monitor_service.acquire_lock(config.state_dir)
    assert lock is not None
    lock.close()


def test_start_failure_still_cleans_up_and_releases_lock(wiring):
    config, service, pump, stop = wiring
    pump.start.side_effect = RuntimeError("cannot start pump")
    with pytest.raises(RuntimeError, match="cannot start pump"):
        monitor_service.main(["--once"])
    assert stop.is_set()
    assert service._control_worker.stopping.is_set()
    service._sink.close.assert_called_once_with()
    pump.stop.assert_called_once_with()
    lock = monitor_service.acquire_lock(config.state_dir)
    assert lock is not None
    lock.close()


def test_control_stop_before_start_is_safe(wiring):
    _, service, _, _ = wiring
    service._control_worker.stop()
    assert service._control_worker.stopping.is_set()


def test_shutdown_requests_both_workers_before_waiting_for_pump(wiring):
    config, service, pump, stop = wiring
    service._control_worker.run = lambda: None
    pump.ident = 1

    def join():
        assert stop.is_set()
        assert service._control_worker.stopping.is_set()
        pump.stop.assert_called_once_with()
        assert service._status.snapshot()["components"]["shutdown"]["state"] == "stopping"
        competing = monitor_service.acquire_lock(config.state_dir)
        if competing is not None:
            competing.close()
        assert competing is None

    pump.join.side_effect = join
    assert monitor_service.main(["--once"]) == 0
    pump.join.assert_called_once_with()
    assert service._status.snapshot()["components"]["shutdown"]["state"] == "stopped"


def test_failed_baseline_reset_closes_pipeline_and_releases_lock(wiring, monkeypatch):
    config, _, _, _ = wiring
    pipeline = Mock()
    pipeline.reset_baseline.side_effect = RuntimeError("reset failed")
    monkeypatch.setattr(monitor_service, "BehaviorPipeline", lambda *a: pipeline)
    with pytest.raises(RuntimeError, match="reset failed"):
        monitor_service.main(["--reset-baseline", "a" * 12, "--reason", "test"])
    pipeline.close.assert_called_once_with()
    lock = monitor_service.acquire_lock(config.state_dir)
    assert lock is not None
    lock.close()


def test_behavior_close_waits_for_running_training_and_cancels_queued_work():
    pipe = BehaviorPipeline.__new__(BehaviorPipeline)
    pipe.training_pool = ThreadPoolExecutor(max_workers=1)
    pipe.db = Mock()
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    running = pipe.training_pool.submit(lambda: (entered.set(), release.wait(3)))
    assert entered.wait(1)
    pending = pipe.training_pool.submit(lambda: pytest.fail("queued training must be cancelled"))

    def close():
        pipe.close()
        closed.set()

    owner = threading.Thread(target=close)
    owner.start()
    try:
        assert not closed.wait(0.1), "close returned while model training was still running"
        pipe.db.close.assert_not_called()
    finally:
        release.set()
        owner.join(3)
        pipe.training_pool.shutdown(wait=True, cancel_futures=True)
    assert not owner.is_alive()
    assert running.done()
    assert pending.cancelled()
    pipe.db.close.assert_called_once_with()


def test_control_cleanup_waits_for_explanation_executor(wiring, monkeypatch):
    _, service, _, _ = wiring
    worker = service._control_worker
    db, pool = Mock(), Mock()
    monkeypatch.setattr("control_worker.sqlite3.connect", lambda *a, **k: db)
    monkeypatch.setattr("control_worker.IncidentPipeline", lambda _: SimpleNamespace(executor=pool))
    worker.stopping.set()
    worker.run()
    pool.shutdown.assert_called_once_with(wait=True, cancel_futures=True)
    db.close.assert_called_once_with()
