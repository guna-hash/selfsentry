"""Control-loop ordering tests with fake collaborators; no Docker or backend calls."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
import control_worker  # noqa: E402


@pytest.fixture
def control(tmp_path, monkeypatch):
    monkeypatch.setattr(control_worker, "action_health", Mock(return_value={
        "outcome_not_recorded": 0, "command_failed": 0,
    }))
    db = Mock()
    monkeypatch.setattr(control_worker.sqlite3, "connect", Mock(return_value=db))
    pipeline = Mock(executor=None)
    factory = Mock(return_value=pipeline)
    monkeypatch.setattr(control_worker, "IncidentPipeline", factory)
    delivery = Mock(return_value={"pending": 0, "rejected": 0})
    monkeypatch.setattr(control_worker, "flush_deployments", delivery)
    watcher = Mock(container_ids=[], tracked_count=0, pending_count=0)
    worker = control_worker.ControlWorker(
        SimpleNamespace(state_dir=tmp_path, poll_interval_seconds=0, backend_url="unused"),
        watcher, Mock(), Mock(),
    )
    return worker, db, pipeline, factory, delivery


@pytest.mark.parametrize("counts,state", [
    ({"pending": 2, "rejected": 1}, "degraded"),
    ({"pending": 0, "rejected": 0}, "ok"),
])
def test_deployment_delivery_health_uses_actual_journal_counts(control, monkeypatch, counts, state):
    worker, _, _, _, delivery = control
    delivery.return_value = counts
    monkeypatch.setattr(worker.stopping, "wait", lambda _: worker.stopping.set())
    worker.run()
    worker.status.set_value.assert_any_call("deployment_outbox", counts)
    detail = "2 pending; 1 require review" if state == "degraded" else None
    worker.status.set_component.assert_any_call("deployment_backend", state, detail)


def test_initialization_failure_closes_database(control):
    worker, db, _, factory, _ = control
    factory.side_effect = RuntimeError("pipeline initialization failed")
    with pytest.raises(RuntimeError, match="initialization"):
        worker.run()
    db.close.assert_called_once_with()


def test_event_queue_capacity_returns_backpressure_without_dropping(control):
    worker, *_ = control
    assert worker.events.maxsize == 1000
    for index in range(worker.events.maxsize):
        assert worker.handle_docker_event({"sequence": index}) is True
    assert worker.handle_docker_event({"sequence": 1000}) is False
    assert worker.events.qsize() == 1000
    assert worker.events.get_nowait() == {"sequence": 0}
    assert worker.handle_docker_event({"sequence": 1000}) is True


def test_database_setup_failure_closes_database(control):
    worker, db, _, factory, _ = control
    db.execute.side_effect = RuntimeError("WAL unavailable")
    with pytest.raises(RuntimeError, match="WAL unavailable"):
        worker.run()
    db.close.assert_called_once_with()
    factory.assert_not_called()


def test_executor_cleanup_failure_still_closes_database(control):
    worker, db, pipeline, _, _ = control
    worker.stopping.set()
    pipeline.executor = Mock()
    pipeline.executor.shutdown.side_effect = RuntimeError("executor cleanup failed")
    with pytest.raises(RuntimeError, match="executor cleanup"):
        worker.run()
    db.close.assert_called_once_with()


def test_reconcile_request_during_reconcile_survives(control, monkeypatch):
    worker, db, _, _, _ = control
    waits = []

    def wait(_):
        waits.append(None)
        if len(waits) == 2:
            worker.stopping.set()

    monkeypatch.setattr(worker.stopping, "wait", wait)
    # A second request arrives after the first reconciliation has started.
    worker.watcher.reconcile.side_effect = worker.reconcile
    worker.run()
    assert worker.watcher.reconcile.call_count == 2
    db.close.assert_called_once_with()


def test_stop_during_event_does_not_start_more_work(control):
    worker, db, pipeline, _, delivery = control
    worker.events.put({"sequence": 1})
    worker.events.put({"sequence": 2})
    worker.watcher.handle_docker_event.side_effect = lambda _: worker.stopping.set()
    worker.run()
    worker.watcher.handle_docker_event.assert_called_once_with({"sequence": 1})
    assert worker.events.get_nowait() == {"sequence": 2}
    worker.watcher.reconcile.assert_not_called()
    worker.watcher.tick.assert_not_called()
    pipeline.tick.assert_not_called()
    worker.audit.flush_spool.assert_not_called()
    delivery.assert_not_called()
    db.close.assert_called_once_with()


def test_failed_reconcile_is_requested_again(control):
    worker, _, _, _, _ = control

    def fail():
        worker.stopping.set()
        raise RuntimeError("Docker unavailable")

    worker.watcher.reconcile.side_effect = fail
    worker.run()
    assert worker.reconcile_requested.is_set()


def test_stop_during_pipeline_does_not_start_delivery(control):
    worker, _, pipeline, _, delivery = control
    pipeline.tick.side_effect = worker.stopping.set
    worker.run()
    worker.audit.flush_spool.assert_not_called()
    delivery.assert_not_called()


@pytest.mark.parametrize("counts,state", [
    ({"outcome_not_recorded": 1, "command_failed": 0}, "degraded"),
    ({"outcome_not_recorded": 0, "command_failed": 2}, "degraded"),
    ({"outcome_not_recorded": 0, "command_failed": 0}, "ok"),
    ({"active": 1, "outcome_not_recorded": 0, "command_failed": 0}, "ok"),
    ({"active": 1, "outcome_not_recorded": 1, "command_failed": 0}, "degraded"),
    ({"active": 1, "outcome_not_recorded": 0, "command_failed": 1}, "degraded"),
])
def test_action_health_uses_durable_counts(control, monkeypatch, counts, state):
    worker, *_ = control
    monkeypatch.setattr(control_worker, "action_health", lambda: counts)
    monkeypatch.setattr(worker.stopping, "wait", lambda _: worker.stopping.set())
    worker.run()
    worker.status.set_value.assert_any_call("deployment_actions", counts)
    calls = worker.status.set_component.call_args_list
    assert any(c.args[:2] == ("deployment_actions", state) for c in calls)


def test_progress_marker_follows_all_control_work(control, monkeypatch):
    worker, _, pipeline, _, delivery = control
    order = []
    pipeline.tick.side_effect = lambda: order.append("incidents")
    worker.audit.flush_spool.side_effect = lambda: order.append("audit")

    def flush(_):
        order.append("deployments")
        return {"pending": 0, "rejected": 0}

    delivery.side_effect = flush

    def value(name, value):
        if name == "control_updated_at":
            order.append("completed")

    worker.status.set_value.side_effect = value
    monkeypatch.setattr(worker.stopping, "wait", lambda _: worker.stopping.set())
    worker.run()
    assert order == ["incidents", "audit", "deployments", "completed"]


def test_failed_cycle_does_not_publish_successful_progress(control, monkeypatch):
    worker, _, pipeline, _, _ = control
    pipeline.tick.side_effect = RuntimeError("pipeline failed")
    monkeypatch.setattr(worker.stopping, "wait", lambda _: worker.stopping.set())
    worker.run()
    assert not any(
        c.args[0] == "control_updated_at" for c in worker.status.set_value.call_args_list
    )
    assert not any(c.args[:2] == ("control", "ok")
                   for c in worker.status.set_component.call_args_list)
    worker.status.set_component.assert_any_call("control", "degraded", "pipeline failed")


def test_blocked_cycle_cannot_publish_completion_while_main_heartbeat_updates(
    control, monkeypatch, tmp_path
):
    import threading
    from monitor_status import StatusBoard

    worker, _, pipeline, _, _ = control
    board = StatusBoard(tmp_path / "status.json")
    board.set_running(True)
    worker.status = board
    entered, release = threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(5), "test did not release fake pipeline"

    pipeline.tick.side_effect = blocked
    monkeypatch.setattr(worker.stopping, "wait", lambda _: worker.stopping.set())
    thread = threading.Thread(target=worker.run)
    thread.start()
    try:
        assert entered.wait(5)
        board.write()  # The independent main heartbeat remains live.
        snapshot = board.snapshot()
        assert snapshot["updated_at"] is not None
        assert snapshot.get("control_updated_at") is None
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert isinstance(board.snapshot()["control_updated_at"], float)
