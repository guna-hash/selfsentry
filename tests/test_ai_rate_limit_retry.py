"""Bounded advisory retries with fake provider calls; no real API use."""

import json
from types import SimpleNamespace
from unittest.mock import Mock
from tests.test_incident_pipeline import coordinator
from incident_pipeline import IncidentPipeline


class Limited(Exception):
    status_code = 429

    def __init__(self, retry_after="120"):
        self.response = SimpleNamespace(headers={"Retry-After": retry_after})


def state(pipe):
    return json.loads(pipe.db.execute("SELECT body FROM actions").fetchone()[0])


def test_rate_limit_retries_without_repeating_response(tmp_path):
    pipe, clock, _, delivery, http, isolate, synth = coordinator(
        tmp_path, auto_isolation_enabled=True
    )
    delivery.summarize = Mock(side_effect=[Limited(), {"plain_summary": "ready"}])
    delivery.tick()
    assert state(pipe)["workflow"]["explanation"]["status"] == "pending_retry"
    for _ in range(5):
        delivery.tick()
    assert delivery.summarize.call_count == 1
    clock[0] += 121
    delivery.tick()
    assert state(pipe)["workflow"]["explanation"]["status"] == "ready"
    assert delivery.summarize.call_count == 2
    isolate.assert_called_once()
    assert sum(url.endswith("/confirm") for url in http.calls) == 1


def test_retry_budget_and_provider_cooldown(tmp_path):
    pipe, clock, _, delivery, _, _, _ = coordinator(tmp_path)
    delivery.summarize = Mock(side_effect=Limited())
    for _ in range(4):
        delivery.tick()
        clock[0] += 1000
    assert delivery.summarize.call_count == 4
    assert state(pipe)["workflow"]["explanation"]["status"] == "unavailable"
    delivery.tick()
    assert delivery.summarize.call_count == 4


def test_retry_after_and_restart_preserve_cooldown(tmp_path):
    pipe, clock, _, delivery, http, isolate, synth = coordinator(tmp_path)
    delivery.summarize = Mock(side_effect=Limited("600"))
    delivery.tick()
    assert state(pipe)["ai_retry_at"] == clock[0] + 600
    recovered = IncidentPipeline(
        pipe,
        http=http,
        isolate=isolate,
        synthesize=synth,
        summarize=Mock(return_value={}),
        clock=lambda: clock[0],
        async_explanations=False,
    )
    clock[0] += 599
    recovered.tick()
    assert recovered.summarize.call_count == 0
    clock[0] += 2
    recovered.tick()
    recovered.summarize.assert_called_once()


def test_other_errors_are_terminal(tmp_path):
    pipe, _, _, delivery, _, _, _ = coordinator(tmp_path)
    delivery.summarize = Mock(side_effect=RuntimeError("unset"))
    delivery.tick()
    delivery.tick()
    delivery.summarize.assert_called_once()
    assert state(pipe)["workflow"]["explanation"]["status"] == "unavailable"


def test_cooldown_applies_to_other_incidents(tmp_path):
    pipe, clock, _, delivery, _, _, _ = coordinator(tmp_path)
    delivery.summarize = Mock(side_effect=Limited())
    delivery.tick()
    body = state(pipe)
    body.pop("ai_attempts", None)
    body.pop("ai_retry_at", None)
    body["id"] = 2
    assert delivery._process("second-window", body, "explain") is False
    assert delivery.summarize.call_count == 1


def test_retry_after_http_date(tmp_path):
    from datetime import datetime, timezone
    from email.utils import format_datetime

    _, clock, _, delivery, _, _, _ = coordinator(tmp_path)
    stamp = datetime.fromtimestamp(clock[0] + 900, timezone.utc)
    assert delivery._ai_retry_delay(Limited(format_datetime(stamp)), 1) == 900
    assert delivery._ai_retry_delay(Limited("invalid"), 1) == 120
    assert delivery._ai_retry_delay(Limited("nan"), 1) == 120
