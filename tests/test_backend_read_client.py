"""Authenticated tools must not silently truncate or loop over incident history."""

from pathlib import Path
import sys
from unittest.mock import Mock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
import backend_auth as client  # noqa: E402


def response(rows):
    return Mock(json=Mock(return_value=rows))


def test_incident_reads_follow_cursor_and_send_credentials_on_every_page(monkeypatch):
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "test-read-token")
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return response([{"id": n} for n in range(505, 5, -1)] if len(calls) == 1
                        else [{"id": n} for n in range(5, 0, -1)])

    monkeypatch.setattr(client.requests, "get", get)
    rows = client.backend_json("http://localhost:8000/", "/incidents/")
    assert len(rows) == 505
    assert calls[0][1]["params"] == {"limit": 500}
    assert calls[1][1]["params"] == {"limit": 500, "before_id": 6}
    assert all(item[1]["headers"] == {"Authorization": "Bearer test-read-token"} for item in calls)
    assert all(item[1]["allow_redirects"] is False for item in calls)


@pytest.mark.parametrize("rows", [{"items": []}, [{"id": "bad"}], [{"id": 1}, {"id": 2}],
                                  [{"id": 1}, {"id": 1}]])
def test_invalid_pages_are_not_accepted_as_evidence(monkeypatch, rows):
    monkeypatch.setattr(client.requests, "get", lambda *a, **kw: response(rows))
    with pytest.raises(ValueError):
        client.backend_json("http://localhost:8000", "/incidents/")


def test_repeated_page_and_exceeded_cap_fail_explicitly(monkeypatch):
    page = [{"id": n} for n in range(500, 0, -1)]
    monkeypatch.setattr(client.requests, "get", lambda *a, **kw: response(page))
    with pytest.raises(ValueError, match="did not progress"):
        client.backend_json("http://localhost:8000", "/incidents/")
    with pytest.raises(ValueError, match="cap reached"):
        client.backend_json("http://localhost:8000", "/incidents/", max_pages=1)


def test_authentication_failure_is_propagated_instead_of_becoming_empty_history(monkeypatch):
    result = response([])
    result.raise_for_status.side_effect = requests.HTTPError("401")
    monkeypatch.setattr(client.requests, "get", lambda *a, **kw: result)
    with pytest.raises(requests.HTTPError):
        client.backend_json("http://localhost:8000", "/incidents/")
