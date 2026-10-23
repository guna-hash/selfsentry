"""Inventory polling must release Docker connections on success and failure."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import docker
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
from container_watcher import DockerInspector  # noqa: E402


@pytest.mark.parametrize("operation", ["inspect", "list_running"])
@pytest.mark.parametrize("failure", [False, True])
def test_inspection_closes_client(operation, failure):
    client = MagicMock()
    container = MagicMock()
    container.attrs = {"Config": {"Image": "image"}, "State": {"StartedAt": "time"}}
    call = client.containers.get if operation == "inspect" else client.containers.list
    call.return_value = container if operation == "inspect" else [container]
    if failure:
        call.side_effect = docker.errors.DockerException("daemon unavailable")
    inspector = DockerInspector(lambda: client)
    args = ("a" * 64,) if operation == "inspect" else ()
    if failure:
        with pytest.raises(docker.errors.DockerException):
            getattr(inspector, operation)(*args)
    else:
        assert getattr(inspector, operation)(*args)
    client.close.assert_called_once()
