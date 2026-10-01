"""
auto_isolate.py
-------------------
Automated Response ("SOAR-lite").

Pauses and network-isolates a container flagged high-risk by the
Correlation Engine, while preserving forensic state — the container is
paused, not removed, so its filesystem/process state remains
inspectable afterward.
"""

from __future__ import annotations

import logging

import docker

logger = logging.getLogger(__name__)


class IsolationError(RuntimeError):
    """Raised when a container cannot be isolated."""


def isolate_container(container_id: str, reason: str) -> None:
    """
    Isolates a container: disconnects it from all networks, then pauses
    it. Does NOT stop, remove, or delete the container or its data —
    forensic state must remain available for investigation.
    """
    client = docker.from_env()
    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound as exc:
        raise IsolationError(f"Container {container_id} not found: {exc}") from exc

    for network in client.networks.list():
        try:
            network.disconnect(container, force=True)
        except docker.errors.APIError:
            pass  # container wasn't attached to this network — fine

    try:
        container.pause()
    except docker.errors.APIError as exc:
        raise IsolationError(f"Failed to pause container {container_id}: {exc}") from exc

    logger.warning("Isolated container %s (reason: %s)", container_id, reason)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SelfSentry - Isolate a high-risk container")
    parser.add_argument("container_id")
    parser.add_argument("reason")
    args = parser.parse_args()

    isolate_container(args.container_id, args.reason)
    print(f"Container {args.container_id} isolated: {args.reason}")
