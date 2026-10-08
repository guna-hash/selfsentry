"""
auto_isolate.py
-------------------
Automated Response ("SOAR-lite"): isolate a high-risk container, and let an admin
resume it afterwards.

Isolation pauses the container and disconnects it from every network it was attached
to. The container is never stopped or removed, so its filesystem and process state stay
inspectable. Before touching anything, the attached networks are saved to an isolation
record on disk (state/isolations/<full container id>.json, or under $SELFSENTRY_STATE_DIR),
because resume_container() needs them to put the container back exactly as it was.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import docker

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[1]


class IsolationError(RuntimeError):
    """Raised when a container cannot be isolated."""


class ResumeError(RuntimeError):
    """Raised when a container cannot be resumed."""


class ContainerNotFound(IsolationError, ResumeError):
    """Raised by both isolate and resume when the container does not exist."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _isolation_dir() -> Path:
    base = os.environ.get("SELFSENTRY_STATE_DIR") or str(_REPO_ROOT / "state")
    return Path(base) / "isolations"


def _record_path(full_container_id: str) -> Path:
    return _isolation_dir() / f"{full_container_id}.json"


def _write_record(full_container_id: str, record: dict) -> None:
    path = _record_path(full_container_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(record, indent=2))
    tmp_path.replace(path)


def get_isolation_record(full_container_id: str) -> dict | None:
    """The saved isolation record, or None if missing or unreadable."""
    path = _record_path(full_container_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        logger.warning("Isolation record %s is unreadable: %s", path, exc)
        return None


def is_isolated(record: dict | None) -> bool:
    return bool(record) and record.get("state") == "isolated"


def _attached_networks(container) -> dict:
    networks = (container.attrs.get("NetworkSettings") or {}).get("Networks") or {}
    return {name: {"aliases": list(cfg.get("Aliases") or [])} for name, cfg in networks.items()}


def _get_container(client, container_id: str):
    try:
        return client.containers.get(container_id)
    except docker.errors.NotFound as exc:
        raise ContainerNotFound(f"Container {container_id} not found: {exc}") from exc


def isolate_container(container_id: str, reason: str) -> None:
    """
    Isolates a container: saves its network attachments, disconnects it from them, then
    pauses it. Does NOT stop, remove, or delete the container or its data. Isolating an
    already-isolated container keeps the original record and just makes sure it is paused.
    """
    client = docker.from_env()
    container = _get_container(client, container_id)

    existing = get_isolation_record(container.id)
    if is_isolated(existing):
        container.reload()
        if container.status != "paused":
            try:
                container.pause()
            except docker.errors.APIError as exc:
                raise IsolationError(f"Failed to pause container {container_id}: {exc}") from exc
        logger.info("Container %s was already isolated; original record kept", container_id)
        return

    networks = _attached_networks(container)
    # Written BEFORE anything is changed, so a crash midway can never lose the networks.
    _write_record(
        container.id,
        {
            "container_id": container.id,
            "container_name": container.name,
            "reason": reason,
            "isolated_at": _now(),
            "networks": networks,
            "state": "isolated",
            "resumed_at": None,
            "resumed_by": None,
        },
    )

    for name in networks:
        try:
            client.networks.get(name).disconnect(container, force=True)
        except docker.errors.APIError as exc:
            logger.warning("Could not disconnect %s from network %s: %s", container_id, name, exc)

    try:
        container.pause()
    except docker.errors.APIError as exc:
        raise IsolationError(f"Failed to pause container {container_id}: {exc}") from exc

    logger.warning("Isolated container %s (reason: %s)", container_id, reason)


def resume_container(container_id: str, resumed_by: str) -> dict:
    """
    Reverses isolate_container(): unpauses the container and reconnects the networks saved
    in its isolation record. Refuses to act without a record (it will not guess networks).
    If some networks cannot be reconnected, the record stays active so a retry only
    reconnects what is still missing.
    """
    if not resumed_by or not resumed_by.strip():
        raise ValueError("resumed_by must be a non-empty string (who is resuming this?)")

    client = docker.from_env()
    container = _get_container(client, container_id)

    record = get_isolation_record(container.id)
    if not is_isolated(record):
        raise ResumeError(
            f"No active isolation record for {container_id}; "
            "refusing to resume because its original networks are unknown"
        )

    container.reload()
    if container.status == "paused":
        try:
            container.unpause()
        except docker.errors.APIError as exc:
            raise ResumeError(f"Failed to unpause container {container_id}: {exc}") from exc

    container.reload()
    already_attached = set(_attached_networks(container))
    failed = {}
    for name, config in record["networks"].items():
        if name in already_attached:
            continue
        try:
            client.networks.get(name).connect(container, aliases=config.get("aliases") or None)
        except docker.errors.APIError as exc:
            failed[name] = str(exc)
    if failed:
        raise ResumeError(
            f"Container {container_id} was unpaused but these networks could not be "
            f"reconnected (retry resume): {failed}"
        )

    record.update(state="resumed", resumed_by=resumed_by, resumed_at=_now())
    _write_record(container.id, record)
    logger.warning("Resumed container %s (by %s)", container_id, resumed_by)
    return {
        "container_id": container.id,
        "networks": list(record["networks"]),
        "resumed_by": resumed_by,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SelfSentry - Isolate or resume a container")
    parser.add_argument("container_id")
    parser.add_argument("detail", help="isolation reason; with --resume, the admin's name")
    parser.add_argument("--resume", action="store_true", help="resume an isolated container")
    args = parser.parse_args()

    if args.resume:
        outcome = resume_container(args.container_id, args.detail)
        print(f"Container {args.container_id} resumed; networks restored: {outcome['networks']}")
    else:
        isolate_container(args.container_id, args.detail)
        print(f"Container {args.container_id} isolated: {args.detail}")
