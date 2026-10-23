"""
auto_isolate.py
-------------------
Automated Response ("SOAR-lite"): isolate a high-risk container, and let an admin
resume it afterwards.

Isolation pauses the container and disconnects it from every network it was attached
to. The container is never stopped or removed, so its filesystem and process state stay
inspectable. Before touching anything, the attached networks are saved to an isolation
record on disk (state/isolations/<full container id>.json, or under $SELFSENTRY_STATE_DIR),
because resume_container() needs them to restore network membership and aliases.
Static IPs and other Docker endpoint options are not preserved.
"""

from __future__ import annotations

import json
import logging
import os
import fcntl
import tempfile
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path

import docker
import requests

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[1]
# Docker's SDK can propagate requests transport failures without wrapping APIError.
_DOCKER_OPERATION_ERRORS = (docker.errors.DockerException, requests.RequestException)


class IsolationError(RuntimeError):
    """Raised when a container cannot be isolated."""


class ResumeError(RuntimeError):
    """Raised when a container cannot be resumed."""


class ContainerNotFound(IsolationError, ResumeError):
    """Raised by both isolate and resume when the container does not exist."""


class IsolationRecordError(IsolationError, ResumeError):
    """Recovery state is invalid or cannot be durably saved; refuse further actions."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _isolation_dir() -> Path:
    base = os.environ.get("SELFSENTRY_STATE_DIR") or str(_REPO_ROOT / "state")
    return Path(base) / "isolations"


def _record_path(full_container_id: str) -> Path:
    if (
        not isinstance(full_container_id, str)
        or len(full_container_id) != 64
        or any(c not in "0123456789abcdef" for c in full_container_id)
    ):
        raise IsolationRecordError("Isolation records require a full Docker hexadecimal ID")
    return _isolation_dir() / f"{full_container_id}.json"


def _validate_record(record, full_container_id):
    valid = (
        isinstance(record, dict)
        and record.get("container_id") == full_container_id
        and record.get("state") in (
            "isolating", "isolated", "isolation_failed", "resuming", "resume_failed", "resumed"
        )
        and isinstance(record.get("networks"), dict)
    )
    if valid:
        for name, config in record["networks"].items():
            if not isinstance(name, str) or not name.strip() or not isinstance(config, dict):
                valid = False
                break
            aliases, network_id = config.get("aliases"), config.get("id")
            if (
                (aliases is not None and (
                    not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases)
                ))
                or (network_id is not None and (
                    not isinstance(network_id, str) or not network_id
                ))
            ):
                valid = False
                break
    if not valid:
        raise IsolationRecordError("Invalid isolation recovery record; operator repair required")


def _write_record(full_container_id: str, record: dict) -> None:
    path = _record_path(full_container_id)
    _validate_record(record, full_container_id)
    tmp_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, filename = tempfile.mkstemp(prefix=f".{full_container_id}.", dir=path.parent)
        tmp_path = Path(filename)
        with os.fdopen(descriptor, "w") as handle:
            json.dump(record, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise IsolationRecordError(
            "Cannot durably save isolation recovery state; inspect the container before retrying"
        ) from exc
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove unused isolation temporary file")


def get_isolation_record(full_container_id: str) -> dict | None:
    """Return validated recovery state; only a genuinely missing file returns None."""
    path = _record_path(full_container_id)
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError as exc:
        if path.is_symlink():
            raise IsolationRecordError(
                "Unreadable isolation recovery record; repair required"
            ) from exc
        return None
    except (OSError, ValueError) as exc:
        raise IsolationRecordError("Unreadable isolation recovery record; repair required") from exc
    _validate_record(record, full_container_id)
    return record


def is_isolated(record: dict | None) -> bool:
    return record is not None and record.get("state") == "isolated"


def _attached_networks(container) -> dict:
    networks = (container.attrs.get("NetworkSettings") or {}).get("Networks") or {}
    return {
        name: {"aliases": list(cfg.get("Aliases") or []), "id": cfg.get("NetworkID")}
        for name, cfg in networks.items()
    }


def _get_container(client, container_id: str):
    try:
        return client.containers.get(container_id)
    except docker.errors.NotFound as exc:
        raise ContainerNotFound(f"Container {container_id} not found: {exc}") from exc


def is_protected(container, protected=None):
    """Exact name or Docker ID (12+ hexadecimal prefix); no wildcard matching."""
    entries = (
        protected
        if protected is not None
        else os.environ.get("MONITOR_PROTECTED_CONTAINERS", "").split(",")
    )
    for entry in entries:
        value = str(entry).strip().lstrip("/")
        if not value:
            continue
        if value == container.name or value == container.id:
            return True
        if 12 <= len(value) <= 64 and all(c in "0123456789abcdef" for c in value):
            if container.id.startswith(value):
                return True
    return False


def _locked_action(function):
    @wraps(function)
    def wrapped(container_id, *args, **kwargs):
        client = docker.from_env(timeout=5)
        try:
            container = _get_container(client, container_id)
            full_id = container.id
            lock_path = _record_path(full_id).with_suffix(".lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_path, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                return function(full_id, *args, _client=client, _container=container, **kwargs)
        finally:
            close = getattr(client, "close", None)
            if close:
                close()

    return wrapped


@_locked_action
def isolate_container(container_id: str, reason: str, *, _client=None, _container=None) -> None:
    """
    Isolates a container: saves its network attachments, disconnects it from them, then
    pauses it. Does NOT stop, remove, or delete the container or its data. Isolating an
    already-isolated container keeps the original record and just makes sure it is paused.
    """
    client, container = _client, _container

    container.reload()
    if is_protected(container):
        raise IsolationError(
            "Protected container: isolation is disabled by MONITOR_PROTECTED_CONTAINERS"
        )
    mode = (container.attrs.get("HostConfig") or {}).get("NetworkMode", "")
    if mode == "host" or mode.startswith("container:"):
        raise IsolationError("host/shared network namespace cannot be safely disconnected")
    existing = get_isolation_record(container.id)
    networks = _attached_networks(container)
    if is_isolated(existing) and not networks and container.status == "paused":
        return
    # Retain original network attachments even when retrying a partial manual attempt.
    record = (
        existing
        if existing and existing.get("state") != "resumed"
        else {
            "container_id": container.id,
            "container_name": container.name,
            "reason": reason,
            "isolated_at": _now(),
            "networks": networks,
            "resumed_at": None,
            "resumed_by": None,
        }
    )
    record["networks"] = {**networks, **record["networks"]}
    record.update(state="isolating", error=None)
    _write_record(container.id, record)
    failures = {}
    for name in networks:
        try:
            client.networks.get(networks[name].get("id") or name).disconnect(container, force=True)
        except _DOCKER_OPERATION_ERRORS as exc:
            failures[name] = str(exc)
    try:
        if container.status != "paused":
            container.pause()
        container.reload()
        if container.status != "paused" or _attached_networks(container):
            failures["verification"] = "container is not paused with all networks disconnected"
    except _DOCKER_OPERATION_ERRORS as exc:
        failures["pause"] = str(exc)
    if failures:
        record.update(state="isolation_failed", error=failures)
        _write_record(container.id, record)
        raise IsolationError(f"Containment incomplete for {container_id}: {failures}")
    record.update(state="isolated", error=None)
    _write_record(container.id, record)
    logger.warning("Isolated container %s (reason: %s)", container_id, reason)


@_locked_action
def resume_container(container_id: str, resumed_by: str, *, _client=None, _container=None) -> dict:
    """
    Reverses isolate_container(): unpauses the container and reconnects the networks saved
    in its isolation record. Refuses to act without a record (it will not guess networks).
    If some networks cannot be reconnected, the record stays active so a retry only
    reconnects what is still missing.
    """
    if not resumed_by or not resumed_by.strip():
        raise ValueError("resumed_by must be a non-empty string (who is resuming this?)")

    client, container = _client, _container

    record = get_isolation_record(container.id)
    if not record or record.get("state") not in (
        "isolated",
        "isolating",
        "isolation_failed",
        "resuming",
        "resume_failed",
    ):
        raise ResumeError(
            f"No active isolation record for {container_id}; "
            "refusing to resume because its original networks are unknown"
        )

    container.reload()
    if container.status not in ("running", "paused"):
        raise ResumeError("Container is stopped; resume does not start stopped workloads")
    record.update(state="resuming", resumed_by=resumed_by, resume_attempt_at=_now())
    _write_record(container.id, record)
    failed = {}
    try:
        if container.status == "paused":
            container.unpause()
        container.reload()
        already_attached = set(_attached_networks(container))
        for name, config in record["networks"].items():
            if name in already_attached:
                continue
            try:
                client.networks.get(config.get("id") or name).connect(
                    container, aliases=config.get("aliases") or None
                )
            except _DOCKER_OPERATION_ERRORS as exc:
                failed[name] = str(exc)
        container.reload()
        live_networks = _attached_networks(container)
        for name, config in record["networks"].items():
            if config.get("id") and live_networks.get(name, {}).get("id") != config["id"]:
                failed[name] = "network identity differs from saved attachment"
        if container.status != "running" or not set(record["networks"]) <= set(live_networks):
            failed["verification"] = "container is not running with all original networks attached"
    except _DOCKER_OPERATION_ERRORS as exc:
        failed["docker"] = str(exc)
    if failed:
        # A failed request may have reached the daemon. Inspect again, and attempt pause
        # even with unknown state rather than trusting the pre-request cached status.
        needs_pause = True
        try:
            container.reload()
            needs_pause = container.status == "running"
        except _DOCKER_OPERATION_ERRORS as exc:
            failed["repause_inspect"] = str(exc)
        if needs_pause:
            try:
                container.pause()
            except _DOCKER_OPERATION_ERRORS as exc:
                failed["repause"] = str(exc)
        try:
            container.reload()
            if container.status != "paused":
                failed["repause_verification"] = "container is not verified paused"
        except _DOCKER_OPERATION_ERRORS as exc:
            failed["repause_verification"] = str(exc)
        record.update(state="resume_failed", error=failed)
        _write_record(container.id, record)
        raise ResumeError(
            f"Container {container_id} recovery incomplete; inspect host state before retrying: "
            f"{failed}"
        )

    record.update(state="resumed", resumed_by=resumed_by, resumed_at=_now(), error=None)
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
