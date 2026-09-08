"""
feature_extractor.py
---------------------
Module 4a of SelfSentry: Behavioral Runtime Monitor.

Converts a list of raw kernel-level events for a single container over a
single time window into a fixed-length numeric feature vector, suitable
for both baseline storage (Phase 4b) and anomaly scoring (Phase 4c).

Design notes:
  - Input events are intentionally a *superset* of what Phase 3's Falco
    alert stream (interface shape #1) provides. Falco's alert output only
    surfaces events that already matched a rule (i.e. already-suspicious
    events) - to build a meaningful "normal" baseline we need the raw
    underlying event stream (every process spawn, connection, file access),
    not just the subset Falco already flagged. This is supplied by
    falco-rules/baseline-capture-rules.yaml + baseline_collector.py.
  - Kept to 8 features intentionally (per the project guide's own
    guidance to start with 5-10 and expand later). Each feature is a
    simple, explainable count/flag - no engineered ratios yet.
  - Pure, side-effect-free, and fully unit-testable without any live
    Falco/eBPF process - see tests/test_feature_extractor.py.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Optional

# Syscalls considered "sensitive" for the sensitive_syscall_count feature.
# Deliberately a small, defensible watchlist to start - expand as you
# gather real data on what actually shows up during attacks vs normal use.
SENSITIVE_SYSCALLS = frozenset(
    {
        "ptrace",
        "setuid",
        "setgid",
        "mount",
        "umount",
        "reboot",
        "init_module",
        "delete_module",
        "chmod",
        "chown",
    }
)

# Process names treated as "shell" for the shell_spawned_count feature.
SHELL_PROCESS_NAMES = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh"})


class EventType(str, Enum):
    PROCESS_SPAWN = "process_spawn"
    NETWORK_CONNECT = "network_connect"
    FILE_ACCESS = "file_access"
    SYSCALL = "syscall"


@dataclass
class RawEvent:
    """
    Generic normalized kernel-level event for one container.

    Only the fields relevant to `event_type` need to be populated; the
    rest are left as None. This is the schema Phase 3's collector output
    (via baseline_collector.py) must be mapped into before reaching this
    module.
    """

    container_id: str
    timestamp: datetime
    event_type: EventType

    # process_spawn fields
    proc_name: Optional[str] = None
    parent_proc_name: Optional[str] = None

    # network_connect fields
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

    # file_access fields
    file_path: Optional[str] = None

    # syscall fields
    syscall_name: Optional[str] = None

    @staticmethod
    def from_dict(d: dict) -> "RawEvent":
        ts = d["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return RawEvent(
            container_id=d["container_id"],
            timestamp=ts,
            event_type=EventType(d["event_type"]),
            proc_name=d.get("proc_name"),
            parent_proc_name=d.get("parent_proc_name"),
            dest_ip=d.get("dest_ip"),
            dest_port=d.get("dest_port"),
            file_path=d.get("file_path"),
            syscall_name=d.get("syscall_name"),
        )


@dataclass
class FeatureVector:
    """
    Fixed-order, fixed-length numeric feature vector for one
    (container_id, window) pair. Field order defines array order - do not
    reorder fields without also updating FEATURE_NAMES and any already-
    trained/persisted models.
    """

    container_id: str
    window_start: datetime
    window_end: datetime

    distinct_process_count: int = 0
    distinct_network_dest_count: int = 0
    distinct_ports_count: int = 0
    distinct_files_accessed: int = 0
    total_event_count: int = 0
    shell_spawned_count: int = 0
    distinct_parent_child_pairs: int = 0
    sensitive_syscall_count: int = 0

    def to_array(self) -> list[float]:
        """Numeric-only view, in FEATURE_NAMES order, for feeding sklearn."""
        return [float(getattr(self, name)) for name in FEATURE_NAMES]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["window_start"] = self.window_start.isoformat()
        d["window_end"] = self.window_end.isoformat()
        return d


# Single source of truth for feature ordering - anomaly_model.py imports
# this so the training array and the scoring array can never drift apart.
FEATURE_NAMES: tuple[str, ...] = (
    "distinct_process_count",
    "distinct_network_dest_count",
    "distinct_ports_count",
    "distinct_files_accessed",
    "total_event_count",
    "shell_spawned_count",
    "distinct_parent_child_pairs",
    "sensitive_syscall_count",
)


def extract_features(
    events: list[RawEvent],
    container_id: str,
    window_start: datetime,
    window_end: datetime,
) -> FeatureVector:
    """
    Aggregate a list of RawEvents (already filtered to one container and
    one time window by the caller) into a single FeatureVector.

    Events for other containers are ignored defensively (not assumed
    pre-filtered), so callers can pass a slightly wider event slice
    without corrupting another container's baseline.
    """
    fv = FeatureVector(
        container_id=container_id, window_start=window_start, window_end=window_end
    )

    proc_names: set[str] = set()
    dest_ips: set[str] = set()
    ports: set[int] = set()
    files: set[str] = set()
    parent_child_pairs: set[tuple[str, str]] = set()

    for event in events:
        if event.container_id != container_id:
            continue
        if not (window_start <= event.timestamp <= window_end):
            continue

        fv.total_event_count += 1

        if event.event_type == EventType.PROCESS_SPAWN:
            if event.proc_name:
                proc_names.add(event.proc_name)
                if event.proc_name in SHELL_PROCESS_NAMES:
                    fv.shell_spawned_count += 1
            if event.proc_name and event.parent_proc_name:
                parent_child_pairs.add((event.parent_proc_name, event.proc_name))

        elif event.event_type == EventType.NETWORK_CONNECT:
            if event.dest_ip:
                dest_ips.add(event.dest_ip)
            if event.dest_port is not None:
                ports.add(event.dest_port)

        elif event.event_type == EventType.FILE_ACCESS:
            if event.file_path:
                files.add(event.file_path)

        elif event.event_type == EventType.SYSCALL:
            if event.syscall_name in SENSITIVE_SYSCALLS:
                fv.sensitive_syscall_count += 1

    fv.distinct_process_count = len(proc_names)
    fv.distinct_network_dest_count = len(dest_ips)
    fv.distinct_ports_count = len(ports)
    fv.distinct_files_accessed = len(files)
    fv.distinct_parent_child_pairs = len(parent_child_pairs)

    return fv
