"""
baseline_builder.py
----------------------
Module 4 of ContainerGuard AI: Behavioral Runtime Monitor (baseline half).

STATUS: NOT YET IMPLEMENTED — Phase 4 stub.

Planned responsibility:
During an initial "learning window" (e.g. first N hours/days of a
container's life, or a manually-triggered training period), record
per-container normal behavior (process tree shape, network destinations,
file-access patterns, syscall frequency distributions) and persist it
as that container's behavioral baseline.

Planned interface:
    def build_baseline(container_id: str, events: list[dict]) -> dict:
        \"\"\"Returns a baseline profile dict from a window of events.\"\"\"
        raise NotImplementedError("Phase 4 not yet built")
"""

# Intentionally left as a stub. Implement in Phase 4, after Phase 3 (event
# collection) is working — this module has nothing to consume until then.
