"""
ebpf_collector.py
-------------------
Module 4 of ContainerGuard AI: Behavioral Runtime Monitor (event collection half).

STATUS: NOT YET IMPLEMENTED — Phase 3 stub.

Planned responsibility:
Collect kernel-level events (process spawns, network connections, file
access, syscalls) per-container via Falco's eBPF driver / plugin output,
and forward them into two parallel paths: falco_integration.py (rule
matching) and behavioral-engine/ (baseline + anomaly scoring).

Requires: a Linux host, Falco installed, eBPF driver loaded.
This CANNOT be meaningfully implemented/tested without a real Falco
install on Linux — do not attempt this phase inside a non-Linux
environment or without Falco running first.

Planned interface:
    def stream_events(container_id: str | None = None) -> Iterator[dict]:
        \"\"\"Yields normalized kernel events as they arrive from Falco.\"\"\"
        raise NotImplementedError("Phase 3 not yet built")
"""

# Intentionally left as a stub. Implement in Phase 3, after Falco is installed
# and verified working (see docs/phase3_falco_ebpf.md once that phase begins).
