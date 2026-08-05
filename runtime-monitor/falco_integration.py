"""
falco_integration.py
-----------------------
Module 3 of ContainerGuard AI: Falco Rule Engine (integration layer).

STATUS: NOT YET IMPLEMENTED — Phase 3 stub.

Planned responsibility:
Interface with a running Falco instance (via its gRPC output, or by
tailing its JSON output / syslog) to receive rule-based alerts and
normalize them into ContainerGuard AI's internal alert schema for the
Correlation Engine (Phase 5) to consume.

Falco itself (the rule-matching engine) is used as-is (off-the-shelf).
This file is the original glue code connecting Falco's output to the
rest of this pipeline.

Planned interface:
    def stream_falco_alerts() -> Iterator[dict]:
        \"\"\"Yields normalized Falco alerts as they fire.\"\"\"
        raise NotImplementedError("Phase 3 not yet built")
"""

# Intentionally left as a stub. Implement in Phase 3.
