"""
auto_isolate.py
-------------------
Module 10 of ContainerGuard AI: Automated Response ("SOAR-lite").

STATUS: NOT YET IMPLEMENTED — Phase 10 stub (built late, needs Phase 5's
risk score and Phase 7's severity to decide when to act).

Planned responsibility:
Pause/isolate containers flagged high-risk by the Correlation Engine,
while preserving forensic state (e.g. don't delete, just network-isolate
and snapshot) for later incident investigation.

Planned interface (using Docker SDK — see requirements.txt):
    def isolate_container(container_id: str, reason: str) -> None:
        raise NotImplementedError("Phase 10 not yet built")
"""
