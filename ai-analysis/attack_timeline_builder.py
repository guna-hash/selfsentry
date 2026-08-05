"""
attack_timeline_builder.py
------------------------------
Module 9 of ContainerGuard AI: Attack Timeline.

STATUS: NOT YET IMPLEMENTED — Phase 7 stub.

Planned responsibility:
Use the LLM to reconstruct a chronological sequence of attacker actions
from correlated events (e.g. "1. Reverse shell spawned via curl | pipe sh
-> 2. Outbound connection to unknown IP -> 3. /etc/passwd read attempt").
Advisory/explanatory only, same constraint as root_cause_summarizer.py.

Planned interface:
    def build_timeline(incident: dict, related_events: list[dict]) -> list[dict]:
        raise NotImplementedError("Phase 7 not yet built")
"""
