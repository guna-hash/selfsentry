"""Falco-derived telemetry facade; this module does not load an eBPF probe.

Falco's driver captures kernel activity. Loaded security and baseline-capture
rules select which events Falco emits to its JSON output file. SelfSentry reads
that file; it does not receive an unfiltered, pre-rule-matching syscall stream
or use Falco's gRPC output API.

The legacy stream_raw_events name is retained for callers. This facade delegates
to falco_integration.stream_falco_alerts and yields its normalized alert shape.
The continuous monitor uses monitor-service/falco_ingest.py:FalcoTailer for
checkpointed ingestion, then classifies security alerts and baseline telemetry.
Missing Falco output cannot be recovered by this facade.
"""

from __future__ import annotations

from typing import Iterator

from falco_integration import stream_falco_alerts


def stream_raw_events(
    log_path: str,
    container_only: bool = True,
    poll_interval_seconds: float = 0.5,
    from_start: bool = False,
) -> Iterator[dict]:
    """Yield normalized Falco JSON alerts through the existing facade API.

    Arguments and return shape match falco_integration.stream_falco_alerts.
    The name does not imply direct kernel access or unfiltered syscall capture.
    """
    yield from stream_falco_alerts(
        log_path,
        container_only=container_only,
        poll_interval_seconds=poll_interval_seconds,
        from_start=from_start,
    )
