# Containers console, isolation records and resume

## What it does
- `response-engine/auto_isolate.py`
  - `isolate_container()` saves the container's network attachments to an isolation record, disconnects
    the networks, then pauses the container. Nothing is stopped or deleted, so forensic state stays intact.
  - `resume_container()` unpauses the container and reconnects the saved networks. It refuses to act
    without an active record, and a partial failure leaves the record active so a retry finishes the job.
- Backend: `GET /containers/` (live from Docker, joined with each container's latest incident risk),
  `POST /containers/{id}/resume`, `POST /containers/{id}/isolate`.
- Dashboard: Containers page with status, latest risk, and Resume / Isolate buttons.

## Isolation records
Stored as `state/isolations/<full container id>.json` (override the base directory with
`SELFSENTRY_STATE_DIR`). The `state/` directory is gitignored. Fields: container name, reason, time,
networks with aliases, state (`isolated` or `resumed`), and who resumed it.

## Known limitations
- Records live on the host's disk, so the backend and the response engine must run on the same host.
- A container isolated by the old code (before records existed) cannot be resumed through this path;
  `resume_container()` refuses rather than guess its networks.
- If someone runs `docker unpause` by hand, the container stays disconnected until `resume` is used.
- Static IP addresses are not restored; only network membership and aliases are.
- The Containers list queries the latest incident once per container, fine for a single host.
