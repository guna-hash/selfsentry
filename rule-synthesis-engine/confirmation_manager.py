"""
confirmation_manager.py
--------------------------
Rule Synthesis Engine — Confirmation Manager.

Marks a correlated incident as CONFIRMED by a human analyst, by calling
the real backend-api endpoint built in Phase 8:

    POST /incidents/{incident_id}/confirm?confirmed_by=<name>

This is the trigger for the rest of the Rule Synthesis pipeline
(pattern_extractor.py onward). Per project design constraints, this
stays a fully manual, human-driven action for now — no auto-confirm
heuristics are implemented here.

Design note: this module does NOT maintain its own local confirmation
store. The backend's PostgreSQL confirmed_incidents table (Phase 8) is
the single source of truth, since it already exists and is what the
dashboard's Rule Review Queue (Phase 9) will read from too. Keeping
one source of truth avoids the two systems silently disagreeing about
which incidents are confirmed.
"""

from __future__ import annotations

import argparse
import sys

import requests

DEFAULT_BACKEND_URL = "http://localhost:8000"


class ConfirmationError(RuntimeError):
    """Raised when the backend rejects or fails a confirm request."""


def confirm_incident(
    incident_id: int,
    confirmed_by: str,
    backend_url: str = DEFAULT_BACKEND_URL,
    timeout_seconds: int = 10,
) -> dict:
    """
    Confirms an incident as a real, human-verified threat by calling the
    real backend-api endpoint. Returns the parsed JSON response on success.

    Raises ConfirmationError on any non-200 response or network failure,
    so callers (and the CLI below) never silently treat a failed confirm
    as a success.
    """
    if not confirmed_by or not confirmed_by.strip():
        raise ValueError("confirmed_by must be a non-empty string (who is confirming this?)")

    url = f"{backend_url}/incidents/{incident_id}/confirm"
    try:
        response = requests.post(
            url,
            params={"confirmed_by": confirmed_by},
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        raise ConfirmationError(f"Could not reach backend at {url}: {exc}") from exc

    if response.status_code != 200:
        raise ConfirmationError(
            f"Backend rejected confirm for incident {incident_id}: "
            f"HTTP {response.status_code} - {response.text}"
        )

    try:
        return response.json()
    except ValueError:
        # Backend returned 200 but non-JSON body — still treat as success,
        # just return an empty dict rather than crashing the caller.
        return {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SelfSentry - Confirm a correlated incident as a real threat"
    )
    parser.add_argument("incident_id", type=int, help="The incident ID to confirm (from /incidents/)")
    parser.add_argument("confirmed_by", help="Name/identifier of the human confirming this incident")
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    args = parser.parse_args()

    try:
        result = confirm_incident(args.incident_id, args.confirmed_by, backend_url=args.backend_url)
    except (ConfirmationError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Incident {args.incident_id} confirmed by '{args.confirmed_by}'.")
    print(result)
