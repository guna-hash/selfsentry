"""Shared local backend credentials; never include the token in logs or evidence."""

import os
from pathlib import Path

import requests
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


def backend_headers():
    load_dotenv(_ENV_PATH)
    token = os.environ.get("SELFSENTRY_API_TOKEN", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def backend_json(base, path, timeout=10, max_pages=100):
    """Read authenticated JSON; explicitly traverse bounded incident pages.

    Incident snapshots exclude records inserted after the first page. Refuse
    malformed/non-progressing pages or an exceeded cap instead of silently
    treating partial evaluation evidence as a complete incident collection.
    """
    if path != "/incidents/":
        response = requests.get(base.rstrip("/") + path, headers=backend_headers(),
                                timeout=timeout, allow_redirects=False)
        response.raise_for_status()
        return response.json()
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("max_pages must be a positive integer")
    result = []
    before = None
    for _ in range(max_pages):
        params = {"limit": 500}
        if before is not None:
            params["before_id"] = before
        response = requests.get(base.rstrip("/") + path, params=params,
                                headers=backend_headers(), timeout=timeout,
                                allow_redirects=False)
        response.raise_for_status()
        rows = response.json()
        if not isinstance(rows, list) or len(rows) > 500:
            raise ValueError("Invalid incident page")
        ids: list[int] = []
        for row in rows:
            value = row.get("id") if isinstance(row, dict) else None
            if type(value) is not int or value <= 0:
                raise ValueError("Invalid incident page identity")
            ids.append(value)
        if ids != sorted(set(ids), reverse=True) or (ids and before and ids[0] >= before):
            raise ValueError("Incident cursor did not progress")
        result.extend(rows)
        if len(rows) < 500:
            return result
        before = ids[-1]
    raise ValueError("Incident page cap reached; use an explicit export for larger history")
