"""Shared local backend credentials; never include the token in logs or evidence."""

import os
from pathlib import Path
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


def backend_headers():
    load_dotenv(_ENV_PATH)
    token = os.environ.get("SELFSENTRY_API_TOKEN", "")
    return {"Authorization": f"Bearer {token}"} if token else {}
