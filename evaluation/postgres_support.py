"""Shared safety checks for the disposable PostgreSQL concurrency runner."""


import os
import re

import requests


IDENTITY = """SELECT json_build_object(
    'database_oid', (SELECT oid::text FROM pg_database WHERE datname=current_database()),
    'server_start_epoch', extract(epoch FROM pg_postmaster_start_time())::text,
    'port', current_setting('port'))"""


class CheckFailed(RuntimeError):
    pass


def pg_environment(url, database):
    # Avoid inherited libpq options silently selecting a service or another database.
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update({
        "PGHOST": url.host, "PGPORT": str(url.port or 5432),
        "PGUSER": url.username, "PGPASSWORD": url.password or "",
        "PGDATABASE": database, "PGCONNECT_TIMEOUT": "5",
        "PGAPPNAME": "selfsentry-acceptance",
    })
    for name, value in url.query.items():
        option = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
                  "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY"}.get(name)
        if option:
            env[option] = str(value)
        elif name != "connect_timeout":
            raise CheckFailed(f"Connection option needs review before acceptance: {name}")
    return env


def target_url(source_url, name, owned):
    if name not in owned or not re.fullmatch(r"ss_accept_[a-f0-9]{12}_(restore|migrate)", name):
        raise CheckFailed("Refusing an unowned database target")
    if name == source_url.database:
        raise CheckFailed("Refusing the active database as a write target")
    return source_url.set(database=name)


def monitor_status():
    response = requests.get("http://127.0.0.1:8000/monitor/status", timeout=15)
    response.raise_for_status()
    return response.json()
