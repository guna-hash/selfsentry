"""Read-only comparison of DATABASE_URL against the backend's declared schema."""

import json
from pathlib import Path
import sys

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]


def schema_differences(connection, metadata):
    context = MigrationContext.configure(
        connection, opts={"compare_type": True, "compare_server_default": True}
    )
    return compare_metadata(context, metadata)


def main() -> int:
    sys.path.insert(0, str(ROOT / "backend-api"))
    from database import Base, engine
    import models.db_models  # noqa: F401

    try:
        with engine.connect() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(text("SET TRANSACTION READ ONLY"))
            elif connection.dialect.name == "sqlite":
                connection.execute(text("PRAGMA query_only = ON"))
            else:
                raise RuntimeError("Read-only schema verification supports PostgreSQL and SQLite")
            differences = schema_differences(connection, Base.metadata)
        print(json.dumps({"matches": not differences,
                          "differences": [repr(item) for item in differences]}, indent=2))
        return 1 if differences else 0
    except Exception as exc:
        # Driver errors can embed connection credentials; don't echo them.
        print(f"Schema verification unavailable ({type(exc).__name__})", file=sys.stderr)
        return 2
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
