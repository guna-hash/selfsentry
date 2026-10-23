"""Use backend metadata and environment configuration without importing the app."""

from alembic import context
from database import Base, engine
import models.db_models  # noqa: F401


def configure(connection=None):
    if connection is None:
        context.configure(
            url=engine.url, literal_binds=True, dialect_opts={"paramstyle": "named"},
            target_metadata=Base.metadata, compare_type=True
        )
    else:
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    configure()
else:
    supplied = context.config.attributes.get("connection")
    if supplied is not None:
        configure(supplied)
    else:
        try:
            with engine.connect() as connection:
                configure(connection)
        finally:
            engine.dispose()
