import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

# Make the backend package importable when Alembic is invoked from the repo root.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _BACKEND_DIR)

from app.core.config import get_settings  # noqa: E402
from app.core.database import Base  # noqa: E402
import app.models.models  # noqa: E402, F401

_settings = get_settings()
# Use a dedicated NullPool engine for migrations so there is zero chance of
# pooled connection locks interfering with the application's connection pool.
_is_sqlite = _settings.DATABASE_URL.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {"connect_timeout": 10}
_migration_engine = create_engine(
    _settings.DATABASE_URL,
    connect_args=_connect_args,
    poolclass=NullPool,
)

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_settings().DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    with _migration_engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # SQLite can't ALTER most things directly; batch mode copies the
            # table, applies the change, and swaps names. Harmless on other
            # dialects, but we gate it to SQLite to keep Postgres output clean.
            render_as_batch=_migration_engine.dialect.name == "sqlite",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
