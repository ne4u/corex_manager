"""Tests for the UVICORN_WORKERS SQLite clamp.

When DATABASE_URL is SQLite, UVICORN_WORKERS must be forced to 1 regardless
of the configured value — multiple worker processes contend on the database
file and hit 'database is locked' errors. PostgreSQL allows N workers.
"""

import secrets

from app.core.config import Settings


def _make_settings(**overrides) -> Settings:
    """Create a Settings instance with a valid SECRET_KEY and overrides."""
    defaults = {"SECRET_KEY": secrets.token_urlsafe(32)}
    defaults.update(overrides)
    return Settings(**defaults)


def test_sqlite_clamps_workers_to_1():
    """SQLite + UVICORN_WORKERS=4 → clamped to 1."""
    s = _make_settings(DATABASE_URL="sqlite:///data/test.db", UVICORN_WORKERS=4)
    assert s.UVICORN_WORKERS == 1


def test_sqlite_default_workers_stays_1():
    """SQLite + UVICORN_WORKERS=1 (default) → stays 1."""
    s = _make_settings(DATABASE_URL="sqlite:///data/test.db")
    assert s.UVICORN_WORKERS == 1


def test_postgres_allows_multiple_workers():
    """PostgreSQL + UVICORN_WORKERS=4 → stays 4."""
    s = _make_settings(
        DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/db",
        UVICORN_WORKERS=4,
    )
    assert s.UVICORN_WORKERS == 4


def test_postgres_default_workers_stays_1():
    """PostgreSQL + UVICORN_WORKERS=1 (default) → stays 1."""
    s = _make_settings(
        DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/db",
    )
    assert s.UVICORN_WORKERS == 1
