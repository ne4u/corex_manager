"""Automatic SQLite-to-PostgreSQL migration on first startup.

When the backend starts with a PostgreSQL DATABASE_URL but finds a legacy
SQLite database file at /app/data/haproxy_manager.db (the old Docker default),
this module copies all table data from SQLite to PostgreSQL before Alembic
runs.  After a successful migration the SQLite file is renamed to
``haproxy_manager.db.migrated`` so it is not migrated again on subsequent
restarts.

The migration is purely data-level: Alembic creates the schema in PostgreSQL
first, then we copy rows table-by-table from SQLite using raw SQL.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

_log = logging.getLogger(__name__)

LEGACY_SQLITE_PATH = "/app/data/haproxy_manager.db"
MIGRATED_SUFFIX = ".migrated"


def _find_legacy_sqlite() -> Optional[str]:
    """Return the path to a legacy SQLite database if one exists, else None."""
    path = LEGACY_SQLITE_PATH
    if not os.path.isfile(path) or path.endswith(MIGRATED_SUFFIX):
        return None
    # Skip if already migrated
    if os.path.isfile(path + MIGRATED_SUFFIX):
        return None
    # Must be a real SQLite file. Modern SQLite creates 0-byte files for
    # empty databases, so accept those. Otherwise check the magic header.
    try:
        size = os.path.getsize(path)
        if size == 0:
            return path
        with open(path, "rb") as f:
            header = f.read(16)
        if header[:15] == b"SQLite format 3":
            return path
    except Exception:
        pass
    return None


def _get_sqlite_tables(sqlite_engine) -> list[str]:
    """Return user table names from the SQLite database, in dependency order."""
    inspector = inspect(sqlite_engine)
    tables = inspector.get_table_names()
    # Sort by foreign key dependencies so parents are inserted before children
    # Simple topological sort: move tables with no FKs referencing other
    # user-tables to the front.  This is a best-effort heuristic; circular
    # FKs (rare) will still work because we insert with deferrable constraints
    # off and SQLite data typically doesn't violate FK order in practice.
    deps: dict[str, set[str]] = {}
    table_set = set(tables)
    for t in tables:
        fks = inspector.get_foreign_keys(t)
        dep = {fk["referred_table"] for fk in fks if fk["referred_table"] in table_set}
        deps[t] = dep

    ordered: list[str] = []
    visited: set[str] = set()

    def visit(t: str):
        if t in visited:
            return
        visited.add(t)
        for d in deps.get(t, ()):
            visit(d)
        ordered.append(t)

    for t in tables:
        visit(t)

    return ordered


def migrate_sqlite_to_postgres(pg_url: str) -> bool:
    """Migrate data from a legacy SQLite DB to PostgreSQL.

    Returns True if a migration was performed, False if skipped.
    """
    sqlite_path = _find_legacy_sqlite()
    if not sqlite_path:
        return False

    _log.info("sqlite_migrator: found legacy SQLite database at %s", sqlite_path)

    sqlite_engine = create_engine(
        f"sqlite:///{sqlite_path}",
        connect_args={"check_same_thread": False},
    )
    pg_engine = create_engine(pg_url, pool_pre_ping=True)

    try:
        sqlite_inspector = inspect(sqlite_engine)
        sqlite_tables = set(sqlite_inspector.get_table_names())
        pg_inspector = inspect(pg_engine)
        pg_tables = set(pg_inspector.get_table_names())

        if not pg_tables:
            _log.info("sqlite_migrator: PostgreSQL has no tables yet — schema will be created by Alembic. Skipping data migration; will retry after Alembic runs.")
            return False

        if "alembic_version" not in pg_tables:
            _log.info("sqlite_migrator: PostgreSQL has no alembic_version table — skipping data migration.")
            return False

        # Check if PostgreSQL already has data (skip if so)
        with pg_engine.connect() as conn:
            result = conn.execute(text("SELECT count(*) FROM alembic_version"))
            if result.scalar() == 0:
                _log.info("sqlite_migrator: PostgreSQL alembic_version is empty — skipping.")
                return False

        # Tables to migrate (must exist in both databases)
        common_tables = _get_sqlite_tables(sqlite_engine)
        common_tables = [t for t in common_tables if t in pg_tables and t != "alembic_version"]

        if not common_tables:
            _log.info("sqlite_migrator: no common tables to migrate")
            _rename_migrated(sqlite_path)
            return True

        total_rows = 0
        sqlite_conn = sqlite_engine.connect()
        pg_conn = pg_engine.connect()

        # Disable FK enforcement for the migration session. SQLite data may
        # have orphaned FK references (SQLite doesn't enforce FKs by default).
        # PostgreSQL's session_replication_role=replica disables all trigger-
        # based FK checks, which is the standard approach for bulk data loads.
        _is_pg = not pg_url.startswith("sqlite")
        if _is_pg:
            pg_conn.execute(text("SET session_replication_role = 'replica'"))

        # Truncate all target tables so a partial migration from a previous
        # failed attempt doesn't cause duplicate-key errors. FK enforcement is
        # already disabled, so order doesn't matter.
        for table_name in common_tables:
            if _is_pg:
                pg_conn.execute(text(f'TRUNCATE TABLE "{table_name}" RESTART IDENTITY CASCADE'))
            else:
                pg_conn.execute(text(f'DELETE FROM "{table_name}"'))
        pg_conn.commit()

        for table_name in common_tables:
            # Get column names from both databases. SQLite may have columns
            # that were removed by later Alembic migrations (e.g. certificate_ids
            # was dropped from backends). Only insert columns that exist in the
            # PostgreSQL target schema.
            sqlite_columns = [col["name"] for col in sqlite_inspector.get_columns(table_name)]
            pg_columns = pg_inspector.get_columns(table_name)
            pg_column_names = {col["name"] for col in pg_columns}
            columns = [c for c in sqlite_columns if c in pg_column_names]
            if not columns:
                continue

            # Detect boolean columns from the PostgreSQL schema so we can
            # convert SQLite integer 0/1 values to Python bool. SQLite stores
            # booleans as integers, but PostgreSQL rejects integer literals
            # for boolean columns.
            bool_columns = {
                col["name"] for col in pg_columns
                if str(col["type"]).lower() == "boolean"
            }

            col_list = ", ".join(f'"{c}"' for c in columns)
            placeholders = ", ".join(f":{c}" for c in columns)

            # Read all rows from SQLite
            rows = sqlite_conn.execute(text(f'SELECT {col_list} FROM "{table_name}"')).mappings().all()
            if not rows:
                continue

            # Insert into PostgreSQL, converting boolean columns
            insert_sql = f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders})'
            for row in rows:
                row_dict = dict(row)
                for col_name in bool_columns:
                    val = row_dict.get(col_name)
                    if val is not None:
                        row_dict[col_name] = bool(val)
                pg_conn.execute(text(insert_sql), row_dict)

            pg_conn.commit()
            total_rows += len(rows)
            _log.info("sqlite_migrator: migrated %d rows from %s", len(rows), table_name)

        sqlite_conn.close()
        # Re-enable FK enforcement
        if _is_pg:
            pg_conn.execute(text("SET session_replication_role = 'origin'"))
        pg_conn.commit()
        pg_conn.close()

        # Reset PostgreSQL sequences to max(id)+1 for all tables that have
        # an auto-increment/serial primary key. Without this, the sequence
        # stays at 1 and the next INSERT gets a duplicate-key error because
        # the migrated rows already used IDs 1..N.
        if _is_pg:
            _reset_pg_sequences(pg_engine)

        _log.info("sqlite_migrator: migration complete — %d total rows migrated", total_rows)
        _rename_migrated(sqlite_path)
        return True

    except Exception as exc:
        _log.exception("sqlite_migrator: migration failed: %s", exc)
        return False
    finally:
        sqlite_engine.dispose()
        pg_engine.dispose()


def _rename_migrated(sqlite_path: str) -> None:
    """Rename the SQLite file so we don't try to migrate it again."""
    try:
        os.rename(sqlite_path, sqlite_path + MIGRATED_SUFFIX)
        _log.info("sqlite_migrator: renamed %s -> %s", sqlite_path, sqlite_path + MIGRATED_SUFFIX)
    except Exception as exc:
        _log.warning("sqlite_migrator: could not rename legacy file: %s", exc)


def _reset_pg_sequences(pg_engine) -> None:
    """Reset all PostgreSQL sequences to max(id)+1.

    After a data migration that inserts rows with explicit IDs, the sequences
    backing SERIAL/IDENTITY columns are still at their initial values (typically 1).
    This causes duplicate-key errors on the next INSERT because the sequence
    generates an ID that already exists.

    For each table with an integer primary key column named ``id``, find the
    associated sequence (via ``pg_get_serial_sequence``) and set it to
    ``max(id)`` so the next ``nextval()`` returns ``max(id)+1``.
    """
    try:
        with pg_engine.connect() as conn:
            # Find all tables with a serial/identity column
            result = conn.execute(text("""
                SELECT
                    c.relname AS table_name,
                    a.attname AS column_name
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_attribute a ON a.attrelid = c.oid
                WHERE c.relkind = 'r'
                  AND n.nspname = 'public'
                  AND a.attnum > 0
                  AND NOT a.attisdropped
                  AND pg_get_serial_sequence(c.relname, a.attname) IS NOT NULL
            """))
            for table_name, column_name in result:
                seq = conn.execute(
                    text(f"SELECT pg_get_serial_sequence('{table_name}', '{column_name}')")
                ).scalar()
                if not seq:
                    continue
                # setval(seq, COALESCE(max(id), 0) + 1, false) — the third arg
                # 'false' means the next nextval() will return max+1 (not max).
                # If the table is empty, set to 1 so nextval returns 1.
                conn.execute(text(
                    f"SELECT setval('{seq}', COALESCE((SELECT max(\"{column_name}\") FROM \"{table_name}\"), 0) + 1, false)"
                ))
                _log.info("sqlite_migrator: reset sequence %s for %s.%s", seq, table_name, column_name)
            conn.commit()
    except Exception as exc:
        _log.warning("sqlite_migrator: failed to reset sequences: %s", exc)
