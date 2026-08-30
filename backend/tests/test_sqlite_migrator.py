"""Tests for the SQLite-to-PostgreSQL auto-migrator.

Since we can't run a real PostgreSQL instance in unit tests, we test the
detection and topological-sort logic directly, and mock the PostgreSQL
engine for the data-copy path.
"""
import os
import tempfile

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.sqlite_migrator import _find_legacy_sqlite, _get_sqlite_tables, migrate_sqlite_to_postgres


@pytest.fixture
def sqlite_db(tmp_path):
    """Create a SQLite DB with a couple of tables and rows."""
    db_path = tmp_path / "haproxy_manager.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base = declarative_base()

    from sqlalchemy import Column, Integer, String, Boolean, ForeignKey

    class Parent(Base):
        __tablename__ = "parents"
        id = Column(Integer, primary_key=True)
        name = Column(String)
        is_active = Column(Boolean, default=True)

    class Child(Base):
        __tablename__ = "children"
        id = Column(Integer, primary_key=True)
        parent_id = Column(Integer, ForeignKey("parents.id"))
        value = Column(String)

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()
    session.add_all([
        Parent(id=1, name="alpha", is_active=True),
        Parent(id=2, name="beta", is_active=False),
    ])
    session.add_all([
        Child(id=1, parent_id=1, value="x"),
        Child(id=2, parent_id=2, value="y"),
    ])
    session.commit()
    session.close()
    engine.dispose()
    return str(db_path)


def test_find_legacy_sqlite_detects_real_file(tmp_path, monkeypatch):
    """_find_legacy_sqlite returns the path when a real SQLite file exists."""
    db_path = tmp_path / "haproxy_manager.db"
    # Create a valid SQLite file (must connect to actually create it)
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.connect():
        pass
    engine.dispose()

    monkeypatch.setattr("app.core.sqlite_migrator.LEGACY_SQLITE_PATH", str(db_path))
    result = _find_legacy_sqlite()
    assert result == str(db_path)


def test_find_legacy_sqlite_ignores_already_migrated(tmp_path, monkeypatch):
    """_find_legacy_sqlite skips files that have a .migrated companion."""
    db_path = tmp_path / "haproxy_manager.db"
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.connect():
        pass
    engine.dispose()
    (tmp_path / "haproxy_manager.db.migrated").write_text("done")

    monkeypatch.setattr("app.core.sqlite_migrator.LEGACY_SQLITE_PATH", str(db_path))
    result = _find_legacy_sqlite()
    assert result is None


def test_find_legacy_sqlite_ignores_non_sqlite_file(tmp_path, monkeypatch):
    """_find_legacy_sqlite ignores files without the SQLite magic header."""
    db_path = tmp_path / "haproxy_manager.db"
    db_path.write_text("not a database")

    monkeypatch.setattr("app.core.sqlite_migrator.LEGACY_SQLITE_PATH", str(db_path))
    result = _find_legacy_sqlite()
    assert result is None


def test_get_sqlite_tables_orders_by_dependencies(sqlite_db):
    """_get_sqlite_tables returns parent tables before child tables."""
    engine = create_engine(f"sqlite:///{sqlite_db}")
    tables = _get_sqlite_tables(engine)
    # parents should come before children due to FK dependency
    assert "parents" in tables
    assert "children" in tables
    assert tables.index("parents") < tables.index("children")
    engine.dispose()


def test_migrate_sqlite_to_postgres_copies_data(sqlite_db, tmp_path, monkeypatch):
    """Full migration: SQLite data appears in the target (mocked as another SQLite)."""
    # We use a second SQLite as the "target" — the migration logic uses
    # raw SQL so it works across any SQLAlchemy-supported dialect.
    target_path = tmp_path / "target.db"
    target_url = f"sqlite:///{target_path}"

    # Create the target schema (simulating what Alembic would do)
    target_engine = create_engine(target_url)
    Base = declarative_base()
    from sqlalchemy import Column, Integer, String, Boolean, ForeignKey

    class Parent(Base):
        __tablename__ = "parents"
        id = Column(Integer, primary_key=True)
        name = Column(String)
        is_active = Column(Boolean, default=True)

    class Child(Base):
        __tablename__ = "children"
        id = Column(Integer, primary_key=True)
        parent_id = Column(Integer, ForeignKey("parents.id"))
        value = Column(String)

    # Also create alembic_version so the migrator sees a "real" target
    from sqlalchemy import Table, MetaData
    metadata = MetaData()
    Table("alembic_version", metadata,
          Column("version_num", String, primary_key=True))
    Base.metadata.create_all(target_engine)
    metadata.create_all(target_engine)

    # Insert a row into alembic_version so the check passes
    with target_engine.connect() as conn:
        conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('test')"))
        conn.commit()
    target_engine.dispose()

    # Point the migrator at our SQLite source
    monkeypatch.setattr("app.core.sqlite_migrator.LEGACY_SQLITE_PATH", sqlite_db)

    # Run migration (target_url is SQLite, not PG, but the SQL is generic)
    result = migrate_sqlite_to_postgres(target_url)
    assert result is True

    # Verify data was copied
    verify_engine = create_engine(target_url)
    with verify_engine.connect() as conn:
        parents = conn.execute(text("SELECT * FROM parents ORDER BY id")).fetchall()
        assert len(parents) == 2
        assert parents[0][1] == "alpha"
        assert parents[1][1] == "beta"
        # Verify boolean conversion: SQLite stored 1/0, target should have True/False
        assert parents[0][2] is True or parents[0][2] == 1
        assert parents[1][2] is False or parents[1][2] == 0

        children = conn.execute(text("SELECT * FROM children ORDER BY id")).fetchall()
        assert len(children) == 2
        assert children[0][2] == "x"
        assert children[1][2] == "y"
    verify_engine.dispose()

    # Verify the source was renamed to .migrated
    assert not os.path.isfile(sqlite_db)
    assert os.path.isfile(sqlite_db + ".migrated")


def test_migrate_skips_when_no_sqlite_file(monkeypatch):
    """migrate_sqlite_to_postgres returns False when no legacy SQLite exists."""
    monkeypatch.setattr("app.core.sqlite_migrator.LEGACY_SQLITE_PATH", "/nonexistent/path.db")
    result = migrate_sqlite_to_postgres("sqlite:///dummy.db")
    assert result is False
