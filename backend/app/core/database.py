import os
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import get_settings

settings = get_settings()

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if db_path:
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False,
    )
else:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_timeout=30,
        connect_args={"connect_timeout": 10},
        echo=False,
    )

# SQLite: set a long busy_timeout and enable WAL mode on every connection.
# WAL mode allows concurrent readers alongside a single writer, preventing
# API requests from blocking when background samplers write to the DB.
if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _conn_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA wal_autocheckpoint=1000")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_admin_user():
    """Create an admin user on first startup using ADMIN_PASSWORD env var or a generated value."""
    import os
    import secrets
    from .security import get_password_hash
    from ..models.models import User

    admin_password = os.environ.get("ADMIN_PASSWORD")
    generated = False
    if not admin_password:
        admin_password = secrets.token_urlsafe(16)
        generated = True

    db = SessionLocal()
    try:
        if not db.query(User).first():
            user = User(
                username="admin",
                hashed_password=get_password_hash(admin_password),
                role="admin",
                is_admin=True,
            )
            db.add(user)
            db.commit()
            if generated:
                print(f"WARNING: ADMIN_PASSWORD not set. Generated admin password: {admin_password}")
    finally:
        db.close()


def init_db():
    """Run Alembic migrations to bring the database to the latest revision.

    Existing databases created by the legacy create_all + _add_missing_columns
    path have all baseline tables but no alembic_version table. We detect this
    and stamp them at the baseline revision so only the follow-up data
    migration revision runs. Fresh databases get the full upgrade from zero.
    """
    import logging
    _log = logging.getLogger(__name__)

    from ..models import models as _  # noqa: F401 — register all models on Base.metadata
    from alembic import command
    from alembic.config import Config

    db_dir = os.path.dirname(os.path.abspath(__file__))
    alembic_ini_path = os.path.join(db_dir, "..", "db", "alembic.ini")
    script_location = os.path.join(db_dir, "..", "db")
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("script_location", script_location)

    _log.info("init_db: checking database state")

    # If the DB has tables but no alembic_version table, it's a legacy DB
    # created by the old create_all path. Stamp it at the baseline revision
    # so only follow-up migrations run (not the full baseline re-creation).
    needs_stamp = False
    with engine.connect() as conn:
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        if tables and "alembic_version" not in tables:
            needs_stamp = True
        conn.commit()

    _log.info("init_db: tables=%d, needs_stamp=%s", len(tables), needs_stamp)

    # Check the current alembic version to see if we're already at head.
    # This avoids a hanging command.upgrade() call on PostgreSQL when
    # the DB is already up-to-date (the alembic env.py creates a separate
    # NullPool engine that can deadlock with the app's engine pool).
    current_version = None
    if "alembic_version" in tables:
        with engine.connect() as conn:
            from sqlalchemy import text
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
            if row:
                current_version = row[0]
            conn.commit()
    _log.info("init_db: current_version=%s", current_version)

    # Dispose all pooled connections so they don't block Alembic's DDL.
    # On SQLite this releases file locks; on PostgreSQL this prevents
    # idle connections from interfering with schema changes.
    engine.dispose()

    if needs_stamp:
        _log.info("init_db: stamping at baseline 8b9ba74c6828")
        command.stamp(alembic_cfg, "8b9ba74c6828")
        _log.info("init_db: stamp complete")

    # Only run upgrade if we're not already at head. On PostgreSQL,
    # command.upgrade("head") can hang even when there's nothing to do
    # because the alembic env.py creates a separate engine that may
    # deadlock with disposed app connections.
    from alembic.script import ScriptDirectory
    script_dir = ScriptDirectory.from_config(alembic_cfg)
    head_revision = script_dir.get_current_head()
    _log.info("init_db: head_revision=%s", head_revision)

    if current_version == head_revision:
        _log.info("init_db: already at head, skipping upgrade")
    else:
        _log.info("init_db: running upgrade to head")
        command.upgrade(alembic_cfg, "head")
        _log.info("init_db: upgrade complete")

    # Fixup: ensure risk_rulesets rows have created_at/updated_at set
    # (the initial migration INSERT may have omitted them on some DBs).
    try:
        with engine.connect() as conn:
            from sqlalchemy import text
            conn.execute(text(
                "UPDATE risk_rulesets SET created_at = NOW() WHERE created_at IS NULL"
            ))
            conn.execute(text(
                "UPDATE risk_rulesets SET updated_at = NOW() WHERE updated_at IS NULL"
            ))
            conn.commit()
    except Exception as exc:
        _log.warning("init_db: risk_rulesets timestamp fixup failed: %s", exc)

    # If we're on PostgreSQL and a legacy SQLite database exists in the data
    # volume, migrate its data now (after schema is created by Alembic).
    if not _is_sqlite:
        try:
            from .sqlite_migrator import migrate_sqlite_to_postgres
            migrated = migrate_sqlite_to_postgres(settings.DATABASE_URL)
            if migrated:
                _log.info("init_db: SQLite-to-PostgreSQL data migration completed")
        except Exception as exc:
            _log.warning("init_db: SQLite migration check failed: %s", exc)

        # Always reset PostgreSQL sequences on startup. This fixes databases
        # that were migrated from SQLite before the migrator had sequence
        # reset logic, and is a no-op on healthy databases (setval to the
        # same value is cheap).
        try:
            from .sqlite_migrator import _reset_pg_sequences
            _reset_pg_sequences(engine)
        except Exception as exc:
            _log.warning("init_db: sequence reset failed: %s", exc)

    _ensure_admin_user()
    _log.info("init_db: done")


def _add_missing_columns() -> None:
    """Legacy no-op migration helper kept for test compatibility.

    The production schema is now managed by Alembic. Tests still call this
    helper after create_all, so a no-op is sufficient.
    """
    pass
