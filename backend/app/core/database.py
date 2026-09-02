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
    """Run Alembic migrations to bring the database to the latest revision."""
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

    # Check the current alembic version to see if we're already at head.
    # This avoids a hanging command.upgrade() call on PostgreSQL when
    # the DB is already up-to-date (the alembic env.py creates a separate
    # NullPool engine that can deadlock with the app's engine pool).
    current_version = None
    with engine.connect() as conn:
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        if "alembic_version" in tables:
            from sqlalchemy import text
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
            if row:
                current_version = row[0]
        conn.commit()

    _log.info("init_db: tables=%d, current_version=%s", len(tables), current_version)

    # Dispose all pooled connections so they don't block Alembic's DDL.
    # On SQLite this releases file locks; on PostgreSQL this prevents
    # idle connections from interfering with schema changes.
    engine.dispose()

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

    _ensure_admin_user()
    _migrate_stale_beacon_paths()
    _log.info("init_db: done")


def _migrate_stale_beacon_paths():
    """One-time migration: update stale /_asset-beacon paths to /_cx-assets.

    The default Page Protect beacon paths were renamed from /_asset-beacon
    to /_cx-assets to avoid ad blocker filter lists. Existing deployments
    have the old paths stored in the settings table; update them to the
    new defaults so the UI and HAProxy config use the non-blocked paths.
    """
    from ..models.models import Setting
    db = SessionLocal()
    try:
        renames = {
            "page_protect_beacon_path": ("/_asset-beacon", "/_cx-assets"),
            "page_protect_beacon_script_path": ("/_asset-beacon.js", "/_cx-assets.js"),
        }
        for key, (old_val, new_val) in renames.items():
            row = db.query(Setting).filter(Setting.key == key).first()
            if row and row.value == old_val:
                row.value = new_val
                db.commit()
                import logging
                logging.getLogger(__name__).info(
                    "Migrated %s: %s → %s", key, old_val, new_val
                )
    except Exception:
        db.rollback()
    finally:
        db.close()
