import atexit
import os
import shutil
import tempfile

# Use an in-memory SQLite database with shared cache so the same DB is
# visible across the main test thread and the TestClient/ASGI worker threads.
# Shared-cache in-memory DBs persist as long as at least one connection is
# open; the engine's connection pool keeps them alive for the test session.
os.environ["DATABASE_URL"] = "sqlite:///file::memory:?cache=shared&uri=true"
os.environ["SECRET_KEY"] = "test-secret-key-do-not-use-in-production"
os.environ.setdefault("CORAZA_SPOA_ENABLED", "true")
os.environ.setdefault("CAPTCHA_SITE_KEY", "test-site-key")
os.environ.setdefault("CAPTCHA_SECRET", "test-secret")

# Override Docker-container-specific absolute paths from .env (e.g.
# HAPROXY_CONFIG_PATH=/app/data/haproxy.cfg, CERT_DIR=/app/certs) with a
# temp directory so tests that call os.makedirs on derived paths don't fail
# with "Read-only file system: '/app'" on macOS host runs.
test_data_dir = tempfile.mkdtemp(prefix="hpm_test_")
os.environ["HAPROXY_CONFIG_PATH"] = os.path.join(test_data_dir, "haproxy.cfg")
os.environ["CERT_DIR"] = os.path.join(test_data_dir, "certs")
atexit.register(shutil.rmtree, test_data_dir, ignore_errors=True)

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, engine, get_db
from app.core.dependencies import get_current_user, rate_limit, rate_limit_by_ip
from app.main import app
from app.models.models import User


class LifespanOff:
    """ASGI wrapper that suppresses startup/shutdown lifespan events.

    Background samplers, the GeoIP downloader, and config writes are not
    triggered for each test, while all HTTP handling still goes to the app.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            message = await receive()
            assert message["type"] == "lifespan.startup"
            await send({"type": "lifespan.startup.complete"})
            message = await receive()
            assert message["type"] == "lifespan.shutdown"
            await send({"type": "lifespan.shutdown.complete"})
            return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Session-scoped schema: create all 68 tables once, drop them at session end.
# This eliminates ~114,000 DDL operations (create+drop per test) that were the
# primary bottleneck in the test suite.
# ---------------------------------------------------------------------------

# Keep a persistent connection open for the entire session so the shared-cache
# in-memory database isn't destroyed when all pool connections are recycled.
_session_keepalive_conn = None


@pytest.fixture(scope="session", autouse=True)
def _session_schema():
    """Create the schema once per session and tear it down at the end."""
    global _session_keepalive_conn
    _session_keepalive_conn = engine.connect()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    _session_keepalive_conn.close()


def _truncate_all_tables(session):
    """Delete all rows from all tables, respecting FK ordering.

    Uses SQLAlchemy's sorted_tables (topological order) reversed so that
    child tables are cleared before parent tables. SQLite FK enforcement
    is disabled during the truncate for speed (it's off by default in the
    test engine anyway — the app's connect pragmas don't enable it).
    """
    from sqlalchemy import text

    # Disable FK enforcement for bulk delete speed
    session.execute(text("PRAGMA foreign_keys=OFF"))
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    # Don't re-enable FKs — the test engine has never had them on, and some
    # tests (e.g. test_backup.py) delete parent rows while children exist.


@pytest.fixture(scope="function")
def db():
    # Use the app's shared engine/SessionLocal so background services
    # (e.g. waf_metrics.sample_waf_metrics) write to the same DB the test sees.
    # Tables are created once at session scope; we just clean rows between tests.
    from app.core.database import SessionLocal

    session = SessionLocal()
    _truncate_all_tables(session)

    # Ensure the "default" risk ruleset exists (id=1) so RiskRule.ruleset_id
    # FK constraints are satisfied. The migration seeds this in production;
    # tests using Base.metadata.create_all skip the migration.
    from app.models.models import RiskRuleset
    rs = RiskRuleset(id=1, name="Default", slug="default", description="Default", enabled=True, priority=0)
    session.add(rs)
    session.commit()
    yield session
    session.close()


# ---------------------------------------------------------------------------
# Session-scoped TestClient: instantiated once, dependency overrides swapped
# per-test via the `client` fixture.
# ---------------------------------------------------------------------------

_test_client = None
_test_client_cm = None


@pytest.fixture
def client(db, monkeypatch):
    """FastAPI TestClient with auth/DB/rate-limit dependencies overridden."""

    def _get_db():
        return db

    def _get_current_user():
        return User(
            username="test-admin",
            role="admin",
            is_admin=True,
            hashed_password="x",
        )

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_current_user
    app.dependency_overrides[rate_limit] = lambda: None
    app.dependency_overrides[rate_limit_by_ip] = lambda: None

    global _test_client, _test_client_cm
    if _test_client is None:
        _test_client_cm = TestClient(LifespanOff(app))
        _test_client = _test_client_cm.__enter__()

    yield _test_client

    app.dependency_overrides.clear()


@pytest.fixture
def tmp_map_files(tmp_path):
    """Create temporary HAProxy map files for geo/ASN tests."""
    country = tmp_path / "geo_country.map"
    asn = tmp_path / "geo_asn.map"
    country.write_text("")
    asn.write_text("")
    return {"country": str(country), "asn": str(asn)}


@pytest.fixture
def temp_coraza_paths(tmp_path, monkeypatch):
    """Redirect Coraza config/log paths to a temp directory for the test."""
    from app.core.config import get_settings

    settings = get_settings()
    log = tmp_path / "coraza-spoa.log"
    cfg = tmp_path / "coraza-spoa.yaml"
    offset = tmp_path / ".waf_metrics_offset"

    monkeypatch.setattr(settings, "CORAZA_SPOA_LOG_PATH", str(log))
    monkeypatch.setattr(settings, "CORAZA_SPOA_CONFIG_PATH", str(cfg))
    # sample_waf_metrics hard-codes the offset path next to the log file;
    # by setting the log path in a temp dir the offset is also temp.
    return {"log": str(log), "cfg": str(cfg), "offset": str(offset)}
