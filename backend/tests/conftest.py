import atexit
import os
import shutil
import tempfile

# Use a file-based SQLite database so the same DB is visible across the
# main test thread and the TestClient/ASGI worker threads.
test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
test_db.close()
os.environ["DATABASE_URL"] = f"sqlite:///{test_db.name}"
os.environ["SECRET_KEY"] = "test-secret-key-do-not-use-in-production"
os.environ.setdefault("CORAZA_SPOA_ENABLED", "true")
os.environ.setdefault("CAPTCHA_SITE_KEY", "test-site-key")
os.environ.setdefault("CAPTCHA_SECRET", "test-secret")
atexit.register(os.unlink, test_db.name)

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


@pytest.fixture(scope="function")
def db():
    # Use the app's shared in-memory engine/SessionLocal so background services
    # (e.g. waf_metrics.sample_waf_metrics) write to the same DB the test sees.
    # Tests create tables directly from model metadata (always current); the
    # Alembic migration path is tested separately in test_migrations.py.
    from app.core.database import SessionLocal

    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    # Ensure the "default" risk ruleset exists (id=1) so RiskRule.ruleset_id
    # FK constraints are satisfied. The migration seeds this in production;
    # tests using Base.metadata.create_all skip the migration.
    from app.models.models import RiskRuleset
    rs = RiskRuleset(id=1, name="Default", slug="default", description="Default", enabled=True, priority=0)
    session.add(rs)
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


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

    with TestClient(LifespanOff(app)) as c:
        yield c

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
