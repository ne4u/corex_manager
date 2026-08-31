import logging
import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from .core.config import get_settings
from .core.database import init_db

_settings = get_settings()
logging.basicConfig(
    stream=sys.stdout,
    level=getattr(logging, _settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(levelname)s [%(name)s] %(message)s",
)
from .core.middleware import AuditEventMiddleware, ProxyHeadersMiddleware
from .core.password_expiry_middleware import PasswordExpiryMiddleware
from .api.routers import router as api_router
from .api.v1 import build_v1_router
from .services.metrics import start_sampler as start_metrics_sampler
from .services.waf_metrics import start_waf_sampler
from .services.tasks import start_task_worker, AutoRenewScheduler
from .services.geoip import GeoIpDownloader
from .services.security_list_feeds import DynamicFeedUpdater
from .services.rule_set_downloader import RuleSetUpdater
from .services.siem_forwarder import SiemForwarder
from .services.page_protect_sampler import start_page_protect_sampler
from .services.page_protect_hasher import start_page_protect_hasher
from .services.cache_metrics import start_sampler as start_cache_metrics_sampler
from .services.mcp_metrics import start_mcp_sampler
from .services import coraza_config

_geoip_downloader = GeoIpDownloader(interval_hours=_settings.GEOIP_DOWNLOAD_INTERVAL_HOURS)
_security_list_feed_updater = DynamicFeedUpdater()
_rule_set_updater = RuleSetUpdater()
_siem_forwarder = SiemForwarder()
_auto_renew_scheduler = AutoRenewScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .core.database import SessionLocal
    from .services.certificates import migrate_cert_bundles
    db = SessionLocal()
    try:
        coraza_config.write_coraza_spoa_config(db)
        migrate_cert_bundles(db)
        # Regenerate the Varnish VCL on every startup. The VCL lives on the
        # shared haproxy-data volume, which survives container rebuilds, so a
        # stale VCL would otherwise persist until the next config apply.
        # Rewriting here makes an API restart sufficient to recover, and also
        # seeds the file on first boot so varnishd has something to load.
        from .services.settings import get_setting as _get_setting
        from .services import varnish as _varnish
        import os as _os
        _disk_cache_on = _get_setting(db, "disk_cache_enabled", str(_settings.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")
        if _disk_cache_on:
            try:
                _vcl_text = _varnish.generate_vcl(db)
                _os.makedirs(_os.path.dirname(_settings.VARNISH_VCL_PATH), exist_ok=True)
                _existing = None
                if _os.path.exists(_settings.VARNISH_VCL_PATH):
                    with open(_settings.VARNISH_VCL_PATH) as _f:
                        _existing = _f.read()
                if _existing != _vcl_text:
                    with open(_settings.VARNISH_VCL_PATH, "w") as _f:
                        _f.write(_vcl_text)
                    logging.getLogger(__name__).info("Varnish VCL regenerated at startup; reloading")
                    _reloaded = _varnish.reload_vcl()
                    if not _reloaded:
                        logging.getLogger(__name__).warning(
                            "Varnish VCL was written to disk but reload failed — "
                            "Varnish is still running with the old VCL. "
                            "Restart the Varnish container to load the new VCL."
                        )
            except Exception as _exc:
                logging.getLogger(__name__).warning("Varnish VCL startup refresh failed: %s", _exc)
    finally:
        db.close()
    # Prune old CAPTCHA challenge events beyond the retention window
    try:
        from .api.v1.captcha import prune_challenge_events
        from .core.database import SessionLocal as _CapSL
        _cap_db = _CapSL()
        try:
            _deleted = prune_challenge_events(_cap_db)
            if _deleted:
                logging.getLogger(__name__).info("Pruned %d old challenge events", _deleted)
        finally:
            _cap_db.close()
    except Exception as _exc:
        logging.getLogger(__name__).warning("Challenge event pruning failed: %s", _exc)
    # MCP gateway self-registration — idempotently registers the coreX Manager
    # MCP server and skill into the gateway's DB tables, then regenerates the
    # config bundle. Guarded by MCP_GATEWAY_ENABLED + MCP_SELF_REGISTER.
    try:
        from .services.mcp_self_register import ensure_self_registration
        from .core.database import SessionLocal as _SL
        _reg_db = _SL()
        try:
            ensure_self_registration(_reg_db)
        finally:
            _reg_db.close()
    except Exception as _exc:
        logging.getLogger(__name__).warning("MCP self-registration failed: %s", _exc)
    start_metrics_sampler()
    start_cache_metrics_sampler()
    start_mcp_sampler()
    if _settings.CORAZA_SPOA_ENABLED:
        start_waf_sampler()
    start_task_worker()
    _auto_renew_scheduler.start()
    _geoip_downloader.start()
    _security_list_feed_updater.start()
    if _settings.CORAZA_SPOA_ENABLED:
        _rule_set_updater.start()
        _siem_forwarder.start()
    # Page Protect — start sampler + hasher if enabled in settings
    from .services.page_protect import is_page_protect_enabled, is_page_protect_hashing_enabled
    pp_db = SessionLocal()
    try:
        if is_page_protect_enabled(pp_db):
            start_page_protect_sampler()
        if is_page_protect_hashing_enabled(pp_db):
            start_page_protect_hasher()
    finally:
        pp_db.close()
    # API Armor — start profiler if enabled + profiling learning is on
    from .services.api_armor_profiler import start_profiler as start_api_armor_profiler, stop_profiler as stop_api_armor_profiler
    start_api_armor_profiler()
    yield
    stop_api_armor_profiler()
    _siem_forwarder.stop()
    _rule_set_updater.stop()
    _security_list_feed_updater.stop()
    _geoip_downloader.stop()
    _auto_renew_scheduler.stop()


app = FastAPI(
    title="coreX Manager",
    description="Control plane API and data plane orchestration for HAProxy load balancing and WAF.",
    version="1.0.0",
    lifespan=lifespan,
)

cors_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
allowed_origins = [origin.strip() for origin in cors_origins.split(",") if origin.strip()]

app.add_middleware(AuditEventMiddleware)
# PasswordExpiryMiddleware is added after AuditEventMiddleware so it runs
# first (outermost) — blocked requests short-circuit before audit logging.
app.add_middleware(PasswordExpiryMiddleware)
app.add_middleware(ProxyHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

app.include_router(api_router, prefix="/api/v1")
app.include_router(build_v1_router(), prefix="/api/v1")

# Serve static frontend build if available
_project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_static_candidates = ["/app/static", os.path.join(_project_dir, "..", "frontend", "dist"), os.path.join(_project_dir, "static")]
_static_dir = next((p for p in _static_candidates if os.path.isdir(p)), None)
if _static_dir:
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


@app.get("/openapi.json", include_in_schema=False)
def openapi():
    return app.openapi()
