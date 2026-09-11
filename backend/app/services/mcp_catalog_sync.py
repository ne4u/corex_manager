"""Background sync of MCP catalog state from Valkey into the database.

The mcp-gateway worker stores discovered catalogs in Valkey.  This service
watches those keys and mirrors the server's health/last_catalog_at state into
the backend database so the UI (Servers tab, builder metadata) reflects what
the worker found without requiring a manual backend refresh.
"""
import datetime
import logging
import os
import threading
import time
from typing import Dict, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..core.valkey_client import _get_client
from ..models.mcp import McpServer

logger = logging.getLogger(__name__)

CATALOG_KEY_PREFIX = "mcp:catalog:"
SYNC_INTERVAL_SECONDS = int(os.environ.get("MCP_CATALOG_SYNC_INTERVAL_SECONDS", "10"))
# Minimum seconds between backend-catalog-refresh fallbacks for a missing server.
_FALLBACK_REFRESH_INTERVAL = 30
_last_fallback_refresh: Dict[int, float] = {}


def _get_valkey():
    try:
        return _get_client()
    except Exception:
        return None


def _update_server_state(db: Session, server: McpServer) -> None:
    """Update health/last_catalog_at/last_error from the worker's Valkey catalog."""
    client = _get_valkey()
    if not client:
        return

    raw = client.get(f"{CATALOG_KEY_PREFIX}{server.id}")
    if raw:
        try:
            catalog = raw if isinstance(raw, (dict, list)) else None
            if isinstance(raw, (str, bytes)):
                import json
                catalog = json.loads(raw)
        except Exception:
            catalog = None

        has_catalog = isinstance(catalog, dict) and (
            catalog.get("tools") or catalog.get("resources") or catalog.get("prompts")
        )
        if has_catalog:
            if server.health_status != "healthy" or server.last_error:
                logger.info("Catalog sync: server %s has a catalog, marking healthy", server.name)
                server.health_status = "healthy"
                server.last_error = None
            server.last_catalog_at = datetime.datetime.now(datetime.timezone.utc)
            db.commit()
            return

    # Worker has not produced a usable catalog for this server.  Only mark it
    # unhealthy if we have never successfully cataloged it (startup race) or it
    # has been stale for more than two intervals.
    now = datetime.datetime.now(datetime.timezone.utc)
    stale_threshold = datetime.timedelta(seconds=SYNC_INTERVAL_SECONDS * 2 + 5)
    last_cat = server.last_catalog_at
    if last_cat and last_cat.tzinfo is None:
        last_cat = last_cat.replace(tzinfo=datetime.timezone.utc)
    if not last_cat or (now - last_cat) > stale_threshold:
        if server.health_status != "unhealthy" or not server.last_error:
            server.health_status = "unhealthy"
            server.last_error = "Catalog not yet available from worker"
            db.commit()

    # Fallback: if the gateway worker cannot reach a server but the backend
    # process can, trigger a backend refresh.  This handles network/DNS races
    # where the gateway container starts before the upstream is resolvable.
    _maybe_trigger_backend_refresh(server, now)


def _maybe_trigger_backend_refresh(server: McpServer, now: datetime.datetime) -> None:
    """Trigger a backend catalog refresh if one has not run recently."""
    from .mcp_policies import trigger_background_catalog_refresh

    last = _last_fallback_refresh.get(server.id, 0)
    if (time.time() - last) < _FALLBACK_REFRESH_INTERVAL:
        return
    _last_fallback_refresh[server.id] = time.time()
    logger.info("Catalog sync: triggering backend catalog refresh for %s", server.name)
    try:
        trigger_background_catalog_refresh([server.id])
    except Exception:
        logger.exception("Failed to trigger backend catalog refresh for %s", server.name)


def _catalog_sync_loop() -> None:
    """Loop that periodically syncs Valkey catalog state to the DB."""
    settings = get_settings()
    interval = getattr(settings, "MCP_CATALOG_SYNC_INTERVAL_SECONDS", SYNC_INTERVAL_SECONDS)
    while True:
        try:
            time.sleep(interval)
            db = SessionLocal()
            try:
                servers = db.query(McpServer).filter(McpServer.enabled == True).all()  # noqa: E712
                for server in servers:
                    try:
                        _update_server_state(db, server)
                    except Exception:
                        logger.exception("Catalog sync failed for server %s", server.name)
            finally:
                db.close()
        except Exception as exc:
            logger.exception("MCP catalog sync loop error: %s", exc)


def start_mcp_catalog_sync() -> Optional[threading.Thread]:
    """Start the background catalog sync thread (unless running under pytest)."""
    if os.environ.get("PYTEST_VERSION"):
        return None
    t = threading.Thread(target=_catalog_sync_loop, daemon=True)
    t.start()
    return t
