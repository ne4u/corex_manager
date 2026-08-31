"""Catalog worker for MCP Gateway — periodic upstream catalog refresh.

For each enabled server, the worker:
1. Initializes an upstream session (if not already cached)
2. Fetches tools/list, resources/list, prompts/list (with pagination)
3. Stores the merged catalog in Valkey: mcp:catalog:<server_id>
4. Tracks a content hash to detect list_changed events

The catalog is used by the protocol handler to serve merged list responses
without making live upstream calls on every client request.
"""
import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

CATALOG_KEY_PREFIX = "mcp:catalog:"
CATALOG_HASH_KEY_PREFIX = "mcp:catalog_hash:"
CATALOG_TTL = 7200  # 2 hours (worker refreshes well before this)

# In-memory catalog cache (fallback when Valkey unavailable)
_catalog_cache: dict[int, dict] = {}
_catalog_hashes: dict[int, str] = {}

# List of changed server IDs since last check
_changed_servers: set[int] = set()


def _get_valkey():
    """Return a Valkey client or None."""
    try:
        from valkey import Valkey
        import os
        host = os.environ.get("VALKEY_HOST", "valkey")
        port = int(os.environ.get("VALKEY_PORT", "6379"))
        password = os.environ.get("VALKEY_PASSWORD") or None
        client = Valkey(
            host=host, port=port, db=0, password=password,
            socket_connect_timeout=1, socket_timeout=2,
            decode_responses=True,
        )
        client.ping()
        return client
    except Exception as e:
        logger.debug("Valkey not available for catalog: %s", e)
        return None


def _compute_hash(data: dict) -> str:
    """Compute a stable hash of catalog data for list_changed detection."""
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def store_catalog(server_id: int, catalog: dict) -> None:
    """Store a server's catalog in Valkey and update the in-memory cache."""
    catalog_key = f"{CATALOG_KEY_PREFIX}{server_id}"
    hash_key = f"{CATALOG_HASH_KEY_PREFIX}{server_id}"

    new_hash = _compute_hash(catalog)
    old_hash = _catalog_hashes.get(server_id)

    client = _get_valkey()
    if client:
        client.setex(catalog_key, CATALOG_TTL, json.dumps(catalog))
        client.setex(hash_key, CATALOG_TTL, new_hash)

    _catalog_cache[server_id] = catalog
    if old_hash and old_hash != new_hash:
        _changed_servers.add(server_id)
        logger.info("Catalog changed for server %d (hash %s -> %s)", server_id, old_hash, new_hash)
    _catalog_hashes[server_id] = new_hash


def get_catalog(server_id: int) -> Optional[dict]:
    """Get a server's catalog from cache or Valkey."""
    if server_id in _catalog_cache:
        return _catalog_cache[server_id]

    client = _get_valkey()
    if not client:
        return None

    raw = client.get(f"{CATALOG_KEY_PREFIX}{server_id}")
    if not raw:
        return None
    try:
        catalog = json.loads(raw)
        _catalog_cache[server_id] = catalog
        return catalog
    except json.JSONDecodeError:
        return None


def get_all_catalogs(servers: list[dict]) -> dict[int, dict]:
    """Get catalogs for all given servers. Returns {server_id: catalog}."""
    result = {}
    for server in servers:
        catalog = get_catalog(server["id"])
        if catalog:
            result[server["id"]] = catalog
    return result


def pop_changed_servers() -> set[int]:
    """Return and clear the set of server IDs whose catalog changed since last call."""
    changed = set(_changed_servers)
    _changed_servers.clear()
    return changed


def clear_catalog(server_id: int) -> None:
    """Remove a server's catalog (e.g., when disabled)."""
    _catalog_cache.pop(server_id, None)
    _catalog_hashes.pop(server_id, None)
    client = _get_valkey()
    if client:
        client.delete(f"{CATALOG_KEY_PREFIX}{server_id}")
        client.delete(f"{CATALOG_HASH_KEY_PREFIX}{server_id}")


def clear_all_catalogs() -> None:
    """Clear all cached catalogs."""
    _catalog_cache.clear()
    _catalog_hashes.clear()
    _changed_servers.clear()


class CatalogWorker:
    """Background task that periodically refreshes upstream catalogs."""

    def __init__(self, refresh_interval: int = 60):
        self.refresh_interval = refresh_interval
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def start(self):
        """Start the catalog worker as an asyncio task."""
        if self._task is not None:
            return
        self._running = True
        try:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._run())
            logger.info("Catalog worker started (interval=%ds)", self.refresh_interval)
        except RuntimeError:
            logger.warning("No event loop — catalog worker not started")

    async def stop(self):
        """Stop the catalog worker."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Catalog worker stopped")

    async def _run(self):
        """Main loop: refresh catalogs periodically."""
        # Initial refresh on startup
        await self.refresh_all()

        while self._running:
            try:
                await asyncio.sleep(self.refresh_interval)
                await self.refresh_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Catalog worker error: %s", e)
                await asyncio.sleep(self.refresh_interval)

    async def refresh_all(self):
        """Refresh catalogs for all enabled servers."""
        try:
            from .config_loader import get_enabled_servers
        except ImportError:
            from config_loader import get_enabled_servers

        try:
            from .upstream import fetch_catalog, initialize_upstream
        except ImportError:
            from upstream import fetch_catalog, initialize_upstream

        servers = get_enabled_servers()
        if not servers:
            return

        tasks = [self._refresh_one(s, fetch_catalog, initialize_upstream) for s in servers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _refresh_one(self, server: dict, fetch_catalog_fn, initialize_upstream_fn):
        """Refresh catalog for a single server."""
        sid = server["id"]
        try:
            # Ensure upstream session exists
            from .sessions import get_upstream_session, set_upstream_session
        except ImportError:
            from sessions import get_upstream_session, set_upstream_session

        # Use a gateway-wide session for catalog (not tied to a client session)
        # We store it under a synthetic session key for reuse
        catalog_session_key = f"catalog:{sid}"
        upstream_sid = get_upstream_session(catalog_session_key, sid)
        if not upstream_sid:
            upstream_sid = await initialize_upstream_fn(server)
            if upstream_sid:
                # Store in a synthetic session so future catalog refreshes reuse it
                from .sessions import create_session
                try:
                    synthetic = create_session(0, server.get("team_id", 0))
                    set_upstream_session(synthetic, sid, upstream_sid)
                except Exception:
                    pass  # Valkey may not be available

        catalog = await fetch_catalog_fn(server, upstream_sid)
        if catalog:
            store_catalog(sid, catalog)
            logger.debug("Refreshed catalog for server %s (%d tools, %d resources, %d prompts)",
                         server.get("name"), len(catalog.get("tools", [])),
                         len(catalog.get("resources", [])),
                         len(catalog.get("prompts", [])))
        else:
            logger.warning("Failed to fetch catalog for server %s", server.get("name"))


# Singleton instance
_worker: Optional[CatalogWorker] = None


def get_worker() -> CatalogWorker:
    """Get or create the singleton catalog worker."""
    global _worker
    if _worker is None:
        import os
        interval = int(os.environ.get("MCP_CATALOG_REFRESH_SECONDS", "60"))
        _worker = CatalogWorker(refresh_interval=interval)
    return _worker
