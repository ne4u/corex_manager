"""MCP policy helpers: expression validation and builder metadata."""
import asyncio
import datetime
import json
import logging
import os
import sys
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from sqlalchemy.orm import Session

# Import shared expression engine
# In Docker, PYTHONPATH=/app makes 'shared' importable.
# For local dev, add the project root to sys.path.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from shared.expression_core import (
    parse_expression as _shared_parse_expression,
    validate_expression as _shared_validate_expression,
)

from ..core.config import get_settings
from ..core.valkey_client import _get_client
from ..models.mcp import McpIdentity, McpServer, McpServerReplica, Team

logger = logging.getLogger(__name__)
settings = get_settings()

_CATALOG_TTL = 7200  # seconds


MCP_METHODS = [
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "sampling/createMessage",
    "completion/complete",
]


def parse_mcp_expression(text: str) -> Dict[str, Any]:
    """Parse an MCP policy expression into an AST dict."""
    return _shared_parse_expression(text)


def validate_mcp_expression(text: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Validate an MCP policy expression. Returns (ok, ast, error)."""
    return _shared_validate_expression(text)


def _prefix_tool_name(namespace: str, name: str) -> str:
    """Prefix a tool/prompt name the same way the gateway does: namespace__name."""
    return f"{namespace}__{name}"


def _wrap_resource_uri(namespace: str, original_uri: str) -> str:
    """Wrap a resource URI the same way the gateway does: mcp://namespace/urlencoded."""
    return f"mcp://{namespace}/{quote(original_uri, safe='')}"


def _get_server_catalog(server: McpServer, client: Any) -> Optional[Dict[str, Any]]:
    """Return the cached catalog dict for a server, or None if unavailable."""
    if not client:
        return None
    try:
        raw = client.get(f"mcp:catalog:{server.id}")
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


def _store_server_catalog(server_id: int, catalog: Dict[str, Any]) -> None:
    """Store a server catalog in Valkey using the backend Valkey client."""
    client = _get_client()
    if not client:
        return
    try:
        client.setex(f"mcp:catalog:{server_id}", _CATALOG_TTL, json.dumps(catalog, default=str))
    except Exception:
        pass


def _clear_server_catalog(server_id: int) -> None:
    """Remove a stale or failed server catalog from Valkey."""
    client = _get_client()
    if not client:
        return
    try:
        client.delete(f"mcp:catalog:{server_id}")
    except Exception:
        pass


def _server_is_stale(server: McpServer, client: Any) -> bool:
    """Return True if a server has no usable cached catalog."""
    catalog = _get_server_catalog(server, client)
    if catalog is None:
        return True
    # Catalogs that were stored empty and never successfully refreshed are treated as stale
    # so the UI offers a manual refresh and the worker retries.
    if not server.last_catalog_at:
        if not catalog.get("tools") and not catalog.get("resources") and not catalog.get("prompts"):
            return True
    return False


async def _close_upstream_clients(upstream_mod: Any) -> None:
    """Close any httpx clients the gateway upstream module has cached."""
    for client in list(upstream_mod._clients.values()):
        try:
            await client.aclose()
        except Exception:
            pass
    upstream_mod._clients.clear()
    upstream_mod._circuit_state.clear()


async def _fetch_catalog_async(server: McpServer, db: Session) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch the catalog from the upstream server using the gateway upstream client.

    Returns (catalog, error).  catalog is None on any failure; error describes why.
    """
    import importlib

    upstream_mod = None
    for mod_name in ("mcp-gateway.upstream", "gateway.upstream"):
        try:
            upstream_mod = importlib.import_module(mod_name)
            break
        except ImportError:
            continue
    if not upstream_mod:
        return None, "MCP gateway upstream module is not available in this environment"

    await _close_upstream_clients(upstream_mod)
    initialize_upstream = upstream_mod.initialize_upstream
    fetch_catalog = upstream_mod.fetch_catalog

    from ..services.mcp_config import _build_server_dict

    replicas = db.query(McpServerReplica).filter(McpServerReplica.server_id == server.id).all()
    server_dict = _build_server_dict(server, replicas)
    # Talk to the upstream directly from the backend process (not through HAProxy)
    server_dict["url"] = server_dict.get("original_url") or server.url

    try:
        upstream_sid = await initialize_upstream(server_dict)
        if upstream_sid is None:
            # Run a diagnostic initialize to capture the exact HTTP status/body.
            status, body, _ = await upstream_mod.send_request(server_dict, {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": "0.1.0"},
                },
            })
            if isinstance(body, dict) and "error" in body:
                return None, f"MCP server initialize failed (HTTP {status}): {body['error']}"
            return None, f"MCP server initialize failed (HTTP {status}): {body}"
        catalog = await fetch_catalog(server_dict, upstream_sid)
        if not catalog:
            return None, "MCP server returned no catalog"
        return catalog, None
    except Exception as e:
        logger.error("Failed to refresh catalog for server %s: %s", server.name, e)
        return None, str(e)


def refresh_server_catalog(server: McpServer, db: Session) -> Optional[Dict[str, Any]]:
    """Refresh and store the catalog for a single server (synchronous wrapper)."""
    try:
        catalog, error = asyncio.run(_fetch_catalog_async(server, db))
    except RuntimeError:
        # Should only happen if called from inside an existing event loop;
        # fall back to a new thread with a fresh loop.
        catalog, error = None, "MCP catalog refresh could not run in the current event loop"
    except Exception as e:
        logger.error("Unexpected error refreshing catalog for %s: %s", server.name, e)
        catalog, error = None, str(e)

    now = datetime.datetime.now(datetime.timezone.utc)
    server.last_seen_at = now
    if not catalog:
        _clear_server_catalog(server.id)
        server.health_status = "unhealthy"
        server.last_error = error or "Failed to fetch server catalog"
        db.commit()
        return None

    _store_server_catalog(server.id, catalog)
    server.last_catalog_at = now
    server.health_status = "healthy"
    server.last_error = None
    db.commit()
    return catalog


def _background_refresh_thread(server_ids: List[int]) -> None:
    """Refresh catalogs for the given server IDs in a background thread."""
    from ..core.database import SessionLocal
    for sid in server_ids:
        db = SessionLocal()
        try:
            try:
                server = db.get(McpServer, sid)
                if not server or not server.enabled:
                    continue
                refresh_server_catalog(server, db)
            except Exception:
                # Tests may delete/lock rows while the thread runs; ignore.
                logger.exception("Background catalog refresh failed for server %s", sid)
        finally:
            db.close()


def trigger_background_catalog_refresh(server_ids: List[int]) -> None:
    """Fire-and-forget background refresh for a list of server IDs."""
    if not server_ids:
        return
    # Don't spawn background threads during unit tests; the shared SQLite
    # database and threadpools can deadlock with the test teardown.
    if os.environ.get("PYTEST_VERSION"):
        return
    t = threading.Thread(target=_background_refresh_thread, args=(server_ids,), daemon=True)
    t.start()


def build_policy_builder_metadata(db: Session, team_ids: List[int]) -> Dict[str, Any]:
    """Return all dynamic data needed by the Add Policy builder for the user's teams."""
    client = _get_client()

    servers: List[Dict[str, Any]] = []
    stale_servers: List[Dict[str, Any]] = []
    tools: List[str] = []
    resources: List[str] = []
    prompts: List[str] = []

    if team_ids:
        for server in (
            db.query(McpServer)
            .filter(McpServer.team_id.in_(team_ids), McpServer.enabled == True)  # noqa: E712
            .order_by(McpServer.name)
            .all()
        ):
            server_meta = {
                "id": server.id,
                "namespace": server.namespace,
                "name": server.name,
                "last_catalog_at": server.last_catalog_at.isoformat() if server.last_catalog_at else None,
                "stale": _server_is_stale(server, client),
            }
            servers.append(server_meta)

            if server_meta["stale"]:
                stale_servers.append({
                    "id": server.id,
                    "namespace": server.namespace,
                    "name": server.name,
                    "last_catalog_at": server_meta["last_catalog_at"],
                })

            catalog = _get_server_catalog(server, client)
            if not catalog:
                continue

            namespace = server.namespace
            for tool in catalog.get("tools", []):
                name = tool.get("name") if isinstance(tool, dict) else None
                if name:
                    tools.append(_prefix_tool_name(namespace, name))
            for resource in catalog.get("resources", []):
                uri = resource.get("uri") if isinstance(resource, dict) else None
                if uri:
                    resources.append(_wrap_resource_uri(namespace, uri))
            for prompt in catalog.get("prompts", []):
                name = prompt.get("name") if isinstance(prompt, dict) else None
                if name:
                    prompts.append(_prefix_tool_name(namespace, name))

    identities: List[str] = []
    if team_ids:
        for identity in (
            db.query(McpIdentity)
            .filter(McpIdentity.team_id.in_(team_ids))
            .order_by(McpIdentity.name)
            .all()
        ):
            identities.append(identity.name)

    teams: List[Dict[str, Any]] = []
    if team_ids:
        for team in db.query(Team).filter(Team.id.in_(team_ids)).order_by(Team.name).all():
            teams.append({"id": team.id, "name": team.name, "slug": team.slug})

    return {
        "methods": MCP_METHODS,
        "servers": servers,
        "stale_servers": stale_servers,
        "tools": sorted(set(t for t in tools if t)),
        "resources": sorted(set(r for r in resources if r)),
        "prompts": sorted(set(p for p in prompts if p)),
        "identities": identities,
        "identity_kinds": ["pat", "jwt"],
        "teams": teams,
    }
