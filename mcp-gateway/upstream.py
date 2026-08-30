"""Upstream MCP client — httpx-based Streamable HTTP client.

Manages per-server httpx.AsyncClient instances, creates upstream sessions
on first use (initialize), and forwards JSON-RPC requests with the stored
auth header and Mcp-Session-Id.

Phase 2 additions:
- fetch_catalog: paginated tools/list, resources/list, prompts/list
- In-flight task tracking for notifications/cancelled
"""
import asyncio
import json
import logging
import time
from typing import Any, Optional

import httpx

try:
    from .ssrf import is_url_safe
    from .stdio_proxy import get_process_manager
except ImportError:
    from ssrf import is_url_safe
    from stdio_proxy import get_process_manager

logger = logging.getLogger(__name__)

# Per-server httpx clients: {server_id: httpx.AsyncClient}
_clients: dict[int, httpx.AsyncClient] = {}

# In-flight tasks keyed by (session_id, jsonrpc_id) for cancellation
_inflight: dict[tuple[str, Any], asyncio.Task] = {}

# --- Circuit breaker ---
# Per-server circuit breaker state: {server_id: {failures, last_failure, open_until}}
_CB_FAILURE_THRESHOLD = int(__import__("os").environ.get("MCP_CB_FAILURE_THRESHOLD", "5"))
_CB_RESET_SECONDS = int(__import__("os").environ.get("MCP_CB_RESET_SECONDS", "60"))
_circuit_state: dict[int, dict] = {}


def _get_client(server: dict) -> httpx.AsyncClient:
    """Get or create an httpx.AsyncClient for a server."""
    sid = server["id"]
    if sid not in _clients:
        verify = server.get("verify_tls", True)
        timeout = (server.get("timeout_ms", 30000)) / 1000.0
        _clients[sid] = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=10.0),
            verify=verify,
            http2=False,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _clients[sid]


def _build_headers(server: dict, upstream_session_id: Optional[str] = None) -> dict:
    """Build request headers for an upstream call."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    auth_type = server.get("auth_type", "none")
    if auth_type == "bearer" and server.get("auth_secret"):
        headers["Authorization"] = f"Bearer {server['auth_secret']}"
    elif auth_type == "header" and server.get("auth_secret"):
        header_name = server.get("auth_header", "Authorization")
        headers[header_name] = server["auth_secret"]
    if upstream_session_id:
        headers["Mcp-Session-Id"] = upstream_session_id
    return headers


def _check_circuit(server_id: int) -> bool:
    """Check if circuit breaker is open. Returns True if request should proceed."""
    state = _circuit_state.get(server_id)
    if not state:
        return True
    open_until = state.get("open_until", 0)
    if open_until > time.time():
        return False  # Circuit open
    # Half-open: allow one request through
    return True


def _record_upstream_success(server_id: int) -> None:
    """Record a successful upstream request — reset circuit breaker."""
    _circuit_state.pop(server_id, None)


def _record_upstream_failure(server_id: int) -> None:
    """Record an upstream failure — may trip circuit breaker."""
    state = _circuit_state.setdefault(server_id, {"failures": 0, "last_failure": 0, "open_until": 0})
    state["failures"] = state.get("failures", 0) + 1
    state["last_failure"] = time.time()
    if state["failures"] >= _CB_FAILURE_THRESHOLD:
        state["open_until"] = time.time() + _CB_RESET_SECONDS
        logger.warning("Circuit breaker opened for server %d (%d failures)",
                       server_id, state["failures"])


def is_circuit_open(server_id: int) -> bool:
    """Public API: check if circuit is open for a server."""
    return not _check_circuit(server_id)


def _is_stdio(server: dict) -> bool:
    """Check if a server uses stdio transport."""
    return server.get("transport_type") == "stdio"


async def initialize_upstream(server: dict) -> Optional[str]:
    """Send initialize to upstream, return the upstream session ID."""
    if _is_stdio(server):
        return await get_process_manager().initialize_upstream(server)

    # SSRF check
    safe, reason = is_url_safe(server["url"])
    if not safe:
        logger.error("SSRF blocked upstream URL %s: %s", server["url"], reason)
        return None

    if not _check_circuit(server["id"]):
        logger.warning("Circuit breaker open for server %s, skipping initialize", server.get("name"))
        return None

    client = _get_client(server)
    url = server["url"]
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-gateway",
                "version": "0.1.0",
            },
        },
    }
    headers = _build_headers(server)
    try:
        resp = await client.post(url, json=body, headers=headers)
        # Extract session ID from response header
        upstream_sid = resp.headers.get("Mcp-Session-Id")
        if resp.status_code == 200:
            _record_upstream_success(server["id"])
            return upstream_sid
        logger.warning("Upstream initialize returned %d for %s", resp.status_code, url)
        _record_upstream_failure(server["id"])
        return upstream_sid  # Some servers may return session even on partial success
    except Exception as e:
        logger.error("Upstream initialize failed for %s: %s", url, e)
        _record_upstream_failure(server["id"])
        return None


async def send_request(
    server: dict,
    message: dict,
    upstream_session_id: Optional[str] = None,
) -> tuple[int, dict | str, dict]:
    """Send a JSON-RPC request to an upstream server.

    Returns (status_code, body, response_headers).
    Body is parsed JSON if Content-Type is application/json, raw text otherwise.
    """
    if _is_stdio(server):
        return await get_process_manager().send_request(server, message)

    sid = server["id"]
    if not _check_circuit(sid):
        return 503, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Upstream circuit breaker open"}}, {}

    client = _get_client(server)
    url = server["url"]
    headers = _build_headers(server, upstream_session_id)
    try:
        resp = await client.post(url, json=message, headers=headers)
        resp_headers = dict(resp.headers)
        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type:
            body = resp.json()
        else:
            body = resp.text
        if resp.status_code < 500:
            _record_upstream_success(sid)
        else:
            _record_upstream_failure(sid)
        return resp.status_code, body, resp_headers
    except httpx.TimeoutException:
        logger.error("Upstream timeout for %s", url)
        _record_upstream_failure(sid)
        return 504, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Upstream timeout"}}, {}
    except Exception as e:
        logger.error("Upstream request failed for %s: %s", url, e)
        _record_upstream_failure(sid)
        return 502, {"jsonrpc": "2.0", "error": {"code": -32000, "message": f"Upstream error: {e}"}}, {}


async def send_notification(
    server: dict,
    message: dict,
    upstream_session_id: Optional[str] = None,
) -> int:
    """Send a JSON-RPC notification (no response expected). Returns status code."""
    if _is_stdio(server):
        return await get_process_manager().send_notification(server, message)

    client = _get_client(server)
    url = server["url"]
    headers = _build_headers(server, upstream_session_id)
    try:
        resp = await client.post(url, json=message, headers=headers)
        return resp.status_code
    except Exception as e:
        logger.error("Upstream notification failed for %s: %s", url, e)
        return 502


def close_client(server_id: int) -> None:
    """Close and remove an httpx client for a server."""
    client = _clients.pop(server_id, None)
    if client:
        # Schedule close — can't await here
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(client.aclose())
        except RuntimeError:
            pass  # No event loop


async def send_request_tracked(
    session_id: str,
    msg_id: Any,
    server: dict,
    message: dict,
    upstream_session_id: Optional[str] = None,
) -> tuple[int, dict | str, dict]:
    """Send a JSON-RPC request, tracking it for cancellation.

    Registers the task in _inflight keyed by (session_id, msg_id) so
    notifications/cancelled can abort it.
    """
    task = asyncio.current_task()
    if task:
        _inflight[(session_id, msg_id)] = task
    try:
        return await send_request(server, message, upstream_session_id)
    finally:
        _inflight.pop((session_id, msg_id), None)


def cancel_inflight(session_id: str, msg_id: Any) -> bool:
    """Cancel an in-flight upstream request. Returns True if cancelled."""
    key = (session_id, msg_id)
    task = _inflight.get(key)
    if task and not task.done():
        task.cancel()
        _inflight.pop(key, None)
        return True
    return False


async def _fetch_list(
    server: dict,
    method: str,
    upstream_session_id: Optional[str],
    key: str,
) -> list[dict]:
    """Fetch a paginated list method from upstream. Returns items list."""
    items: list[dict] = []
    cursor = None
    client = _get_client(server)
    url = server["url"]
    headers = _build_headers(server, upstream_session_id)
    req_id = 1

    while True:
        params: dict = {}
        if cursor:
            params["cursor"] = cursor
        body = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }
        try:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code != 200:
                logger.warning("Upstream %s returned %d for %s", url, resp.status_code, method)
                break
            data = resp.json()
            if "error" in data:
                logger.warning("Upstream %s error on %s: %s", url, method, data["error"])
                break
            result = data.get("result", {})
            items.extend(result.get(key, []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
            req_id += 1
        except Exception as e:
            logger.error("Upstream %s failed on %s: %s", url, method, e)
            break

    return items


async def fetch_catalog(
    server: dict,
    upstream_session_id: Optional[str] = None,
) -> Optional[dict]:
    """Fetch the full catalog (tools, resources, prompts) from an upstream server.

    Returns {"tools": [...], "resources": [...], "prompts": [...]} or None on failure.
    """
    if _is_stdio(server):
        return await get_process_manager().fetch_catalog(server)

    try:
        tools = await _fetch_list(server, "tools/list", upstream_session_id, "tools")
    except Exception as e:
        logger.error("Failed to fetch tools/list for %s: %s", server.get("name"), e)
        tools = []

    try:
        resources = await _fetch_list(server, "resources/list", upstream_session_id, "resources")
    except Exception as e:
        logger.error("Failed to fetch resources/list for %s: %s", server.get("name"), e)
        resources = []

    try:
        prompts = await _fetch_list(server, "prompts/list", upstream_session_id, "prompts")
    except Exception as e:
        logger.error("Failed to fetch prompts/list for %s: %s", server.get("name"), e)
        prompts = []

    return {
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
        "fetched_at": __import__("time").time(),
    }


async def close_all_clients() -> None:
    """Close all upstream clients on shutdown."""
    # Cancel any in-flight tasks
    for key, task in list(_inflight.items()):
        if not task.done():
            task.cancel()
    _inflight.clear()

    for sid in list(_clients.keys()):
        client = _clients.pop(sid, None)
        if client:
            await client.aclose()

    # Stop all stdio processes
    await get_process_manager().shutdown_all()
