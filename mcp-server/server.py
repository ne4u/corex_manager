"""coreX Manager MCP Server — Streamable HTTP JSON-RPC endpoint.

Implements MCP spec 2025-11-25:
- POST /mcp: JSON-RPC request/notification/response (Streamable HTTP)
- GET /mcp: 405 (no unsolicited server messages in v1)
- GET /healthz: liveness check
- GET /.well-known/oauth-protected-resource: RFC 9728 metadata

Tools are auto-generated from the backend v1 router and executed in-process.
The skill guidance is served as the `corex-manager-guide` MCP prompt, making
it portable to any MCP-compatible AI CLI agent.
"""
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

try:
    from . import tools, resources, prompts
except ImportError:
    import tools
    import resources
    import prompts

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-11-25"
SERVER_NAME = "corex-manager"
SERVER_VERSION = "1.0.0"

# Bearer token auth (optional)
_MCP_TOKEN = os.environ.get("COREX_MCP_TOKEN", "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("coreX Manager MCP Server starting")
    # Pre-warm tool discovery so the first tools/list is fast
    try:
        _tools_cache = tools.discover_tools()
        logger.info("Discovered %d tools", len(_tools_cache))
    except Exception as e:
        logger.warning("Tool discovery at startup failed (will retry on first call): %s", e)
    yield
    logger.info("coreX Manager MCP Server shutting down")
    await tools.close_client()


app = FastAPI(
    title="coreX Manager MCP Server",
    description="MCP server exposing the coreX Manager (HAProxy + WAF) control plane.",
    version=SERVER_VERSION,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _check_auth(request: Request) -> bool:
    """Validate bearer token if COREX_MCP_TOKEN is configured."""
    if not _MCP_TOKEN:
        return True  # Open — the gateway is the gatekeeper
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:] == _MCP_TOKEN
    return False


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _error_response(msg_id: Any, code: int, message: str, data: Any = None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": err}


def _result_response(msg_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _is_request(msg: dict) -> bool:
    return "method" in msg


def _is_notification(msg: dict) -> bool:
    return "method" in msg and "id" not in msg


def _is_response(msg: dict) -> bool:
    return "method" not in msg and ("result" in msg or "error" in msg)


# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# ---------------------------------------------------------------------------
# Tool cache
# ---------------------------------------------------------------------------

_tools_cache: list[dict] | None = None


def _get_tools() -> list[dict]:
    global _tools_cache
    if _tools_cache is None:
        _tools_cache = tools.discover_tools()
    return _tools_cache


def _find_tool(name: str) -> dict | None:
    return next((t for t in _get_tools() if t["name"] == name), None)


# ---------------------------------------------------------------------------
# Method handlers
# ---------------------------------------------------------------------------

def _handle_initialize(params: dict, msg_id: Any) -> dict:
    result = {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"listChanged": False, "subscribe": False},
            "prompts": {"listChanged": False},
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        },
    }
    resp = _result_response(msg_id, result)
    # The gateway extracts session ID from the response header; we set it on
    # the JSONResponse in the route handler.
    return resp


def _handle_tools_list(params: dict, msg_id: Any) -> dict:
    tool_list = []
    for t in _get_tools():
        tool_list.append({
            "name": t["name"],
            "description": t["description"],
            "inputSchema": t["inputSchema"],
        })
    return _result_response(msg_id, {"tools": tool_list})


async def _handle_tools_call(params: dict, msg_id: Any) -> dict:
    name = params.get("name", "")
    args = params.get("arguments", {}) or {}
    tool = _find_tool(name)
    if not tool:
        return _error_response(msg_id, METHOD_NOT_FOUND, f"Unknown tool: {name}")
    try:
        text, is_error = await tools.call_tool(tool, args)
    except Exception as e:
        logger.exception("Tool execution failed: %s", name)
        return _error_response(msg_id, INTERNAL_ERROR, f"Tool execution failed: {e}")
    return _result_response(msg_id, {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    })


def _handle_resources_list(params: dict, msg_id: Any) -> dict:
    return _result_response(msg_id, {"resources": resources.list_resources()})


async def _handle_resources_read(params: dict, msg_id: Any) -> dict:
    uri = params.get("uri", "")
    result = await resources.read_resource(uri)
    if result is None:
        return _error_response(msg_id, METHOD_NOT_FOUND, f"Unknown resource: {uri}")
    return _result_response(msg_id, result)


def _handle_resources_templates(params: dict, msg_id: Any) -> dict:
    return _result_response(msg_id, {"resourceTemplates": []})


def _handle_prompts_list(params: dict, msg_id: Any) -> dict:
    return _result_response(msg_id, {"prompts": prompts.list_prompts()})


def _handle_prompts_get(params: dict, msg_id: Any) -> dict:
    name = params.get("name", "")
    args = params.get("arguments", {}) or {}
    result = prompts.get_prompt(name, args)
    if result is None:
        return _error_response(msg_id, METHOD_NOT_FOUND, f"Unknown prompt: {name}")
    return _result_response(msg_id, result)


# ---------------------------------------------------------------------------
# Main POST /mcp handler
# ---------------------------------------------------------------------------

async def _handle_message(msg: dict) -> dict | None:
    """Handle a single JSON-RPC message. Returns a response dict or None (notification)."""
    if not isinstance(msg, dict):
        return _error_response(None, INVALID_REQUEST, "Message must be an object")

    msg_id = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params", {}) or {}

    if _is_notification(msg):
        # Acknowledge notifications silently (no response)
        if method == "notifications/initialized":
            pass
        return None

    if not _is_request(msg):
        return _error_response(msg_id, INVALID_REQUEST, "Not a valid request")

    if method == "initialize":
        return _handle_initialize(params, msg_id)
    if method == "ping":
        return _result_response(msg_id, {})
    if method == "tools/list":
        return _handle_tools_list(params, msg_id)
    if method == "tools/call":
        return await _handle_tools_call(params, msg_id)
    if method == "resources/list":
        return _handle_resources_list(params, msg_id)
    if method == "resources/read":
        return await _handle_resources_read(params, msg_id)
    if method == "resources/templates/list":
        return _handle_resources_templates(params, msg_id)
    if method == "prompts/list":
        return _handle_prompts_list(params, msg_id)
    if method == "prompts/get":
        return _handle_prompts_get(params, msg_id)

    return _error_response(msg_id, METHOD_NOT_FOUND, f"Unknown method: {method}")


@app.api_route("/mcp", methods=["POST"])
async def mcp_post(request: Request):
    # Auth check
    if not _check_auth(request):
        return JSONResponse(
            status_code=401,
            content={"jsonrpc": "2.0", "error": {"code": -32001, "message": "Unauthorized"}},
        )

    # Parse body
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=200,
            content=_error_response(None, PARSE_ERROR, "Invalid JSON"),
        )

    # Handle batch or single request
    is_batch = isinstance(body, list)
    messages = body if is_batch else [body]

    responses = []
    for msg in messages:
        try:
            resp = await _handle_message(msg)
        except Exception as e:
            logger.exception("Unhandled error processing message")
            resp = _error_response(
                msg.get("id") if isinstance(msg, dict) else None,
                INTERNAL_ERROR,
                str(e),
            )
        if resp is not None:
            responses.append(resp)

    # For notifications, return 202 with empty body
    if not responses:
        return Response(status_code=202)

    result = responses if is_batch else responses[0]
    json_resp = JSONResponse(status_code=200, content=result)
    # Set a session ID header (gateway extracts this on initialize)
    json_resp.headers["Mcp-Session-Id"] = str(uuid.uuid4())
    return json_resp


@app.api_route("/mcp", methods=["GET"])
async def mcp_get():
    # No unsolicited server messages in v1
    return Response(status_code=405)


@app.api_route("/mcp", methods=["DELETE"])
async def mcp_delete():
    # Session termination — stateless, just acknowledge
    return Response(status_code=200)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "server": SERVER_NAME, "version": SERVER_VERSION}


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    """RFC 9728 Protected Resource Metadata."""
    host = request.headers.get("host", "")
    scheme = request.headers.get("x-forwarded-proto", "https")
    base_url = f"{scheme}://{host}"
    return {
        "resource": f"{base_url}/mcp",
        "authorization_servers": [],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }
