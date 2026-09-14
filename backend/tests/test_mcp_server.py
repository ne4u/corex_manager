"""Tests for the coreX Manager MCP server (mcp-server/ package).

Exercises:
- Tool discovery (OpenAPI spec → MCP tool transform).
- Tool execution forwarded over HTTP (tested via an ASGI-transport client).
- Resource listing and reading.
- Prompt listing and fetching.
- The JSON-RPC dispatch over the FastAPI app (initialize, tools/list, tools/call).
- Auth gating when COREX_MCP_TOKEN is set.
- Self-registration service (ensure_self_registration) against the DB.
"""

import importlib
import sys
from pathlib import Path

import pytest

# Make the mcp-server package importable. It lives at the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MCP_SERVER_DIR = _REPO_ROOT / "mcp-server"
if str(_MCP_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_SERVER_DIR))


# ---------------------------------------------------------------------------
# Tool discovery (OpenAPI spec → MCP tools)
# ---------------------------------------------------------------------------


@pytest.fixture
def openapi_spec():
    """The backend app's real OpenAPI spec, injected into discover_tools."""
    from app.main import app as backend_app

    return backend_app.openapi()


@pytest.mark.asyncio
async def test_discover_tools_returns_non_empty_list(openapi_spec):
    import tools as mcp_tools  # noqa: F401  (the mcp-server module)

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    assert isinstance(discovered, list)
    assert len(discovered) > 0, "expected backend v1 routes to produce MCP tools"


@pytest.mark.asyncio
async def test_discover_tools_have_required_fields(openapi_spec):
    import tools as mcp_tools

    for t in await mcp_tools.discover_tools(spec=openapi_spec):
        assert "name" in t and isinstance(t["name"], str) and t["name"]
        assert "description" in t
        assert "inputSchema" in t and isinstance(t["inputSchema"], dict)
        # JSON Schema must declare an object type for arguments
        assert t["inputSchema"].get("type") == "object"


@pytest.mark.asyncio
async def test_discover_tool_names_unique(openapi_spec):
    import tools as mcp_tools

    names = [t["name"] for t in await mcp_tools.discover_tools(spec=openapi_spec)]
    assert len(names) == len(set(names)), f"duplicate tool names: {names}"


@pytest.mark.asyncio
async def test_discover_tools_include_core_endpoints(openapi_spec):
    """A few well-known backend endpoints should be present as tools."""
    import tools as mcp_tools

    names = {t["name"] for t in await mcp_tools.discover_tools(spec=openapi_spec)}
    # At least one tool should mention backends or listeners
    assert any("backend" in n for n in names), names
    assert any("listener" in n for n in names), names


@pytest.mark.asyncio
async def test_tool_names_match_operation_function_names(openapi_spec):
    """operationId suffix stripping should recover clean function names."""
    import tools as mcp_tools

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    names = {t["name"] for t in discovered}
    # These are endpoint function names; if suffix stripping regressed the
    # names would look like list_backends_api_v1_backends_get.
    assert "list_backends" in names
    assert "list_listener_endpoints" in names
    assert not any("_api_v1_" in n for n in names), [n for n in names if "_api_v1_" in n]


@pytest.mark.asyncio
async def test_tool_name_derivation_unit():
    import tools as mcp_tools

    assert mcp_tools._tool_name("list_backends_api_v1_backends_get", "/api/v1/backends", "GET") == "list_backends"
    # Fallback: non-matching operationId passes through
    assert mcp_tools._tool_name("customOp", "/api/v1/x", "GET") == "customOp"
    # Missing operationId derives from method+path
    assert mcp_tools._tool_name("", "/api/v1/backends", "GET") == "get_api_v1_backends"


@pytest.mark.asyncio
async def test_path_and_query_params_mapped(openapi_spec):
    import tools as mcp_tools

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    by_key = {(t["_method"], t["_path"]): t for t in discovered}
    tool = by_key.get(("GET", "/api/v1/backends/{bid}"))
    assert tool is not None, "expected GET /api/v1/backends/{bid} tool"
    props = tool["inputSchema"]["properties"]
    assert "bid" in props and props["bid"]["type"] == "integer"
    assert "bid" in tool["inputSchema"]["required"]
    assert "bid" in tool["_path_params"]


@pytest.mark.asyncio
async def test_json_body_schema_inlines_defs(openapi_spec):
    """Body schemas must be self-contained ($defs inlined, refs rewritten)."""
    import tools as mcp_tools

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    body_tools = [t for t in discovered if t["_body_kind"] == "json"]
    assert body_tools, "expected at least one JSON-body tool"
    import json as _json

    for t in body_tools:
        blob = _json.dumps(t["inputSchema"]["properties"]["body"])
        assert "#/components/schemas/" not in blob, f"{t['name']}: unresolved component ref leaked into tool schema"


@pytest.mark.asyncio
async def test_form_body_tool_exists(openapi_spec):
    """Form-encoded endpoints (e.g. /auth/token) are exposed with form bodies."""
    import tools as mcp_tools

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    by_key = {(t["_method"], t["_path"]): t for t in discovered}
    token_tool = by_key.get(("POST", "/api/v1/auth/token"))
    assert token_tool is not None, "expected POST /api/v1/auth/token tool"
    assert token_tool["_body_kind"] == "form"


@pytest.mark.asyncio
async def test_file_upload_tools_skipped(openapi_spec):
    """Operations whose only body is a file upload are not exposed as tools."""
    import tools as mcp_tools

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    for t in discovered:
        props = t["inputSchema"]["properties"]
        if "body" in props and t["_body_kind"] == "form":
            import json as _json

            assert '"binary"' not in _json.dumps(props["body"]), t["name"]


@pytest.mark.asyncio
async def test_call_tool_via_asgi_transport(db, monkeypatch, openapi_spec):
    """call_tool forwards to the backend; test with an in-process ASGI client."""
    import httpx
    import tools as mcp_tools
    from app.main import app as backend_app
    from app.models.models import User

    db.add(User(username="admin", hashed_password="x", role="admin", is_admin=True))
    db.commit()

    asgi_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend_app), base_url="http://test")
    monkeypatch.setattr(mcp_tools, "_client", asgi_client)

    discovered = await mcp_tools.discover_tools(spec=openapi_spec)
    tool = next(t for t in discovered if t["_method"] == "GET" and t["_path"] == "/api/v1/backends")
    text, is_error = await mcp_tools.call_tool(tool, {})
    assert not is_error, text
    import json as _json

    assert isinstance(_json.loads(text), list)


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


def test_list_resources_returns_list():
    import resources as mcp_resources

    res = mcp_resources.list_resources()
    assert isinstance(res, list)
    for r in res:
        assert "uri" in r
        assert "name" in r


@pytest.mark.asyncio
async def test_read_unknown_resource_returns_none():
    import resources as mcp_resources

    result = await mcp_resources.read_resource("corex://does-not-exist")
    assert result is None


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


def test_list_prompts_returns_list():
    import prompts as mcp_prompts

    plist = mcp_prompts.list_prompts()
    assert isinstance(plist, list)
    assert len(plist) > 0
    for p in plist:
        assert "name" in p
        assert "description" in p


def test_get_prompt_corex_manager_guide():
    import prompts as mcp_prompts

    result = mcp_prompts.get_prompt("corex-manager-guide", {})
    assert result is not None
    # MCP prompt result shape: {"description": ..., "messages": [...]}
    assert "messages" in result
    messages = result["messages"]
    assert len(messages) > 0
    # The guide body should mention coreX Manager
    blob = json_blob(messages)
    assert "coreX Manager" in blob or "corex" in blob.lower()


def test_get_unknown_prompt_returns_none():
    import prompts as mcp_prompts

    assert mcp_prompts.get_prompt("no-such-prompt", {}) is None


def json_blob(messages):
    import json as _json

    return _json.dumps(messages)


# ---------------------------------------------------------------------------
# JSON-RPC dispatch via the FastAPI app (TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_app_client(monkeypatch, openapi_spec):
    """Spin up the mcp-server FastAPI app with auth disabled and a fresh tool cache."""
    monkeypatch.delenv("COREX_MCP_TOKEN", raising=False)
    # Stub the OpenAPI fetch — the spec comes from the backend app in-process.
    import tools as mcp_tools

    async def _fake_fetch():
        return openapi_spec

    monkeypatch.setattr(mcp_tools, "_fetch_openapi", _fake_fetch)
    # Reset the tools cache so a stale cache from another test doesn't leak.
    import server as mcp_server

    mcp_server._tools_cache = None
    from fastapi.testclient import TestClient

    with TestClient(mcp_server.app) as c:
        yield c


def _rpc(client, method, params=None, msg_id=1):
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}},
    )


def test_initialize(mcp_app_client):
    resp = _rpc(
        mcp_app_client,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.0"},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    result = body["result"]
    assert result["serverInfo"]["name"] == "corex-manager"
    assert "tools" in result["capabilities"]
    assert "resources" in result["capabilities"]
    assert "prompts" in result["capabilities"]


def test_tools_list_via_rpc(mcp_app_client):
    resp = _rpc(mcp_app_client, "tools/list")
    assert resp.status_code == 200
    tools = resp.json()["result"]["tools"]
    assert len(tools) > 0
    names = {t["name"] for t in tools}
    assert any("backend" in n for n in names)


def test_resources_list_via_rpc(mcp_app_client):
    resp = _rpc(mcp_app_client, "resources/list")
    assert resp.status_code == 200
    resources = resp.json()["result"]["resources"]
    assert len(resources) > 0


def test_prompts_list_via_rpc(mcp_app_client):
    resp = _rpc(mcp_app_client, "prompts/list")
    assert resp.status_code == 200
    prompts = resp.json()["result"]["prompts"]
    names = {p["name"] for p in prompts}
    assert "corex-manager-guide" in names


def test_unknown_method_returns_error(mcp_app_client):
    resp = _rpc(mcp_app_client, "no/such/method")
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == -32601  # METHOD_NOT_FOUND


def test_healthz(mcp_app_client):
    resp = mcp_app_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_auth_required_when_token_set(monkeypatch, openapi_spec):
    monkeypatch.setenv("COREX_MCP_TOKEN", "secret-token-123")
    import tools as mcp_tools

    async def _fake_fetch():
        return openapi_spec

    monkeypatch.setattr(mcp_tools, "_fetch_openapi", _fake_fetch)
    import server as mcp_server

    importlib.reload(mcp_server)
    mcp_server._tools_cache = None
    from fastapi.testclient import TestClient

    with TestClient(mcp_server.app) as c:
        # No auth header -> 401
        resp = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp.status_code == 401
        # With correct bearer token -> 200
        resp = c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={"Authorization": "Bearer secret-token-123"},
        )
        assert resp.status_code == 200
    # Cleanup: reload without the token so other tests aren't affected.
    monkeypatch.delenv("COREX_MCP_TOKEN", raising=False)
    importlib.reload(mcp_server)
    mcp_server._tools_cache = None


# ---------------------------------------------------------------------------
# Self-registration service
# ---------------------------------------------------------------------------


def test_self_registration_skipped_when_gateway_disabled(db, monkeypatch):
    """When MCP_GATEWAY_ENABLED is False, ensure_self_registration is a no-op."""
    from app.models.mcp import McpServer
    from app.services.mcp_self_register import ensure_self_registration

    monkeypatch.setattr("app.services.mcp_self_register.settings.MCP_GATEWAY_ENABLED", False)
    ensure_self_registration(db)
    assert db.query(McpServer).filter(McpServer.namespace == "corex-manager").count() == 0


def test_self_registration_creates_server_and_skill(db, monkeypatch):
    """With gateway enabled + secrets key set, registration creates the rows."""
    from app.models.mcp import McpServer, McpSkill, Team
    from app.services import mcp_self_register as mod

    monkeypatch.setattr(
        mod,
        "settings",
        type(
            "S",
            (),
            {
                "MCP_GATEWAY_ENABLED": True,
                "MCP_SELF_REGISTER": True,
                "MCP_SERVER_INTERNAL_HOST": "mcp-server",
                "MCP_SERVER_INTERNAL_PORT": 8082,
            },
        )(),
    )
    monkeypatch.setattr(mod, "has_secrets_key", lambda: True)
    monkeypatch.setattr(mod, "encrypt_secret", lambda raw: f"enc:{raw}")
    # decrypt_secret is imported lazily inside ensure_self_registration
    monkeypatch.setattr(
        "app.services.mcp_secrets.decrypt_secret",
        lambda raw: raw.split("enc:", 1)[-1] if raw else "",
    )
    monkeypatch.setenv("COREX_MCP_TOKEN", "test-token")
    # Stub write_config_bundle so it doesn't touch the filesystem.
    monkeypatch.setattr(
        "app.services.mcp_config.write_config_bundle",
        lambda _db: None,
        raising=False,
    )

    mod.ensure_self_registration(db)

    server = db.query(McpServer).filter(McpServer.namespace == "corex-manager").first()
    assert server is not None
    assert server.enabled is True
    assert server.url == "http://mcp-server:8082/mcp"

    skill = db.query(McpSkill).filter(McpSkill.name == "corex-manager").first()
    assert skill is not None
    assert skill.enabled is True

    team = db.query(Team).filter(Team.slug == "platform").first()
    assert team is not None

    # Idempotent: running again should not duplicate rows.
    mod.ensure_self_registration(db)
    assert db.query(McpServer).filter(McpServer.namespace == "corex-manager").count() == 1
    assert db.query(McpSkill).filter(McpSkill.name == "corex-manager").count() == 1
