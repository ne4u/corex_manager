"""Tests for the coreX Manager MCP server (mcp-server/ package).

Exercises:
- Tool discovery (introspection of the backend v1 router).
- Resource listing and reading.
- Prompt listing and fetching.
- The JSON-RPC dispatch over the FastAPI app (initialize, tools/list, tools/call).
- Auth gating when COREX_MCP_TOKEN is set.
- Self-registration service (ensure_self_registration) against the DB.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

# Make the mcp-server package importable. It lives at the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MCP_SERVER_DIR = _REPO_ROOT / "mcp-server"
if str(_MCP_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_SERVER_DIR))


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def test_discover_tools_returns_non_empty_list():
    import tools as mcp_tools  # noqa: F401  (the mcp-server module)
    discovered = mcp_tools.discover_tools()
    assert isinstance(discovered, list)
    assert len(discovered) > 0, "expected backend v1 routes to produce MCP tools"


def test_discover_tools_have_required_fields():
    import tools as mcp_tools
    for t in mcp_tools.discover_tools():
        assert "name" in t and isinstance(t["name"], str) and t["name"]
        assert "description" in t
        assert "inputSchema" in t and isinstance(t["inputSchema"], dict)
        # JSON Schema must declare an object type for arguments
        assert t["inputSchema"].get("type") == "object"


def test_discover_tool_names_unique():
    import tools as mcp_tools
    names = [t["name"] for t in mcp_tools.discover_tools()]
    assert len(names) == len(set(names)), f"duplicate tool names: {names}"


def test_discover_tools_include_core_endpoints():
    """A few well-known backend endpoints should be present as tools."""
    import tools as mcp_tools
    names = {t["name"] for t in mcp_tools.discover_tools()}
    # At least one tool should mention backends or listeners
    assert any("backend" in n for n in names), names
    assert any("listener" in n for n in names), names


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
def mcp_app_client(monkeypatch):
    """Spin up the mcp-server FastAPI app with auth disabled and a fresh tool cache."""
    monkeypatch.delenv("COREX_MCP_TOKEN", raising=False)
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
    resp = _rpc(mcp_app_client, "initialize", {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0.0"},
    })
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

def test_auth_required_when_token_set(monkeypatch):
    monkeypatch.setenv("COREX_MCP_TOKEN", "secret-token-123")
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
    from app.services.mcp_self_register import ensure_self_registration
    from app.models.mcp import McpServer
    monkeypatch.setattr("app.services.mcp_self_register.settings.MCP_GATEWAY_ENABLED", False)
    ensure_self_registration(db)
    assert db.query(McpServer).filter(McpServer.namespace == "corex-manager").count() == 0


def test_self_registration_creates_server_and_skill(db, monkeypatch):
    """With gateway enabled + secrets key set, registration creates the rows."""
    from app.services import mcp_self_register as mod
    from app.models.mcp import McpServer, McpSkill, Team

    monkeypatch.setattr(mod, "settings", type("S", (), {
        "MCP_GATEWAY_ENABLED": True,
        "MCP_SELF_REGISTER": True,
        "MCP_SERVER_INTERNAL_HOST": "mcp-server",
        "MCP_SERVER_INTERNAL_PORT": 8082,
    })())
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
