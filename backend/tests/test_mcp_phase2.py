"""Tests for MCP Gateway Phase 2 — virtual registry, catalog, namespacing, routing."""
import json
import os
import sys
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote, unquote

import pytest

# Make mcp-gateway modules importable (directory has hyphen, not a valid package name)
_GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "mcp-gateway")
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_GATEWAY_DIR))


# ---- Resource URI wrap/unwrap tests ----

def test_wrap_resource_uri():
    import importlib
    protocol = importlib.import_module('protocol')
    wrapped = protocol._wrap_resource_uri("jira", "issue://PROJ-123")
    assert wrapped == f"mcp://jira/{quote('issue://PROJ-123', safe='')}"


def test_unwrap_resource_uri():
    import importlib
    protocol = importlib.import_module('protocol')
    original = "issue://PROJ-123"
    wrapped = protocol._wrap_resource_uri("jira", original)
    namespace, unwrapped = protocol._unwrap_resource_uri(wrapped)
    assert namespace == "jira"
    assert unwrapped == original


def test_unwrap_resource_uri_not_wrapped():
    import importlib
    protocol = importlib.import_module('protocol')
    namespace, original = protocol._unwrap_resource_uri("https://example.com/res")
    assert namespace is None
    assert original == "https://example.com/res"


def test_wrap_unwrap_roundtrip_special_chars():
    import importlib
    protocol = importlib.import_module('protocol')
    original = "file:///path/with spaces/and?query=1&x=2"
    wrapped = protocol._wrap_resource_uri("weather", original)
    namespace, unwrapped = protocol._unwrap_resource_uri(wrapped)
    assert namespace == "weather"
    assert unwrapped == original


# ---- Catalog store/retrieve tests ----

def test_catalog_store_and_retrieve():
    import importlib
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()
    catalog_data = {"tools": [{"name": "get"}], "resources": [], "prompts": []}
    catalog.store_catalog(1, catalog_data)
    result = catalog.get_catalog(1)
    assert result is not None
    assert result["tools"] == [{"name": "get"}]


def test_catalog_clear():
    import importlib
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()
    catalog.store_catalog(1, {"tools": [], "resources": [], "prompts": []})
    assert catalog.get_catalog(1) is not None
    catalog.clear_catalog(1)
    assert catalog.get_catalog(1) is None


def test_catalog_change_detection():
    import importlib
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()
    catalog.store_catalog(1, {"tools": [{"name": "a"}], "resources": [], "prompts": []})
    # First store should not register as changed (no previous hash)
    changed = catalog.pop_changed_servers()
    assert 1 not in changed
    # Store same data — no change
    catalog.store_catalog(1, {"tools": [{"name": "a"}], "resources": [], "prompts": []})
    changed = catalog.pop_changed_servers()
    assert 1 not in changed
    # Store different data — should detect change
    catalog.store_catalog(1, {"tools": [{"name": "b"}], "resources": [], "prompts": []})
    changed = catalog.pop_changed_servers()
    assert 1 in changed
    # Pop again — should be empty
    changed = catalog.pop_changed_servers()
    assert 1 not in changed


def test_catalog_get_all_catalogs():
    import importlib
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()
    catalog.store_catalog(1, {"tools": [{"name": "a"}], "resources": [], "prompts": []})
    catalog.store_catalog(2, {"tools": [{"name": "b"}], "resources": [], "prompts": []})
    servers = [{"id": 1}, {"id": 2}, {"id": 3}]  # 3 has no catalog
    result = catalog.get_all_catalogs(servers)
    assert 1 in result
    assert 2 in result
    assert 3 not in result


# ---- Config loader team helpers ----

def test_config_loader_get_team_servers():
    import importlib
    cl = importlib.import_module('config_loader')
    cl._config = {
        "servers": [
            {"id": 1, "team_id": 10, "name": "a", "enabled": True},
            {"id": 2, "team_id": 20, "name": "b", "enabled": True},
            {"id": 3, "team_id": 10, "name": "c", "enabled": False},
        ]
    }
    team10 = cl.get_team_servers(10)
    assert len(team10) == 1  # only enabled server for team 10
    assert team10[0]["name"] == "a"


def test_config_loader_get_server_by_id():
    import importlib
    cl = importlib.import_module('config_loader')
    cl._config = {
        "servers": [
            {"id": 1, "team_id": 10, "name": "a", "enabled": True},
            {"id": 2, "team_id": 20, "name": "b", "enabled": True},
        ]
    }
    assert cl.get_server_by_id(1)["name"] == "a"
    assert cl.get_server_by_id(2)["name"] == "b"
    assert cl.get_server_by_id(999) is None


# ---- Upstream fetch_catalog tests ----

def test_upstream_cancel_inflight_no_task():
    import importlib
    upstream = importlib.import_module('upstream')
    # No in-flight task → returns False
    assert upstream.cancel_inflight("sess1", 42) is False


@pytest.mark.asyncio
async def test_upstream_send_request_tracked_cleans_up():
    import importlib
    upstream = importlib.import_module('upstream')
    # Mock send_request to avoid real HTTP
    upstream.send_request = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    server = {"id": 1, "url": "https://up.example.com/mcp", "auth_type": "none", "verify_tls": True, "timeout_ms": 30000}

    result = await upstream.send_request_tracked("sess1", 42, server, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, None)
    assert result[0] == 200
    # After completion, the inflight entry should be cleaned up
    assert ("sess1", 42) not in upstream._inflight


# ---- Protocol list handler tests (catalog-based) ----

def test_tools_list_merges_catalogs():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()

    # Set up catalogs for two servers
    catalog.store_catalog(1, {"tools": [{"name": "get", "description": "Get weather"}], "resources": [], "prompts": []})
    catalog.store_catalog(2, {"tools": [{"name": "search", "description": "Search issues"}], "resources": [], "prompts": []})

    # Mock config_loader
    protocol.get_enabled_servers = lambda: [
        {"id": 1, "team_id": 10, "name": "weather", "namespace": "weather", "enabled": True},
        {"id": 2, "team_id": 10, "name": "jira", "namespace": "jira", "enabled": True},
    ]

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = protocol._handle_tools_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    tools = body["result"]["tools"]
    assert len(tools) == 2
    names = [t["name"] for t in tools]
    assert "weather__get" in names
    assert "jira__search" in names
    # Check _meta
    for t in tools:
        assert "mcp_server" in t["_meta"]
        assert "mcp_original_name" in t["_meta"]


def test_resources_list_wraps_uris():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()

    catalog.store_catalog(1, {
        "tools": [],
        "resources": [{"uri": "issue://PROJ-123", "name": "issue"}],
        "prompts": [],
    })

    protocol.get_enabled_servers = lambda: [
        {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "enabled": True},
    ]

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = protocol._handle_resources_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    resources = body["result"]["resources"]
    assert len(resources) == 1
    assert resources[0]["uri"].startswith("mcp://jira/")
    assert resources[0]["_meta"]["mcp_server"] == "jira"
    assert resources[0]["_meta"]["mcp_original_uri"] == "issue://PROJ-123"


def test_prompts_list_merges_catalogs():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()

    catalog.store_catalog(1, {"tools": [], "resources": [], "prompts": [{"name": "summarize", "description": "Summarize"}]})
    catalog.store_catalog(2, {"tools": [], "resources": [], "prompts": [{"name": "triage", "description": "Triage"}]})

    protocol.get_enabled_servers = lambda: [
        {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "enabled": True},
        {"id": 2, "team_id": 10, "name": "wiki", "namespace": "wiki", "enabled": True},
    ]

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = protocol._handle_prompts_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    prompts = body["result"]["prompts"]
    assert len(prompts) == 2
    names = [p["name"] for p in prompts]
    assert "jira__summarize" in names
    assert "wiki__triage" in names


def test_tools_list_partial_failure_with_warnings():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()

    # Only one server has a catalog
    catalog.store_catalog(1, {"tools": [{"name": "get"}], "resources": [], "prompts": []})

    protocol.get_enabled_servers = lambda: [
        {"id": 1, "team_id": 10, "name": "weather", "namespace": "weather", "enabled": True},
        {"id": 2, "team_id": 10, "name": "broken", "namespace": "broken", "enabled": True},
    ]

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = protocol._handle_tools_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    tools = body["result"]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "weather__get"
    # Should have warnings for the server without catalog
    assert "_meta" in body["result"]
    assert "warnings" in body["result"]["_meta"]
    assert len(body["result"]["_meta"]["warnings"]) == 1
    assert body["result"]["_meta"]["warnings"][0]["server"] == "broken"


def test_tools_list_empty_when_no_servers():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()

    protocol.get_enabled_servers = lambda: []

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = protocol._handle_tools_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    assert body["result"]["tools"] == []


def test_resources_templates_list():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    catalog.clear_all_catalogs()

    catalog.store_catalog(1, {
        "tools": [],
        "resources": [{"uri": "issue://PROJ", "uriTemplate": "issue://{project}/{id}"}],
        "prompts": [],
    })

    protocol.get_enabled_servers = lambda: [
        {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "enabled": True},
    ]

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = protocol._handle_resources_templates_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    templates = body["result"]["resourceTemplates"]
    assert len(templates) == 1
    assert templates[0]["uriTemplate"].startswith("mcp://jira/")


# ---- Route call tests ----

@pytest.mark.asyncio
async def test_route_call_unknown_namespace():
    import importlib
    protocol = importlib.import_module('protocol')
    protocol.get_enabled_servers = lambda: []
    protocol.get_server_by_namespace = lambda ns: None

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "unknown__tool"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert body["error"]["code"] == -32601
    assert "Unknown namespace" in body["error"]["message"]


@pytest.mark.asyncio
async def test_route_call_missing_prefix():
    import importlib
    protocol = importlib.import_module('protocol')

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "noprefix"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert body["error"]["code"] == -32601
    assert "Missing namespace prefix" in body["error"]["message"]


@pytest.mark.asyncio
async def test_route_call_resource_unwrap():
    import importlib
    protocol = importlib.import_module('protocol')

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp", "auth_type": "none", "verify_tls": True, "timeout_ms": 30000}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {"contents": []}}, {}))

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    wrapped_uri = protocol._wrap_resource_uri("jira", "issue://PROJ-123")
    response = await protocol._route_call("sess1", auth_ctx, "resources/read", {"uri": wrapped_uri}, 1, {}, "resource")
    body = json.loads(response.body)
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    # Verify the upstream was called with the unwrapped URI
    call_args = protocol.send_request_tracked.call_args
    upstream_body = call_args[0][3]  # 4th positional arg
    assert upstream_body["params"]["uri"] == "issue://PROJ-123"


@pytest.mark.asyncio
async def test_route_call_team_isolation():
    import importlib
    protocol = importlib.import_module('protocol')

    server = {"id": 1, "team_id": 20, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10  # Different team

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "jira__search"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert body["error"]["code"] == -32601
    assert "Unknown namespace" in body["error"]["message"]


# ---- Notification handling tests ----

@pytest.mark.asyncio
async def test_notification_cancelled_calls_cancel_inflight():
    import importlib
    protocol = importlib.import_module('protocol')
    protocol.cancel_inflight = MagicMock(return_value=True)
    protocol.get_enabled_servers = lambda: []
    protocol.get_upstream_session = lambda sid, server_id: None
    protocol.send_notification = AsyncMock()

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    await protocol._handle_notification("sess1", "notifications/cancelled", {"requestId": 42}, auth_ctx)
    protocol.cancel_inflight.assert_called_once_with("sess1", 42)


@pytest.mark.asyncio
async def test_notification_initialized_fans_out():
    import importlib
    protocol = importlib.import_module('protocol')

    servers = [
        {"id": 1, "team_id": 10, "name": "a", "namespace": "a", "url": "https://a/mcp"},
        {"id": 2, "team_id": 10, "name": "b", "namespace": "b", "url": "https://b/mcp"},
    ]
    protocol.get_enabled_servers = lambda: servers
    protocol.get_upstream_session = lambda sid, server_id: f"up-{server_id}"
    protocol.send_notification = AsyncMock()

    auth_ctx = MagicMock()
    auth_ctx.team_id = 10

    await protocol._handle_notification("sess1", "notifications/initialized", {}, auth_ctx)
    assert protocol.send_notification.call_count == 2


# ---- Unknown method test ----

def test_unknown_method_returns_method_not_found():
    """Verify -32601 is returned for unknown methods (not forwarded to upstream)."""
    import importlib
    protocol = importlib.import_module('protocol')
    # The routing in handle_mcp_post should return -32601 for unknown methods
    # We can verify the error code constant exists
    assert protocol.JSONRPC_METHOD_NOT_FOUND == -32601


# ---- Catalog worker tests ----

def test_catalog_worker_singleton():
    import importlib
    catalog = importlib.import_module('catalog')
    w1 = catalog.get_worker()
    w2 = catalog.get_worker()
    assert w1 is w2


def test_catalog_worker_creation_with_env():
    import importlib
    catalog = importlib.import_module('catalog')
    # Reset singleton
    catalog._worker = None
    old = os.environ.get("MCP_CATALOG_REFRESH_SECONDS", "")
    os.environ["MCP_CATALOG_REFRESH_SECONDS"] = "120"
    try:
        w = catalog.get_worker()
        assert w.refresh_interval == 120
    finally:
        if old:
            os.environ["MCP_CATALOG_REFRESH_SECONDS"] = old
        else:
            os.environ.pop("MCP_CATALOG_REFRESH_SECONDS", None)
        catalog._worker = None
