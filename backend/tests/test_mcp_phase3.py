"""Tests for MCP Gateway Phase 3 — security policy evaluation.

Tests cover:
- Expression tokenizer/parser parity with security_rules.py
- In-process evaluator against MCP context
- Policy loading, first-match-wins, deny default
- Call-time policy check (deny → -32010)
- List-time policy filtering (clients don't see denied tools)
- Acceptance criteria from the plan
"""
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Make mcp-gateway modules importable
_GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "mcp-gateway")
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_GATEWAY_DIR))


# ---- Expression parser tests ----

def test_parse_simple_comparison():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool = "jira__delete_issue"')
    assert ast["type"] == "compare"
    assert ast["field"] == "mcp.tool"
    assert ast["op"] == "="
    assert ast["value"] == "jira__delete_issue"


def test_parse_and_expression():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool = "jira__delete_issue" and mcp.identity != "admin-bot"')
    assert ast["type"] == "and"
    assert len(ast["children"]) == 2


def test_parse_or_expression():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.identity = "a" or mcp.identity = "b"')
    assert ast["type"] == "or"
    assert len(ast["children"]) == 2


def test_parse_not_expression():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('not mcp.identity = "admin-bot"')
    assert ast["type"] == "not"
    assert ast["child"]["type"] == "compare"


def test_parse_contains():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.arg["path"] contains ".."')
    assert ast["type"] == "compare"
    assert ast["op"] == "contains"
    assert ast["value"] == ".."


def test_parse_bracket_field():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.arg["file"] = "test.txt"')
    assert ast["type"] == "compare"
    assert ast["field"] == 'mcp.arg["file"]'


def test_parse_in_literals():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.identity in ["alice", "bob"]')
    assert ast["type"] == "in_literals"
    assert ast["values"] == ["alice", "bob"]


def test_parse_exists():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.arg["path"] exists')
    assert ast["type"] == "exists"
    assert ast["field"] == 'mcp.arg["path"]'


def test_parse_not_exists():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('not mcp.arg["path"] exists')
    assert ast["type"] == "not"
    assert ast["child"]["type"] == "exists"


def test_parse_complex_expression():
    import importlib
    expr = importlib.import_module('expression')
    text = '(mcp.tool = "jira__delete" and mcp.identity != "admin-bot") or mcp.identity = "super-admin"'
    ast = expr.parse_expression(text)
    assert ast["type"] == "or"


def test_parse_invalid_expression():
    import importlib
    expr = importlib.import_module('expression')
    with pytest.raises(ValueError):
        expr.parse_expression("not a valid expression !!!")


def test_parse_empty_expression():
    import importlib
    expr = importlib.import_module('expression')
    with pytest.raises(ValueError):
        expr.parse_expression("")


def test_validate_expression_ok():
    import importlib
    expr = importlib.import_module('expression')
    ok, ast, err = expr.validate_expression('mcp.tool = "test"')
    assert ok is True
    assert ast is not None
    assert err is None


def test_validate_expression_error():
    import importlib
    expr = importlib.import_module('expression')
    ok, ast, err = expr.validate_expression('mcp.tool = ')
    assert ok is False
    assert ast is None
    assert err is not None


def test_validate_expression_empty():
    import importlib
    expr = importlib.import_module('expression')
    ok, ast, err = expr.validate_expression("")
    assert ok is True
    assert ast is None


# ---- Evaluator tests ----

def test_eval_simple_eq():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool = "jira__delete"')
    ctx = expr.build_mcp_context(tool="jira__delete")
    assert expr.evaluate(ast, ctx) is True


def test_eval_simple_neq():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.identity != "admin-bot"')
    ctx = expr.build_mcp_context(identity_name="alice")
    assert expr.evaluate(ast, ctx) is True
    ctx2 = expr.build_mcp_context(identity_name="admin-bot")
    assert expr.evaluate(ast, ctx2) is False


def test_eval_and():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool = "jira__delete" and mcp.identity != "admin-bot"')
    ctx = expr.build_mcp_context(tool="jira__delete", identity_name="alice")
    assert expr.evaluate(ast, ctx) is True
    ctx2 = expr.build_mcp_context(tool="jira__delete", identity_name="admin-bot")
    assert expr.evaluate(ast, ctx2) is False


def test_eval_or():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.identity = "a" or mcp.identity = "b"')
    ctx = expr.build_mcp_context(identity_name="a")
    assert expr.evaluate(ast, ctx) is True
    ctx2 = expr.build_mcp_context(identity_name="c")
    assert expr.evaluate(ast, ctx2) is False


def test_eval_not():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('not mcp.identity = "admin-bot"')
    ctx = expr.build_mcp_context(identity_name="alice")
    assert expr.evaluate(ast, ctx) is True


def test_eval_contains():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.arg["path"] contains ".."')
    ctx = expr.build_mcp_context(args={"path": "/etc/../passwd"})
    assert expr.evaluate(ast, ctx) is True
    ctx2 = expr.build_mcp_context(args={"path": "/etc/passwd"})
    assert expr.evaluate(ast, ctx2) is False


def test_eval_starts_with():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool starts_with "jira"')
    ctx = expr.build_mcp_context(tool="jira__search")
    assert expr.evaluate(ast, ctx) is True


def test_eval_ends_with():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool ends_with "search"')
    ctx = expr.build_mcp_context(tool="jira__search")
    assert expr.evaluate(ast, ctx) is True


def test_eval_in_literals():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.identity in ["alice", "bob"]')
    ctx = expr.build_mcp_context(identity_name="alice")
    assert expr.evaluate(ast, ctx) is True
    ctx2 = expr.build_mcp_context(identity_name="charlie")
    assert expr.evaluate(ast, ctx2) is False


def test_eval_exists():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.arg["path"] exists')
    ctx = expr.build_mcp_context(args={"path": "/test"})
    assert expr.evaluate(ast, ctx) is True
    ctx2 = expr.build_mcp_context(args={})
    assert expr.evaluate(ast, ctx2) is False


def test_eval_not_exists():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('not mcp.arg["path"] exists')
    ctx = expr.build_mcp_context(args={})
    assert expr.evaluate(ast, ctx) is True


def test_eval_regex():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.tool ~ "jira.*"')
    ctx = expr.build_mcp_context(tool="jira__search")
    assert expr.evaluate(ast, ctx) is True


def test_eval_auth_claim():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('auth.claim.sub = "user-123"')
    ctx = expr.build_mcp_context(claims={"sub": "user-123"})
    assert expr.evaluate(ast, ctx) is True


def test_eval_auth_claim_bracket():
    import importlib
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('auth.claim["role"] = "admin"')
    ctx = expr.build_mcp_context(claims={"role": "admin"})
    assert expr.evaluate(ast, ctx) is True


def test_eval_complex_and_or():
    import importlib
    expr = importlib.import_module('expression')
    text = '(mcp.tool = "jira__delete" and mcp.identity != "admin-bot") or mcp.identity = "super-admin"'
    ast = expr.parse_expression(text)
    # First clause matches
    ctx = expr.build_mcp_context(tool="jira__delete", identity_name="alice")
    assert expr.evaluate(ast, ctx) is True
    # Second clause matches
    ctx2 = expr.build_mcp_context(tool="other", identity_name="super-admin")
    assert expr.evaluate(ast, ctx2) is True
    # Neither matches
    ctx3 = expr.build_mcp_context(tool="jira__delete", identity_name="admin-bot")
    assert expr.evaluate(ast, ctx3) is False


# ---- Policy engine tests ----

def test_policy_load_and_evaluate_allow():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "allow-all", "enabled": True, "priority": 0,
             "expression": 'mcp.identity = "alice"', "expression_ast": None,
             "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "jira__search", "jira", auth_ctx)
    assert pr.allowed is True


def test_policy_deny():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "deny-delete", "enabled": True, "priority": 0,
             "expression": 'mcp.tool = "jira__delete_issue" and mcp.identity != "admin-bot"',
             "expression_ast": None, "action": "deny"},
            {"name": "allow-rest", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    # alice trying to delete → denied
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "jira__delete_issue", "jira", auth_ctx)
    assert pr.denied is True
    assert pr.rule_name == "deny-delete"
    # admin-bot trying to delete → allowed (first rule doesn't match, second allows)
    auth_ctx_admin = SimpleNamespace(name="admin-bot", kind="pat", team_id=1, claims={})
    pr2 = policy.check_tool_access("tools/call", "jira__delete_issue", "jira", auth_ctx_admin)
    assert pr2.allowed is True


def test_policy_no_policies_allows_all():
    """When no policies are configured, gateway is open (backward compat)."""
    import importlib
    policy = importlib.import_module('policy')
    policy.load_policies({"policies": []})
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "jira__search", "jira", auth_ctx)
    assert pr.allowed is True
    assert "no policies" in pr.rule_name


def test_policy_default_deny_when_no_match():
    """When policies exist but none match, deny (fail closed)."""
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "deny-specific", "enabled": True, "priority": 0,
             "expression": 'mcp.tool = "jira__delete"', "expression_ast": None,
             "action": "deny"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    # tool is not "jira__delete", so no policy matches → deny
    pr = policy.check_tool_access("tools/call", "jira__search", "jira", auth_ctx)
    assert pr.denied is True
    assert "no match" in pr.rule_name


def test_policy_first_match_wins():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "first-allow", "enabled": True, "priority": 0,
             "expression": "true", "expression_ast": None, "action": "allow"},
            {"name": "second-deny", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "deny"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "test__tool", "test", auth_ctx)
    assert pr.allowed is True
    assert pr.rule_name == "first-allow"


def test_policy_disabled_skipped():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "disabled-rule", "enabled": False, "priority": 0,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "test__tool", "test", auth_ctx)
    assert pr.denied is True  # No enabled policy → default deny


def test_policy_skip_dlp():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "skip-dlp-for-admin", "enabled": True, "priority": 0,
             "expression": 'mcp.identity = "admin"', "expression_ast": None,
             "action": "skip_dlp"},
            {"name": "allow-all", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="admin", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "test__tool", "test", auth_ctx)
    assert pr.skip_dlp is True
    assert pr.action == "skip_dlp"


def test_policy_arg_path_contains_deny():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "no-path-traversal", "enabled": True, "priority": 0,
             "expression": 'mcp.arg["path"] contains ".."', "expression_ast": None,
             "action": "deny"},
            {"name": "allow-all", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    # Path traversal → denied
    pr = policy.check_tool_access("tools/call", "fs__read", "fs", auth_ctx, args={"path": "/etc/../passwd"})
    assert pr.denied is True
    # Normal path → allowed
    pr2 = policy.check_tool_access("tools/call", "fs__read", "fs", auth_ctx, args={"path": "/etc/passwd"})
    assert pr2.allowed is True


def test_policy_uses_precompiled_ast():
    import importlib
    policy = importlib.import_module('policy')
    expr = importlib.import_module('expression')
    ast = expr.parse_expression('mcp.identity = "alice"')
    config = {
        "policies": [
            {"name": "precompiled", "enabled": True, "priority": 0,
             "expression": 'mcp.identity = "alice"', "expression_ast": ast,
             "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    pr = policy.check_tool_access("tools/call", "test__tool", "test", auth_ctx)
    assert pr.allowed is True


# ---- List-time filtering tests ----

def test_filter_tool_list_hides_denied():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "deny-delete", "enabled": True, "priority": 0,
             "expression": 'mcp.tool = "jira__delete"', "expression_ast": None,
             "action": "deny"},
            {"name": "allow-rest", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    tools = [
        {"name": "jira__delete", "description": "Delete"},
        {"name": "jira__search", "description": "Search"},
        {"name": "jira__create", "description": "Create"},
    ]
    filtered = policy.filter_tool_list(tools, "jira", auth_ctx)
    names = [t["name"] for t in filtered]
    assert "jira__delete" not in names
    assert "jira__search" in names
    assert "jira__create" in names


def test_filter_tool_list_no_policies_shows_all():
    """When no policies are configured, all tools are visible (open gateway)."""
    import importlib
    policy = importlib.import_module('policy')
    policy.load_policies({"policies": []})
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    tools = [{"name": "test__tool"}]
    filtered = policy.filter_tool_list(tools, "test", auth_ctx)
    assert len(filtered) == 1


def test_filter_resource_list():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "deny-secret", "enabled": True, "priority": 0,
             "expression": 'mcp.resource contains "secret"', "expression_ast": None,
             "action": "deny"},
            {"name": "allow-rest", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    resources = [
        {"uri": "mcp://jira/issue://PROJ-123", "name": "issue"},
        {"uri": "mcp://jira/secret://key", "name": "secret"},
    ]
    filtered = policy.filter_resource_list(resources, "jira", auth_ctx)
    uris = [r["uri"] for r in filtered]
    assert len(filtered) == 1
    assert "secret" not in uris[0]


def test_filter_prompt_list():
    import importlib
    policy = importlib.import_module('policy')
    config = {
        "policies": [
            {"name": "deny-admin-prompt", "enabled": True, "priority": 0,
             "expression": 'mcp.prompt = "jira__admin"', "expression_ast": None,
             "action": "deny"},
            {"name": "allow-rest", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    }
    policy.load_policies(config)
    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=1, claims={})
    prompts = [
        {"name": "jira__admin", "description": "Admin"},
        {"name": "jira__summarize", "description": "Summarize"},
    ]
    filtered = policy.filter_prompt_list(prompts, "jira", auth_ctx)
    names = [p["name"] for p in filtered]
    assert "jira__admin" not in names
    assert "jira__summarize" in names


# ---- Protocol integration tests ----

def test_protocol_tools_list_filters_by_policy():
    import importlib
    protocol = importlib.import_module('protocol')
    catalog = importlib.import_module('catalog')
    policy = importlib.import_module('policy')
    catalog.clear_all_catalogs()

    catalog.store_catalog(1, {"tools": [{"name": "delete"}, {"name": "search"}], "resources": [], "prompts": []})

    # Policy: deny delete, allow rest
    policy.load_policies({
        "policies": [
            {"name": "deny-delete", "enabled": True, "priority": 0,
             "expression": 'mcp.tool = "jira__delete"', "expression_ast": None, "action": "deny"},
            {"name": "allow-rest", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    })

    protocol.get_enabled_servers = lambda: [
        {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "enabled": True},
    ]
    # Return a config with the same policies so _ensure_policies_loaded doesn't overwrite
    _test_policies = [
        {"name": "deny-delete", "enabled": True, "priority": 0,
         "expression": 'mcp.tool = "jira__delete"', "expression_ast": None, "action": "deny"},
        {"name": "allow-rest", "enabled": True, "priority": 1,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]
    protocol.get_config = lambda: {"policies": _test_policies}

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = protocol._handle_tools_list(auth_ctx, {}, 1)
    body = json.loads(response.body)
    tools = body["result"]["tools"]
    names = [t["name"] for t in tools]
    assert "jira__delete" not in names
    assert "jira__search" in names


@pytest.mark.asyncio
async def test_protocol_route_call_denied_by_policy():
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')

    # Policy: deny delete
    policy.load_policies({
        "policies": [
            {"name": "deny-delete", "enabled": True, "priority": 0,
             "expression": 'mcp.tool = "jira__delete"', "expression_ast": None, "action": "deny"},
            {"name": "allow-rest", "enabled": True, "priority": 1,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    })

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    _test_policies = [
        {"name": "deny-delete", "enabled": True, "priority": 0,
         "expression": 'mcp.tool = "jira__delete"', "expression_ast": None, "action": "deny"},
        {"name": "allow-rest", "enabled": True, "priority": 1,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]
    protocol.get_config = lambda: {"policies": _test_policies}

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "jira__delete"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert body["error"]["code"] == -32010
    assert "Policy denied" in body["error"]["message"]


@pytest.mark.asyncio
async def test_protocol_route_call_allowed_by_policy():
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')

    # Policy: allow all
    policy.load_policies({
        "policies": [
            {"name": "allow-all", "enabled": True, "priority": 0,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    })

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp",
              "auth_type": "none", "verify_tls": True, "timeout_ms": 30000}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    _test_policies = [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]
    protocol.get_config = lambda: {"policies": _test_policies}

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "jira__search"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert "error" not in body
    assert body["jsonrpc"] == "2.0"


# ---- Config bundle tests ----

def test_config_bundle_includes_policies():
    """Verify that _build_policy_dict includes expression_ast."""
    import sys
    backend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "backend")
    if backend_dir not in sys.path:
        sys.path.insert(0, os.path.abspath(backend_dir))
    from app.services.mcp_config import _build_policy_dict

    policy_mock = MagicMock()
    policy_mock.id = 1
    policy_mock.team_id = 10
    policy_mock.name = "test-policy"
    policy_mock.enabled = True
    policy_mock.priority = 0
    policy_mock.expression = 'mcp.tool = "test"'
    policy_mock.expression_ast = {"type": "compare", "field": "mcp.tool", "op": "=", "value": "test"}
    policy_mock.action = "deny"
    policy_mock.log = True
    policy_mock.no_log = False

    result = _build_policy_dict(policy_mock)
    assert result["name"] == "test-policy"
    assert result["expression_ast"] is not None
    assert result["action"] == "deny"


# ---- Error code test ----

def test_policy_denied_error_code():
    import importlib
    policy = importlib.import_module('policy')
    assert policy.MCP_POLICY_DENIED == -32010
