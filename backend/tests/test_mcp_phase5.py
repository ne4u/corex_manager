"""Tests for MCP Gateway Phase 5 — Data Loss Prevention (DLP).

Tests cover:
- Built-in detector patterns (email, ssn, aws_key, github_token, etc.)
- Custom detector regex
- Actions: block, redact, tokenize
- Direction filtering (request, response, both)
- DLP rule loading from config bundle
- Protocol integration: request blocked → -32050, response blocked, redacted
- skip_dlp policy action bypasses DLP
- Config bundle includes DLP rules
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


# ---- Detector pattern tests ----

def test_email_detector():
    """Email detector matches standard email addresses."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "emails", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"text": "Contact alice@example.com"}, rules)
    assert not result.blocked
    assert result.modified
    assert "[REDACTED]" in result.modified_data["text"]
    assert "alice@example.com" not in result.modified_data["text"]


def test_ssn_detector():
    """SSN detector matches XXX-XX-XXXX format."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "ssn", "enabled": True, "priority": 0,
         "direction": "both", "detector": "ssn", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"ssn": "123-45-6789"}, rules)
    assert result.modified
    assert "[REDACTED]" in result.modified_data["ssn"]


def test_aws_key_detector():
    """AWS key detector matches AKIA-prefixed keys."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "aws", "enabled": True, "priority": 0,
         "direction": "both", "detector": "aws_key", "action": "block"},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"key": "AKIAIOSFODNN7EXAMPLE"}, rules)
    assert result.blocked
    assert len(result.hits) == 1
    assert result.hits[0].action == "block"


def test_github_token_detector():
    """GitHub token detector matches ghp_/ghs_/gho_ prefixed tokens."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "gh", "enabled": True, "priority": 0,
         "direction": "both", "detector": "github_token", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"token": "ghp_" + "A" * 36}, rules)
    assert result.modified
    assert "[REDACTED]" in result.modified_data["token"]


def test_custom_detector():
    """Custom detector uses user-provided regex."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "custom", "enabled": True, "priority": 0,
         "direction": "both", "detector": "custom",
         "find_regex": r"\bSECRET-\d+\b", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"code": "SECRET-12345"}, rules)
    assert result.modified
    assert "SECRET-12345" not in result.modified_data["code"]
    assert "[REDACTED]" in result.modified_data["code"]


def test_no_match_returns_original():
    """When no detector matches, data is unchanged."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "emails", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    params = {"text": "no sensitive data here"}
    result = dlp.scan_request("tools/call", params, rules)
    assert not result.modified
    assert not result.blocked
    assert result.modified_data == params


# ---- Action tests ----

def test_block_action():
    """Block action sets blocked=True and returns original data."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "block-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "block"},
    ]})
    rules = dlp.get_dlp_rules()
    params = {"text": "alice@example.com"}
    result = dlp.scan_request("tools/call", params, rules)
    assert result.blocked
    assert result.modified_data == params  # Original returned on block
    assert len(result.hits) == 1
    assert result.hits[0].action == "block"


def test_redact_action():
    """Redact action replaces matches with [REDACTED]."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "redact-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"a": "x@y.com", "b": "z@w.com"}, rules)
    assert not result.blocked
    assert result.modified
    assert result.modified_data["a"] == "[REDACTED]"
    assert result.modified_data["b"] == "[REDACTED]"


def test_tokenize_action_no_valkey():
    """Tokenize action falls back to [REDACTED] when Valkey unavailable."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp._client = None
    dlp._get_client = lambda: None
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "tok-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "tokenize",
         "token_prefix": "tok_", "token_ttl": 3600},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"email": "test@example.com"}, rules)
    assert not result.blocked
    assert result.modified
    assert "test@example.com" not in result.modified_data["email"]


def test_tokenize_action_with_valkey():
    """Tokenize action stores mapping in Valkey when available."""
    import importlib
    dlp = importlib.import_module('dlp')
    mock_client = MagicMock()
    mock_client.setex = MagicMock()
    dlp._client = mock_client
    dlp._get_client = lambda: mock_client
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "tok-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "tokenize",
         "token_prefix": "tok_", "token_ttl": 3600},
    ]})
    rules = dlp.get_dlp_rules()
    result = dlp.scan_request("tools/call", {"email": "test@example.com"}, rules)
    assert not result.blocked
    assert result.modified
    assert result.modified_data["email"].startswith("tok_")
    assert "test@example.com" not in result.modified_data["email"]
    assert mock_client.setex.called


# ---- Direction filtering tests ----

def test_direction_request_only():
    """Rules with direction=request only scan requests, not responses."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "req-only", "enabled": True, "priority": 0,
         "direction": "request", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()

    # Request scan should match
    req_result = dlp.scan_request("tools/call", {"text": "alice@example.com"}, rules)
    assert req_result.modified

    # Response scan should not match
    resp_result = dlp.scan_response({"text": "alice@example.com"}, rules)
    assert not resp_result.modified


def test_direction_response_only():
    """Rules with direction=response only scan responses, not requests."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "resp-only", "enabled": True, "priority": 0,
         "direction": "response", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()

    # Request scan should not match
    req_result = dlp.scan_request("tools/call", {"text": "alice@example.com"}, rules)
    assert not req_result.modified

    # Response scan should match
    resp_result = dlp.scan_response({"text": "alice@example.com"}, rules)
    assert resp_result.modified


def test_direction_both():
    """Rules with direction=both scan both requests and responses."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "both", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()

    req_result = dlp.scan_request("tools/call", {"text": "alice@example.com"}, rules)
    assert req_result.modified

    resp_result = dlp.scan_response({"text": "alice@example.com"}, rules)
    assert resp_result.modified


# ---- DLP rule loading tests ----

def test_load_dlp_rules_empty():
    """Loading with no dlp_rules key sets has_dlp_configured=False."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({})
    assert not dlp.has_dlp_rules()
    assert len(dlp.get_dlp_rules()) == 0


def test_load_dlp_rules_disabled():
    """Disabled rules are not compiled."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "disabled", "enabled": False, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})
    assert not dlp.has_dlp_rules()


def test_load_dlp_rules_invalid_detector():
    """Unknown detector is skipped without error."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "bad", "enabled": True, "priority": 0,
         "direction": "both", "detector": "nonexistent", "action": "redact"},
    ]})
    assert len(dlp.get_dlp_rules()) == 0


def test_load_dlp_rules_invalid_regex():
    """Invalid custom regex is skipped without error."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "bad-regex", "enabled": True, "priority": 0,
         "direction": "both", "detector": "custom",
         "find_regex": "[invalid", "action": "redact"},
    ]})
    assert len(dlp.get_dlp_rules()) == 0


def test_dlp_error_code():
    """MCP_DLP_BLOCKED is -32050."""
    import importlib
    dlp = importlib.import_module('dlp')
    assert dlp.MCP_DLP_BLOCKED == -32050


# ---- Recursive scanning tests ----

def test_scan_nested_json():
    """DLP scans recursively through nested JSON structures."""
    import importlib
    dlp = importlib.import_module('dlp')
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})
    rules = dlp.get_dlp_rules()
    params = {
        "user": {"email": "alice@example.com"},
        "items": ["x@y.com", "no match"],
    }
    result = dlp.scan_request("tools/call", params, rules)
    assert result.modified
    assert result.modified_data["user"]["email"] == "[REDACTED]"
    assert result.modified_data["items"][0] == "[REDACTED]"
    assert result.modified_data["items"][1] == "no match"


# ---- Protocol integration tests ----

@pytest.mark.asyncio
async def test_protocol_dlp_request_blocked():
    """DLP block on request returns -32050."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    dlp = importlib.import_module('dlp')
    events = importlib.import_module('events')

    # Allow-all policy
    policy.load_policies({"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]})

    # DLP rule: block emails
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "block-email", "enabled": True, "priority": 0,
         "direction": "request", "detector": "email", "action": "block"},
    ]})

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    protocol.get_config = lambda: {"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ], "dlp_rules": [
        {"name": "block-email", "enabled": True, "priority": 0,
         "direction": "request", "detector": "email", "action": "block"},
    ], "default_rpm": 60}

    # Rate limiter allows
    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (True, max_rpm)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = await protocol._route_call(
        "sess1", auth_ctx, "tools/call",
        {"name": "jira__search", "arguments": {"email": "test@example.com"}},
        1, {}, "tool",
    )
    body = json.loads(response.body)
    assert body["error"]["code"] == -32050
    assert "DLP blocked" in body["error"]["message"]


@pytest.mark.asyncio
async def test_protocol_dlp_request_redacted():
    """DLP redact on request modifies params before upstream call."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    dlp = importlib.import_module('dlp')

    policy.load_policies({"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]})

    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "redact-email", "enabled": True, "priority": 0,
         "direction": "request", "detector": "email", "action": "redact"},
    ]})

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"

    # Capture the forwarded params
    captured_params = {}
    async def _capture_request(sid, mid, srv, body, usid):
        captured_params.update(body.get("params", {}))
        return (200, {"jsonrpc": "2.0", "result": {}}, {})

    protocol.send_request_tracked = _capture_request
    protocol.get_config = lambda: {"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ], "dlp_rules": [
        {"name": "redact-email", "enabled": True, "priority": 0,
         "direction": "request", "detector": "email", "action": "redact"},
    ], "default_rpm": 60}

    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (True, max_rpm)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    await protocol._route_call(
        "sess1", auth_ctx, "tools/call",
        {"name": "jira__search", "arguments": {"email": "test@example.com"}},
        1, {}, "tool",
    )

    # The upstream should have received redacted params
    assert captured_params.get("arguments", {}).get("email") == "[REDACTED]"


@pytest.mark.asyncio
async def test_protocol_dlp_response_blocked():
    """DLP block on response returns -32050."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    dlp = importlib.import_module('dlp')

    policy.load_policies({"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]})

    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "block-ssn", "enabled": True, "priority": 0,
         "direction": "response", "detector": "ssn", "action": "block"},
    ]})

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    # Upstream returns a response containing an SSN
    protocol.send_request_tracked = AsyncMock(return_value=(
        200, {"jsonrpc": "2.0", "result": {"text": "123-45-6789"}}, {},
    ))
    protocol.get_config = lambda: {"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ], "dlp_rules": [
        {"name": "block-ssn", "enabled": True, "priority": 0,
         "direction": "response", "detector": "ssn", "action": "block"},
    ], "default_rpm": 60}

    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (True, max_rpm)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = await protocol._route_call(
        "sess1", auth_ctx, "tools/call",
        {"name": "jira__search", "arguments": {}},
        1, {}, "tool",
    )
    body = json.loads(response.body)
    assert body["error"]["code"] == -32050
    assert "response" in body["error"]["message"].lower()


@pytest.mark.asyncio
async def test_protocol_dlp_skip_dlp_policy():
    """Policy with skip_dlp action bypasses DLP scanning."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    dlp = importlib.import_module('dlp')

    # skip_dlp policy
    policy.load_policies({"policies": [
        {"name": "skip-dlp", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "skip_dlp"},
    ]})

    # DLP rule that would block
    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "block-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "block"},
    ]})

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    protocol.get_config = lambda: {"policies": [
        {"name": "skip-dlp", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "skip_dlp"},
    ], "dlp_rules": [
        {"name": "block-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "block"},
    ], "default_rpm": 60}

    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (True, max_rpm)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    # Should not be blocked despite DLP rule
    response = await protocol._route_call(
        "sess1", auth_ctx, "tools/call",
        {"name": "jira__search", "arguments": {"email": "test@example.com"}},
        1, {}, "tool",
    )
    body = json.loads(response.body)
    assert "error" not in body
    assert body["jsonrpc"] == "2.0"


# ---- Config bundle tests ----

def test_config_bundle_includes_dlp_rules(db):
    """Config bundle includes dlp_rules from the database."""
    from app.services.mcp_config import build_config_bundle
    from app.models.mcp import McpDlpRule, Team

    # Create a team
    team = Team(name="Test", slug="test")
    db.add(team)
    db.commit()

    # Create a DLP rule
    rule = McpDlpRule(
        team_id=team.id, name="test-email",
        enabled=True, priority=0, direction="both",
        detector="email", action="redact",
        apply_to="json_strings",
    )
    db.add(rule)
    db.commit()

    bundle = build_config_bundle(db)
    assert "dlp_rules" in bundle
    assert len(bundle["dlp_rules"]) == 1
    assert bundle["dlp_rules"][0]["name"] == "test-email"
    assert bundle["dlp_rules"][0]["detector"] == "email"
    assert bundle["dlp_rules"][0]["action"] == "redact"


def test_config_bundle_dlp_rules_empty(db):
    """Config bundle has empty dlp_rules when none exist."""
    from app.services.mcp_config import build_config_bundle

    bundle = build_config_bundle(db)
    assert "dlp_rules" in bundle
    assert bundle["dlp_rules"] == []


# ---- Event logging with DLP hits ----

@pytest.mark.asyncio
async def test_protocol_dlp_event_logged(tmp_path):
    """DLP hits are logged in the event."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    dlp = importlib.import_module('dlp')
    events = importlib.import_module('events')

    log_file = str(tmp_path / "events.ndjson")
    events._log_path = log_file
    events._log_payloads = False

    policy.load_policies({"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]})

    dlp.load_dlp_rules({"dlp_rules": [
        {"name": "redact-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ]})

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    protocol.get_config = lambda: {"policies": [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ], "dlp_rules": [
        {"name": "redact-email", "enabled": True, "priority": 0,
         "direction": "both", "detector": "email", "action": "redact"},
    ], "default_rpm": 60}

    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (True, max_rpm)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    await protocol._route_call(
        "sess1", auth_ctx, "tools/call",
        {"name": "jira__search", "arguments": {"email": "test@example.com"}},
        1, {}, "tool",
    )

    with open(log_file) as f:
        lines = f.readlines()
    assert len(lines) >= 1
    data = json.loads(lines[-1])
    assert data["action"] == "allow"
    assert data["dlp_hits"] is not None
    assert len(data["dlp_hits"]) >= 1
    assert data["dlp_hits"][0]["detector"] == "email"
    assert data["dlp_hits"][0]["action"] == "redact"
