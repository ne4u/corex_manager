"""Tests for MCP Gateway Phase 4 — rate limiting + observability.

Tests cover:
- Rate limiter (check_rate_limit) — allow within quota, deny when exceeded
- Event logger (log_event) — NDJSON format, fields, payload logging toggle
- Protocol integration — rate limit error (-32029), event logging on deny/allow
- Metrics sampler — tail NDJSON, store McpEvent rows, prune old data
- Metrics API — GET /mcp/metrics with breakdown
"""
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Make mcp-gateway modules importable
_GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "mcp-gateway")
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_GATEWAY_DIR))


# ---- Rate limiter tests ----

def test_rate_limit_allows_within_quota():
    """Requests within the RPM quota are allowed."""
    import importlib
    rl = importlib.import_module('ratelimit')
    # Mock Valkey client with pipeline-based ZSET sliding window
    mock_client = MagicMock()
    # Each check_rate_limit call does two pipeline rounds:
    #   1st pipeline: zremrangebyscore + zcard → execute returns [removed, count]
    #   2nd pipeline: zadd + expire → execute returns [1, True]
    # Counts seen: 0, 1, 2 (all < 60, so all allowed)
    mock_pipe = MagicMock()
    mock_pipe.execute = MagicMock(side_effect=[
        [0, 0], [1, True],   # 1st call: count=0 → allowed
        [0, 1], [1, True],   # 2nd call: count=1 → allowed
        [0, 2], [1, True],   # 3rd call: count=2 → allowed
    ])
    mock_client.pipeline = MagicMock(return_value=mock_pipe)
    rl._client = mock_client
    rl._get_client = lambda: mock_client

    for i in range(3):
        allowed, remaining = rl.check_rate_limit(1, "test__tool", max_rpm=60)
        assert allowed is True
    assert mock_pipe.execute.call_count == 6  # 2 pipeline rounds per call


def test_rate_limit_denies_when_exceeded():
    """Requests beyond the quota are denied."""
    import importlib
    rl = importlib.import_module('ratelimit')
    mock_client = MagicMock()
    # Sliding window: counts 0,1,2,3,4 are < 5 (allowed), count 5 >= 5 (denied)
    # Allowed calls do 2 pipeline rounds; denied call does only 1 (returns early)
    mock_pipe = MagicMock()
    mock_pipe.execute = MagicMock(side_effect=[
        [0, 0], [1, True],   # 1st: count=0 → allowed
        [0, 1], [1, True],   # 2nd: count=1 → allowed
        [0, 2], [1, True],   # 3rd: count=2 → allowed
        [0, 3], [1, True],   # 4th: count=3 → allowed
        [0, 4], [1, True],   # 5th: count=4 → allowed
        [0, 5],              # 6th: count=5 >= 5 → denied (no 2nd pipeline)
    ])
    mock_client.pipeline = MagicMock(return_value=mock_pipe)
    rl._client = mock_client
    rl._get_client = lambda: mock_client

    for i in range(5):
        allowed, _ = rl.check_rate_limit(1, "test__tool", max_rpm=5)
        assert allowed is True

    allowed, remaining = rl.check_rate_limit(1, "test__tool", max_rpm=5)
    assert allowed is False
    assert remaining == 0


def test_rate_limit_no_valkey_allows():
    """When Valkey is unavailable, requests are allowed (fail open)."""
    import importlib
    rl = importlib.import_module('ratelimit')
    rl._client = None
    rl._get_client = lambda: None

    allowed, remaining = rl.check_rate_limit(1, "test__tool", max_rpm=60)
    assert allowed is True
    assert remaining == 60


def test_rate_limit_zero_rpm_allows():
    """max_rpm=0 means no limit (disabled)."""
    import importlib
    rl = importlib.import_module('ratelimit')
    rl._client = None
    rl._get_client = lambda: None

    allowed, _ = rl.check_rate_limit(1, "test__tool", max_rpm=0)
    assert allowed is True


def test_rate_limit_error_code():
    """MCP_RATE_LIMITED is -32029."""
    import importlib
    rl = importlib.import_module('ratelimit')
    assert rl.MCP_RATE_LIMITED == -32029


# ---- Event logger tests ----

def test_event_log_writes_ndjson(tmp_path):
    """log_event writes a valid NDJSON line with expected fields."""
    import importlib
    events = importlib.import_module('events')
    log_file = str(tmp_path / "events.ndjson")
    events._log_path = log_file
    events._log_payloads = False

    events.log_event(
        request_id="req-1",
        session_id="sess-1",
        identity_id=1,
        team_id=10,
        server_id=5,
        jsonrpc_method="tools/call",
        tool="jira__search",
        action="allow",
        status="ok",
        latency_ms=42,
    )

    with open(log_file) as f:
        line = f.readline()
    data = json.loads(line)
    assert data["request_id"] == "req-1"
    assert data["method"] == "tools/call"
    assert data["tool"] == "jira__search"
    assert data["action"] == "allow"
    assert data["latency_ms"] == 42
    assert "params" not in data  # payload logging off


def test_event_log_payload_logging(tmp_path):
    """When MCP_LOG_PAYLOADS is true, params/result are included."""
    import importlib
    events = importlib.import_module('events')
    log_file = str(tmp_path / "events.ndjson")
    events._log_path = log_file
    events._log_payloads = True

    events.log_event(
        request_id="req-2",
        session_id="sess-2",
        identity_id=1,
        team_id=10,
        server_id=5,
        jsonrpc_method="tools/call",
        tool="jira__create",
        action="allow",
        params={"summary": "test"},
        result={"id": "ISSUE-1"},
    )

    with open(log_file) as f:
        data = json.loads(f.readline())
    assert "params" in data
    assert "result" in data


def test_event_log_generate_request_id():
    """generate_request_id returns a non-empty string."""
    import importlib
    events = importlib.import_module('events')
    rid = events.generate_request_id()
    assert isinstance(rid, str)
    assert len(rid) > 0


def test_event_log_rate_limited_action(tmp_path):
    """log_event can log a rate_limited action."""
    import importlib
    events = importlib.import_module('events')
    log_file = str(tmp_path / "events.ndjson")
    events._log_path = log_file
    events._log_payloads = False

    events.log_event(
        request_id="req-3",
        session_id="sess-3",
        identity_id=1,
        team_id=10,
        server_id=5,
        jsonrpc_method="tools/call",
        tool="jira__delete",
        action="rate_limited",
        status="rate_limited",
        error="Rate limit exceeded for jira__delete",
    )

    with open(log_file) as f:
        data = json.loads(f.readline())
    assert data["action"] == "rate_limited"
    assert data["status"] == "rate_limited"


# ---- Protocol integration tests ----

@pytest.mark.asyncio
async def test_protocol_route_call_rate_limited():
    """When rate limit is exceeded, protocol returns -32029."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    ratelimit = importlib.import_module('ratelimit')

    # Allow-all policy
    policy.load_policies({
        "policies": [
            {"name": "allow-all", "enabled": True, "priority": 0,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    })

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    _test_policies = [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]
    protocol.get_config = lambda: {"policies": _test_policies, "default_rpm": 60}

    # Mock rate limiter to deny (patch the reference already imported in protocol)
    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (False, 0)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "jira__search"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert body["error"]["code"] == -32029
    assert "Rate limit" in body["error"]["message"]


@pytest.mark.asyncio
async def test_protocol_route_call_skip_ratelimit():
    """Policy with skip_ratelimit action bypasses rate limiting."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    ratelimit = importlib.import_module('ratelimit')

    # skip_ratelimit policy
    policy.load_policies({
        "policies": [
            {"name": "skip-rl", "enabled": True, "priority": 0,
             "expression": "true", "expression_ast": None, "action": "skip_ratelimit"},
        ]
    })

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    _test_policies = [
        {"name": "skip-rl", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "skip_ratelimit"},
    ]
    protocol.get_config = lambda: {"policies": _test_policies, "default_rpm": 60}

    # Rate limiter would deny if called, but skip_ratelimit should bypass it
    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (False, 0)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    response = await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "jira__search"}, 1, {}, "tool")
    body = json.loads(response.body)
    assert "error" not in body
    assert body["jsonrpc"] == "2.0"


@pytest.mark.asyncio
async def test_protocol_event_logged_on_allow(tmp_path):
    """Event is logged when a call is allowed."""
    import importlib
    protocol = importlib.import_module('protocol')
    policy = importlib.import_module('policy')
    events = importlib.import_module('events')

    log_file = str(tmp_path / "events.ndjson")
    events._log_path = log_file
    events._log_payloads = False

    policy.load_policies({
        "policies": [
            {"name": "allow-all", "enabled": True, "priority": 0,
             "expression": "true", "expression_ast": None, "action": "allow"},
        ]
    })

    server = {"id": 1, "team_id": 10, "name": "jira", "namespace": "jira", "url": "https://up/mcp"}
    protocol.get_enabled_servers = lambda: [server]
    protocol.get_server_by_namespace = lambda ns: server if ns == "jira" else None
    protocol.get_upstream_session = lambda sid, server_id: "upstream-sess"
    protocol.send_request_tracked = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "result": {}}, {}))
    _test_policies = [
        {"name": "allow-all", "enabled": True, "priority": 0,
         "expression": "true", "expression_ast": None, "action": "allow"},
    ]
    protocol.get_config = lambda: {"policies": _test_policies, "default_rpm": 60}

    # Rate limiter allows (patch the reference already imported in protocol)
    protocol.check_rate_limit = lambda identity_id, tool, max_rpm: (True, max_rpm)

    from types import SimpleNamespace
    auth_ctx = SimpleNamespace(name="alice", kind="pat", team_id=10, identity_id=1, claims={})

    await protocol._route_call("sess1", auth_ctx, "tools/call", {"name": "jira__search"}, 1, {}, "tool")

    with open(log_file) as f:
        lines = f.readlines()
    assert len(lines) >= 1
    data = json.loads(lines[-1])
    assert data["action"] == "allow"
    assert data["tool"] == "jira__search"
    assert data["method"] == "tools/call"


# ---- Metrics sampler tests ----

def test_mcp_metrics_sampler_stores_events(tmp_path, db):
    """sample_mcp_metrics reads NDJSON and stores McpEvent rows."""
    from app.services import mcp_metrics
    from app.core.config import get_settings
    from app.models.mcp import McpEvent

    settings = get_settings()
    log_file = tmp_path / "events.ndjson"
    offset_file = tmp_path / ".mcp_metrics_offset"

    # Write some events
    events = [
        {"ts": datetime.now(timezone.utc).isoformat(), "request_id": "r1", "session_id": "s1",
         "identity_id": 1, "team_id": 10, "server_id": 5, "method": "tools/call",
         "tool": "jira__search", "action": "allow", "status": "ok", "latency_ms": 42},
        {"ts": datetime.now(timezone.utc).isoformat(), "request_id": "r2", "session_id": "s1",
         "identity_id": 1, "team_id": 10, "server_id": 5, "method": "tools/call",
         "tool": "jira__delete", "action": "deny", "status": "policy_denied"},
    ]
    with open(log_file, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    # Patch settings
    original_path = settings.MCP_EVENTS_LOG_PATH
    settings.MCP_EVENTS_LOG_PATH = str(log_file)

    # Patch offset path
    original_offset = mcp_metrics._offset_path
    mcp_metrics._offset_path = lambda: str(offset_file)

    try:
        mcp_metrics.sample_mcp_metrics()
        rows = db.query(McpEvent).all()
        assert len(rows) == 2
        assert rows[0].tool == "jira__search"
        assert rows[0].action == "allow"
        assert rows[1].tool == "jira__delete"
        assert rows[1].action == "deny"
    finally:
        settings.MCP_EVENTS_LOG_PATH = original_path
        mcp_metrics._offset_path = original_offset


def test_mcp_metrics_sampler_prune_old(db):
    """prune_mcp_metrics deletes rows older than retention."""
    from app.services import mcp_metrics
    from app.models.mcp import McpEvent

    old_date = datetime.now(timezone.utc) - timedelta(days=30)
    old_event = McpEvent(
        captured_at=old_date.replace(tzinfo=None),
        request_id="old", session_id="s1", identity_id=1, team_id=10,
        server_id=5, jsonrpc_method="tools/call", tool="old__tool",
        action="allow", status="ok",
    )
    db.add(old_event)
    db.commit()

    deleted = mcp_metrics.prune_mcp_metrics(db)
    assert deleted >= 1
    rows = db.query(McpEvent).all()
    assert len(rows) == 0


def test_mcp_metrics_aggregation(db):
    """get_mcp_metrics returns time-bucketed series with breakdown."""
    from app.services import mcp_metrics
    from app.models.mcp import McpEvent

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for i in range(5):
        db.add(McpEvent(
            captured_at=now - timedelta(minutes=i),
            request_id=f"r{i}", session_id="s1", identity_id=1, team_id=10,
            server_id=5, jsonrpc_method="tools/call", tool="jira__search",
            action="allow", status="ok", latency_ms=10 + i * 5,
        ))
    for i in range(3):
        db.add(McpEvent(
            captured_at=now - timedelta(minutes=i),
            request_id=f"d{i}", session_id="s1", identity_id=1, team_id=10,
            server_id=5, jsonrpc_method="tools/call", tool="jira__delete",
            action="deny", status="policy_denied",
        ))
    db.commit()

    result = mcp_metrics.get_mcp_metrics(
        db, start=now - timedelta(hours=1), end=now, step=300, breakdown="action",
    )
    assert "allow" in result["totals"]
    assert "deny" in result["totals"]
    assert result["totals"]["allow"] == 5
    assert result["totals"]["deny"] == 3
    assert len(result["latency"]) > 0
    assert result["latency"][0]["p50"] > 0


# ---- Metrics API test ----

def test_mcp_metrics_api(client, db):
    """GET /mcp/metrics returns aggregated metrics."""
    from app.models.mcp import McpEvent

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(McpEvent(
        captured_at=now, request_id="r1", session_id="s1",
        identity_id=1, team_id=10, server_id=5,
        jsonrpc_method="tools/call", tool="jira__search",
        action="allow", status="ok", latency_ms=15,
    ))
    db.commit()

    resp = client.get("/api/v1/mcp/metrics?breakdown=action")
    assert resp.status_code == 200
    data = resp.json()
    assert "series" in data
    assert "totals" in data
    assert "latency" in data
    assert "allow" in data["totals"]


# ---- Payload logging off by default ----

def test_payload_logging_off_by_default():
    """MCP_LOG_PAYLOADS defaults to false."""
    import importlib
    events = importlib.import_module('events')
    events._log_path = None
    events._log_payloads = False
    # Re-init from env
    old_env = os.environ.get("MCP_LOG_PAYLOADS")
    os.environ["MCP_LOG_PAYLOADS"] = "false"
    try:
        assert events._is_log_payloads() is False
    finally:
        if old_env is not None:
            os.environ["MCP_LOG_PAYLOADS"] = old_env
        else:
            os.environ.pop("MCP_LOG_PAYLOADS", None)
