"""Event logger for MCP Gateway — writes NDJSON to MCP_EVENTS_LOG_PATH.

One line per RPC: method, tool, identity, team, server, latency, status, action, etc.
Does not log raw params/results by default (mcp_log_payloads=false).
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_log_path = None
_log_payloads = False


def _get_log_path() -> str:
    global _log_path
    if _log_path is not None:
        return _log_path
    _log_path = os.environ.get("MCP_EVENTS_LOG_PATH", "data/mcp/events.ndjson")
    _log_payloads = os.environ.get("MCP_LOG_PAYLOADS", "false").lower() in ("true", "1", "yes")
    return _log_path


def _is_log_payloads() -> bool:
    global _log_payloads
    if _log_path is None:
        _get_log_path()
    return _log_payloads


def generate_request_id() -> str:
    """Generate a unique request ID."""
    return uuid.uuid4().hex[:16]


def log_event(
    request_id: str,
    session_id: str,
    identity_id: Optional[int],
    team_id: Optional[int],
    server_id: Optional[int],
    jsonrpc_method: str,
    tool: Optional[str] = None,
    resource_uri: Optional[str] = None,
    prompt: Optional[str] = None,
    action: str = "allow",
    status: str = "ok",
    latency_ms: Optional[int] = None,
    error: Optional[str] = None,
    bytes_in: Optional[int] = None,
    bytes_out: Optional[int] = None,
    dlp_hits: Optional[list] = None,
    guardrail_hits: Optional[list] = None,
    params: Optional[dict] = None,
    result: Optional[Any] = None,
) -> None:
    """Write a single NDJSON event line to the events log."""
    path = _get_log_path()
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "session_id": session_id,
        "identity_id": identity_id,
        "team_id": team_id,
        "server_id": server_id,
        "method": jsonrpc_method,
        "tool": tool,
        "resource_uri": resource_uri,
        "prompt": prompt,
        "action": action,
        "status": status,
        "latency_ms": latency_ms,
        "error": error,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "dlp_hits": dlp_hits,
        "guardrail_hits": guardrail_hits,
    }

    if _is_log_payloads():
        if params is not None:
            try:
                event["params"] = json.dumps(params, default=str)[:4096]
            except Exception:
                event["params"] = None
        if result is not None:
            try:
                event["result"] = json.dumps(result, default=str)[:4096]
            except Exception:
                event["result"] = None

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except Exception as e:
        logger.warning("Failed to write MCP event log: %s", e)
