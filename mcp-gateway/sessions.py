"""Session manager for MCP Gateway — Valkey-backed.

Session state lives in Valkey so any gateway replica can resume.
Key: mcp:sess:<id>
Value: {identity_id, team_id, created_at, upstreams: {server_id: upstream_session_id}}
TTL: 1 hour sliding (refreshed on each request)
"""
import json
import logging
import secrets
import time
from typing import Optional

logger = logging.getLogger(__name__)

SESSION_TTL = 3600  # 1 hour
SESSION_KEY_PREFIX = "mcp:sess:"

_client = None


def _get_client():
    """Return a Valkey client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client
    try:
        from valkey import Valkey
        host = __import__("os").environ.get("VALKEY_HOST", "valkey")
        port = int(__import__("os").environ.get("VALKEY_PORT", "6379"))
        password = __import__("os").environ.get("VALKEY_PASSWORD") or None
        client = Valkey(
            host=host, port=port, db=0, password=password,
            socket_connect_timeout=1, socket_timeout=1,
            decode_responses=True,
        )
        client.ping()
        _client = client
        return client
    except Exception as e:
        logger.debug("Valkey not available: %s", e)
        _client = None
        return None


def create_session(identity_id: int, team_id: int) -> str:
    """Create a new session, store in Valkey, return session ID."""
    session_id = secrets.token_urlsafe(32)
    data = {
        "identity_id": identity_id,
        "team_id": team_id,
        "created_at": time.time(),
        "upstreams": {},
    }
    client = _get_client()
    if client:
        client.setex(
            SESSION_KEY_PREFIX + session_id,
            SESSION_TTL,
            json.dumps(data),
        )
    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """Retrieve session data. Returns None if not found or expired."""
    if not session_id:
        return None
    client = _get_client()
    if not client:
        return None
    raw = client.get(SESSION_KEY_PREFIX + session_id)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def refresh_session(session_id: str) -> None:
    """Slide the TTL forward."""
    client = _get_client()
    if client:
        client.expire(SESSION_KEY_PREFIX + session_id, SESSION_TTL)


def delete_session(session_id: str) -> None:
    """Delete a session."""
    client = _get_client()
    if client:
        client.delete(SESSION_KEY_PREFIX + session_id)


def set_upstream_session(session_id: str, server_id: int, upstream_session_id: str) -> None:
    """Store the upstream MCP session ID for a given server."""
    client = _get_client()
    if not client:
        return
    data = get_session(session_id)
    if not data:
        return
    data.setdefault("upstreams", {})[str(server_id)] = upstream_session_id
    client.setex(SESSION_KEY_PREFIX + session_id, SESSION_TTL, json.dumps(data))


def get_upstream_session(session_id: str, server_id: int) -> Optional[str]:
    """Get the stored upstream session ID for a server."""
    data = get_session(session_id)
    if not data:
        return None
    return data.get("upstreams", {}).get(str(server_id))


def validate_session(session_id: str) -> bool:
    """Check if a session exists and is valid."""
    return get_session(session_id) is not None
