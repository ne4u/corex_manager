"""Token revocation / blocklist for MCP Gateway — Valkey-backed.

Supports:
- Revoking individual JWTs by jti
- Revoking all tokens for an identity (identity_id-based)
- Checking revocation status on every auth

Keys:
- mcp:rev:jti:{jti} — individual JWT revocation (TTL = token remaining lifetime)
- mcp:rev:identity:{identity_id} — identity-level revocation (timestamp cutoff)
"""
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    """Return a Valkey client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client
    try:
        from valkey import Valkey
        host = os.environ.get("VALKEY_HOST", "valkey")
        port = int(os.environ.get("VALKEY_PORT", "6379"))
        password = os.environ.get("VALKEY_PASSWORD") or None
        client = Valkey(
            host=host, port=port, db=0, password=password,
            socket_connect_timeout=1, socket_timeout=1,
            decode_responses=True,
        )
        client.ping()
        _client = client
        return client
    except Exception as e:
        logger.debug("Valkey not available for revocation: %s", e)
        _client = None
        return None


def revoke_jti(jti: str, ttl_seconds: int = 3600) -> bool:
    """Revoke a specific JWT by its jti claim. Returns True if stored."""
    client = _get_client()
    if not client or not jti:
        return False
    try:
        client.setex(f"mcp:rev:jti:{jti}", ttl_seconds, "1")
        return True
    except Exception as e:
        logger.warning("Failed to revoke jti: %s", e)
        return False


def revoke_identity(identity_id: int) -> bool:
    """Revoke all tokens for an identity. Returns True if stored."""
    client = _get_client()
    if not client:
        return False
    try:
        client.set(f"mcp:rev:identity:{identity_id}", str(time.time()))
        # Also kill all sessions for this identity
        _revoke_identity_sessions(identity_id)
        return True
    except Exception as e:
        logger.warning("Failed to revoke identity: %s", e)
        return False


def _revoke_identity_sessions(identity_id: int) -> None:
    """Delete all sessions belonging to an identity."""
    client = _get_client()
    if not client:
        return
    try:
        for key in client.scan_iter("mcp:sess:*"):
            raw = client.get(key)
            if raw:
                import json
                data = json.loads(raw)
                if data.get("identity_id") == identity_id:
                    client.delete(key)
    except Exception as e:
        logger.warning("Failed to revoke sessions for identity %d: %s", identity_id, e)


def is_jti_revoked(jti: str) -> bool:
    """Check if a JWT jti has been revoked."""
    if not jti:
        return False
    client = _get_client()
    if not client:
        return False
    try:
        return client.exists(f"mcp:rev:jti:{jti}") > 0
    except Exception:
        return False


def is_identity_revoked(identity_id: int) -> bool:
    """Check if an identity has been revoked at the identity level."""
    client = _get_client()
    if not client:
        return False
    try:
        return client.exists(f"mcp:rev:identity:{identity_id}") > 0
    except Exception:
        return False


def is_token_valid(identity_id: int, jti: Optional[str] = None) -> bool:
    """Check if a token is still valid (not revoked).

    Returns True if valid, False if revoked.
    If Valkey is unavailable, returns True (fail-open for availability).
    """
    client = _get_client()
    if not client:
        return True
    if is_identity_revoked(identity_id):
        return False
    if jti and is_jti_revoked(jti):
        return False
    return True
