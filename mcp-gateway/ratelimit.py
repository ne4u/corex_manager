"""Rate limiting for MCP Gateway — Valkey-backed sliding-window quotas.

Implements:
- Sliding window per-identity/tool rate limiting (ZSET-based)
- Per-IP rate limiting (blocks credential stuffing / distributed abuse)
- Concurrent request limits per-identity
- Per-team RPM overrides (from config bundle)
- Configurable fail mode: fail-open (default) or fail-closed

Exceed → JSON-RPC error -32029 "rate_limited".
"""
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

MCP_RATE_LIMITED = -32029

_client = None

# Default config: fail-open for backward compat, configurable via env
_FAIL_CLOSED = os.environ.get("MCP_RATELIMIT_FAIL_CLOSED", "false").lower() in ("true", "1", "yes")
_DEFAULT_MAX_IP_RPM = int(os.environ.get("MCP_MAX_IP_RPM", "0"))  # 0 = disabled
_DEFAULT_MAX_CONCURRENT = int(os.environ.get("MCP_MAX_CONCURRENT", "0"))  # 0 = disabled
_WINDOW_SECONDS = 60


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
        logger.debug("Valkey not available: %s", e)
        _client = None
        return None


def _sliding_window_check(
    client,
    key: str,
    max_count: int,
    window: int = _WINDOW_SECONDS,
) -> tuple[bool, int]:
    """Sliding window check using ZSET. Returns (allowed, remaining).

    Removes entries older than window, counts remaining, adds current timestamp.
    """
    now = time.time()
    cutoff = now - window

    pipe = client.pipeline()
    pipe.zremrangebyscore(key, 0, cutoff)
    pipe.zcard(key)
    _, count = pipe.execute()

    if count >= max_count:
        return False, 0

    member = f"{now}:{count}"
    pipe = client.pipeline()
    pipe.zadd(key, {member: now})
    pipe.expire(key, window + 5)
    pipe.execute()

    return True, max_count - count - 1


def check_rate_limit(
    identity_id: int,
    tool: str,
    max_rpm: int,
) -> tuple[bool, int]:
    """Check if a request is within the sliding-window rate limit.

    Returns (allowed, remaining). Uses a 60-second sliding window via ZSET.
    Key: mcp:rl:{identity_id}:{tool}
    """
    client = _get_client()
    if not client:
        if _FAIL_CLOSED:
            logger.warning("Rate limit check failed (fail-closed: denying)")
            return False, 0
        return True, max_rpm

    if max_rpm <= 0:
        return True, max_rpm

    key = f"mcp:rl:{identity_id}:{tool}"
    try:
        return _sliding_window_check(client, key, max_rpm)
    except Exception as e:
        if _FAIL_CLOSED:
            logger.warning("Rate limit check failed (fail-closed: denying): %s", e)
            return False, 0
        logger.warning("Rate limit check failed (allowing): %s", e)
        return True, max_rpm


def check_ip_rate_limit(
    ip: str,
    max_ip_rpm: Optional[int] = None,
) -> tuple[bool, int]:
    """Check per-IP rate limit. Returns (allowed, remaining).

    Disabled if max_ip_rpm is 0 or None.
    """
    limit = max_ip_rpm if max_ip_rpm is not None else _DEFAULT_MAX_IP_RPM
    if limit <= 0:
        return True, limit

    client = _get_client()
    if not client:
        if _FAIL_CLOSED:
            return False, 0
        return True, limit

    key = f"mcp:rl:ip:{ip}"
    try:
        return _sliding_window_check(client, key, limit)
    except Exception as e:
        if _FAIL_CLOSED:
            logger.warning("IP rate limit check failed (fail-closed: denying): %s", e)
            return False, 0
        return True, limit


def acquire_concurrent_slot(
    identity_id: int,
    max_concurrent: Optional[int] = None,
) -> bool:
    """Acquire a concurrent request slot. Returns True if allowed.

    Uses INCR with TTL as a lease. Must be released with release_concurrent_slot.
    Disabled if max_concurrent is 0 or None.
    """
    limit = max_concurrent if max_concurrent is not None else _DEFAULT_MAX_CONCURRENT
    if limit <= 0:
        return True

    client = _get_client()
    if not client:
        if _FAIL_CLOSED:
            return False
        return True

    key = f"mcp:conc:{identity_id}"
    try:
        count = client.incr(key)
        if count == 1:
            client.expire(key, 300)  # 5-min safety expiry
        if count > limit:
            client.decr(key)
            return False
        return True
    except Exception as e:
        if _FAIL_CLOSED:
            logger.warning("Concurrent check failed (fail-closed: denying): %s", e)
            return False
        return True


def release_concurrent_slot(identity_id: int) -> None:
    """Release a concurrent request slot."""
    if _DEFAULT_MAX_CONCURRENT <= 0:
        return
    client = _get_client()
    if not client:
        return
    key = f"mcp:conc:{identity_id}"
    try:
        client.decr(key)
    except Exception:
        pass


def get_team_rpm(config: dict, team_id: int, default_rpm: int) -> int:
    """Get the RPM for a team, falling back to default_rpm.

    Config bundle may include 'team_rpm_overrides': {team_id: rpm}.
    """
    overrides = config.get("team_rpm_overrides") or {}
    return int(overrides.get(str(team_id), overrides.get(team_id, default_rpm)))


def get_rate_limit_remaining(identity_id: int, tool: str, max_rpm: int) -> int:
    """Return remaining requests in the current sliding window."""
    client = _get_client()
    if not client or max_rpm <= 0:
        return max_rpm
    key = f"mcp:rl:{identity_id}:{tool}"
    try:
        now = time.time()
        cutoff = now - _WINDOW_SECONDS
        client.zremrangebyscore(key, 0, cutoff)
        count = client.zcard(key)
        return max(0, max_rpm - count)
    except Exception:
        return max_rpm
