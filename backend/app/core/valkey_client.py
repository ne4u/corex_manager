"""Valkey (Redis-compatible) client for caching, rate limiting, task queue, and token revocation.

Replaces the former memcache.py module. Valkey provides:
- Native list types (LPUSH/BRPOP) for the task queue instead of CAS-retry on a JSON blob.
- Atomic INCR for rate limiting.
- TTL-based key expiry for caching and token revocation.
- Optional persistence (AOF/RDB) so the token denylist survives restarts.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from sqlalchemy.orm import Session

from .config import get_settings

logger = logging.getLogger(__name__)

_settings = get_settings()

# Lazy-init: the client is created on first use so that startup doesn't fail
# when Valkey isn't reachable yet (e.g. compose cold start). Every public
# function degrades gracefully (returns None / True / passes through) if the
# client can't connect.
_client = None


def _get_client():
    """Return a shared Valkey client, or None if Valkey is unreachable.

    When ``VALKEY_SENTINEL_ENABLED`` is true, the client is resolved through
    Sentinel (``master_for``) so that failover is handled transparently —
    if the current master changes, ``_reset_client()`` is called on the next
    error and the new master is discovered. When Sentinel is disabled (the
    default), the direct ``VALKEY_HOST:VALKEY_PORT`` connection is used,
    preserving the original single-instance behavior.
    """
    global _client
    if _client is not None:
        return _client

    try:
        from valkey import Valkey
    except ImportError:
        return None

    # Sentinel mode (HA)
    if getattr(_settings, "VALKEY_SENTINEL_ENABLED", False):
        try:
            from valkey.sentinel import Sentinel

            sentinel_hosts_raw = getattr(_settings, "VALKEY_SENTINEL_HOSTS", "") or ""
            sentinel_hosts = []
            for chunk in sentinel_hosts_raw.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if ":" in chunk:
                    h, p = chunk.rsplit(":", 1)
                    sentinel_hosts.append((h, int(p)))
                else:
                    sentinel_hosts.append((chunk, 26379))
            if not sentinel_hosts:
                logger.warning("Sentinel enabled but no hosts configured; falling back to direct")
            else:
                service_name = getattr(_settings, "VALKEY_SENTINEL_SERVICE", "mymaster")
                sentinel_password = getattr(_settings, "VALKEY_PASSWORD", None) or None
                sentinel = Sentinel(
                    sentinel_hosts,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                    password=sentinel_password,
                    decode_responses=True,
                )
                client = sentinel.master_for(service_name, db=_settings.VALKEY_DB)
                client.ping()
                _client = client
                return client
        except Exception as e:
            logger.debug("Valkey Sentinel not available: %s", e)
            _client = None
            # Fall through to direct mode as a last resort

    # Direct mode (single-instance or Sentinel fallback)
    try:
        client = Valkey(
            host=_settings.VALKEY_HOST,
            port=_settings.VALKEY_PORT,
            db=_settings.VALKEY_DB,
            password=_settings.VALKEY_PASSWORD or None,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )
        client.ping()
        _client = client
        return client
    except Exception as e:
        logger.debug("Valkey not available: %s", e)
        _client = None
        return None


def _reset_client() -> None:
    """Drop the cached client so the next call re-connects (used on failures)."""
    global _client
    if _client is not None:
        try:
            _client.close()
        except Exception:
            pass
    _client = None


def _hash_key(args: tuple, kwargs: dict) -> str:
    """Build a stable, deterministic hash key for cached function results.

    Uses sha256 over a JSON-serialized representation so the key is stable
    across processes and restarts (Python's built-in ``hash()`` is salted per
    process via ``PYTHONHASHSEED``, which would produce different keys in each
    uvicorn worker and on every restart — defeating the shared Valkey cache).

    SQLAlchemy sessions and other ORM objects are skipped (they are not part
    of the cacheable identity). Unhashable args are stringified.
    """
    clean_args = []
    for arg in args:
        if isinstance(arg, Session):
            continue
        clean_args.append(arg)
    clean_kwargs = []
    for k, v in sorted(kwargs.items()):
        if isinstance(v, Session):
            continue
        clean_kwargs.append((k, v))
    payload = json.dumps(
        (clean_args, clean_kwargs),
        default=str,
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_available() -> bool:
    return _get_client() is not None


# ---------------------------------------------------------------------------
# Function-result caching
# ---------------------------------------------------------------------------


def cache(ttl: int = 10, key_prefix: str = "cache") -> Callable[..., Any]:
    """Decorator that caches a function result in Valkey for ``ttl`` seconds."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            client = _get_client()
            if not client:
                return func(*args, **kwargs)

            cache_key = f"{key_prefix}:{func.__name__}:{_hash_key(args, kwargs)}"
            try:
                cached = client.get(cache_key)
                if cached is not None:
                    return json.loads(cached)
            except Exception:
                _reset_client()

            result = func(*args, **kwargs)
            try:
                client.set(cache_key, json.dumps(result, default=str), ex=ttl)
            except Exception:
                _reset_client()
            return result

        return wrapper

    return decorator


def cache_set(key: str, value: Any, ttl: int = 60) -> bool:
    client = _get_client()
    if not client:
        return False
    try:
        client.set(key, json.dumps(value, default=str), ex=ttl)
        return True
    except Exception:
        _reset_client()
        return False


def cache_get(key: str) -> Any:
    client = _get_client()
    if not client:
        return None
    try:
        cached = client.get(key)
        if cached is None:
            return None
        return json.loads(cached)
    except Exception:
        _reset_client()
        return None


def cache_delete(key: str) -> bool:
    """Delete a single cache key. Best-effort; returns False if Valkey is down."""
    client = _get_client()
    if not client:
        return False
    try:
        client.delete(key)
        return True
    except Exception:
        _reset_client()
        return False


# ---------------------------------------------------------------------------
# Rate limiting (fixed-window counter)
# ---------------------------------------------------------------------------


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Fixed-window rate limiter. Returns True if the request is allowed."""
    client = _get_client()
    if not client:
        return True

    now = int(time.time())
    window = now // window_seconds
    bucket_key = f"ratelimit:{key}:{window}"

    try:
        # SET NX EX atomically creates the key with a TTL only if it doesn't
        # exist, matching the old memcached add()+incr() pattern.
        client.set(bucket_key, 0, ex=window_seconds, nx=True)
        count = client.incr(bucket_key)
        return count <= max_requests
    except Exception:
        _reset_client()
        return True


def get_rate_limit_remaining(key: str, max_requests: int, window_seconds: int) -> int:
    client = _get_client()
    if not client:
        return max_requests
    now = int(time.time())
    window = now // window_seconds
    bucket_key = f"ratelimit:{key}:{window}"
    try:
        count = client.get(bucket_key)
        return max(0, max_requests - int(count or 0))
    except Exception:
        _reset_client()
        return max_requests


# ---------------------------------------------------------------------------
# Task queue (backed by Valkey lists — LPUSH/BRPOP)
# ---------------------------------------------------------------------------


def enqueue(queue_name: str, payload: Any) -> bool:
    client = _get_client()
    if not client:
        return False
    key = f"queue:{queue_name}"
    try:
        client.lpush(key, json.dumps(payload, default=str))
        return True
    except Exception:
        _reset_client()
        return False


def dequeue(queue_name: str, timeout: int = 1) -> Any | None:
    client = _get_client()
    if not client:
        return None
    key = f"queue:{queue_name}"
    try:
        result = client.brpop(key, timeout=timeout)
        if result is None:
            return None
        # brpop returns (key, value) tuple; with decode_responses both are str.
        _key, value = result
        return json.loads(value)
    except Exception:
        _reset_client()
        return None


def queue_length(queue_name: str) -> int:
    client = _get_client()
    if not client:
        return 0
    try:
        return client.llen(f"queue:{queue_name}")
    except Exception:
        _reset_client()
        return 0


# ---------------------------------------------------------------------------
# JWT token revocation
# ---------------------------------------------------------------------------


def revoke_token(token: str, ttl: int) -> bool:
    """Add a JWT token to the deny-list until it expires."""
    client = _get_client()
    if not client:
        return False
    try:
        client.set(f"revoked:token:{token}", "1", ex=ttl)
        return True
    except Exception:
        _reset_client()
        return False


def is_token_revoked(token: str) -> bool:
    client = _get_client()
    if not client:
        return False
    try:
        return client.exists(f"revoked:token:{token}") > 0
    except Exception:
        _reset_client()
        return False


# ---------------------------------------------------------------------------
# Captcha validation cookie (_cv) — client-bound token
# ---------------------------------------------------------------------------


def set_cv_token(token: str, binding_hash: str, ttl: int) -> bool:
    """Store the client-binding hash for a solved captcha cookie token.

    Unlike ``cache_set`` (which JSON-encodes the value), this stores the raw
    hash string so the HAProxy Lua validation action can compare it directly
    with the hash it computes from the live request's IP / User-Agent / JA4.
    """
    client = _get_client()
    if not client:
        return False
    try:
        client.set(f"cap:_cv:{token}", binding_hash, ex=ttl)
        return True
    except Exception:
        _reset_client()
        return False


def get_cv_token(token: str) -> str | None:
    """Return the stored binding hash for a captcha cookie token (or None)."""
    client = _get_client()
    if not client:
        return None
    try:
        return client.get(f"cap:_cv:{token}")
    except Exception:
        _reset_client()
        return None


# ---------------------------------------------------------------------------
# Cache invalidation (prefix scan + delete)
# ---------------------------------------------------------------------------


def invalidate(prefix: str, max_batches: int = 1000) -> int:
    """Delete all cache keys matching ``{prefix}:*``.

    Uses a bounded SCAN (capped by ``max_batches`` batches of ~200 keys) so a
    large keyspace can't block Valkey. Returns the number of keys deleted.
    Best-effort: returns 0 if Valkey is unavailable.
    """
    client = _get_client()
    if not client:
        return 0
    pattern = f"{prefix}:*"
    deleted = 0
    try:
        cursor = 0
        batches = 0
        while True:
            cursor, keys = client.scan(cursor=cursor, match=pattern, count=200)
            if keys:
                deleted += client.delete(*keys)
            batches += 1
            if cursor == 0 or batches >= max_batches:
                break
        return deleted
    except Exception:
        _reset_client()
        return deleted


# ---------------------------------------------------------------------------
# Leader election (multi-worker safety for background samplers/schedulers)
# ---------------------------------------------------------------------------

_LEADER_KEY = "corex:leader"
# Unique per-process identifier (pid + a random salt so forked children differ).
_LEADER_ID = f"{os.getpid()}:{secrets.token_hex(4)}"

# PostgreSQL advisory lock fallback: when Valkey is unavailable, use a
# session-level Postgres advisory lock to elect a single leader among
# workers. This prevents all workers from becoming leader simultaneously
# (which would start duplicate background services). The lock is held on a
# dedicated connection for the process lifetime; on SQLite (no advisory
# locks) we fall back to True (single-worker assumption).
_PG_ADVISORY_KEY = 0x434F524558  # "COREX" as a bigint
_pg_lock_conn = None


def _pg_try_advisory_lock() -> bool:
    """Try to acquire a PostgreSQL session-level advisory lock.

    Returns True if acquired (or if the DB is SQLite — single-worker
    fallback). Returns False if another process holds the lock. The lock
    is held on a dedicated connection stored in ``_pg_lock_conn`` for the
    process lifetime; it persists until the connection closes.
    """
    global _pg_lock_conn
    if _pg_lock_conn is not None:
        return True  # already holding it
    try:
        from .database import _is_sqlite, engine

        if _is_sqlite:
            return True  # no advisory locks on SQLite; single-worker fallback
        from sqlalchemy import text

        conn = engine.connect()
        acquired = conn.execute(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": _PG_ADVISORY_KEY}
        ).scalar()
        if acquired:
            _pg_lock_conn = conn
            logger.info("Acquired PostgreSQL advisory lock for leader election")
            return True
        conn.close()
        return False
    except Exception as exc:
        logger.debug("PostgreSQL advisory lock unavailable: %s", exc)
        return False


def _pg_release_advisory_lock() -> None:
    """Release the PostgreSQL advisory lock if this process holds it."""
    global _pg_lock_conn
    if _pg_lock_conn is None:
        return
    try:
        from sqlalchemy import text

        _pg_lock_conn.execute(
            text("SELECT pg_advisory_unlock(:key)"), {"key": _PG_ADVISORY_KEY}
        )
        _pg_lock_conn.close()
        logger.info("Released PostgreSQL advisory lock")
    except Exception as exc:
        logger.debug("Failed to release PostgreSQL advisory lock: %s", exc)
    finally:
        _pg_lock_conn = None


def acquire_leader_lock(ttl: int = 30) -> bool:
    """Try to become the leader for this deployment.

    Tries Valkey first (``SET NX EX``). If Valkey is unavailable, falls back
    to a PostgreSQL session-level advisory lock (``pg_try_advisory_lock``)
    so that exactly one worker becomes leader even without Valkey. If
    neither is available (e.g. SQLite local dev), returns True — the
    single-worker fallback so background work continues.
    """
    client = _get_client()
    if client:
        try:
            ok = client.set(_LEADER_KEY, _LEADER_ID, nx=True, ex=ttl)
            return bool(ok)
        except Exception:
            _reset_client()
            # Fall through to PostgreSQL advisory lock
    return _pg_try_advisory_lock()


def renew_leader_lock(ttl: int = 30) -> bool:
    """Renew the leader lock if this process still owns it.

    Uses a Lua compare-and-swap on Valkey so a process that lost the lock
    cannot silently re-seize it. When Valkey is unavailable, the PostgreSQL
    advisory lock is session-level (persists until the connection closes),
    so no renewal is needed — returns True if we hold it, otherwise tries
    to acquire it (handles the case where the connection died).
    """
    client = _get_client()
    if client:
        _renew_script = """
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('expire', KEYS[1], ARGV[2])
            else
                return 0
            end
        """
        try:
            result = client.eval(_renew_script, 1, _LEADER_KEY, _LEADER_ID, ttl)
            return bool(result)
        except Exception:
            _reset_client()
            # Fall through to PostgreSQL advisory lock
    # Valkey unavailable — the PG advisory lock is session-level, so if we
    # hold it we're still the leader. If we don't (e.g. connection died),
    # try to re-acquire.
    return _pg_lock_conn is not None or _pg_try_advisory_lock()


def release_leader_lock() -> None:
    """Release the leader lock if this process owns it (best-effort).

    Releases both the Valkey lock and the PostgreSQL advisory lock.
    """
    client = _get_client()
    if client:
        _release_script = """
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end
        """
        try:
            client.eval(_release_script, 1, _LEADER_KEY, _LEADER_ID)
        except Exception:
            _reset_client()
    _pg_release_advisory_lock()


def leader_id() -> str:
    """Return this process's leader-election identifier (for diagnostics)."""
    return _LEADER_ID
