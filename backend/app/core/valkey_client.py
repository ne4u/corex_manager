"""Valkey (Redis-compatible) client for caching, rate limiting, task queue, and token revocation.

Replaces the former memcache.py module. Valkey provides:
- Native list types (LPUSH/BRPOP) for the task queue instead of CAS-retry on a JSON blob.
- Atomic INCR for rate limiting.
- TTL-based key expiry for caching and token revocation.
- Optional persistence (AOF/RDB) so the token denylist survives restarts.
"""

import json
import logging
import time
from functools import wraps
from typing import Any, Callable, Optional

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
    """Return a shared Valkey client, or None if Valkey is unreachable."""
    global _client
    if _client is not None:
        return _client

    try:
        from valkey import Valkey
        from valkey.exceptions import ValkeyError
    except ImportError:
        return None

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
    """Build a stable hash key, ignoring SQLAlchemy sessions and other ORM objects."""
    clean_args = []
    for arg in args:
        if isinstance(arg, Session):
            continue
        try:
            hash(arg)
            clean_args.append(arg)
        except TypeError:
            clean_args.append(str(arg))
    clean_kwargs = []
    for k, v in sorted(kwargs.items()):
        if isinstance(v, Session):
            continue
        try:
            hash(v)
            clean_kwargs.append((k, v))
        except TypeError:
            clean_kwargs.append((k, str(v)))
    return str(hash((tuple(clean_args), tuple(clean_kwargs))))


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


def dequeue(queue_name: str, timeout: int = 1) -> Optional[Any]:
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


def get_cv_token(token: str) -> Optional[str]:
    """Return the stored binding hash for a captcha cookie token (or None)."""
    client = _get_client()
    if not client:
        return None
    try:
        return client.get(f"cap:_cv:{token}")
    except Exception:
        _reset_client()
        return None
