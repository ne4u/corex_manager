"""Valkey (Redis-compatible) inspector — list namespaces, browse keys, delete a key.

Talks to the live Valkey client from ``core.valkey_client``. Keys are grouped by
namespace prefix (the substring before the first ``:``; keys without ``:`` are
grouped under the sentinel ``NO_NAMESPACE``).

The scanned key list for a namespace is cached in Valkey for
``VALKEY_INSPECT_CACHE_TTL_SECONDS`` (default 5s) so repeated pagination clicks
don't rescan. SCAN is bounded by ``VALKEY_INSPECT_MAX_SCAN_BATCHES`` batches of
~200 keys each (default 1000 → ~200k keys max) to avoid unbounded scans on large
keyspaces; on bigger stores the namespace list will be approximate.

All access degrades gracefully when Valkey is unreachable (returns empty/``available=False``
shapes), matching the pattern in ``valkey_client.py`` and ``stick_tables.py``.
"""
import json
import logging
from typing import Any, Dict, List, Optional

from ..core import valkey_client
from ..core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Sentinel for keys without a `:` namespace separator. Exposed as a module
# constant so the API layer and tests can reference it. Chosen to be unlikely
# to collide with real prefixes (real prefixes don't contain `__`).
NO_NAMESPACE = "__none__"

# Refuse to delete our own cache keys (avoids confusing the inspector mid-scan).
_OWN_CACHE_PREFIX = "valkey_inspect:"


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _client():
    """Return the shared Valkey client, or None if unreachable."""
    return valkey_client._get_client()


def _scan_keys(pattern: str) -> List[str]:
    """Bounded SCAN over the keyspace matching ``pattern``.

    Returns a list of key strings. SCAN iterates in batches of 200; we cap the
    number of batches at ``VALKEY_INSPECT_MAX_SCAN_BATCHES`` so a huge keyspace
    doesn't block the request indefinitely. On stores larger than the cap, the
    returned list is an approximate sample.
    """
    client = _client()
    if not client:
        return []
    max_batches = getattr(settings, "VALKEY_INSPECT_MAX_SCAN_BATCHES", 1000)
    keys: List[str] = []
    try:
        # valkey-py's scan_iter wraps SCAN into a generator. We break early once
        # we've issued enough batches to stay within the bound.
        batch = 0
        for key in client.scan_iter(match=pattern, count=200):
            keys.append(key)
            # Cheap check every 200 keys (one batch worth) to avoid per-key overhead.
            if len(keys) % 200 == 0:
                batch += 1
                if batch >= max_batches:
                    logger.info(
                        "valkey_inspect: SCAN cap reached (%d batches, %d keys) for %r",
                        batch, len(keys), pattern,
                    )
                    break
    except Exception as e:
        logger.warning("valkey_inspect: SCAN failed for %r: %s", pattern, e)
        valkey_client._reset_client()
        return []
    return keys


def _namespace_of(key: str) -> str:
    """Return the namespace prefix of ``key`` (substring before first ``:``).

    Keys without ``:`` are grouped under ``NO_NAMESPACE``.
    """
    idx = key.find(":")
    if idx <= 0:
        return NO_NAMESPACE
    return key[:idx]


# ---------------------------------------------------------------------------
# Caching (cached scanned key list per namespace)
# ---------------------------------------------------------------------------

def _ns_cache_key(prefix: str) -> str:
    return f"valkey_inspect:ns:{prefix}"


def _ns_cache_get(prefix: str) -> Optional[List[str]]:
    return valkey_client.cache_get(_ns_cache_key(prefix))


def _ns_cache_set(prefix: str, keys: List[str]) -> None:
    valkey_client.cache_set(
        _ns_cache_key(prefix),
        keys,
        ttl=getattr(settings, "VALKEY_INSPECT_CACHE_TTL_SECONDS", 5),
    )


def _ns_cache_invalidate(prefix: str) -> None:
    client = _client()
    if not client:
        return
    try:
        client.delete(_ns_cache_key(prefix))
    except Exception:
        valkey_client._reset_client()


# ---------------------------------------------------------------------------
# Server info
# ---------------------------------------------------------------------------

def server_info() -> Dict[str, Any]:
    """Return a summary of the Valkey server state.

    Degrades to ``{available: False, error: ...}`` when Valkey is unreachable.
    """
    client = _client()
    if not client:
        return {"available": False, "error": "valkey not reachable"}

    try:
        info = client.info()
        dbsize = client.dbsize()
    except Exception as e:
        logger.warning("valkey_inspect: INFO/DBSIZE failed: %s", e)
        valkey_client._reset_client()
        return {"available": False, "error": str(e)}

    # valkey-py (like redis-py) parses the INFO reply into a FLAT dict — the
    # section names (Server, Clients, Memory, Keyspace) are NOT nested keys.
    # Scalar fields live at the top level (redis_version, uptime_in_seconds,
    # connected_clients, used_memory_human, role, ...). The Keyspace section is
    # parsed into per-DB sub-dicts keyed by `db0`, `db1`, ... at the top level.
    # The `databases` field (from the Server section) gives the total number of
    # configured databases (the `databases` config directive, default 16).
    db_count = int(info.get("databases", 0) or 0)

    return {
        "available": True,
        "version": info.get("valkey_version") or info.get("redis_version"),
        "uptime_seconds": int(info.get("uptime_in_seconds", 0) or 0),
        "connected_clients": int(info.get("connected_clients", 0) or 0),
        "used_memory_human": info.get("used_memory_human", "") or "",
        "used_memory_peak_human": info.get("used_memory_peak_human", "") or "",
        "total_keys": int(dbsize),
        "db_count": db_count,
        "role": info.get("role", "") or "",
        "error": None,
    }


# ---------------------------------------------------------------------------
# Namespace listing
# ---------------------------------------------------------------------------

def list_namespaces() -> List[Dict[str, Any]]:
    """Group all keys by namespace prefix and return a sorted summary list.

    Each entry: ``{prefix, count, sample_keys}`` (up to 5 sample keys).
    The full scan is cached for ``VALKEY_INSPECT_CACHE_TTL_SECONDS``.
    """
    cache_key = "valkey_inspect:namespaces"
    cached = valkey_client.cache_get(cache_key)
    if cached is not None:
        return cached

    keys = _scan_keys("*")
    groups: Dict[str, List[str]] = {}
    for k in keys:
        ns = _namespace_of(k)
        groups.setdefault(ns, []).append(k)

    out: List[Dict[str, Any]] = []
    for prefix in sorted(groups.keys(), key=lambda p: (p == NO_NAMESPACE, p)):
        members = groups[prefix]
        out.append({
            "prefix": prefix,
            "count": len(members),
            "sample_keys": sorted(members)[:5],
        })

    valkey_client.cache_set(
        cache_key,
        out,
        ttl=getattr(settings, "VALKEY_INSPECT_CACHE_TTL_SECONDS", 5),
    )
    return out


# ---------------------------------------------------------------------------
# Namespace detail (paginated keys with type/ttl/size/preview)
# ---------------------------------------------------------------------------

def _preview_value(client, key: str, ktype: str) -> str:
    """Build a short human-readable preview of a key's value.

    Strings are truncated to 200 chars (with a trailing ``…`` if longer); if the
    string parses as JSON, the pretty-printed JSON is shown (still truncated).
    Collections show their cardinality plus a few sample members.
    """
    try:
        if ktype == "string":
            val = client.get(key)
            if val is None:
                return ""
            s = val if isinstance(val, str) else str(val)
            # Try JSON pretty-print for readability.
            try:
                parsed = json.loads(s)
                s = json.dumps(parsed, default=str, ensure_ascii=False)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
            return _truncate(s, 200)
        if ktype == "list":
            n = client.llen(key)
            sample = client.lrange(key, 0, 2)
            sample_str = ", ".join(str(x) for x in sample)
            return f"list[{n}] [{_truncate(sample_str, 160)}]"
        if ktype == "hash":
            n = client.hlen(key)
            # HSCAN returns (cursor, {field: value})
            _, sample = client.hscan(key, 0, count=3)
            sample_str = ", ".join(f"{k}={v}" for k, v in list(sample.items())[:3])
            return f"hash[{n}] {{{_truncate(sample_str, 160)}}}"
        if ktype == "set":
            n = client.scard(key)
            _, sample = client.sscan(key, 0, count=3)
            sample_str = ", ".join(str(x) for x in list(sample)[:3])
            return f"set[{n}] {{{_truncate(sample_str, 160)}}}"
        if ktype == "zset":
            n = client.zcard(key)
            sample = client.zrange(key, 0, 2, withscores=True)
            sample_str = ", ".join(f"{m}({s})" for m, s in sample)
            return f"zset[{n}] [{_truncate(sample_str, 160)}]"
        if ktype == "stream":
            n = client.xlen(key)
            return f"stream[{n}]"
        if ktype == "none":
            return ""
    except Exception as e:
        logger.debug("valkey_inspect: preview failed for %r (%s): %s", key, ktype, e)
        return ""
    return ""


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + "\u2026"


def get_namespace(
    prefix: str,
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a paginated, optionally key-substring-filtered slice of a namespace.

    Returns ``{prefix, total, offset, limit, keys}`` where each key is
    ``{key, type, ttl, size, preview}``.
    """
    max_page = getattr(settings, "VALKEY_INSPECT_MAX_PAGE_SIZE", 500)
    limit = max(1, min(limit, max_page))
    offset = max(0, offset)

    # Resolve the actual prefix back from the sentinel.
    real_prefix = "" if prefix == NO_NAMESPACE else prefix

    cached = _ns_cache_get(prefix)
    if cached is None:
        pattern = f"{real_prefix}:*" if real_prefix else "*"
        cached = _scan_keys(pattern)
        # When scanning the no-namespace group, filter out keys that DO contain
        # `:` (the `*` pattern matches everything). For real prefixes, the
        # `{prefix}:*` pattern already restricts correctly.
        if not real_prefix:
            cached = [k for k in cached if ":" not in k]
        _ns_cache_set(prefix, cached)

    keys = cached

    if search:
        s_lower = search.lower()
        filtered = [k for k in keys if s_lower in k.lower()]
    else:
        filtered = keys

    total = len(filtered)
    page = filtered[offset:offset + limit]

    client = _client()
    entries: List[Dict[str, Any]] = []
    if client:
        for key in page:
            entry: Dict[str, Any] = {
                "key": key,
                "type": "none",
                "ttl": -2,
                "size": None,
                "preview": "",
            }
            try:
                entry["type"] = client.type(key) or "none"
            except Exception:
                entry["type"] = "none"
            try:
                entry["ttl"] = int(client.ttl(key))
            except Exception:
                entry["ttl"] = -2
            try:
                # MEMORY USAGE may be unavailable on some builds; tolerate None.
                size = client.memory_usage(key)
                entry["size"] = int(size) if size is not None else None
            except Exception:
                entry["size"] = None
            entry["preview"] = _preview_value(client, key, entry["type"])
            entries.append(entry)

    return {
        "prefix": prefix,
        "total": total,
        "offset": offset,
        "limit": limit,
        "keys": entries,
    }


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def delete_key(key: str) -> Dict[str, Any]:
    """Delete a single key. Refuses to delete our own cache keys.

    Returns ``{ok, deleted}`` where ``deleted`` is the number of keys removed
    (0 if the key didn't exist).
    """
    if key.startswith(_OWN_CACHE_PREFIX):
        return {"ok": False, "deleted": 0}
    client = _client()
    if not client:
        return {"ok": False, "deleted": 0}
    try:
        removed = int(client.delete(key))
    except Exception as e:
        logger.warning("valkey_inspect: delete failed for %r: %s", key, e)
        valkey_client._reset_client()
        return {"ok": False, "deleted": 0}
    # Invalidate the namespace cache for this key's prefix so the next browse
    # reflects the deletion.
    _ns_cache_invalidate(_namespace_of(key))
    return {"ok": True, "deleted": removed}
