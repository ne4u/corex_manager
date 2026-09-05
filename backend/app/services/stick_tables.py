"""HAProxy stick-table viewer — list tables, fetch paginated entries, clear entries.

Talks to the HAProxy stats socket via ``stats._send_command`` (and a longer-timeout
variant for ``show table`` since large tables can take several seconds to dump).

Socket command reference:
- ``show table`` → one line per table: ``# table: <name>, type: <type>, size:<n>, used:<n>``
- ``show table <name>`` → header ``# table: ...`` then one line per entry:
  ``0x<hex>: key=<k> use=<n> exp=<n> <store>=<v> ...``
- ``clear table <name>`` → remove all entries
- ``clear table <name> key <k>`` → remove one entry

Parsed entry lists are cached in Valkey for ``STICK_TABLE_CACHE_TTL_SECONDS`` (default 5s)
so repeated pagination clicks on a 100k+ entry table don't re-fetch+re-parse the whole
dump. The cache is invalidated on clear operations.
"""
import logging
import re
import socket
from typing import Any, Dict, List, Optional

from ..core import valkey_client
from ..core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


# ---------------------------------------------------------------------------
# Low-level socket helper (longer timeout for large `show table` dumps)
# ---------------------------------------------------------------------------

def _send_table_command(cmd: str, timeout: float = 15.0) -> str:
    """Send a command to the HAProxy socket with a longer timeout for table dumps.

    ``stats._send_command`` uses a 5s timeout which is too short for ``show table``
    on tables with hundreds of thousands of entries.
    """
    import os
    from . import stats

    path = settings.HAPROXY_SOCKET_PATH
    if not os.path.exists(path):
        logger.warning("HAProxy socket not found at %s", path)
        return ""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall(f"{cmd}\n".encode())
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            data = b""
            while True:
                try:
                    chunk = s.recv(16384)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode()
    except Exception as e:
        logger.warning("HAProxy socket error for '%s': %s", cmd, e)
        return f"error: {e}"


# ---------------------------------------------------------------------------
# Parsers (pure functions — unit-testable without a socket)
# ---------------------------------------------------------------------------

_TABLE_HEADER_RE = re.compile(
    r"^#\s*table:\s*(?P<name>[^,]+),\s*type:\s*(?P<type>[^,]+),\s*size:(?P<size>\d+),?\s*used:(?P<used>\d+)"
)


def parse_show_tables(raw: str) -> List[Dict[str, Any]]:
    """Parse the output of ``show table`` into a list of table summaries.

    Each line looks like:
        # table: beacon_trust_table, type: ip, size:1048576 used:1234
    """
    tables: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("#"):
            continue
        m = _TABLE_HEADER_RE.match(line)
        if not m:
            continue
        tables.append({
            "name": m.group("name").strip(),
            "type": m.group("type").strip(),
            "size": int(m.group("size")),
            "used": int(m.group("used")),
        })
    tables.sort(key=lambda t: t["name"])
    return tables


# Entry line: ``0x<hex>: key=<k> use=<n> exp=<n> <store>=<v> ...``
# The address prefix is `0x...:` — split on the first `:` after the hex, but the
# key value may itself contain `:` (IPv6). We anchor on the ` key=` marker.
_ENTRY_PREFIX_RE = re.compile(r"^0x[0-9a-fA-F]+:\s")


def _parse_entry_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single entry line from ``show table <name>`` output."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("table:"):
        return None
    # Strip the `0x<hex>:` address prefix
    line = _ENTRY_PREFIX_RE.sub("", line, count=1)
    # Now split into `key=value` tokens. The key value may contain `=` only inside
    # the value, so split on whitespace first, then split each token on the first `=`.
    entry: Dict[str, Any] = {"key": "", "use": 0, "exp": 0, "stores": {}}
    tokens = line.split()
    for tok in tokens:
        if "=" not in tok:
            continue
        field, _, val = tok.partition("=")
        field = field.strip()
        if field == "key":
            entry["key"] = val
        elif field == "use":
            try:
                entry["use"] = int(val)
            except ValueError:
                entry["use"] = val
        elif field == "exp":
            try:
                entry["exp"] = int(val)
            except ValueError:
                entry["exp"] = val
        else:
            # Store counter (gpc0, gpc0_rate(60s), http_req_rate(10s), gpt0, etc.)
            entry["stores"][field] = val
    if not entry["key"]:
        return None
    return entry


def parse_show_table(raw: str) -> List[Dict[str, Any]]:
    """Parse the output of ``show table <name>`` into a list of entry dicts."""
    entries: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        parsed = _parse_entry_line(line)
        if parsed is not None:
            entries.append(parsed)
    return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _cache_key(name: str) -> str:
    return f"stick_table:{name}"


def _get_cached(name: str) -> Optional[Dict[str, Any]]:
    """Return the cached ``{type, size, used, entries}`` blob, or None."""
    return valkey_client.cache_get(_cache_key(name))


def _set_cached(name: str, blob: Dict[str, Any]) -> None:
    valkey_client.cache_set(
        _cache_key(name),
        blob,
        ttl=getattr(settings, "STICK_TABLE_CACHE_TTL_SECONDS", 5),
    )


def _invalidate_cache(name: str) -> None:
    """Drop the cached entry list for a table (e.g. after a clear)."""
    client = valkey_client._get_client()
    if not client:
        return
    try:
        client.delete(_cache_key(name))
    except Exception:
        valkey_client._reset_client()


def list_tables() -> List[Dict[str, Any]]:
    """Return a list of all HAProxy stick-tables with their type/size/used counts."""
    raw = _send_table_command("show table")
    if not raw or raw.startswith("error:"):
        return []
    return parse_show_tables(raw)


def get_table(
    name: str,
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a paginated, optionally filtered slice of a stick-table's entries.

    Returns ``{name, type, size, used, total, offset, limit, entries}``.
    The full parsed entry list is cached in Valkey for ~5s so repeated pagination
    clicks don't re-dump the whole table over the socket.
    """
    max_page = getattr(settings, "STICK_TABLE_MAX_PAGE_SIZE", 500)
    limit = max(1, min(limit, max_page))
    offset = max(0, offset)

    # Try cache first — the blob holds {type, size, used, entries}
    cached = _get_cached(name)
    if cached is None:
        raw = _send_table_command(f"show table {name}")
        if not raw or raw.startswith("error:"):
            return {
                "name": name,
                "type": "",
                "size": 0,
                "used": 0,
                "total": 0,
                "offset": offset,
                "limit": limit,
                "entries": [],
            }
        # Extract table metadata from the header line
        header_meta: Dict[str, Any] = {"type": "", "size": 0, "used": 0}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("#"):
                m = _TABLE_HEADER_RE.match(line)
                if m:
                    header_meta = {
                        "type": m.group("type").strip(),
                        "size": int(m.group("size")),
                        "used": int(m.group("used")),
                    }
                break
        entries = parse_show_table(raw)
        cached = {
            "type": header_meta["type"],
            "size": header_meta["size"],
            "used": header_meta["used"],
            "entries": entries,
        }
        _set_cached(name, cached)

    table_type = cached.get("type", "")
    table_size = cached.get("size", 0)
    table_used = cached.get("used", 0)
    entries = cached.get("entries", [])

    # Apply optional key-substring search
    if search:
        s_lower = search.lower()
        filtered = [e for e in entries if s_lower in str(e.get("key", "")).lower()]
    else:
        filtered = entries

    total = len(filtered)
    page = filtered[offset:offset + limit]

    return {
        "name": name,
        "type": table_type,
        "size": table_size,
        "used": table_used,
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": page,
    }


def clear_entry(name: str, key: str) -> Dict[str, Any]:
    """Remove a single entry from a stick-table. Returns ``{ok, cleared}``."""
    raw = _send_table_command(f"clear table {name} key {key}")
    ok = not (raw and raw.startswith("error:"))
    if ok:
        _invalidate_cache(name)
    return {"ok": ok, "cleared": 1 if ok else 0}


def clear_table(name: str) -> Dict[str, Any]:
    """Remove all entries from a stick-table. Returns ``{ok, cleared}``."""
    raw = _send_table_command(f"clear table {name}")
    ok = not (raw and raw.startswith("error:"))
    if ok:
        _invalidate_cache(name)
    return {"ok": ok, "cleared": -1 if ok else 0}
