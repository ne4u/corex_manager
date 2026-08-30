"""Cache clearing service — clears memory cache (HAProxy native) and disk cache.

HAProxy's memory cache lives entirely in process RAM and has no admin socket
command for purging individual entries or sections. The only way to clear it
is to reload HAProxy (the new worker starts with an empty cache). See
https://github.com/haproxy/haproxy/issues/452 for the upstream statement.

Disk cache (Varnish) is cleared via `varnishadm ban`, which invalidates objects
by matching the X-Cache-Backend header stored on each cached object.
"""
import logging
from typing import Any, Dict

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import Backend, CacheConfig
from . import varnish

logger = logging.getLogger(__name__)
settings = get_settings()


def clear_backend_cache(db: Session, backend_id: int) -> Dict[str, Any]:
    """Clear the cache for a specific backend.

    Memory cache (HAProxy native) is cleared by reloading HAProxy — the cache
    lives in process RAM and there is no per-entry purge command. Disk cache
    (Varnish) is cleared via BAN on the X-Cache-Backend header value.

    Returns a summary dict with ``memory_cleared``, ``disk_cleared``, and
    ``message`` keys.
    """
    backend = db.get(Backend, backend_id)
    if not backend:
        return {"memory_cleared": False, "disk_cleared": False, "message": "Backend not found"}

    cc = db.query(CacheConfig).filter(CacheConfig.backend_id == backend_id).first()
    if not cc:
        return {"memory_cleared": False, "disk_cleared": False, "message": "No cache config for this backend"}

    memory_cleared = False
    disk_cleared = False
    messages = []

    # Clear disk cache (Varnish BAN) — do this first because it's instant.
    # The BAN invalidates objects in the running Varnish without a restart.
    if cc.disk_cache_enabled:
        from .haproxy import _get_section_names
        _, backend_names, _, _ = _get_section_names(db)
        x_cache_backend_value = backend_names.get(backend.id, backend.name)
        if varnish.purge_backend(x_cache_backend_value):
            disk_cleared = True
            messages.append(f"Disk cache cleared for backend '{backend.name}'")
        else:
            messages.append(f"Disk cache clear failed for backend '{backend.name}'")

    # Clear memory cache (HAProxy native) via reload.
    # HAProxy's cache is in-process RAM; a reload spawns a new worker with an
    # empty cache. There is no `clear cache` admin socket command — see
    # https://github.com/haproxy/haproxy/issues/452. The reload uses the
    # existing config on disk (no rewrite needed).
    if cc.haproxy_enabled:
        from .haproxy import reload_haproxy
        result = reload_haproxy()
        if result.get("status") == "ok":
            memory_cleared = True
            messages.append(f"Memory cache cleared for backend '{backend.name}' (HAProxy reloaded)")
        else:
            messages.append(f"Memory cache clear failed: {result.get('message', 'unknown error')}")

    if not messages:
        messages.append("No cache enabled for this backend")

    return {
        "memory_cleared": memory_cleared,
        "disk_cleared": disk_cleared,
        "message": "; ".join(messages),
    }


def clear_all_caches(db: Session) -> Dict[str, Any]:
    """Clear all caches (memory + disk) for all backends.

    Disk cache (Varnish) is cleared via a single `varnishadm ban` that matches
    all X-Cache-Backend values. Memory cache (HAProxy native) is cleared by a
    single HAProxy reload — one reload empties all cache sections since they
    all live in the same process RAM.

    Returns a summary dict with ``memory_cleared``, ``disk_cleared``, and
    ``message`` keys.
    """
    memory_cleared = False
    disk_cleared = False
    messages = []

    # Clear all disk cache objects (Varnish BAN) — instant, no restart.
    disk_configs = db.query(CacheConfig).filter(CacheConfig.disk_cache_enabled == True).all()  # noqa: E712
    if disk_configs:
        if varnish.purge_all():
            disk_cleared = True
            messages.append(f"Cleared {len(disk_configs)} disk cache(s)")
        else:
            messages.append("Disk cache clear failed")

    # Clear all memory caches (HAProxy reload) — one reload empties all
    # cache sections. Only needed if at least one backend has memory cache.
    memory_configs = db.query(CacheConfig).filter(CacheConfig.haproxy_enabled == True).all()  # noqa: E712
    if memory_configs:
        from .haproxy import reload_haproxy
        result = reload_haproxy()
        if result.get("status") == "ok":
            memory_cleared = True
            messages.append(f"Cleared {len(memory_configs)} memory cache(s) (HAProxy reloaded)")
        else:
            messages.append(f"Memory cache clear failed: {result.get('message', 'unknown error')}")

    if not messages:
        messages.append("No caches configured")

    return {
        "memory_cleared": memory_cleared,
        "disk_cleared": disk_cleared,
        "message": "; ".join(messages),
    }
