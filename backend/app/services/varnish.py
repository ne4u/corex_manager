"""Disk cache (Varnish) service — VCL generation, validation, reload, purge, and stats.

This module manages the Varnish sidecar container that provides file-backed
disk caching for large objects. The VCL is auto-generated from the existing
Backend/Server/CacheConfig models so there is no duplicate configuration.

The Varnish implementation detail is NOT exposed in the GUI — all user-facing
text refers to "Disk Cache".
"""
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import Backend, CacheConfig, Listener, ResponseHeader, PageProtectPolicy
from .cache_rules import emit_vcl_decision
from .runtime import get_runtime

logger = logging.getLogger(__name__)
settings = get_settings()

# Sanitization: VCL identifiers and values must not contain newlines or quotes.
_VCL_NAME_RE = re.compile(r"[^A-Za-z0-9_]")
_VCL_VALUE_RE = re.compile(r"[\r\n\"\\]")


def _safe_vcl_name(name: str) -> str:
    """Sanitize a value used as a VCL identifier (backend name, etc.)."""
    if not isinstance(name, str):
        name = str(name)
    return _VCL_NAME_RE.sub("_", name).strip("_") or "unnamed"


def _safe_vcl_string(value: str) -> str:
    """Escape a string for safe inclusion in a VCL string literal."""
    if not isinstance(value, str):
        value = str(value)
    return _VCL_VALUE_RE.sub("", value)


def _haproxy_managed_response_headers(db: Session) -> List[str]:
    """Return HTTP header names that HAProxy adds to responses via config.

    These are stripped from Varnish cached objects in vcl_backend_response so
    they're never baked into cache. HAProxy re-adds them on the Varnish→client
    delivery path (guarded by !is_varnish_fetch on the origin→Varnish fetch).
    Without stripping, a stale cache object from before the guard was added
    would still carry duplicates.

    Includes:
    - All user-configured ResponseHeader entries (set/add actions only — del
      doesn't add anything).
    - Alt-Svc (emitted per-listener for QUIC).
    - Content-Security-Policy / Content-Security-Policy-Report-Only (Page Protect).
    """
    names: set = set()
    for h in db.query(ResponseHeader).all():
        if h.action in ("set", "override", "add"):
            names.add(h.header)
    # Alt-Svc is emitted per HTTP listener with QUIC enabled
    for listener in db.query(Listener).filter(Listener.quic == True).all():
        names.add("Alt-Svc")
        break
    # CSP headers from Page Protect policies
    for policy in db.query(PageProtectPolicy).filter(PageProtectPolicy.enabled == True).all():
        if policy.mode == "monitor":
            names.add("Content-Security-Policy-Report-Only")
        else:
            names.add("Content-Security-Policy")
    # Sort for deterministic output
    return sorted(names)


def _disk_cache_backends(db: Session) -> List[Tuple[Backend, CacheConfig, str, str]]:
    """Return (backend, cache_config, vcl_name, haproxy_name) for disk-cached backends.

    `vcl_name` is a VCL identifier (letters/digits/underscore only) used to
    declare the backend. `haproxy_name` is the HAProxy section name, which is
    what HAProxy sends in the X-Cache-Backend routing header — it may contain
    dots, colons and dashes that are illegal in a VCL identifier, so the two
    must be tracked separately and never used interchangeably.
    """
    # Imported lazily to avoid a circular import (haproxy imports varnish).
    from .haproxy import _get_section_names

    _, backend_names, _, _ = _get_section_names(db)

    result: List[Tuple[Backend, CacheConfig, str, str]] = []
    used: set = set()
    for cc in db.query(CacheConfig).filter(CacheConfig.disk_cache_enabled == True).all():  # noqa: E712
        backend = db.get(Backend, cc.backend_id)
        if not backend:
            continue
        # TCP backends can't use disk cache
        if backend.protocol == "tcp":
            continue
        vcl_name = _safe_vcl_name(backend.name)
        # Ensure uniqueness
        base = vcl_name
        i = 2
        while vcl_name in used:
            vcl_name = f"{base}_{i}"
            i += 1
        used.add(vcl_name)
        haproxy_name = backend_names.get(backend.id) or backend.name
        result.append((backend, cc, vcl_name, haproxy_name))
    return result


def _haproxy_internal_port(db: Session) -> int:
    """Find the port Varnish should use to fetch through HAProxy.

    Varnish speaks plain HTTP to HAProxy, so it must target a non-SSL HTTP
    listener. Returns the bind_port of the first enabled HTTP-mode listener
    with ssl_enabled=False (the one HAProxy listens on inside the container).
    Falls back to 80 if no suitable listener exists — Varnish can't reach
    HAProxy without one, but a syntactically valid VCL is still generated so
    validation doesn't fail.
    """
    listener = (
        db.query(Listener)
        .filter(
            Listener.enabled == True,  # noqa: E712
            Listener.mode == "http",
            Listener.ssl_enabled == False,  # noqa: E712
        )
        .order_by(Listener.id)
        .first()
    )
    if listener:
        return int(listener.bind_port)

    # No non-SSL HTTP listener — Varnish won't be able to fetch through
    # HAProxy. Log a warning so the issue is diagnosable. Varnish cache
    # misses will return 503, and HAProxy's retry-on/redispatch will fall
    # back to origin servers (so the site works, but without Varnish).
    logger.warning(
        "No enabled non-SSL HTTP listener found — Varnish cannot fetch "
        "through HAProxy. Disk cache will not work. Create an HTTP-mode "
        "listener with SSL disabled for Varnish to use."
    )
    return 80


def generate_vcl(db: Session) -> str:
    """Generate the Varnish VCL file content from the database models.

    Varnish fetches through HAProxy (not directly from origin servers) so that
    HAProxy's response filters (img_2_webp, compression, resp_transform) run on
    the response before Varnish caches it. This lets Varnish cache the
    *converted* output (e.g. WebP images) instead of the raw origin response,
    eliminating re-conversion on every cache hit.

    The loop-prevention mechanism is the X-Varnish-Fetch header: Varnish sets it
    on every backend fetch, and HAProxy's ``use-server disk_cache`` directives
    have ``!is_varnish_fetch`` conditions that skip routing back to Varnish.

    Varnish varies the cache hash on a normalized Accept header (``image/webp``
    vs not) so WebP and non-WebP clients get separate cache entries. The
    X-Cache-Backend header (set by HAProxy on the client request) is stored in
    the Varnish object to enable per-backend purging.
    """
    entries = _disk_cache_backends(db)
    if not entries:
        # Minimal valid VCL with no backends. Health checks (no routing header)
        # get a 200 so the disk_cache server stays UP before any backend is
        # configured; anything else is a genuine misroute and gets a 503.
        return """vcl 4.1;

backend default none;

sub vcl_recv {
    if (!req.http.X-Cache-Backend) {
        return(synth(200, "OK"));
    }
    return(synth(503, "No disk cache backends configured"));
}
"""

    # Varnish fetches through HAProxy. The host is the HAProxy container name
    # (Docker's internal DNS resolves it on haproxy-net); the port is derived
    # from the first enabled HTTP-mode listener in the database.
    haproxy_host = _safe_vcl_string(settings.HAPROXY_CONTAINER_NAME)
    haproxy_port = _haproxy_internal_port(db)

    lines: List[str] = ["vcl 4.1;", ""]

    # Purge ACL — allows purges from the Docker network (haproxy-net).
    any_purge = any(cc.disk_cache_purge_enabled for _, cc, _, _ in entries)
    if any_purge:
        lines.append("acl purge {")
        lines.append('    "localhost";')
        lines.append('    "172.16.0.0"/12;')
        lines.append('    "10.0.0.0"/8;')
        lines.append('    "192.168.0.0"/16;')
        lines.append("}")
        lines.append("")

    # Single backend: HAProxy. Varnish fetches through HAProxy so response
    # filters (img_2_webp, compression, resp_transform) run before Varnish
    # caches the response. HAProxy handles origin server selection, load
    # balancing, and failover — Varnish doesn't need per-origin backends.
    lines.append("backend haproxy {")
    lines.append(f'    .host = "{haproxy_host}";')
    lines.append(f'    .port = "{haproxy_port}";')
    lines.append("}")
    lines.append("")

    # vcl_recv: routing, caching, and loop-prevention logic
    lines.append("sub vcl_recv {")
    if any_purge:
        lines.append("    # PURGE/BAN handling")
        lines.append("    if (req.method == \"PURGE\") {")
        lines.append("        if (!client.ip ~ purge) {")
        lines.append('            return(synth(405, "Not allowed."));')
        lines.append("        }")
        lines.append("        return(purge);")
        lines.append("    }")
        lines.append("    if (req.method == \"BAN\") {")
        lines.append("        if (!client.ip ~ purge) {")
        lines.append('            return(synth(405, "Not allowed."));')
        lines.append("        }")
        lines.append('        ban("obj.http.X-Cache-Backend == " + req.http.X-Cache-Backend);')
        lines.append('        return(synth(200, "Ban added"));')
        lines.append("    }")
        lines.append("")

    # HAProxy health checks are plain requests with no X-Cache-Backend header.
    lines.append("    # HAProxy health check — no routing header is set")
    lines.append("    if (!req.http.X-Cache-Backend) {")
    lines.append('        return(synth(200, "OK"));')
    lines.append("    }")
    lines.append("")

    # Validate X-Cache-Backend against known backends (for error reporting).
    # Routing to the correct origin is handled by HAProxy's frontend rules
    # (Host/path-based), not by Varnish.
    first = True
    for backend, cc, vcl_name, haproxy_name in entries:
        match_value = _safe_vcl_string(haproxy_name)
        if first:
            lines.append(f'    if (req.http.X-Cache-Backend == "{match_value}") {{')
            first = False
        else:
            lines.append(f'    }} else if (req.http.X-Cache-Backend == "{match_value}") {{')
    if entries:
        lines.append("    } else {")
        lines.append('        return(synth(503, "Unknown cache backend"));')
        lines.append("    }")
    lines.append("")

    # All requests go through HAProxy. X-Varnish-Fetch prevents HAProxy from
    # routing back to Varnish (use-server disk_cache has !is_varnish_fetch).
    lines.append("    set req.backend_hint = haproxy;")
    lines.append('    set req.http.X-Varnish-Fetch = "1";')
    lines.append("")

    # Cache GET/HEAD, pass everything else
    lines.append("    if (req.method != \"GET\" && req.method != \"HEAD\") {")
    lines.append("        return(pass);")
    lines.append("    }")
    lines.append("")
    lines.append("    return(hash);")
    lines.append("}")
    lines.append("")

    # vcl_hash: vary on normalized Accept so WebP and non-WebP clients get
    # separate cache entries. Without this, a cached WebP response could be
    # served to a non-WebP client (the img_2_webp filter would skip it since
    # Content-Type is already image/webp, but the non-WebP client would receive
    # WebP it can't display). Normalizing to "webp" vs nothing avoids
    # excessive variants from different Accept header formats.
    lines.append("sub vcl_hash {")
    lines.append("    hash_data(req.url);")
    lines.append("    if (req.http.host) {")
    lines.append("        hash_data(req.http.host);")
    lines.append("    } else {")
    lines.append("        hash_data(server.ip);")
    lines.append("    }")
    lines.append("    if (req.http.Accept ~ \"(?i)image/webp\") {")
    lines.append('        hash_data("webp");')
    lines.append("    }")
    lines.append("    return(lookup);")
    lines.append("}")
    lines.append("")

    # vcl_backend_response: set TTL, grace, and store X-Cache-Backend for purging
    # Use the first backend's TTL/grace as the default (Varnish applies per-backend
    # via beresp.ttl in vcl_backend_response; we set a global default and override
    # per-backend if values differ).
    default_ttl = entries[0][1].disk_cache_ttl if entries else 120
    default_grace = entries[0][1].disk_cache_grace if entries else 600
    lines.append("sub vcl_backend_response {")
    lines.append(f"    set beresp.ttl = {int(default_ttl)}s;")
    lines.append(f"    set beresp.grace = {int(default_grace)}s;")
    lines.append("")
    lines.append("    # Store X-Cache-Backend in the object for per-backend purging.")
    lines.append("    # In vcl_backend_response, the client request is available as")
    lines.append("    # bereq (the backend fetch request), not req.")
    lines.append("    if (bereq.http.X-Cache-Backend) {")
    lines.append("        set beresp.http.X-Cache-Backend = bereq.http.X-Cache-Backend;")
    lines.append("    }")
    lines.append("")
    lines.append("    # Strip Set-Cookie and Cache-Control from the backend response so")
    lines.append("    # Varnish can cache it. HAProxy's cache rules already determined")
    lines.append("    # which requests are cacheable (static files like .png, .css, .js),")
    lines.append("    # so Varnish only sees responses that should be cached. Origin")
    lines.append("    # servers (especially PHP/nginx) often send Set-Cookie or")
    lines.append("    # Cache-Control: private on every response, which would otherwise")
    lines.append("    # prevent Varnish from caching anything.")
    lines.append("    unset beresp.http.Set-Cookie;")
    lines.append("    unset beresp.http.Cache-Control;")
    lines.append("")

    # Strip HAProxy-managed response headers from cached objects so they're
    # not baked into cache. HAProxy adds these on the Varnish→client delivery
    # path (guarded by !is_varnish_fetch on the origin→Varnish fetch). Without
    # stripping, stale cache objects from before the guard was added would
    # carry duplicates. This is defense-in-depth — the HAProxy guard is the
    # primary fix, but this ensures Varnish never caches these headers even
    # if HAProxy's guard is bypassed or a new header type is added.
    managed_headers = _haproxy_managed_response_headers(db)
    if managed_headers:
        lines.append("    # Strip HAProxy-managed response headers (re-added by HAProxy on delivery)")
        for header_name in managed_headers:
            safe_name = _safe_vcl_string(header_name)
            lines.append(f"    unset beresp.http.{safe_name};")
        lines.append("")
    lines.append("    # Cache only successful responses")
    lines.append("    if (beresp.status >= 200 && beresp.status < 400) {")
    lines.append("        return(deliver);")
    lines.append("    } else {")
    lines.append("        set beresp.uncacheable = true;")
    lines.append("    }")
    lines.append("    return(deliver);")
    lines.append("}")
    lines.append("")

    # vcl_deliver: add cache hit/miss headers and strip internal headers
    lines.append("sub vcl_deliver {")
    lines.append("    if (obj.hits > 0) {")
    lines.append('        set resp.http.X-Cache = "HIT";')
    lines.append("    } else {")
    lines.append('        set resp.http.X-Cache = "MISS";')
    lines.append("    }")
    lines.append("    # Strip internal headers so they don't leak to clients.")
    lines.append("    unset resp.http.X-Cache-Backend;")
    lines.append("    # Strip the Varnish Via header so the proxy hop is not exposed")
    lines.append("    # to clients (e.g. \"Via: 1.1 <hostname> (Varnish/7.6)\").")
    lines.append("    unset resp.http.Via;")
    lines.append("    # Rename the X-Varnish debug header to a neutral name so the")
    lines.append("    # underlying cache software is not advertised to clients.")
    lines.append("    if (resp.http.X-Varnish) {")
    lines.append("        set resp.http.X-VCache = resp.http.X-Varnish;")
    lines.append("        unset resp.http.X-Varnish;")
    lines.append("    }")
    lines.append("    return(deliver);")
    lines.append("}")
    lines.append("")

    return "\n".join(lines) + "\n"


def _container_vcl_path() -> str:
    """Map the VCL path to its location inside the Varnish container.

    The API and Varnish containers share the haproxy-data volume, but the API
    may reference it by a different prefix. Preserve any subdirectory (e.g.
    `varnish/default.vcl`) — using only the basename would point at a path
    that does not exist inside the container.
    """
    vcl_path = settings.VARNISH_VCL_PATH
    if vcl_path.startswith("/app/data/"):
        return vcl_path
    # Keep the trailing "<dir>/<file>" so the varnish/ subdirectory survives.
    parent = os.path.basename(os.path.dirname(vcl_path))
    name = os.path.basename(vcl_path)
    return f"/app/data/{parent}/{name}" if parent else f"/app/data/{name}"


def _get_container():
    """Check if the Varnish container is available via the runtime backend.

    Returns True if available, False otherwise. The actual container/pod
    management is handled by the runtime backend (DockerRuntime or
    KubernetesRuntime).
    """
    runtime = get_runtime()
    return runtime if runtime.is_available() else None


def validate_vcl(vcl_text: str) -> Tuple[bool, str]:
    """Validate VCL syntax using varnishd -C in the Varnish container.

    Falls back to local varnishd if available. Returns (is_valid, details).
    """
    runtime = get_runtime()
    # Try container first via the runtime backend
    if runtime.is_available():
        try:
            # Write VCL to a temp file inside the container's data volume
            # Write locally first (the volume is shared with the API container)
            local_path = os.path.join(os.path.dirname(settings.HAPROXY_CONFIG_PATH), "_validate.vcl")
            with open(local_path, "w") as f:
                f.write(vcl_text)
            # The Varnish container mounts haproxy-data at /app/data
            container_vcl_path = f"/app/data/_validate.vcl"
            ok, details = runtime.validate_vcl(container_vcl_path)
            try:
                os.remove(local_path)
            except OSError:
                pass
            if ok or not details.startswith("Varnish container not available"):
                return ok, details
        except Exception as e:
            return False, f"VCL validation via container failed: {e}"

    # Fallback: local varnishd
    varnishd_bin = _which("varnishd")
    if not varnishd_bin:
        return True, "varnishd binary not found, skipping validation"

    with tempfile.NamedTemporaryFile("w", suffix=".vcl", delete=False) as f:
        f.write(vcl_text)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [varnishd_bin, "-C", "-f", tmp_path],
            capture_output=True, text=True
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except Exception as e:
        return False, f"VCL validation failed: {e}"
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def _which(binary: str) -> Optional[str]:
    """Find a binary on PATH."""
    import shutil
    return shutil.which(binary)


def write_vcl(db: Session) -> str:
    """Generate, validate, and write the VCL file, then reload Varnish.

    Returns the VCL content. Raises ValueError if validation fails.
    """
    vcl_text = generate_vcl(db)

    is_valid, details = validate_vcl(vcl_text)
    if not is_valid:
        raise ValueError(f"Generated Varnish VCL failed validation:\n{details}")

    vcl_path = settings.VARNISH_VCL_PATH
    os.makedirs(os.path.dirname(vcl_path), exist_ok=True)
    with open(vcl_path, "w") as f:
        f.write(vcl_text)

    # Reload Varnish config without losing cache
    reload_vcl()
    return vcl_text


def reload_vcl() -> bool:
    """Reload the VCL in the running Varnish container."""
    runtime = get_runtime()
    if not runtime.is_available():
        logger.warning("Varnish container not available, VCL written but not reloaded")
        return False

    container_vcl_path = _container_vcl_path()
    return runtime.reload_vcl(container_vcl_path)


def purge_backend(x_cache_backend_value: str) -> bool:
    """Purge (ban) all cached objects for a specific backend.

    Uses varnishadm ban to invalidate objects where X-Cache-Backend matches.
    The ``x_cache_backend_value`` must be the actual HAProxy section name
    (the value HAProxy sets in the X-Cache-Backend request header), NOT the
    raw backend name or a VCL-safe identifier — those may differ when the
    backend name contains dots/colons/dashes or was suffixed for uniqueness.
    """
    runtime = get_runtime()
    if not runtime.is_available():
        logger.warning("Varnish container not available, cannot purge backend")
        return False

    safe_value = _safe_vcl_string(x_cache_backend_value)
    ban_expr = f'obj.http.X-Cache-Backend == "{safe_value}"'
    return runtime.purge_vcl(ban_expr)


def purge_all() -> bool:
    """Purge (ban) all cached objects in the disk cache."""
    runtime = get_runtime()
    if not runtime.is_available():
        logger.warning("Varnish container not available, cannot purge all")
        return False
    return runtime.purge_all()


def get_stats() -> Dict[str, Any]:
    """Fetch disk cache statistics via varnishstat -j.

    Returns a dict with key counters: cache_hit, cache_miss, n_object,
    n_lru_nuked, etc. Returns empty dict if unavailable.
    """
    runtime = get_runtime()
    if not runtime.is_available():
        return {}
    return runtime.varnish_stats()


def is_running() -> bool:
    """Check if the Varnish container is running."""
    runtime = get_runtime()
    return runtime.is_available()
