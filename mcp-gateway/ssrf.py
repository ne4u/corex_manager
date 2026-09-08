"""SSRF protection for MCP Gateway — validates upstream URLs.

Blocks requests to loopback, link-local (cloud metadata), multicast, reserved,
and unspecified addresses. Private/RFC1918 ranges are ALLOWED by default —
MCP upstreams are typically internal services, so blocking private IPs would
break normal deployments. Set MCP_SSRF_BLOCK_PRIVATE=true to restore strict
blocking of private ranges.

Called at config load time and before each upstream request.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)

# Configurable allowlist of IPs or hostnames that are permitted even if the
# resolved address is private. Hostname entries are needed for Docker
# deployments where upstreams are internal service names (e.g. "mcp-server").
# Set via env: MCP_UPSTREAM_ALLOWLIST=10.0.0.1,mcp-server,opensearch-mcp
import os
_allowlist_env = os.environ.get("MCP_UPSTREAM_ALLOWLIST", "")
_ALLOWED_IPS: set[str] = set()
_ALLOWED_HOSTS: set[str] = set()
for _entry in _allowlist_env.split(","):
    _entry = _entry.strip()
    if not _entry:
        continue
    try:
        ipaddress.ip_address(_entry)
        _ALLOWED_IPS.add(_entry)
    except ValueError:
        _ALLOWED_HOSTS.add(_entry.lower())

# Dynamic allowlist: hosts of upstreams present in the signed config bundle.
# Registering a server already requires admin approval in the control plane,
# so bundle-listed upstreams are trusted without needing a container redeploy.
_DYNAMIC_ALLOWED: set[str] = set()


def update_allowed_upstreams(urls) -> None:
    """Replace the dynamic allowlist with hostnames/IPs from upstream URLs.

    Called by config_loader each time the config bundle is (re)loaded, so
    newly registered MCP servers are reachable without restarting the gateway.
    """
    global _DYNAMIC_ALLOWED
    allowed: set[str] = set()
    for url in urls:
        try:
            host = urlparse(url).hostname
        except Exception:
            continue
        if host:
            allowed.add(host.lower())
    _DYNAMIC_ALLOWED = allowed


# Whether SSRF protection is enabled (default: true)
_SSRF_ENABLED = os.environ.get("MCP_SSRF_PROTECTION", "true").lower() not in ("false", "0", "no")

# Whether to also block private/RFC1918 addresses (default: false — internal
# upstreams are the normal case for this gateway). Set "true" for strict mode.
_BLOCK_PRIVATE = os.environ.get("MCP_SSRF_BLOCK_PRIVATE", "false").lower() in ("true", "1", "yes")


def _is_blocked_ip(ip_str: str) -> bool:
    """Check if an IP address is in a blocked range.

    Loopback, link-local (cloud metadata), multicast, reserved, and
    unspecified addresses are always blocked. Private/RFC1918 ranges are
    blocked only when MCP_SSRF_BLOCK_PRIVATE is enabled.
    """
    if ip_str in _ALLOWED_IPS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if _BLOCK_PRIVATE and ip.is_private:
            return True
        return (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        # Not a valid IP — could be a hostname, allow it
        return False


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to IP addresses. Returns list of IP strings."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return [r[4][0] for r in results]
    except Exception:
        return []


def is_url_safe(url: str) -> tuple[bool, str]:
    """Validate a URL against SSRF rules.

    Returns (is_safe, reason). If unsafe, reason explains why.
    """
    if not _SSRF_ENABLED:
        return True, "SSRF protection disabled"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname in URL"

    hostname_l = hostname.lower()

    # Check if hostname is a literal IP
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    # Admin-registered upstreams (env allowlist or config bundle) are trusted.
    # Exception: link-local/loopback/unspecified literals are always blocked —
    # those are cloud metadata endpoints and friends, never legit upstreams.
    if hostname_l in _ALLOWED_HOSTS or hostname_l in _DYNAMIC_ALLOWED:
        if literal_ip is not None and (
            literal_ip.is_loopback or literal_ip.is_link_local or literal_ip.is_unspecified
        ) and hostname_l not in _ALLOWED_IPS:
            return False, f"Blocked IP: {hostname}"
        return True, ""

    if literal_ip is not None:
        if _is_blocked_ip(hostname):
            return False, f"Blocked IP: {hostname}"
    else:
        # It's a hostname — resolve and check all IPs
        ips = _resolve_hostname(hostname)
        for ip in ips:
            if _is_blocked_ip(ip):
                return False, f"Hostname {hostname} resolves to blocked IP: {ip}"

    return True, ""
