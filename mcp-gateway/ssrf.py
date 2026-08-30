"""SSRF protection for MCP Gateway — validates upstream URLs.

Blocks requests to private/internal IP ranges and loopback addresses.
Called at config load time and before each upstream request.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)

# Allowlist of private CIDR ranges that are blocked by default
_BLOCKED_PREFIXES = [
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "::1", "fc", "fd", "fe80:",
]

# Configurable allowlist of IPs that are permitted even if private
# Set via env: MCP_UPSTREAM_ALLOWLIST=10.0.0.1,10.0.0.2
import os
_allowlist_env = os.environ.get("MCP_UPSTREAM_ALLOWLIST", "")
_ALLOWED_IPS: set[str] = {ip.strip() for ip in _allowlist_env.split(",") if ip.strip()}

# Whether SSRF protection is enabled (default: true)
_SSRF_ENABLED = os.environ.get("MCP_SSRF_PROTECTION", "true").lower() not in ("false", "0", "no")


def _is_blocked_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/loopback range."""
    if ip_str in _ALLOWED_IPS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
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

    # Check if hostname is an IP directly
    try:
        ipaddress.ip_address(hostname)
        if _is_blocked_ip(hostname):
            return False, f"Blocked IP: {hostname}"
    except ValueError:
        # It's a hostname — resolve and check all IPs
        ips = _resolve_hostname(hostname)
        for ip in ips:
            if _is_blocked_ip(ip):
                return False, f"Hostname {hostname} resolves to blocked IP: {ip}"

    return True, ""
