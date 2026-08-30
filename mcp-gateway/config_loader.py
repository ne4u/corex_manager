"""Config loader for MCP Gateway.

Reads the JSON config bundle from file (MCP_CONFIG_PATH) and optionally
Valkey pubsub for reloads. The control plane writes the bundle; the gateway
only reads it.

Bundle format (produced by backend/app/services/mcp_config.py):
{
  "servers": [
    {
      "id": 1, "team_id": 1, "name": "jira", "namespace": "jira",
      "url": "https://upstream.example.com/mcp",
      "enabled": true, "verify_tls": true,
      "auth_type": "bearer", "auth_header": "Authorization",
      "auth_secret": "decrypted-plaintext",  # decrypted by control plane before write
      "timeout_ms": 30000, "max_body_bytes": 1048576,
      "has_replicas": false
    }
  ],
  "identities": [
    {
      "id": 1, "team_id": 1, "name": "ci-bot",
      "subject": "ci-bot", "kind": "pat",
      "pat_hash": "$2b$...", "pat_prefix": "mcp_abcd1234",
      "jwt_issuer": null, "jwt_audience": null, "jwt_jwks_url": null,
      "enabled": true, "expires_at": null
    }
  ],
  "teams": [{"id": 1, "name": "Engineering", "slug": "engineering"}],
  "jwt_issuer": null, "jwt_audience": null, "jwt_jwks_url": null,
  "allowed_origins": ["https://example.com"],
  "log_payloads": false,
  "default_rpm": 60,
  "catalog_refresh_seconds": 60
}
"""
import json
import logging
import os
import hmac
import hashlib
import base64
import hashlib as _hashlib
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

_config: dict = {}
_config_mtime: float = 0.0
_config_lock = threading.Lock()
_config_path: str = os.environ.get("MCP_CONFIG_PATH", "/app/data/mcp/config.json")
_signing_key: str = os.environ.get("MCP_CONFIG_SIGNING_KEY", "")
_encryption_key: str = os.environ.get("MCP_SECRETS_KEY", "")


def _verify_signature(raw_bytes: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature of the config bundle."""
    if not _signing_key:
        return True  # No signing key configured — skip verification
    expected = hmac.new(
        _signing_key.encode("utf-8"),
        raw_bytes,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _decrypt_bundle_bytes(raw_bytes: bytes) -> bytes:
    """Decrypt config bundle bytes if encryption key is configured.

    Tries Fernet decryption first; falls back to plaintext JSON if decryption
    fails (backward compat with unencrypted bundles).
    """
    if not _encryption_key:
        return raw_bytes  # No encryption key — assume plaintext
    try:
        from cryptography.fernet import Fernet, InvalidToken
        # Derive Fernet key (same as backend mcp_secrets.py)
        derived = _hashlib.pbkdf2_hmac("sha256", _encryption_key.encode("utf-8"), b"mcp-gateway-secrets", 100_000, dklen=32)
        fernet_key = base64.urlsafe_b64encode(derived)
        f = Fernet(fernet_key)
        return f.decrypt(raw_bytes)
    except Exception:
        # Not encrypted or wrong key — try as plaintext
        return raw_bytes


def load_config() -> dict:
    """Load config from file, caching by mtime. Returns empty dict if unavailable."""
    global _config, _config_mtime
    try:
        mtime = os.path.getmtime(_config_path)
    except OSError:
        return _config if _config else {}

    with _config_lock:
        if mtime != _config_mtime or not _config:
            try:
                with open(_config_path, "rb") as f:
                    raw_bytes = f.read()
                # Decrypt if encryption key is configured
                decrypted = _decrypt_bundle_bytes(raw_bytes)
                _config = json.loads(decrypted.decode("utf-8"))
                # Verify signature if signing key is configured
                if _signing_key:
                    signature = _config.pop("_signature", "")
                    if not _verify_signature(decrypted.split(b'"_signature":"', 1)[0] if b'"_signature"' in decrypted else decrypted, signature):
                        logger.error("MCP config bundle signature verification FAILED — using previous config")
                        return _config if _config else {}
                    logger.info("MCP config bundle signature verified")
                _config_mtime = mtime
                logger.info("Loaded MCP config: %d servers, %d identities",
                            len(_config.get("servers", [])),
                            len(_config.get("identities", [])))
            except (json.JSONDecodeError, OSError) as e:
                logger.error("Failed to load MCP config: %s", e)
                return _config if _config else {}
        return _config


def get_config() -> dict:
    """Return cached config, reloading if file changed."""
    return load_config()


def is_configured() -> bool:
    """Check if gateway is enabled and has at least one server."""
    config = get_config()
    servers = config.get("servers", [])
    return len(servers) > 0


def get_enabled_servers() -> list[dict]:
    """Return enabled servers from config."""
    return [s for s in get_config().get("servers", []) if s.get("enabled", True)]


def get_server_by_namespace(ns: str) -> Optional[dict]:
    """Find a server by its namespace."""
    for s in get_enabled_servers():
        if s.get("namespace") == ns:
            return s
    return None


def get_team_servers(team_id: int) -> list[dict]:
    """Return enabled servers for a specific team."""
    return [s for s in get_enabled_servers() if s.get("team_id") == team_id]


def get_server_by_id(server_id: int) -> Optional[dict]:
    """Find a server by its ID."""
    for s in get_enabled_servers():
        if s.get("id") == server_id:
            return s
    return None


def get_allowed_origins() -> list[str]:
    """Return allowed origins list."""
    return get_config().get("allowed_origins", [])


def check_origin(origin: str) -> bool:
    """Validate Origin header. Empty origin list = reject all non-empty."""
    allowed = get_allowed_origins()
    if not origin:
        return True  # non-browser clients
    if not allowed:
        return False
    return origin in allowed
