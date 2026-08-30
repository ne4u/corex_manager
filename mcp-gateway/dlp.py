"""DLP engine for MCP Gateway — config loading and Valkey-backed tokenization.

The shared detector patterns, scanning logic, and data classes live in
``shared.dlp_core``. This module provides:
- Config-bundle rule loading (load_dlp_rules, has_dlp_rules, get_dlp_rules)
- Valkey-backed tokenization (_tokenize_value, detokenize_value)
- MCP-specific scan wrappers that pass the tokenize callback

JSON-RPC error for DLP block: -32050.
"""
import logging
import os
import sys
import uuid
from typing import Any, Optional

# Import shared DLP engine
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from shared.dlp_core import (
    DlpHit,
    DlpScanResult,
    compile_rules as _compile_rules,
    scan_request as _scan_request,
    scan_response as _scan_response,
)

logger = logging.getLogger(__name__)

MCP_DLP_BLOCKED = -32050


# ---------------------------------------------------------------------------
# Valkey client for tokenization
# ---------------------------------------------------------------------------

_client = None


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
        return _client
    except Exception as e:
        logger.debug("Valkey not available for DLP tokenization: %s", e)
        _client = None
        return None


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------

def _tokenize_value(value: str, prefix: str, ttl: int) -> str:
    """Replace a sensitive value with a token, storing the mapping in Valkey."""
    token = f"{prefix}{uuid.uuid4().hex[:24]}"
    client = _get_client()
    if client:
        try:
            client.setex(f"mcp:tok:{token}", ttl, value)
            return token
        except Exception as e:
            logger.warning("Tokenization failed (using redaction): %s", e)
            return "[REDACTED]"
    return "[REDACTED]"


def detokenize_value(token: str) -> Optional[str]:
    """Look up a tokenized value's original from Valkey."""
    client = _get_client()
    if not client:
        return None
    try:
        return client.get(f"mcp:tok:{token}")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DLP rule loading
# ---------------------------------------------------------------------------

_compiled_rules: list[dict] = []
_has_dlp_configured = False


def load_dlp_rules(config: dict) -> None:
    """Load and compile DLP rules from the config bundle."""
    global _compiled_rules, _has_dlp_configured

    raw_rules = config.get("dlp_rules", [])
    _has_dlp_configured = len(raw_rules) > 0
    _compiled_rules = _compile_rules(raw_rules)
    logger.info("Loaded %d DLP rules (has_config: %s)", len(_compiled_rules), _has_dlp_configured)


def has_dlp_rules() -> bool:
    """Return True if any DLP rules are configured."""
    return _has_dlp_configured and len(_compiled_rules) > 0


def get_dlp_rules() -> list[dict]:
    """Return the currently compiled DLP rules."""
    return list(_compiled_rules)


# ---------------------------------------------------------------------------
# Scanning — delegates to shared engine with tokenize callback
# ---------------------------------------------------------------------------

def scan_request(method: str, params: dict, rules: list[dict]) -> DlpScanResult:
    """Scan request params for sensitive data."""
    return _scan_request(method, params, rules, tokenize_fn=_tokenize_value)


def scan_response(body: Any, rules: list[dict]) -> DlpScanResult:
    """Scan response body for sensitive data."""
    return _scan_response(body, rules, tokenize_fn=_tokenize_value)
