"""Guardrails engine for MCP Gateway — config loading and scan wrappers.

The shared guardrail packs, scanning logic, and data classes live in
``shared.guardrails_core``. This module provides:
- Config-bundle rule loading (load_guardrails, has_guardrails, get_guardrails)
- MCP-specific scan wrappers

JSON-RPC error for guardrail block: -32051.
"""
import logging
import os
import sys
from typing import Any, Optional

# Import shared guardrails engine
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from shared.guardrails_core import (
    GuardrailHit,
    GuardrailScanResult,
    compile_rules as _compile_rules,
    scan_request as _scan_request,
    scan_response as _scan_response,
)

logger = logging.getLogger(__name__)

MCP_GUARDRAIL_BLOCKED = -32051


# ---------------------------------------------------------------------------
# Guardrail rule loading
# ---------------------------------------------------------------------------

_compiled_rules: list[dict] = []
_has_guardrails_configured = False


def load_guardrails(config: dict) -> None:
    """Load and compile guardrail rules from the config bundle."""
    global _compiled_rules, _has_guardrails_configured

    raw_rules = config.get("guardrails", [])
    _has_guardrails_configured = len(raw_rules) > 0
    _compiled_rules = _compile_rules(raw_rules)
    logger.info("Loaded %d guardrail rules (has_config: %s)", len(_compiled_rules), _has_guardrails_configured)


def has_guardrails() -> bool:
    """Return True if any guardrail rules are configured."""
    return _has_guardrails_configured and len(_compiled_rules) > 0


def get_guardrails() -> list[dict]:
    """Return the currently compiled guardrail rules."""
    return list(_compiled_rules)


# ---------------------------------------------------------------------------
# Scanning — delegates to shared engine
# ---------------------------------------------------------------------------

def scan_request(method: str, params: dict, rules: list[dict]) -> GuardrailScanResult:
    """Scan request params for prompt injection / jailbreak patterns."""
    return _scan_request(method, params, rules)


def scan_response(body: Any, rules: list[dict]) -> GuardrailScanResult:
    """Scan response body for prompt injection / jailbreak patterns."""
    return _scan_response(body, rules)
