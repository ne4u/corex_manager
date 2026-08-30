"""Shared Guardrails engine — prompt injection / jailbreak detection.

This module is the single source of truth for guardrail detection patterns
and scanning logic, usable by both the MCP Gateway and the core HAProxy
platform.

Built-in packs:
- builtin:jailbreak_v1 — common jailbreak patterns (ignore instructions, DAN, etc.)
- builtin:instruction_override — "ignore previous instructions", "you are now", etc.
- builtin:obfuscation — base64-like blobs, unicode escapes, rot13 hints
- custom — user-provided regex

Actions: block, redact, log.
"""
import json
import logging
import os
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Maximum text length for regex scanning (prevents ReDoS on huge inputs)
MAX_SCAN_LENGTH = int(os.environ.get("GUARDRAIL_MAX_SCAN_LENGTH", "100000"))

# Known ReDoS-vulnerable pattern fragments (checked at compile time).
# Use [^)]* instead of .* so the check stays within a single group and
# doesn't span multiple groups (which caused false positives on patterns
# like (?:previous|prior|above) that have no quantifier after the group).
REDOS_PATTERNS = [
    r"\([^)]*[+*][^)]*\)[+*]",  # nested quantifiers like (a+)+
    r"\([^)]*\|[^)]*\)[+*]",   # alternation with quantifier like (a|b)+
]

# ---------------------------------------------------------------------------
# Built-in guardrail packs
# ---------------------------------------------------------------------------

BUILTIN_PACKS: dict[str, list[str]] = {
    "builtin:jailbreak_v1": [
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b",
        r"\bDAN\b.*\bdo\s+anything\s+now\b",
        r"\byou\s+are\s+(?:now|a)\s+(?:DAN|freed|unrestricted)\b",
        r"\bjailbreak\b",
        r"\bdeveloper\s+mode\b",
        r"\bact\s+as\s+(?:if\s+you\s+(?:are|have)\s+no\s+(?:rules|restrictions))\b",
        r"\bpretend\s+(?:that\s+)?you\s+(?:have\s+no|don'?t\s+have\s+(?:any\s+)?(?:rules|restrictions|guidelines))\b",
        r"\bSTAN\b.*\bstrive\s+to\s+avoid\s+norms\b",
        r"\bevil\s+mode\b",
        r"\bgod\s+mode\b",
        r"\bun(?:censored|filtered|restricted)\s+mode\b",
        r"\bAIM\b.*\balways\s+intelligent\s+and\s+machiavellian\b",
    ],
    "builtin:instruction_override": [
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?|directives?)\b",
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b",
        r"\bforget\s+(?:everything|all\s+(?:previous|prior)\s+(?:instructions?|rules?))\b",
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:a\s+)?(?:different|new)\s+mode\b",
        r"\bfrom\s+now\s+on[,\s]+you\s+(?:are|will|must|should)\b",
        r"\boverride\s+(?:your|the)\s+(?:system|safety|content)\s+(?:prompt|instructions?|rules?)\b",
        r"\bnew\s+instructions?\s*:\s*\b",
        r"\bsystem\s+prompt\s*:\s*\b",
        r"\breveal\s+(?:your|the)\s+(?:system|initial)\s+prompt\b",
        r"\bshow\s+me\s+your\s+(?:system|initial)\s+(?:prompt|instructions?)\b",
    ],
    "builtin:obfuscation": [
        r"[A-Za-z0-9+/]{40,}={0,2}",  # base64-like blobs
        r"\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}",  # unicode escape sequences
        r"\brot13\b",
        r"\bbase64\s*(?:decode|encoded)\b",
        r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",  # hex escape sequences
    ],
}


def get_pack_patterns(pack: str, find_regex: Optional[str] = None) -> list[str]:
    """Return regex patterns for a guardrail pack."""
    if pack == "custom":
        return [find_regex] if find_regex else []
    return BUILTIN_PACKS.get(pack, [])


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------

def compile_rules(
    raw_rules: list[dict],
    redos_check: bool = True,
) -> list[dict]:
    """Compile raw guardrail rule dicts into compiled rule dicts.

    Each compiled rule has: name, priority, direction, pack, regexes, action.
    """
    compiled = []
    for r in raw_rules:
        if not r.get("enabled", True):
            continue

        pack = r.get("pack", "custom")
        find_regex = r.get("find_regex")
        patterns = get_pack_patterns(pack, find_regex)
        if not patterns:
            logger.error("Guardrail %s: no patterns for pack %s", r.get("name"), pack)
            continue

        regexes = []
        for p in patterns:
            try:
                regexes.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
            except re.error as e:
                logger.error("Guardrail %s: invalid regex: %s", r.get("name"), e)

            if redos_check:
                for redos_pat in REDOS_PATTERNS:
                    if re.search(redos_pat, p):
                        logger.warning("Guardrail %s: potentially ReDoS-vulnerable regex, skipping pattern", r.get("name"))
                        regexes.pop()
                        break

        if not regexes:
            continue

        compiled.append({
            "name": r["name"],
            "priority": r.get("priority", 0),
            "direction": r.get("direction", "both"),
            "pack": pack,
            "regexes": regexes,
            "action": r.get("action", "block"),
        })

    compiled.sort(key=lambda x: x["priority"])
    return compiled


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class GuardrailHit:
    """A single guardrail detection hit."""
    def __init__(self, rule_name: str, pack: str, action: str, count: int):
        self.rule_name = rule_name
        self.pack = pack
        self.action = action
        self.count = count

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "pack": self.pack,
            "action": self.action,
            "count": self.count,
        }


class GuardrailScanResult:
    """Result of a guardrail scan."""
    def __init__(self):
        self.blocked = False
        self.modified = False
        self.hits: list[GuardrailHit] = []
        self.modified_data: Any = None

    def to_hit_list(self) -> list[dict]:
        return [h.to_dict() for h in self.hits]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _matches_direction(rule_direction: str, scan_direction: str) -> bool:
    if rule_direction == "both":
        return True
    return rule_direction == scan_direction


def _scan_text(text: str, rules: list[dict], scan_direction: str) -> tuple[str, list[GuardrailHit]]:
    """Scan a single text value against guardrail rules. Returns (modified_text, hits)."""
    hits: list[GuardrailHit] = []
    modified = text
    any_block = False

    scan_text = text[:MAX_SCAN_LENGTH] if len(text) > MAX_SCAN_LENGTH else text

    for rule in rules:
        if not _matches_direction(rule["direction"], scan_direction):
            continue

        total_matches = 0
        for regex in rule["regexes"]:
            matches = regex.findall(scan_text)
            total_matches += len(matches)

        if total_matches == 0:
            continue

        action = rule["action"]
        count = total_matches

        if action == "block":
            any_block = True
            hits.append(GuardrailHit(rule["name"], rule["pack"], "block", count))
            break
        elif action == "redact":
            for regex in rule["regexes"]:
                modified = regex.sub("[FILTERED]", modified)
            hits.append(GuardrailHit(rule["name"], rule["pack"], "redact", count))
        elif action == "log":
            hits.append(GuardrailHit(rule["name"], rule["pack"], "log", count))

    if any_block:
        return text, hits
    return modified, hits


def _scan_json_strings(obj: Any, rules: list[dict], scan_direction: str) -> tuple[Any, list[GuardrailHit]]:
    """Recursively scan string values in a JSON-like structure."""
    all_hits: list[GuardrailHit] = []
    any_block = False

    def _walk(o):
        nonlocal any_block
        if any_block:
            return o
        if isinstance(o, str):
            modified, hits = _scan_text(o, rules, scan_direction)
            for h in hits:
                if h.action == "block":
                    any_block = True
                all_hits.append(h)
            return modified
        elif isinstance(o, dict):
            return {k: _walk(v) for k, v in o.items()}
        elif isinstance(o, list):
            return [_walk(v) for v in o]
        return o

    modified_obj = _walk(obj)
    if any_block:
        return obj, all_hits
    return modified_obj, all_hits


def _scan_all_text(data: Any, rules: list[dict], scan_direction: str) -> tuple[Any, list[GuardrailHit]]:
    """Scan everything as text (serialize to string, scan, deserialize)."""
    try:
        text = json.dumps(data, default=str)
    except Exception:
        text = str(data)

    modified, hits = _scan_text(text, rules, scan_direction)
    if hits and any(h.action == "block" for h in hits):
        return data, hits

    if modified == text:
        return data, hits

    try:
        return json.loads(modified), hits
    except (json.JSONDecodeError, TypeError):
        return data, hits


def scan_request(
    method: str,
    params: dict,
    rules: list[dict],
) -> GuardrailScanResult:
    """Scan request params for prompt injection / jailbreak patterns."""
    result = GuardrailScanResult()
    if not rules:
        result.modified_data = params
        return result

    scan_direction = "request"
    applicable_rules = [r for r in rules if _matches_direction(r["direction"], scan_direction)]
    if not applicable_rules:
        result.modified_data = params
        return result

    modified, hits = _scan_json_strings(params, applicable_rules, scan_direction)

    result.hits = hits
    result.modified_data = modified
    result.modified = modified != params
    result.blocked = any(h.action == "block" for h in hits)
    return result


def scan_response(
    body: Any,
    rules: list[dict],
) -> GuardrailScanResult:
    """Scan response body for prompt injection / jailbreak patterns."""
    result = GuardrailScanResult()
    if not rules:
        result.modified_data = body
        return result

    scan_direction = "response"
    applicable_rules = [r for r in rules if _matches_direction(r["direction"], scan_direction)]
    if not applicable_rules:
        result.modified_data = body
        return result

    if isinstance(body, dict):
        modified, hits = _scan_json_strings(body, applicable_rules, scan_direction)
    else:
        result.modified_data = body
        return result

    result.hits = hits
    result.modified_data = modified
    result.modified = modified != body
    result.blocked = any(h.action == "block" for h in hits)
    return result
