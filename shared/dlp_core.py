"""Shared DLP (Data Loss Prevention) engine — detectors, scanning, and data classes.

This module is the single source of truth for DLP detection patterns and
scanning logic, usable by both the MCP Gateway and the core HAProxy platform.

Built-in detectors: email, phone, ssn, credit_card, ip, aws_key,
private_key, github_token, slack_token. Custom detectors use user-provided
regex.

Actions: block, redact, tokenize. Tokenization requires a callback function
provided by the consumer (e.g. the gateway uses Valkey-backed tokenization).
"""
import json
import logging
import os
import re
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Maximum text length for regex scanning (prevents ReDoS on huge inputs)
MAX_SCAN_LENGTH = int(os.environ.get("DLP_MAX_SCAN_LENGTH", "100000"))

# Known ReDoS-vulnerable pattern fragments (checked at compile time)
REDOS_PATTERNS = [
    r"\(.*[+*].*\)[+*]",  # nested quantifiers like (a+)+
    r"\(.*\|.*\)[+*]?",  # alternation with quantifier
]

# ---------------------------------------------------------------------------
# Built-in detector patterns
# ---------------------------------------------------------------------------

DETECTORS: dict[str, str] = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,19}\b",
    "ip": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "github_token": r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
    "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]+\b",
}


def get_detector_pattern(detector: str, find_regex: Optional[str] = None) -> Optional[str]:
    """Return the regex pattern for a detector."""
    if detector == "custom":
        return find_regex
    return DETECTORS.get(detector)


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------

def compile_rules(
    raw_rules: list[dict],
    redos_check: bool = True,
) -> list[dict]:
    """Compile raw DLP rule dicts into compiled rule dicts.

    Each compiled rule has: name, priority, direction, detector, regex,
    action, token_prefix, token_ttl, apply_to.
    """
    compiled = []
    for r in raw_rules:
        if not r.get("enabled", True):
            continue

        detector = r.get("detector", "custom")
        find_regex = r.get("find_regex")
        pattern = get_detector_pattern(detector, find_regex)
        if pattern is None:
            logger.error("DLP rule %s: unknown detector %s", r.get("name"), detector)
            continue

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.error("DLP rule %s: invalid regex: %s", r.get("name"), e)
            continue

        if redos_check:
            skip = False
            for redos_pat in REDOS_PATTERNS:
                if re.search(redos_pat, pattern):
                    logger.warning("DLP rule %s: potentially ReDoS-vulnerable regex, skipping", r.get("name"))
                    skip = True
                    break
            if skip:
                continue

        compiled.append({
            "name": r["name"],
            "priority": r.get("priority", 0),
            "direction": r.get("direction", "both"),
            "detector": detector,
            "regex": regex,
            "action": r.get("action", "block"),
            "token_prefix": r.get("token_prefix", "tok_"),
            "token_ttl": r.get("token_ttl", 3600),
            "apply_to": r.get("apply_to", "json_strings"),
        })

    compiled.sort(key=lambda x: x["priority"])
    return compiled


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class DlpHit:
    """A single DLP detection hit."""
    def __init__(self, rule_name: str, detector: str, action: str, count: int):
        self.rule_name = rule_name
        self.detector = detector
        self.action = action
        self.count = count

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "detector": self.detector,
            "action": self.action,
            "count": self.count,
        }


class DlpScanResult:
    """Result of a DLP scan."""
    def __init__(self):
        self.blocked = False
        self.modified = False
        self.hits: list[DlpHit] = []
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


def _scan_text(
    text: str,
    rules: list[dict],
    scan_direction: str,
    tokenize_fn: Optional[Callable[[str, str, int], str]] = None,
) -> tuple[str, list[DlpHit]]:
    """Scan a single text value against DLP rules. Returns (modified_text, hits)."""
    hits: list[DlpHit] = []
    modified = text
    any_block = False

    scan_text = text[:MAX_SCAN_LENGTH] if len(text) > MAX_SCAN_LENGTH else text

    for rule in rules:
        if not _matches_direction(rule["direction"], scan_direction):
            continue

        matches = rule["regex"].findall(scan_text)
        if not matches:
            continue

        count = len(matches)
        action = rule["action"]

        if action == "block":
            any_block = True
            hits.append(DlpHit(rule["name"], rule["detector"], "block", count))
            break
        elif action == "redact":
            modified = rule["regex"].sub("[REDACTED]", modified)
            hits.append(DlpHit(rule["name"], rule["detector"], "redact", count))
        elif action == "tokenize":
            prefix = rule.get("token_prefix", "tok_")
            ttl = rule.get("token_ttl", 3600)

            if tokenize_fn:
                def _replace_match(m, _fn=tokenize_fn, _prefix=prefix, _ttl=ttl):
                    return _fn(m.group(0), _prefix, _ttl)
                modified = rule["regex"].sub(_replace_match, modified)
            else:
                modified = rule["regex"].sub("[REDACTED]", modified)
            hits.append(DlpHit(rule["name"], rule["detector"], "tokenize", count))

    if any_block:
        return text, hits
    return modified, hits


def _scan_json_strings(
    obj: Any,
    rules: list[dict],
    scan_direction: str,
    tokenize_fn: Optional[Callable[[str, str, int], str]] = None,
) -> tuple[Any, list[DlpHit]]:
    """Recursively scan string values in a JSON-like structure."""
    all_hits: list[DlpHit] = []
    any_block = False

    def _walk(o):
        nonlocal any_block
        if any_block:
            return o
        if isinstance(o, str):
            modified, hits = _scan_text(o, rules, scan_direction, tokenize_fn)
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


def _scan_all_text(
    data: Any,
    rules: list[dict],
    scan_direction: str,
    tokenize_fn: Optional[Callable[[str, str, int], str]] = None,
) -> tuple[Any, list[DlpHit]]:
    """Scan everything as text (serialize to string, scan, deserialize)."""
    try:
        text = json.dumps(data, default=str)
    except Exception:
        text = str(data)

    modified, hits = _scan_text(text, rules, scan_direction, tokenize_fn)
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
    tokenize_fn: Optional[Callable[[str, str, int], str]] = None,
) -> DlpScanResult:
    """Scan request params for sensitive data."""
    result = DlpScanResult()
    if not rules:
        result.modified_data = params
        return result

    scan_direction = "request"
    applicable_rules = [r for r in rules if _matches_direction(r["direction"], scan_direction)]
    if not applicable_rules:
        result.modified_data = params
        return result

    apply_to = applicable_rules[0].get("apply_to", "json_strings")
    if any(r.get("apply_to") == "all_text" for r in applicable_rules):
        apply_to = "all_text"

    if apply_to == "all_text":
        modified, hits = _scan_all_text(params, applicable_rules, scan_direction, tokenize_fn)
    else:
        modified, hits = _scan_json_strings(params, applicable_rules, scan_direction, tokenize_fn)

    result.hits = hits
    result.modified_data = modified
    result.modified = modified != params
    result.blocked = any(h.action == "block" for h in hits)
    return result


def scan_response(
    body: Any,
    rules: list[dict],
    tokenize_fn: Optional[Callable[[str, str, int], str]] = None,
) -> DlpScanResult:
    """Scan response body for sensitive data."""
    result = DlpScanResult()
    if not rules:
        result.modified_data = body
        return result

    scan_direction = "response"
    applicable_rules = [r for r in rules if _matches_direction(r["direction"], scan_direction)]
    if not applicable_rules:
        result.modified_data = body
        return result

    apply_to = applicable_rules[0].get("apply_to", "json_strings")
    if any(r.get("apply_to") == "all_text" for r in applicable_rules):
        apply_to = "all_text"

    if apply_to == "all_text":
        modified, hits = _scan_all_text(body, applicable_rules, scan_direction, tokenize_fn)
    else:
        modified, hits = _scan_json_strings(body, applicable_rules, scan_direction, tokenize_fn)

    result.hits = hits
    result.modified_data = modified
    result.modified = modified != body
    result.blocked = any(h.action == "block" for h in hits)
    return result
