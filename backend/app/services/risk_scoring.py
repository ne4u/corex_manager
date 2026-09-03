"""Risk Scoring engine: Cloudflare-style expression + signed integer points.

A Risk Rule is an ordered rule with a Cloudflare-parity expression and a
signed integer ``points`` value. When a request matches the rule's expression,
the points are added to ``txn.risk.score`` (clamped 0..99). The score is
computed **before** Security Rules so the Security Rules engine can reference
``risk.score`` and ``risk.rules_hit`` in its own expressions.

Architecture (three-phase hybrid):
1. ``lua.risk_capture`` (pure Lua) — derives 10 metadata fields from
   ``txn.req_fp.*`` vars + raw headers + GeoIP, stores in ``txn.risk_fp.*``.
2. Per-rule match flags — Python translates each rule's expression to a
   HAProxy condition and emits ``set-var(txn.risk.match_<id>) bool(1) if {cond}``.
3. ``lua.risk_compute`` (pure Lua) — reads match flags + a generated points
   table (``risk_rules_data.lua``), sums points, clamps to [0,99], sets
   ``txn.risk.score`` and ``txn.risk.rules_hit``.

This module provides:
- Expression validation (reuses ``security_rules.parse_expression`` / ``translate``).
- Category derivation from expression AST fields.
- Score budget enforcement (sum of enabled positive points ≤ 99).
- HAProxy emission (``emit_risk_scoring``).
- Baseline ruleset seeding (32 rules + 4 seed security lists).
- Data file writer (``write_risk_rules_data_file``).
"""
import os
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from . import security_rules
from ..core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Path to the generated Lua data file (relative to project root, same dir as
# security list files). In Docker, this is /app/data/risk_rules_data.lua.
RISK_RULES_DATA_FILENAME = "risk_rules_data.lua"

# ---------------------------------------------------------------------------
# Category derivation
# ---------------------------------------------------------------------------

# Maps expression field names to risk rule categories.
# The FIRST field reference in the expression (by AST traversal order:
# left-to-right, depth-first) determines the category.
_FIELD_CATEGORIES: Dict[str, str] = {
    # Protocol & Transport
    "http.request.version_numeric": "protocol",
    "http.request.version": "protocol",
    "http.request.tls": "protocol",
    "http.request.tls.version": "protocol",
    "http.request.tls.cipher": "protocol",
    "http.request.keep_alive": "protocol",
    "http.request.fingerprint.cipher_count": "protocol",
    "http.request.fingerprint.ext_count": "protocol",
    "http.request.alpn": "protocol",
    # Header Anomalies
    "http.request.fingerprint.header_count": "headers",
    "http.request.fingerprint.header_list": "headers",
    "http.request.user_agent_length": "headers",
    "http.request.headers": "headers",  # bracket field — any header reference
    "http.request.user_agent": "headers",
    "http.request.referer": "headers",
    # Geo & Time
    "http.request.geo_lang_mismatch": "geo",
    "http.request.geoip.timezone_mismatch": "geo",
    "http.request.hour": "geo",
    "ip.geoip.country": "geo",
    "ip.geoip.continent": "geo",
    "ip.geoip.city": "geo",
    "ip.geoip.region": "geo",
    "ip.geoip.timezone": "geo",
    # Behavioral
    "http.request.fingerprint.path_depth": "behavioral",
    "http.request.uri_length": "behavioral",
    "http.request.param_count": "behavioral",
    "http.request.fingerprint.body_depth": "behavioral",
    "http.request.uri.path": "behavioral",
    "http.request.uri": "behavioral",
    "http.request.full_uri": "behavioral",
    "http.request.fingerprint.param_keys": "behavioral",
    "http.request.fingerprint.param_types": "behavioral",
    "http.request.fingerprint.param_lens": "behavioral",
    # Auth (trust)
    "auth.valid": "trust",
    "auth.type": "trust",
    # List-based (usually used with `in $`)
    "ip.src": "list",
    "ip.geoip.asnum": "list",
    "http.request.ja4": "list",
}

# Valid category values (for validation on create/update).
VALID_CATEGORIES = {"protocol", "headers", "geo", "behavioral", "list", "trust", "custom"}


def _collect_fields(node: Dict[str, Any]) -> List[str]:
    """Collect field references from an AST in left-to-right depth-first order."""
    if not isinstance(node, dict):
        return []
    t = node.get("type")
    if t in ("and", "or"):
        fields: List[str] = []
        for child in node.get("children", []):
            fields.extend(_collect_fields(child))
        return fields
    if t == "not":
        return _collect_fields(node.get("child", {}))
    # Leaf nodes
    field = node.get("field")
    if field:
        return [field]
    return []


def _has_in_list(node: Dict[str, Any]) -> bool:
    """Check whether the AST contains any in_list leaf node."""
    if not isinstance(node, dict):
        return False
    t = node.get("type")
    if t in ("and", "or"):
        return any(_has_in_list(c) for c in node.get("children", []))
    if t == "not":
        return _has_in_list(node.get("child", {}))
    return t == "in_list"


def derive_category(ast: Optional[Dict[str, Any]], points: int = 0) -> str:
    """Derive a risk rule category from its expression AST and points.

    Rules:
    - If points < 0 → "trust" (negative-point rules are trust signals).
    - If any AST node has type "in_list" → "list" (list-based rules are distinctive).
    - Otherwise, the FIRST field in the expression (by AST traversal order)
      determines the category via _FIELD_CATEGORIES.
    - If no field matches → "custom".
    """
    if points < 0:
        return "trust"
    if ast and _has_in_list(ast):
        return "list"
    if not ast:
        return "custom"
    fields = _collect_fields(ast)
    for field in fields:
        # Check exact match first
        if field in _FIELD_CATEGORIES:
            return _FIELD_CATEGORIES[field]
        # Check bracket field prefix (e.g. http.request.headers["cookie"] → http.request.headers)
        for bracket_field in ("http.request.headers", "http.request.cookies", "auth.claim"):
            if field.startswith(bracket_field):
                return _FIELD_CATEGORIES.get(bracket_field, "custom")
    return "custom"


# ---------------------------------------------------------------------------
# Slug generation + validation
# ---------------------------------------------------------------------------

_SLUG_RE = re.compile(r'^[a-z_][a-z0-9_]*$')


def slugify_ruleset_name(name: str) -> str:
    """Convert a display name to a HAProxy-safe slug.

    Rules:
    - Lowercase
    - Replace spaces/hyphens/special chars with underscores
    - Strip leading/trailing underscores
    - Must match ^[a-z_][a-z0-9_]*$ (valid HAProxy var name segment)
    - If the result would start with a digit, prepend "rs_"
    - If the result is empty, return "ruleset"
    """
    slug = re.sub(r'[^a-zA-Z0-9]+', '_', name).strip('_').lower()
    if not slug:
        return "ruleset"
    if slug[0].isdigit():
        slug = "rs_" + slug
    return slug


def validate_slug(slug: str) -> bool:
    """Check whether a slug is a valid HAProxy var name segment."""
    return bool(_SLUG_RE.match(slug))


# ---------------------------------------------------------------------------
# Ruleset CRUD helpers
# ---------------------------------------------------------------------------

def create_ruleset(
    db: Session,
    name: str,
    description: Optional[str] = None,
) -> Any:
    """Create a new RiskRuleset with an auto-generated unique slug.

    If the slug collides with an existing ruleset, appends _2, _3, etc.
    """
    from ..models.models import RiskRuleset

    base_slug = slugify_ruleset_name(name)
    slug = base_slug
    suffix = 2
    while db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first():
        slug = f"{base_slug}_{suffix}"
        suffix += 1

    max_priority = db.query(RiskRuleset).order_by(RiskRuleset.priority.desc()).first()
    priority = (max_priority.priority + 1) if max_priority else 0

    ruleset = RiskRuleset(
        name=name,
        slug=slug,
        description=description,
        enabled=True,
        priority=priority,
    )
    db.add(ruleset)
    db.commit()
    db.refresh(ruleset)
    return ruleset


def update_ruleset(
    db: Session,
    ruleset_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Any:
    """Update a RiskRuleset. Regenerates slug if name changes.

    The "default" ruleset's slug is locked and cannot be changed.
    Returns the updated ruleset.
    """
    from ..models.models import RiskRuleset

    ruleset = db.get(RiskRuleset, ruleset_id)
    if not ruleset:
        raise ValueError(f"Ruleset {ruleset_id} not found")

    if name is not None and name != ruleset.name:
        ruleset.name = name
        # Regenerate slug unless this is the default ruleset
        if ruleset.slug != "default":
            new_slug = slugify_ruleset_name(name)
            # Ensure uniqueness (excluding self)
            existing = db.query(RiskRuleset).filter(
                RiskRuleset.slug == new_slug,
                RiskRuleset.id != ruleset_id,
            ).first()
            if existing:
                raise ValueError(f"Slug '{new_slug}' already in use by another ruleset")
            ruleset.slug = new_slug

    if description is not None:
        ruleset.description = description
    if enabled is not None:
        ruleset.enabled = enabled

    db.commit()
    db.refresh(ruleset)
    return ruleset


def delete_ruleset(db: Session, ruleset_id: int, force: bool = False) -> None:
    """Delete a RiskRuleset. Prevents deletion of the "default" ruleset.

    Cascade deletes all rules in the ruleset.
    """
    from ..models.models import RiskRuleset

    ruleset = db.get(RiskRuleset, ruleset_id)
    if not ruleset:
        raise ValueError(f"Ruleset {ruleset_id} not found")

    if ruleset.slug == "default" and not force:
        raise ValueError("Cannot delete the 'default' ruleset. It is required for backward compatibility.")

    db.delete(ruleset)
    db.commit()


# ---------------------------------------------------------------------------
# Expression validation (reuses security_rules engine)
# ---------------------------------------------------------------------------

def parse_expression(text: str) -> Dict[str, Any]:
    """Parse a Cloudflare-style expression string into an AST dict.

    Reuses the security_rules parser so the same field set and boolean fields
    are recognized.
    """
    return security_rules.parse_expression(text)


def validate_expression(text: str, db: Optional[Session] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Validate a risk rule expression.

    Returns (ok, ast, error). Rejects response-phase expressions (all risk
    scoring is request-phase). If db is provided, also resolves list references
    via translate() to catch field/list errors early.
    """
    if not text or not text.strip():
        return True, None, None
    try:
        ast = parse_expression(text)
        if db is not None:
            condition, phase = security_rules.translate(ast, db)
            if phase == "response":
                return False, None, "Risk rules must be request-phase (cannot reference response fields)"
        else:
            # Without db, still check phase by examining the AST
            phase = security_rules._determine_phase(ast)
            if phase == "response":
                return False, None, "Risk rules must be request-phase (cannot reference response fields)"
        return True, ast, None
    except ValueError as e:
        return False, None, str(e)


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------

def rules_for_listener(db: Session, listener_id: int) -> List[Any]:
    """Return enabled RiskRules matching the given listener, ordered by priority."""
    from ..models.models import RiskRule

    rules = db.query(RiskRule).filter(RiskRule.enabled == True).order_by(RiskRule.priority).all()
    matched = []
    for rule in rules:
        lids = rule.listener_ids or []
        # [] = all listeners
        if not lids or listener_id in lids:
            matched.append(rule)
    return matched


def reorder_rules(db: Session, ordered_ids: List[int]) -> None:
    """Reassign priorities based on the given ordered list of rule IDs."""
    from ..models.models import RiskRule

    for priority, rule_id in enumerate(ordered_ids):
        rule = db.get(RiskRule, rule_id)
        if rule:
            rule.priority = priority
    db.commit()


# ---------------------------------------------------------------------------
# HAProxy emission
# ---------------------------------------------------------------------------

# Characters that could break a HAProxy set-var str() value or inject config.
_LOG_VALUE_RE = re.compile(r"[\r\n;\\\"']")


def _safe_log_value(value: str) -> str:
    """Sanitize a value for use inside a HAProxy set-var str(...) expression."""
    if not value:
        return '""'
    return '"' + _LOG_VALUE_RE.sub("", str(value)) + '"'


def emit_risk_scoring(listener: Any, db: Session, lines: List[str]) -> None:
    """Emit http-request lines for risk scoring on a listener.

    Three phases:
    1. lua.risk_capture — derives metadata fields into txn.risk_fp.*
    2. Per-rule match flags — set-var(txn.risk.match_<id>) bool(1) if {cond}
    3. lua.risk_compute — sums points, clamps, sets txn.risk.score + txn.risk.rules_hit

    Called from generate_frontend after lua.req_fp_capture + geo set-vars,
    before security_rules.emit_security_rules.
    """
    rules = rules_for_listener(db, listener.id)

    # When req_fp is excluded for this request (txn.req_fp_excluded), skip
    # risk_capture and risk_compute. Risk scoring rules reference txn.req_fp.*
    # vars (hdr_count, path_depth, param_types, etc.) which are empty when
    # req_fp is skipped. Without this guard, rules like "hdr_count < 5"
    # evaluate as true (empty = 0), inflating the risk score and triggering
    # captcha challenges on legitimate static asset downloads.
    skip_cond = "{ var(txn.req_fp_excluded) -m found }"

    # Phase 1: always emit risk_capture (even with 0 rules, so txn.risk_fp.*
    # vars are available to Security Rules that reference them).
    lines.append("    # Risk Scoring Phase 1: derive metadata fields (Lua)")
    lines.append(f"    http-request lua.risk_capture unless {skip_cond}")

    if not rules:
        # Still emit risk_compute with an empty rules table so txn.risk.score
        # is set to "0" and txn.risk.rules_hit is set to "" (safe defaults).
        lines.append("    # Risk Scoring Phase 3: compute score (no rules configured)")
        lines.append(f"    http-request lua.risk_compute unless {skip_cond}")
        return

    # Phase 2: per-rule match flags
    lines.append("    # Risk Scoring Phase 2: per-rule match flags")
    for rule in rules:
        try:
            ast = parse_expression(rule.expression)
            condition, phase = security_rules.translate(ast, db)
        except (ValueError, KeyError):
            # Skip rules that fail to parse/translate at emit time.
            logger.warning("Risk rule %s (%s) failed to translate, skipping", rule.id, rule.name)
            continue
        if phase == "response":
            # Should have been rejected at validation; skip defensively.
            continue
        # `condition` from security_rules.translate() is already wrapped in
        # { ... } blocks (each leaf is braced by _translate_leaf, AND terms are
        # juxtaposed, OR groups joined by "or"). Do NOT add extra braces —
        # `{ { ... } }` is rejected by HAProxy ("missing fetch method in ACL
        # expression '{'"). Match the convention used by _emit_request_rule.
        #
        # Guard with !{ var(txn.req_fp_excluded) -m found } so rules that
        # reference txn.req_fp.* vars don't match on empty values when req_fp
        # is skipped (e.g. hdr_count < 5 would be true when req_fp vars are
        # unset, inflating the risk score).
        lines.append(
            f"    http-request set-var(txn.risk.match_{rule.id}) bool(1) if {condition} !{skip_cond}"
        )

    # Phase 3: compute score
    lines.append("    # Risk Scoring Phase 3: compute score from match flags (Lua)")
    lines.append(f"    http-request lua.risk_compute unless {skip_cond}")


# ---------------------------------------------------------------------------
# Data file writer
# ---------------------------------------------------------------------------

def _risk_rules_data_path() -> str:
    """Return the filesystem path for the generated risk_rules_data.lua file."""
    base = settings.SECURITY_LISTS_DIR
    # SECURITY_LISTS_DIR is typically "data/lists" — go up one level to "data/"
    parent = os.path.dirname(base.rstrip(os.sep))
    if not parent:
        parent = "data"
    return os.path.join(parent, RISK_RULES_DATA_FILENAME)


def generate_risk_rules_data(db: Session) -> str:
    """Generate the content of the risk_rules_data.lua data file as a string.

    This is the pure generation logic shared by write_risk_rules_data_file
    (which writes to disk) and the config status comparison (which compares
    the generated content against the on-disk file).
    """
    from ..models.models import RiskRule, RiskRuleset

    # Get all enabled rulesets (for the rulesets list)
    rulesets = db.query(RiskRuleset).filter(
        RiskRuleset.enabled == True
    ).order_by(RiskRuleset.priority).all()
    slug_to_id = {rs.slug: rs.id for rs in rulesets}
    id_to_slug = {rs.id: rs.slug for rs in rulesets}

    # Get all rules from enabled rulesets (include disabled rules so Lua
    # can count total_enabled per ruleset for hit_density)
    enabled_ruleset_ids = list(id_to_slug.keys())
    rules = db.query(RiskRule).filter(
        RiskRule.ruleset_id.in_(enabled_ruleset_ids),
    ).order_by(RiskRule.priority).all()

    lines = ["-- Auto-generated by haproxy.py. Do not edit; regenerated on each config write."]
    lines.append("return {")
    # Rulesets list
    slug_list = ", ".join(_safe_lua_string(s) for s in slug_to_id.keys())
    lines.append(f"    rulesets = {{ {slug_list} }},")
    # Rules list (include enabled flag so Lua can count total enabled per ruleset)
    lines.append("    rules = {")
    for rule in rules:
        name = _safe_lua_string(rule.name or "")
        log_val = "true" if rule.log else "false"
        enabled_val = "true" if rule.enabled else "false"
        slug = id_to_slug.get(rule.ruleset_id, "default")
        lines.append(
            f"        {{ id = {rule.id}, ruleset = {_safe_lua_string(slug)}, "
            f"points = {rule.points}, name = {name}, log = {log_val}, "
            f"enabled = {enabled_val} }},"
        )
    lines.append("    },")
    lines.append("}")

    return "\n".join(lines) + "\n"


def write_risk_rules_data_file(db: Session) -> str:
    """Write the risk_rules_data.lua data file for the Lua risk_compute action.

    Delegates content generation to generate_risk_rules_data and writes the
    result to disk. Returns the file path.
    """
    path = _risk_rules_data_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = generate_risk_rules_data(db)
    with open(path, "w") as f:
        f.write(content)
    return path


def _safe_lua_string(value: str) -> str:
    """Escape a string for safe embedding in a Lua double-quoted string."""
    # Escape backslash and double-quote, strip newlines
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", "")
    return f'"{escaped}"'


# ---------------------------------------------------------------------------
# Toggle safety helpers
# ---------------------------------------------------------------------------

# Fields that require req_fp_enabled (set by the Rust haproxy-req-fp module).
_REQ_FP_RISK_FIELDS = {
    "http.request.fingerprint.cipher_count",
    "http.request.fingerprint.ext_count",
    "http.request.user_agent_length",
    "http.request.hour",
    "http.request.uri_length",
    "http.request.param_count",
    "http.request.version_numeric",
    "http.request.keep_alive",
    "http.request.geo_lang_mismatch",
    "http.request.geoip.timezone_mismatch",
    # Also covers fields derived from req_fp subfields
    "http.request.fingerprint.path_depth",
    "http.request.fingerprint.body_depth",
    "http.request.fingerprint.header_count",
    "http.request.fingerprint.header_list",
    "http.request.fingerprint.param_keys",
    "http.request.fingerprint.param_types",
    "http.request.fingerprint.param_lens",
}

# Fields that require ja4_enabled (JA4 Lua script loaded).
_JA4_RISK_FIELDS = {
    "http.request.fingerprint.cipher_count",
    "http.request.fingerprint.ext_count",
    "http.request.ja4",
}


def _ast_references_any_field(node: Dict[str, Any], fields: set) -> bool:
    """Check whether an AST node references any of the given fields."""
    if not isinstance(node, dict):
        return False
    t = node.get("type")
    if t in ("and", "or"):
        return any(_ast_references_any_field(c, fields) for c in node.get("children", []))
    if t == "not":
        return _ast_references_any_field(node.get("child", {}), fields)
    field = node.get("field", "")
    if field in fields:
        return True
    # Check bracket field prefixes
    for f in fields:
        if field.startswith(f + "[") or field.startswith(f + "."):
            return True
    return False


def rules_referencing_req_fp(db: Session) -> List[Any]:
    """Return enabled RiskRules referencing txn.risk_fp.* / req_fp-derived fields.

    Used by the req_fp_enabled toggle to auto-disable rules that would produce
    a broken HAProxy config (referencing vars set by the Rust req_fp module).
    """
    from ..models.models import RiskRule

    matches: List[Any] = []
    for rule in db.query(RiskRule).filter(RiskRule.enabled == True).all():
        ast = rule.expression_ast
        if isinstance(ast, dict) and _ast_references_any_field(ast, _REQ_FP_RISK_FIELDS):
            matches.append(rule)
            continue
        # Fall back to scanning the raw expression text
        if isinstance(rule.expression, str):
            for field in _REQ_FP_RISK_FIELDS:
                if field in rule.expression:
                    matches.append(rule)
                    break
    return matches


def rules_referencing_ja4_fields(db: Session) -> List[Any]:
    """Return enabled RiskRules referencing JA4-derived fields (cipher_count, ext_count, ja4).

    Used by the ja4_enabled toggle to auto-disable rules that would produce
    a broken HAProxy config.
    """
    from ..models.models import RiskRule

    matches: List[Any] = []
    for rule in db.query(RiskRule).filter(RiskRule.enabled == True).all():
        ast = rule.expression_ast
        if isinstance(ast, dict) and _ast_references_any_field(ast, _JA4_RISK_FIELDS):
            matches.append(rule)
            continue
        if isinstance(rule.expression, str):
            for field in _JA4_RISK_FIELDS:
                if field in rule.expression:
                    matches.append(rule)
                    break
    return matches


# ---------------------------------------------------------------------------
# Baseline ruleset seeding (4 rulesets: default, human, api, mobile)
# ---------------------------------------------------------------------------

# Baseline rulesets: (name, slug, description)
_BASELINE_RULESETS: List[Tuple[str, str, str]] = [
    ("Default", "default", "Default risk scoring ruleset — applies to all traffic types"),
]

# Baseline rules per ruleset: (ruleset_slug, name, expression, points, category, log)
# Points are calibrated to actual risk. The total of matched rules is clamped
# to [0, 99] at runtime by the Lua risk_compute action.
_BASELINE_RULES_BY_RULESET: List[Tuple[str, str, str, int, str, bool]] = [
    # === DEFAULT — rules that apply to ALL traffic ===
    ("default", "HTTP/1.0 protocol", 'http.request.version_numeric < 11', 5, "protocol", True),
    ("default", "TLS 1.0 or 1.1", 'http.request.tls.version ~ "(?i)TLSv1\\.[01]"', 8, "protocol", True),
    ("default", "High-risk country", 'ip.geoip.country in $geo:high_risk_countries', 15, "list", True),
    ("default", "IP in blocklist", 'ip.src in $network:ip_blocklist', 85, "list", True),
    ("default", "Datacenter ASN", 'ip.geoip.asnum in $asn:datacenter_asns', 25, "list", True),
    ("default", "Known bot JA4", 'http.request.ja4 in $ja4:known_bot_ja4', 30, "list", True),
    ("default", "Deep path", 'http.request.fingerprint.path_depth > 4', 3, "behavioral", True),
    ("default", "Very deep path", 'http.request.fingerprint.path_depth > 8', 8, "behavioral", True),
    ("default", "Long URI", 'http.request.uri_length > 1024', 5, "behavioral", True),
    ("default", "High param count", 'http.request.param_count > 20', 5, "behavioral", True),
    ("default", "Deep JSON body", 'http.request.fingerprint.body_depth > 10', 5, "behavioral", True),
    ("default", "Geo/Lang mismatch", 'http.request.geo_lang_mismatch', 8, "geo", True),
    ("default", "Timezone mismatch", 'http.request.geoip.timezone_mismatch', 8, "geo", True),
    ("default", "Off-hours request", 'http.request.hour < 5', 3, "geo", True),
    # Trust signals (negative points subtract from score)
    ("default", "Valid auth", 'auth.valid', -15, "trust", True),
    ("default", "HTTP/2+", 'http.request.version_numeric >= 20', -5, "trust", True),
]

# Seed security lists: (name, type, description, entries)
_BASELINE_LISTS: List[Tuple[str, str, str, List[str]]] = [
    ("high_risk_countries", "geo", "High-risk countries (baseline seed — adjust as needed)", ["RU", "CN", "KP", "IR", "SY", "BY", "VE", "UA"]),
    ("datacenter_asns", "asn", "Major cloud/hosting provider ASNs (baseline seed)", [
        "AS14618", "AS15169", "AS8075", "AS16509", "AS13335",
        "AS24940", "AS14061", "AS16276", "AS49505", "AS63949",
    ]),
    ("known_bot_ja4", "ja4", "Known bot/tool JA4 fingerprints (baseline seed — add observed fingerprints)", [
        # curl default (TLS 1.3, no SNI, no ALPN)
        "t13d000000_000000000000_000000000000",
        # Python requests default
        "t13d1516h2_8daaf6152771_b186095e22b6",
    ]),
    ("ip_blocklist", "network", "IP blocklist (empty — populate manually or via dynamic feeds)", []),
]


def seed_baseline_rules(db: Session) -> Tuple[int, int, int, int]:
    """Create the 4 baseline rulesets + rules + 4 seed security lists.

    Idempotent: checks ruleset slugs, rule names, and list names before
    creating; skips existing.

    Returns (created_rules, created_lists, created_rulesets, skipped).
    """
    from ..models.models import (
        RiskRule, RiskRuleset, NetworkList, NetworkListEntry, AsnList, AsnListEntry,
        GeoList, GeoListEntry, Ja4List, Ja4ListEntry,
    )

    created_rules = 0
    created_lists = 0
    created_rulesets = 0
    skipped = 0

    # --- Seed rulesets ---
    slug_to_id: Dict[str, int] = {}
    for name, slug, description in _BASELINE_RULESETS:
        existing = db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first()
        if existing:
            slug_to_id[slug] = existing.id
            skipped += 1
            continue
        # Determine priority
        max_priority = db.query(RiskRuleset).order_by(RiskRuleset.priority.desc()).first()
        priority = (max_priority.priority + 1) if max_priority else 0
        ruleset = RiskRuleset(
            name=name,
            slug=slug,
            description=description,
            enabled=True,
            priority=priority,
        )
        db.add(ruleset)
        db.flush()
        slug_to_id[slug] = ruleset.id
        created_rulesets += 1

    db.flush()

    # --- Seed security lists ---
    for name, list_type, description, entries in _BASELINE_LISTS:
        if list_type == "geo":
            existing = db.query(GeoList).filter(GeoList.name == name).first()
            if existing:
                skipped += 1
                continue
            lst = GeoList(name=name, description=description)
            db.add(lst)
            db.flush()
            for value in entries:
                db.add(GeoListEntry(list_id=lst.id, value=value))
            created_lists += 1
        elif list_type == "asn":
            existing = db.query(AsnList).filter(AsnList.name == name).first()
            if existing:
                skipped += 1
                continue
            lst = AsnList(name=name, description=description)
            db.add(lst)
            db.flush()
            for value in entries:
                db.add(AsnListEntry(list_id=lst.id, value=value))
            created_lists += 1
        elif list_type == "ja4":
            existing = db.query(Ja4List).filter(Ja4List.name == name).first()
            if existing:
                skipped += 1
                continue
            lst = Ja4List(name=name, description=description)
            db.add(lst)
            db.flush()
            for value in entries:
                db.add(Ja4ListEntry(list_id=lst.id, value=value))
            created_lists += 1
        elif list_type == "network":
            existing = db.query(NetworkList).filter(NetworkList.name == name).first()
            if existing:
                skipped += 1
                continue
            lst = NetworkList(name=name, description=description)
            db.add(lst)
            db.flush()
            for value in entries:
                db.add(NetworkListEntry(list_id=lst.id, value=value))
            created_lists += 1

    db.flush()

    # --- Seed risk rules per ruleset ---
    existing_names = set(r.name for r in db.query(RiskRule).all())

    # Track per-ruleset priority counter
    priority_counters: Dict[int, int] = {}
    for rs_id in slug_to_id.values():
        max_pri = db.query(RiskRule).filter(
            RiskRule.ruleset_id == rs_id
        ).order_by(RiskRule.priority.desc()).first()
        priority_counters[rs_id] = (max_pri.priority + 1) if max_pri else 0

    for ruleset_slug, name, expression, points, category, log in _BASELINE_RULES_BY_RULESET:
        if name in existing_names:
            skipped += 1
            continue

        rs_id = slug_to_id.get(ruleset_slug)
        if rs_id is None:
            # Ruleset doesn't exist (shouldn't happen, but defensive)
            skipped += 1
            continue

        # Parse expression to get AST
        try:
            ast = parse_expression(expression)
        except ValueError:
            ast = None

        rule = RiskRule(
            name=name,
            expression=expression,
            expression_ast=ast,
            points=points,
            category=category,
            enabled=True,
            priority=priority_counters.get(rs_id, 0),
            log=log,
            ruleset_id=rs_id,
        )
        db.add(rule)
        priority_counters[rs_id] = priority_counters.get(rs_id, 0) + 1
        created_rules += 1

    db.commit()
    return created_rules, created_lists, created_rulesets, skipped
