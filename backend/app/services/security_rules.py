"""Security Rules: Cloudflare-style expression engine and HAProxy emission.

A Security Rule is an ordered, first-match-wins rule with a Cloudflare-parity
expression language, an action (block / allow / skip_*), and optional listener
scoping. Rules run before rate-limiting and WAF in the HAProxy request pipeline
and use ``txn.sec.*`` flags to skip downstream phases.

This module provides:
- HAProxy field maps and translator (AST → HAProxy ACL condition string).
- ``emit_security_rules`` — emits ``http-request``/``http-response`` lines.
- ``rules_for_listener`` / ``reorder_rules`` helpers.

The tokenizer, parser, AST, and DNF normalizer live in ``shared.expression_core``
and are imported here.
"""
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

from ..core.config import get_settings

# Import shared expression engine
# In Docker, PYTHONPATH=/app makes 'shared' importable.
# For local dev, add the project root to sys.path.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from shared.expression_core import (
    Token,
    _tokenize,
    parse_expression as _shared_parse_expression,
    validate_expression as _shared_validate_expression,
    to_dnf,
)

settings = get_settings()


# ---------------------------------------------------------------------------
# Field → HAProxy fetch mapping
# ---------------------------------------------------------------------------

# Maps Cloudflare-style field names to (haproxy_fetch, phase, value_type).
#   phase: "request" or "response"
#   value_type: "string", "int", "bool", "ip", "geoip", "ja4"
# For geoip fields, the fetch template uses {db} placeholder.
# For header/cookie/query fields, the fetch template uses {key} placeholder.

_FIELD_MAP: Dict[str, Tuple[str, str, str]] = {
    # Request fields
    "http.request.method": ("method", "request", "string"),
    "http.request.uri.path": ("path", "request", "string"),
    "http.request.uri": ("url", "request", "string"),
    "http.request.full_uri": ("base", "request", "string"),
    "http.request.uri.query": ("url_query", "request", "string"),
    "http.host": ("req.hdr(host)", "request", "string"),
    "http.request.user_agent": ("req.fhdr(user-agent)", "request", "string"),
    "http.request.referer": ("req.hdr(referer)", "request", "string"),
    "http.request.version": ("req.ver", "request", "string"),
    # TLS fields
    "http.request.tls.cipher": ("ssl_fc_cipher", "request", "string"),
    "http.request.tls.version": ("ssl_fc_protocol", "request", "string"),
    # IP / GeoIP
    "ip.src": ("src", "request", "ip"),
    "ip.geoip.country": ("src,geoip2({geo_db},country.iso_code)", "request", "geoip"),
    "ip.geoip.asnum": ("src,geoip2({asn_db},autonomous_system_number)", "request", "string"),
    "ip.geoip.continent": ("src,geoip2({geo_db},continent.code)", "request", "geoip"),
    "ip.geoip.city": ("src,geoip2({geo_db},city.names.en)", "request", "geoip"),
    "ip.geoip.region": ("src,geoip2({geo_db},subdivisions.0.iso_code)", "request", "geoip"),
    "ip.geoip.postal_code": ("src,geoip2({geo_db},postal.code)", "request", "geoip"),
    "ip.geoip.timezone": ("src,geoip2({geo_db},location.time_zone)", "request", "geoip"),
    "ip.geoip.latitude": ("src,geoip2({geo_db},location.latitude)", "request", "int"),
    "ip.geoip.longitude": ("src,geoip2({geo_db},location.longitude)", "request", "int"),
    # JA4 (via vendored Lua script)
    "http.request.ja4": ("lua.ja4_fp", "request", "ja4"),
    # Response fields
    "http.response.status_code": ("status", "response", "int"),
    # --- API Armor: Request Fingerprint (req_fp v2) ---
    # Full fingerprint string (response-phase — needs status + body_bytes)
    "http.request.fingerprint": ("var(txn.req_fp.full)", "response", "string"),
    # Request-phase subfields (set by req_fp_capture in http-req)
    "http.request.fingerprint.content_type": ("var(txn.req_fp.ctype)", "request", "string"),
    "http.request.fingerprint.param_keys": ("var(txn.req_fp.param_keys)", "request", "string"),
    "http.request.fingerprint.param_types": ("var(txn.req_fp.param_types)", "request", "string"),
    "http.request.fingerprint.param_lens": ("var(txn.req_fp.param_lens)", "request", "string"),
    "http.request.fingerprint.path_depth": ("var(txn.req_fp.path_depth)", "request", "int"),
    "http.request.fingerprint.header_count": ("var(txn.req_fp.hdr_count)", "request", "int"),
    "http.request.fingerprint.header_list": ("var(txn.req_fp.hdr_list)", "request", "string"),
    "http.request.fingerprint.auth_type": ("var(txn.req_fp.auth_type)", "request", "string"),
    "http.request.fingerprint.body_depth": ("var(txn.req_fp.body_depth)", "request", "int"),
    # Response-phase subfields
    "http.response.fingerprint.status": ("var(txn.req_fp.status)", "response", "int"),
    "http.response.fingerprint.body_bytes": ("var(txn.req_fp.body_bytes)", "response", "int"),
    # --- API Armor: GraphQL (set by Rust graphql module via body_parser) ---
    "graphql.operation": ("var(txn.gql.operation)", "request", "string"),
    "graphql.depth": ("var(txn.gql.depth)", "request", "int"),
    "graphql.complexity": ("var(txn.gql.complexity)", "request", "int"),
    "graphql.field_count": ("var(txn.gql.field_count)", "request", "int"),
    "graphql.alias_count": ("var(txn.gql.alias_count)", "request", "int"),
    "graphql.fragment_count": ("var(txn.gql.fragment_count)", "request", "int"),
    "graphql.query_hash": ("var(txn.gql.query_hash)", "request", "string"),
    "graphql.valid": ("var(txn.gql.valid)", "request", "bool"),
    # --- API Armor: Schema Validation (set by Rust schema_validator) ---
    "api.schema_valid": ("var(txn.api.schema_valid)", "request", "bool"),
    "api.schema_errors": ("var(txn.api.schema_errors)", "request", "string"),
    # --- API Armor: Auth Validation (set by Rust jwt_validator) ---
    "auth.valid": ("var(txn.auth.valid)", "request", "bool"),
    "auth.type": ("var(txn.auth.type)", "request", "string"),
    "auth.error": ("var(txn.auth.error)", "request", "string"),
    "auth.claim.sub": ("var(txn.auth.claim_sub)", "request", "string"),
    "auth.claim.iss": ("var(txn.auth.claim_iss)", "request", "string"),
    "auth.claim.aud": ("var(txn.auth.claim_aud)", "request", "string"),
    # --- API Armor: Behavioral Profiling (set by Rust profile_check) ---
    "api.profile_anomaly": ("var(txn.api.profile_anomaly)", "request", "bool"),
    # --- Risk Scoring engine outputs (set by lua.risk_compute) ---
    "risk.score": ("var(txn.risk.score)", "request", "int"),
    "risk.rules_hit": ("var(txn.risk.rules_hit)", "request", "string"),
    "risk.rules_hit_count": ("var(txn.risk.rules_hit_count)", "request", "int"),
    "risk.hit_density": ("var(txn.risk.hit_density)", "request", "int"),
    # --- Risk Scoring metadata fields (set by lua.risk_capture) ---
    "http.request.fingerprint.cipher_count": ("var(txn.risk_fp.cipher_count)", "request", "int"),
    "http.request.fingerprint.ext_count": ("var(txn.risk_fp.ext_count)", "request", "int"),
    "http.request.user_agent_length": ("var(txn.risk_fp.ua_len)", "request", "int"),
    "http.request.hour": ("var(txn.risk_fp.req_hour)", "request", "int"),
    "http.request.uri_length": ("var(txn.risk_fp.uri_length)", "request", "int"),
    "http.request.param_count": ("var(txn.risk_fp.param_count)", "request", "int"),
    "http.request.version_numeric": ("var(txn.risk_fp.version_numeric)", "request", "int"),
    "http.request.alpn": ("ssl_fc_alpn", "request", "string"),
}

# Fields that use bracket subscripts: field["key"] → fetch with key substituted
_BRACKET_FIELDS: Dict[str, str] = {
    "http.request.headers": "req.hdr({key})",
    "http.request.cookies": "req.cook({key})",
    "http.request.uri.query": "url_query",  # special: regex-based
    "http.response.headers": "res.hdr({key})",
    # API Armor: arbitrary JWT claim access
    "auth.claim": "var(txn.auth.claim_{key})",
}

# Boolean fields (no operator — just existence)
_BOOL_FIELDS: Dict[str, str] = {
    "http.request.tls": "ssl_fc",
    "http.request.scheme": "ssl_fc",  # handled specially for = "https"/"http"
    # Risk Scoring metadata fields (set by lua.risk_capture)
    "http.request.keep_alive": "var(txn.risk_fp.keep_alive)",
    "http.request.geo_lang_mismatch": "var(txn.risk_fp.geo_lang_mismatch)",
    "http.request.geoip.timezone_mismatch": "var(txn.risk_fp.tz_mismatch)",
}

# JA4 fetch name (matches the Lua script's core.register_fetches call)
_JA4_FETCH = "lua.ja4_fp"

# GeoIP field → haproxy-geoip2 Rust Lua module converter mapping.
# Used when GEOIP_LUA_MODULE_ENABLED is True (the primary GeoIP engine).
# The converters take an IP sample + dot-path props matching the maxminddb
# record structure: lua.geoip2-lookup-city("country","iso_code"), etc.
# Covers all 9 geoip fields — no geoip2 build dependency required.
_GEOIP_LUA_FIELDS: Dict[str, Tuple[str, str, str]] = {
    "ip.geoip.country": ('src,lua.geoip2-lookup-city("country","iso_code")', "request", "string"),
    "ip.geoip.asnum": ('src,lua.geoip2-lookup-asn("autonomous_system_number")', "request", "string"),
    "ip.geoip.continent": ('src,lua.geoip2-lookup-city("continent","code")', "request", "string"),
    "ip.geoip.city": ('src,lua.geoip2-lookup-city("city","names","en")', "request", "string"),
    "ip.geoip.region": ('src,lua.geoip2-lookup-city("subdivisions","0","iso_code")', "request", "string"),
    "ip.geoip.postal_code": ('src,lua.geoip2-lookup-city("postal","code")', "request", "string"),
    "ip.geoip.timezone": ('src,lua.geoip2-lookup-city("location","time_zone")', "request", "string"),
    "ip.geoip.latitude": ('src,lua.geoip2-lookup-city("location","latitude")', "request", "string"),
    "ip.geoip.longitude": ('src,lua.geoip2-lookup-city("location","longitude")', "request", "string"),
}

# Actions that set skip flags
_SKIP_ACTIONS = {
    "skip_rules": [],
    "skip_rules_ratelimit": ["skip_ratelimit"],
    "skip_rules_waf": ["skip_waf"],
    "skip_all": ["skip_ratelimit", "skip_waf"],
}

# Actions valid for response-phase rules
_RESPONSE_ACTIONS = {"block", "allow", "redirect"}


# ---------------------------------------------------------------------------
# Boolean fields — passed to the shared parser so bare fields without
# operators are recognized as boolean conditions.
# ---------------------------------------------------------------------------

def _build_bool_fields_set() -> set:
    """Build the set of field names that can appear as bare booleans."""
    s = set(_BOOL_FIELDS.keys())
    for field, (_, _, vtype) in _FIELD_MAP.items():
        if vtype == "bool":
            s.add(field)
    return s


_BOOL_FIELDS_SET = _build_bool_fields_set()


# ---------------------------------------------------------------------------
# parse_expression / validate_expression — wrappers around shared engine
# ---------------------------------------------------------------------------

def parse_expression(text: str) -> Dict[str, Any]:
    """Parse a Cloudflare-style expression string into an AST dict.

    Passes the backend's boolean field set so bare fields like
    ``http.request.tls`` are accepted without an operator.
    """
    return _shared_parse_expression(text, bool_fields=_BOOL_FIELDS_SET)


def validate_expression(text: str, db: Optional[Session] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Validate an expression string.

    Returns (ok, ast, error). If db is provided, also resolves list references
    via translate() to catch field/list errors early.
    """
    if not text or not text.strip():
        return True, None, None
    try:
        ast = parse_expression(text)
        if db is not None:
            translate(ast, db)
        return True, ast, None
    except ValueError as e:
        return False, None, str(e)


# DNF alias for internal use (translate() calls this)
_to_dnf = to_dnf


# ---------------------------------------------------------------------------
# Translator: AST leaf → HAProxy condition fragment
# ---------------------------------------------------------------------------

def _bool_fetch_cond(fetch: str) -> str:
    """Build a HAProxy condition fragment testing that a boolean fetch is true.

    For ``var()`` fetches, HAProxy requires a ``-m`` matching method (the
    ``var`` sample fetch is typeless until a match method is specified).
    These vars store ``"0"``/``"1"`` strings (set by Lua scripts like
    risk_score.lua and the Rust auth/GraphQL modules), so we use ``-m str 1``.
    For native boolean fetches (``ssl_fc``, etc.), the bare form works.
    """
    if fetch.startswith("var("):
        return f"{{ {fetch} -m str 1 }}"
    return f"{{ {fetch} }}"


def _resolve_field(field: str) -> Tuple[str, str, str, Optional[str]]:
    """Resolve a field name to (haproxy_fetch, phase, value_type, bracket_key).

    For bracket fields like http.request.headers["x"], returns the fetch with
    the key substituted. For query fields, returns a special marker.
    """
    # Check for bracket syntax
    bracket_match = re.match(r'^([\w.]+)\["(.+)"\]$', field)
    if bracket_match:
        base_field, key = bracket_match.group(1), bracket_match.group(2)
        if base_field in _BRACKET_FIELDS:
            template = _BRACKET_FIELDS[base_field]
            if base_field == "http.request.uri.query":
                # Special: query param matching via regex
                return ("__query_param__", "request", "string", key)
            fetch = template.replace("{key}", _haproxy_quoted_key(key))
            phase = "response" if base_field.startswith("http.response") else "request"
            return (fetch, phase, "string", None)
        raise ValueError(f"Unknown bracket field: {base_field}")

    if field in _FIELD_MAP:
        fetch_tpl, phase, vtype = _FIELD_MAP[field]
        # GeoIP fields — three tiers:
        #   1. Rust Lua module (primary) — covers all 9 fields, no geoip2 dep
        #   2. Native geoip2 converter — requires HAProxy built with geoip2
        #   3. map_ip fallback — country/ASN only (legacy last resort)
        if "{geo_db}" in fetch_tpl or "{asn_db}" in fetch_tpl:
            # Lazy import to avoid a circular import (haproxy.py imports
            # security_rules lazily at call sites).
            from .haproxy import _geoip_lua_module_available
            if _geoip_lua_module_available() and field in _GEOIP_LUA_FIELDS:
                # Rust Lua module — the primary GeoIP engine.
                lua_fetch, lua_phase, lua_vtype = _GEOIP_LUA_FIELDS[field]
                return (lua_fetch, lua_phase, lua_vtype, None)
            from .haproxy import _haproxy_supports_geoip2
            if _haproxy_supports_geoip2():
                if "{geo_db}" in fetch_tpl:
                    geo_db = os.path.abspath(settings.GEOIP_DB_PATH)
                    if not os.path.exists(geo_db):
                        raise ValueError(f"GeoIP database not found at {geo_db} (required for {field})")
                    fetch = fetch_tpl.replace("{geo_db}", geo_db)
                else:
                    asn_db = os.path.abspath(settings.ASN_DB_PATH)
                    if not os.path.exists(asn_db):
                        raise ValueError(f"ASN database not found at {asn_db} (required for {field})")
                    fetch = fetch_tpl.replace("{asn_db}", asn_db)
            elif field == "ip.geoip.country":
                # map_ip fallback — file is auto-seeded by haproxy/entrypoint.sh
                # and regenerated by write_haproxy_maps() after MaxMind downloads.
                fetch = f"src,map_ip({os.path.abspath(settings.GEOIP_COUNTRY_MAP_PATH)})"
            elif field == "ip.geoip.asnum":
                fetch = f"src,map_ip({os.path.abspath(settings.GEOIP_ASN_MAP_PATH)})"
            else:
                raise ValueError(
                    f"{field} requires HAProxy built with geoip2 support; "
                    f"no map_ip fallback is available for this field"
                )
        else:
            fetch = fetch_tpl
        return (fetch, phase, vtype, None)

    if field in _BOOL_FIELDS:
        return (_BOOL_FIELDS[field], "request", "bool", None)

    raise ValueError(f"Unknown field: {field}")


def _haproxy_quoted_key(key: str) -> str:
    """Sanitize a header/cookie name for use in HAProxy fetch expressions."""
    # HAProxy header names are case-insensitive tokens; allow alnum, -, _
    safe = re.sub(r'[^A-Za-z0-9_-]', '', key)
    return safe.lower() if safe else key.lower()


def _haproxy_string_value(value: str) -> str:
    """Escape a string value for HAProxy (wrap in quotes if needed)."""
    # HAProxy string values: use backslash-escaped quotes
    if re.match(r'^[A-Za-z0-9_./:-]+$', value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _resolve_risk_ruleset_field(field: str, db: Session) -> Optional[Tuple[str, str, str, Optional[str]]]:
    """Check if a field is a dynamic risk ruleset field (risk.<slug>.score /
    .rules_hit / .rules_hit_count / .hit_density) and resolve it.

    Returns (haproxy_fetch, phase, value_type, bracket_key) or None if the
    field is not a dynamic risk ruleset field.
    """
    # risk.<slug>.score
    m = re.match(r'^risk\.([a-z_][a-z0-9_]*)\.score$', field)
    if m:
        slug = m.group(1)
        from ..models.models import RiskRuleset
        if not db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first():
            raise ValueError(f"Unknown risk ruleset: {slug}")
        return (f"var(txn.risk.{slug}.score)", "request", "int", None)
    # risk.<slug>.rules_hit
    m = re.match(r'^risk\.([a-z_][a-z0-9_]*)\.rules_hit$', field)
    if m:
        slug = m.group(1)
        from ..models.models import RiskRuleset
        if not db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first():
            raise ValueError(f"Unknown risk ruleset: {slug}")
        return (f"var(txn.risk.{slug}.rules_hit)", "request", "string", None)
    # risk.<slug>.rules_hit_count
    m = re.match(r'^risk\.([a-z_][a-z0-9_]*)\.rules_hit_count$', field)
    if m:
        slug = m.group(1)
        from ..models.models import RiskRuleset
        if not db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first():
            raise ValueError(f"Unknown risk ruleset: {slug}")
        return (f"var(txn.risk.{slug}.rules_hit_count)", "request", "int", None)
    # risk.<slug>.hit_density
    m = re.match(r'^risk\.([a-z_][a-z0-9_]*)\.hit_density$', field)
    if m:
        slug = m.group(1)
        from ..models.models import RiskRuleset
        if not db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first():
            raise ValueError(f"Unknown risk ruleset: {slug}")
        return (f"var(txn.risk.{slug}.hit_density)", "request", "int", None)
    return None


def _translate_leaf(node: Dict[str, Any], db: Session) -> str:
    """Translate a single leaf condition to a HAProxy condition fragment.

    Returns a string like ``src -f /path/to/file.lst`` or
    ``path -m reg "^.*wp-login"`` that can be placed inside ``{ ... }``.
    """
    t = node["type"]
    negated = node.get("negated", False)

    # Dynamic risk ruleset fields (risk.<slug>.score / .rules_hit / .rules_hit_count)
    # are resolved via DB lookup, not the static _FIELD_MAP.
    field = node.get("field")
    if field:
        risk_resolved = _resolve_risk_ruleset_field(field, db)
        if risk_resolved is not None:
            fetch, _, vtype, _ = risk_resolved
            # Handle the same leaf types as below but with the resolved fetch
            if t == "bool_field":
                cond = _bool_fetch_cond(fetch)
                return f"!{cond}" if negated else cond
            if t == "exists":
                cond = f"{{ {fetch} -m found }}"
                return f"!{cond}" if negated else cond
            if t == "compare":
                op = node["op"]
                value = node["value"]
                if isinstance(value, bool):
                    if op == "=":
                        cond = _bool_fetch_cond(fetch) if value else f"!{_bool_fetch_cond(fetch)}"
                        return f"!{cond}" if negated else cond
                    raise ValueError(f"Boolean field {field!r} only supports = operator")
                if isinstance(value, str):
                    if op == "=":
                        cond = f"{{ {fetch} -m str {_haproxy_string_value(value)} }}"
                    elif op == "!=":
                        cond = f"!{{ {fetch} -m str {_haproxy_string_value(value)} }}"
                    elif op == "~":
                        cond = f'{{ {fetch} -m reg "{_escape_regex(value)}" }}'
                    elif op == "!~":
                        cond = f'!{{ {fetch} -m reg "{_escape_regex(value)}" }}'
                    elif op == "contains":
                        cond = f"{{ {fetch} -m sub {_haproxy_string_value(value)} }}"
                    elif op == "starts_with":
                        cond = f"{{ {fetch} -m beg {_haproxy_string_value(value)} }}"
                    elif op == "ends_with":
                        cond = f"{{ {fetch} -m end {_haproxy_string_value(value)} }}"
                    else:
                        raise ValueError(f"Unsupported string operator: {op}")
                    return f"!{cond}" if negated else cond
                # int comparison
                if op == "=":
                    cond = f"{{ {fetch} -m int {value} }}"
                elif op == "!=":
                    cond = f"!{{ {fetch} -m int {value} }}"
                elif op == ">":
                    cond = f"{{ {fetch} -m int gt {value} }}"
                elif op == "<":
                    cond = f"{{ {fetch} -m int lt {value} }}"
                elif op == ">=":
                    cond = f"{{ {fetch} -m int ge {value} }}"
                elif op == "<=":
                    cond = f"{{ {fetch} -m int le {value} }}"
                else:
                    raise ValueError(f"Unsupported int operator: {op}")
                return f"!{cond}" if negated else cond

    if t == "bool_field":
        fetch, _, _, _ = _resolve_field(node["field"])
        cond = _bool_fetch_cond(fetch)
        return f"!{cond}" if negated else cond

    if t == "exists":
        fetch, _, _, _ = _resolve_field(node["field"])
        cond = f"{{ {fetch} -m found }}"
        return f"!{cond}" if negated else cond

    if t == "compare":
        field = node["field"]
        op = node["op"]
        value = node["value"]
        fetch, phase, vtype, bracket_key = _resolve_field(field)

        # Special handling for http.request.scheme
        if field == "http.request.scheme":
            if op == "=" and isinstance(value, str):
                if value.lower() == "https":
                    cond = "{ ssl_fc }"
                elif value.lower() == "http":
                    cond = "{ !ssl_fc }"
                else:
                    raise ValueError(f"http.request.scheme can only be 'https' or 'http', got {value!r}")
                return f"!{cond}" if negated else cond
            raise ValueError("http.request.scheme only supports = 'https' or = 'http'")

        # Special handling for query params
        if fetch == "__query_param__":
            key = bracket_key
            if op == "=" and isinstance(value, str):
                # Match query param key=value
                regex = f"(^|&){re.escape(key)}={re.escape(value)}($|&)"
                cond = f"{{ url_query -m reg \"{regex}\" }}"
            elif op == "exists":
                regex = f"(^|&){re.escape(key)}="
                cond = f"{{ url_query -m reg \"{regex}\" }}"
            else:
                raise ValueError(f"Query param {key!r} only supports = and exists operators")
            return f"!{cond}" if negated else cond

        # Boolean value comparison (for http.request.tls, auth.valid, etc.)
        if isinstance(value, bool):
            if op == "=":
                if value:
                    cond = _bool_fetch_cond(fetch)
                else:
                    # = false → negate the "is true" condition
                    cond = f"!{_bool_fetch_cond(fetch)}"
                return f"!{cond}" if negated else cond
            raise ValueError(f"Boolean field {field!r} only supports = operator")

        # String comparisons
        if isinstance(value, str):
            if op == "=":
                cond = f"{{ {fetch} -m str {_haproxy_string_value(value)} }}"
            elif op == "!=":
                # Negation must be OUTSIDE the braces: !{ fetch -m str value }
                # HAProxy rejects { !{ ... } } with "missing fetch method".
                cond = f"!{{ {fetch} -m str {_haproxy_string_value(value)} }}"
            elif op == "~":
                cond = f'{{ {fetch} -m reg "{_escape_regex(value)}" }}'
            elif op == "!~":
                cond = f'!{{ {fetch} -m reg "{_escape_regex(value)}" }}'
            elif op == "contains":
                cond = f"{{ {fetch} -m sub {_haproxy_string_value(value)} }}"
            elif op == "starts_with":
                cond = f"{{ {fetch} -m beg {_haproxy_string_value(value)} }}"
            elif op == "ends_with":
                cond = f"{{ {fetch} -m end {_haproxy_string_value(value)} }}"
            else:
                raise ValueError(f"String field {field!r} does not support operator {op!r}")
            # For != and !~, the negation is already in the condition.
            # Apply outer negation only for =, ~, contains, starts_with, ends_with
            if negated and op in ("=", "~", "contains", "starts_with", "ends_with"):
                cond = f"!{cond}"
            return cond

        # Integer comparisons
        if isinstance(value, int):
            if op == "=":
                cond = f"{{ {fetch} -m int {value} }}"
            elif op == "!=":
                cond = f"!{{ {fetch} -m int {value} }}"
            elif op == ">":
                cond = f"{{ {fetch} -m int gt {value} }}"
            elif op == "<":
                cond = f"{{ {fetch} -m int lt {value} }}"
            elif op == ">=":
                cond = f"{{ {fetch} -m int ge {value} }}"
            elif op == "<=":
                cond = f"{{ {fetch} -m int le {value} }}"
            else:
                raise ValueError(f"Integer field {field!r} does not support operator {op!r}")
            if negated and op in ("=", ">", "<", ">=", "<="):
                cond = f"!{cond}"
            return cond

        raise ValueError(f"Unsupported value type for field {field!r}")

    if t == "in_literals":
        field = node["field"]
        fetch, phase, vtype, bracket_key = _resolve_field(field)
        values = node["values"]
        if not values:
            raise ValueError(f"Empty literal list for field {field!r}")
        if all(isinstance(v, str) for v in values):
            vals = " ".join(_haproxy_string_value(v) for v in values)
            cond = f"{{ {fetch} -m str {vals} }}"
        elif all(isinstance(v, int) for v in values):
            vals = " ".join(str(v) for v in values)
            cond = f"{{ {fetch} -m int {vals} }}"
        else:
            raise ValueError(f"Mixed type literal list for field {field!r}")
        return f"!{cond}" if negated else cond

    if t == "in_list":
        field = node["field"]
        list_type = node["list_type"]
        list_name = node["list_name"]
        fetch, phase, vtype, _ = _resolve_field(field)

        # Resolve the list file path and verify the list exists
        list_path = _resolve_list_path(db, list_type, list_name)

        # For ASN lists, the converter returns "AS<n>" strings and the list
        # file contains "AS<n>" entries (normalized by validate_asn_value).
        # Use string -f matching against the .lst file directly.
        if list_type == "asn":
            cond = f"{{ {fetch} -m str -f {list_path} }}"
        elif list_type == "geo":
            cond = f"{{ {fetch} -f {list_path} }}"
        elif list_type == "ja4":
            cond = f"{{ {_JA4_FETCH} -f {list_path} }}"
        elif list_type == "network":
            cond = f"{{ {fetch} -f {list_path} }}"
        elif list_type == "pattern":
            # Pattern lists are field-agnostic but only valid for string-typed
            # fields (regex matching against the sample). Reject non-string fields.
            if vtype != "string":
                raise ValueError(
                    f"Pattern lists can only be used with string-typed fields, "
                    f"not {field!r} (type: {vtype})"
                )
            cond = f"{{ {fetch} -m reg -f {list_path} }}"
        else:
            raise ValueError(f"Unknown list type: {list_type}")

        return f"!{cond}" if negated else cond

    raise ValueError(f"Unknown node type: {t}")


def _escape_regex(s: str) -> str:
    """Escape a string for use inside a HAProxy regex double-quoted string."""
    # Escape backslash and double quote for HAProxy string context
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _resolve_list_path(db: Session, list_type: str, list_name: str) -> str:
    """Resolve a security list reference to a file path, verifying the list exists."""
    from .security_lists import safe_filename
    from ..models.models import NetworkList, AsnList, GeoList, Ja4List, PatternList

    model_map = {
        "network": NetworkList,
        "asn": AsnList,
        "geo": GeoList,
        "ja4": Ja4List,
        "pattern": PatternList,
    }
    if list_type not in model_map:
        raise ValueError(f"Unknown list type: {list_type}")

    model = model_map[list_type]
    exists = db.query(model).filter(model.name == list_name).first()
    if not exists:
        raise ValueError(f"Security list not found: ${list_type}:{list_name}")

    base = settings.SECURITY_LISTS_DIR
    fname = safe_filename(list_name) + ".lst"
    # Return an absolute path so HAProxy can find the file regardless of its
    # working directory when validating/parsing the config (the API and HAProxy
    # containers share the data volume at the same mount point /app/data).
    return os.path.abspath(os.path.join(base, list_type, fname))


# ---------------------------------------------------------------------------
# Full translation: AST → HAProxy condition string
# ---------------------------------------------------------------------------

def translate(ast: Dict[str, Any], db: Session) -> Tuple[str, str]:
    """Translate an AST to a HAProxy condition string and determine the phase.

    Returns (condition_string, phase) where phase is "request" or "response".
    The condition string can be used after ``if`` in an ``http-request`` rule.
    """
    # Determine phase from all fields in the AST
    phase = _determine_phase(ast)

    # Normalize to DNF
    dnf = _to_dnf(ast)

    # Translate each OR-group
    group_strs: List[str] = []
    for group in dnf:
        term_strs = [_translate_leaf(term, db) for term in group]
        if len(term_strs) == 1:
            group_strs.append(term_strs[0])
        else:
            # AND = juxtaposition inside a single { } block
            # But each term is already wrapped in { }, so we just concatenate
            group_strs.append(" ".join(term_strs))

    if len(group_strs) == 1:
        return group_strs[0], phase
    # OR = multiple { } blocks separated by "or"
    return " or ".join(group_strs), phase


def _determine_phase(node: Dict[str, Any]) -> str:
    """Determine if the expression is request-phase or response-phase."""
    t = node["type"]
    if t in ("and", "or"):
        for child in node["children"]:
            if _determine_phase(child) == "response":
                return "response"
        return "request"
    if t == "not":
        return _determine_phase(node["child"])
    # Leaf
    field = node.get("field", "")
    _, phase, _, _ = _resolve_field(field)
    return phase


# ---------------------------------------------------------------------------
# HAProxy emission
# ---------------------------------------------------------------------------

# Skip flag suffix for the condition guard
_DONE_GUARD = "!{ var(txn.sec.done) -m found }"

# Characters that could break a HAProxy set-var str() value or inject config
_LOG_VALUE_RE = re.compile(r"[\r\n;\\\"']")


def _safe_log_value(value: str) -> str:
    """Sanitize a value for use inside a HAProxy set-var str(...) expression.

    Strips characters that could terminate the statement or break the log-format
    JSON string, then wraps the result in double quotes so spaces are preserved
    as a single HAProxy string argument.
    """
    if not value:
        return '""'
    return '"' + _LOG_VALUE_RE.sub("", str(value)) + '"'


def rules_for_listener(db: Session, listener_id: int) -> List[Any]:
    """Return enabled SecurityRules matching the given listener, ordered by priority."""
    from ..models.models import SecurityRule
    rules = db.query(SecurityRule).filter(SecurityRule.enabled == True).order_by(SecurityRule.priority).all()
    matched = []
    for rule in rules:
        lids = rule.listener_ids or []
        # [] = all listeners
        if not lids or listener_id in lids:
            matched.append(rule)
    return matched


def emit_security_rules(listener: Any, db: Session, lines: List[str]) -> None:
    """Emit http-request/http-response lines for security rules on a listener.

    Lines are appended to the ``lines`` list. Called from ``generate_frontend``
    before rate-limit and WAF emission.
    """
    rules = rules_for_listener(db, listener.id)
    if not rules:
        return

    block_status = settings.SECURITY_RULES_BLOCK_STATUS if hasattr(settings, 'SECURITY_RULES_BLOCK_STATUS') else 403

    for rule in rules:
        try:
            ast = parse_expression(rule.expression)
            condition, phase = translate(ast, db)
        except ValueError:
            # Skip rules that fail to parse at emit time (shouldn't happen if
            # validation was done on save, but be defensive).
                continue

        # Skip actions are only valid for request-phase rules
        if phase == "response" and rule.action in _SKIP_ACTIONS:
            continue

        if phase == "response":
            _emit_response_rule(rule, condition, lines, block_status)
        else:
            _emit_request_rule(rule, condition, lines, block_status, db, listener)


def _emit_request_rule(rule: Any, condition: str, lines: List[str], block_status: int,
                       db: Session = None, listener: Any = None) -> None:
    """Emit http-request lines for a request-phase security rule."""
    guarded_cond = f"{condition} {_DONE_GUARD}"

    # no_log: suppress the entire request log line for matching requests
    if getattr(rule, "no_log", False):
        lines.append(f"    http-request set-log-level silent if {guarded_cond}")

    # log: record the rule's action + name in txn vars for the log-format
    if getattr(rule, "log", True):
        rule_name = _safe_log_value(rule.name)
        lines.append(f"    http-request set-var(txn.sec.action) str({rule.action}) if {guarded_cond}")
        lines.append(f"    http-request set-var(txn.sec.rule) str({rule_name}) if {guarded_cond}")

    if rule.action == "block":
        status = rule.status_code or block_status
        lines.append(f"    http-request deny deny_status {status} default-errorfiles if {guarded_cond}")
        return

    if rule.action == "allow":
        lines.append(f"    http-request set-var(txn.sec.done) bool(1) if {guarded_cond}")
        return

    if rule.action == "redirect":
        url = rule.redirect_url or "/"
        code = rule.redirect_code or 302
        lines.append(f"    http-request redirect location {url} code {code} if {guarded_cond}")
        return

    if rule.action == "challenge":
        from .haproxy import _emit_challenge_redirect, _safe_token
        challenge_url = _safe_token(rule.redirect_url or settings.CAPTCHA_CHALLENGE_URL)
        _emit_challenge_redirect(lines, guarded_cond, challenge_url, rule.id, "security", rule.name)
        # Mark as done so no further security rules run after the challenge redirect
        lines.append(f"    http-request set-var(txn.sec.done) bool(1) if {guarded_cond}")
        return

    if rule.action == "custom_response":
        status = rule.status_code or block_status
        if rule.error_page_id and db is not None and listener is not None:
            ep_path, content_type = _resolve_error_page(rule, db, listener)
            if ep_path:
                lines.append(
                    f'    http-request return status {status} content-type "{content_type}" '
                    f'lf-file {ep_path} if {guarded_cond}'
                )
                return
        # Fallback: plain deny with status code
        lines.append(f"    http-request deny deny_status {status} default-errorfiles if {guarded_cond}")
        return

    # Skip actions
    skip_flags = _SKIP_ACTIONS.get(rule.action, [])
    for flag in skip_flags:
        lines.append(f"    http-request set-var(txn.sec.{flag}) bool(1) if {guarded_cond}")
    lines.append(f"    http-request set-var(txn.sec.done) bool(1) if {guarded_cond}")


def _resolve_error_page(rule: Any, db: Session, listener: Any) -> Tuple[Optional[str], str]:
    """Resolve a security rule's error_page_id to a file path + content type.

    Writes the error file to a per-listener directory and returns (path, content_type).
    Returns (None, "text/html") if the error page cannot be resolved.
    """
    from .haproxy import _write_error_file, _safe_path_name, _safe_token
    from ..models.models import CustomErrorPage

    ep = db.get(CustomErrorPage, rule.error_page_id)
    if not ep:
        return None, "text/html"

    base_dir = os.path.dirname(settings.HAPROXY_CONFIG_PATH)
    ep_dir = os.path.join(base_dir, "errorfiles", "security-rules", _safe_path_name(listener.name))
    os.makedirs(ep_dir, exist_ok=True)
    ep_path = os.path.join(ep_dir, f"sr{rule.id}_{ep.code}.http")
    content_type = _safe_token(ep.content_type) or "text/html"
    _write_error_file(ep_path, ep.content, content_type)
    return ep_path, content_type


def _emit_response_rule(rule: Any, condition: str, lines: List[str], block_status: int) -> None:
    """Emit http-response lines for a response-phase security rule."""
    # no_log: suppress the entire request log line for matching requests
    if getattr(rule, "no_log", False):
        lines.append(f"    http-response set-log-level silent if {condition}")

    # log: record the rule's action + name in txn vars for the log-format
    if getattr(rule, "log", True):
        rule_name = _safe_log_value(rule.name)
        lines.append(f"    http-response set-var(txn.sec.action) str({rule.action}) if {condition}")
        lines.append(f"    http-response set-var(txn.sec.rule) str({rule_name}) if {condition}")

    if rule.action == "block":
        status = rule.status_code or block_status
        lines.append(f"    http-response set-var(txn.status_source) str(haproxy) if {condition}")
        lines.append(f"    http-response deny deny_status {status} default-errorfiles if {condition}")
    elif rule.action == "allow":
        # Response allow doesn't set txn.sec.done (request phase already ran)
        pass
    elif rule.action == "redirect":
        url = rule.redirect_url or "/"
        code = rule.redirect_code or 302
        lines.append(f"    http-response set-var(txn.status_source) str(haproxy) if {condition}")
        lines.append(f"    http-response redirect location {url} code {code} if {condition}")


def _is_block_action(action: str) -> bool:
    return action == "block"


# ---------------------------------------------------------------------------
# Reorder
# ---------------------------------------------------------------------------

def reorder_rules(db: Session, ordered_ids: List[int]) -> None:
    """Reassign priorities based on the given ordered list of rule IDs."""
    from ..models.models import SecurityRule
    for priority, rule_id in enumerate(ordered_ids):
        rule = db.get(SecurityRule, rule_id)
        if rule:
            rule.priority = priority
    db.commit()


# ---------------------------------------------------------------------------
# JA4 dependency helper
# ---------------------------------------------------------------------------

# Field name that requires the JA4 Lua sample-fetch to be loaded.
_JA4_FIELD = "http.request.ja4"


def _ast_references_field(node: Dict[str, Any], field: str) -> bool:
    """Recursively check whether an AST node references the given field."""
    if not isinstance(node, dict):
        return False
    t = node.get("type")
    # Composite nodes
    if t in ("and", "or"):
        return any(_ast_references_field(c, field) for c in node.get("children", []))
    if t == "not":
        return _ast_references_field(node.get("child", {}), field)
    # Leaf nodes carry a "field" key
    return node.get("field") == field


def rules_referencing_ja4(db: Session) -> List[Any]:
    """Return enabled SecurityRules whose expression references http.request.ja4.

    Used by the ja4_enabled toggle to auto-disable rules that would produce
    a broken HAProxy config (referencing the unloaded lua.ja4_fp fetch).
    """
    from ..models.models import SecurityRule
    matches: List[SecurityRule] = []
    for rule in db.query(SecurityRule).filter(SecurityRule.enabled == True).all():
        ast = rule.expression_ast
        if isinstance(ast, dict) and _ast_references_field(ast, _JA4_FIELD):
            matches.append(rule)
            continue
        # Fall back to scanning the raw expression text if AST is missing/stale.
        if isinstance(rule.expression, str) and _JA4_FIELD in rule.expression:
            matches.append(rule)
    return matches


def _ast_references_list(node: Dict[str, Any], list_type: str, list_name: str) -> bool:
    """Recursively check whether an AST node references the given security list.

    Matches ``in_list`` leaf nodes whose ``list_type`` and ``list_name`` equal
    the given values.
    """
    if not isinstance(node, dict):
        return False
    t = node.get("type")
    if t in ("and", "or"):
        return any(_ast_references_list(c, list_type, list_name) for c in node.get("children", []))
    if t == "not":
        return _ast_references_list(node.get("child", {}), list_type, list_name)
    if t == "in_list":
        return node.get("list_type") == list_type and node.get("list_name") == list_name
    return False


def rules_referencing_list(db: Session, list_type: str, list_name: str) -> List[Any]:
    """Return SecurityRules whose expression references the given security list.

    Walks each rule's pre-parsed ``expression_ast`` for ``in_list`` leaf nodes
    matching ``list_type`` and ``list_name``. Used by the global "list in use"
    delete protection to block deletion of a list referenced by a rule.
    """
    from ..models.models import SecurityRule
    matches: List[SecurityRule] = []
    for rule in db.query(SecurityRule).all():
        ast = rule.expression_ast
        if isinstance(ast, dict) and _ast_references_list(ast, list_type, list_name):
            matches.append(rule)
    return matches
