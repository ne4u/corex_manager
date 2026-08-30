"""Cacheability rules — ordered, first-match-wins rules deciding what gets cached.

A backend's cache config owns a list of rules. Each rule matches on the request
URL by `match_type` and, when it is the first match, its `action` decides the
outcome: `cache` allows the response to be cached, `bypass` proxies to the
origin without storing. If no rule matches, nothing is cached.

The same rule list drives both cache tiers:

- **Memory cache** (HAProxy native) — rules become ACLs gating
  `http-request cache-use`.
- **Disk cache** (Varnish) — rules become `use-server` directives in HAProxy,
  routing cache-eligible requests to Varnish.

Match types
-----------
``path``       Prefix match on the URL path (``/downloads/`` matches
               ``/downloads/linux.iso``). Case-sensitive.
``filename``   Exact match on the final path segment (``linux.iso``).
               Case-sensitive.
``extension``  Match on the file extension (``png``). Case-insensitive, since
               ``.PNG`` and ``.png`` are the same asset type in practice.

A trailing ``*`` on a path (``/downloads/*``) and a leading ``*.`` or ``.`` on an
extension (``*.png``, ``.png``) are accepted and normalized away, so the
examples users naturally type all work.
"""
import re
from typing import Iterable, List, Optional, Tuple

MATCH_TYPES = ("path", "filename", "extension", "method", "query_string", "content_type", "status_code")
ACTIONS = ("cache", "bypass")
TIERS = ("memory", "disk")

# Request-phase match types (evaluated when deciding to lookup cache)
REQUEST_PHASE_TYPES = ("path", "filename", "extension", "method", "query_string")
# Response-phase match types (evaluated when deciding to store response)
RESPONSE_PHASE_TYPES = ("content_type", "status_code")

# Extensions are bare alphanumerics (png, iso, tar, woff2).
_EXTENSION_RE = re.compile(r"^[A-Za-z0-9]+$")
# Filenames may not contain path separators, wildcards, or whitespace.
_FILENAME_RE = re.compile(r"^[^/\s*?]+$")
# HTTP methods (GET, POST, etc.)
_METHOD_RE = re.compile(r"^[A-Z]+$")
# Content-Type pattern (e.g., "application/json", "image/*", "text/html")
_CONTENT_TYPE_RE = re.compile(r"^[a-z0-9\-]+/([a-z0-9\-\+\.]+|\*)$", re.IGNORECASE)
# HTTP status codes (200, 404, 5xx, 200,301,404)
_STATUS_CODE_RE = re.compile(r"^(\d{3}|[1-5]xx)(,(\d{3}|[1-5]xx))*$")
# Query string parameter name or name=value
_QUERY_PARAM_RE = re.compile(r"^([a-zA-Z0-9_\-]+)(=[^&]*)?$")
# Reject control characters and quotes that could break out of a generated
# VCL string literal or a HAProxy config line.
_UNSAFE_RE = re.compile(r"[\r\n\"'`\\;#|$]")


def normalize_pattern(match_type: str, pattern: str) -> str:
    """Validate and canonicalize a rule pattern for the given match type.

    Raises ValueError with a user-facing message when the pattern is invalid.
    """
    if match_type not in MATCH_TYPES:
        raise ValueError(f"Invalid match type '{match_type}'. Expected one of: {', '.join(MATCH_TYPES)}")
    if not isinstance(pattern, str):
        pattern = str(pattern)
    value = pattern.strip()
    if not value:
        raise ValueError("Pattern must not be empty")
    if _UNSAFE_RE.search(value):
        raise ValueError("Pattern contains unsupported characters")

    if match_type == "path":
        # Accept "/downloads/*" and "/downloads/" alike.
        if value.endswith("*"):
            value = value[:-1]
        if not value.startswith("/"):
            raise ValueError("Path pattern must start with '/' (e.g. /downloads/)")
        if not value.rstrip("/"):
            raise ValueError("Path pattern '/' would match every request; enable the tier without rules instead")
        return value

    if match_type == "filename":
        # Accept a leading slash for convenience but store the bare name.
        value = value.lstrip("/")
        if not _FILENAME_RE.match(value):
            raise ValueError("Filename must be a single path segment with no wildcards (e.g. linux.iso)")
        return value

    if match_type == "extension":
        # extension — accept "*.png", ".png" and "png".
        if value.startswith("*."):
            value = value[2:]
        value = value.lstrip(".")
        if not _EXTENSION_RE.match(value):
            raise ValueError("Extension must be alphanumeric (e.g. png, iso, woff2)")
        return value.lower()
    
    if match_type == "method":
        # HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
        value = value.upper()
        if not _METHOD_RE.match(value):
            raise ValueError("Method must be a valid HTTP method (e.g. GET, POST, PUT)")
        return value
    
    if match_type == "query_string":
        # Query string parameter (param or param=value or * for any query string)
        if value == "*":
            return value  # Match any request with a query string
        if not _QUERY_PARAM_RE.match(value):
            raise ValueError("Query string must be 'param' or 'param=value' or '*' (e.g. nocache, format=json)")
        return value
    
    if match_type == "content_type":
        # Content-Type header (e.g., application/json, image/*, text/html)
        value = value.lower()
        if not _CONTENT_TYPE_RE.match(value):
            raise ValueError("Content-Type must be a valid MIME type (e.g. application/json, image/*, text/html)")
        return value
    
    if match_type == "status_code":
        # HTTP status code (200, 404, 5xx, or comma-separated list)
        if not _STATUS_CODE_RE.match(value):
            raise ValueError("Status code must be specific (200, 404) or range (4xx, 5xx) or list (200,301,404)")
        return value
    
    # Should never reach here due to match_type validation above
    raise ValueError(f"Unhandled match type: {match_type}")


def validate_action(action: str) -> str:
    if action not in ACTIONS:
        raise ValueError(f"Invalid action '{action}'. Expected one of: {', '.join(ACTIONS)}")
    return action


def active_rules(cache_config) -> List:
    """Return enabled rules for a cache config in evaluation order."""
    if cache_config is None:
        return []
    rules = [r for r in (cache_config.rules or []) if r.enabled]
    return sorted(rules, key=lambda r: (r.priority, r.id or 0))


# --------------------------------------------------------------------------
# Varnish VCL
# --------------------------------------------------------------------------

def vcl_condition(rule) -> str:
    """Return a VCL boolean expression matching this rule.

    `req.url` includes the query string, so filename/extension matches allow an
    optional `?...` suffix rather than anchoring hard at end-of-string.
    """
    pattern = rule.pattern
    if rule.match_type == "path":
        return f'req.url ~ "^{re.escape(pattern)}"'
    if rule.match_type == "filename":
        return f'req.url ~ "/{re.escape(pattern)}(\\?.*)?$"'
    if rule.match_type == "extension":
        # extension — case-insensitive
        return f'req.url ~ "(?i)\\.{re.escape(pattern)}(\\?.*)?$"'
    if rule.match_type == "method":
        return f'req.method == "{pattern}"'
    if rule.match_type == "query_string":
        if pattern == "*":
            return 'req.url ~ "\\?"'  # Has any query string
        if "=" in pattern:
            # Match param=value in query string
            param, value = pattern.split("=", 1)
            return f'req.url ~ "[?&]{re.escape(param)}={re.escape(value)}"'
        # Match param presence (any value)
        return f'req.url ~ "[?&]{re.escape(pattern)}="'
    if rule.match_type == "content_type":
        # Response header - use beresp in VCL
        if pattern.endswith("/*"):
            # Wildcard match (e.g., "image/*")
            prefix = pattern[:-2]
            return f'beresp.http.Content-Type ~ "^{re.escape(prefix)}/"'
        return f'beresp.http.Content-Type ~ "^{re.escape(pattern)}"'
    if rule.match_type == "status_code":
        # Response status code
        if "," in pattern:
            # Multiple codes: 200,301,404
            codes = pattern.split(",")
            conditions = " || ".join([f"beresp.status == {c}" if c.isdigit() else f'beresp.status >= {c[0]}00 && beresp.status < {int(c[0])+1}00' for c in codes])
            return f"({conditions})"
        if pattern.endswith("xx"):
            # Range: 2xx, 4xx, 5xx
            first_digit = pattern[0]
            return f"beresp.status >= {first_digit}00 && beresp.status < {int(first_digit)+1}00"
        # Specific code: 200, 404
        return f"beresp.status == {pattern}"
    
    raise ValueError(f"Unsupported match_type for VCL: {rule.match_type}")


def emit_vcl_decision(cache_config, indent: str = "        ") -> List[str]:
    """Emit the VCL decision chain for one backend.

    Sets `req.http.X-Cache-Decision` to "cache" or "bypass". The caller acts on
    the marker after stripping the routing header. With no rules the decision
    stays "bypass", so nothing is cached.
    """
    rules = active_rules(cache_config)
    lines = [f'{indent}set req.http.X-Cache-Decision = "bypass";']
    if not rules:
        lines.append(f"{indent}# No cacheability rules defined — nothing is cached")
        return lines

    for i, rule in enumerate(rules):
        keyword = "if" if i == 0 else "} else if"
        lines.append(f"{indent}{keyword} ({vcl_condition(rule)}) {{")
        lines.append(f'{indent}    set req.http.X-Cache-Decision = "{rule.action}";')
    lines.append(f"{indent}}}")
    return lines


# --------------------------------------------------------------------------
# HAProxy
# --------------------------------------------------------------------------

def haproxy_acl_criterion(rule) -> str:
    """Return the HAProxy ACL criterion + value for this rule.
    
    Returns the criterion for request-phase rules. Response-phase rules
    (content_type, status_code) are handled separately in cache-store phase.
    """
    pattern = rule.pattern
    if rule.match_type == "path":
        return f"path_beg {pattern}"
    if rule.match_type == "filename":
        # Anchor on a full path segment so "linux.iso" does not match
        # "not-linux.iso".
        return f"path_end /{pattern}"
    if rule.match_type == "extension":
        return f"path_end -i .{pattern}"
    if rule.match_type == "method":
        return f"method {pattern}"
    if rule.match_type == "query_string":
        if pattern == "*":
            return "url_param() -m found"  # Has any query parameter
        if "=" in pattern:
            # Match param=value
            param, value = pattern.split("=", 1)
            return f"urlp({param}) -m str {value}"
        # Match param presence (any value)
        return f"urlp({pattern}) -m found"
    if rule.match_type in RESPONSE_PHASE_TYPES:
        # Response-phase rules don't generate ACLs in request phase
        # They're evaluated in http-response cache-store conditions
        raise ValueError(f"Response-phase match type {rule.match_type} should not generate request ACL")
    
    raise ValueError(f"Unsupported match_type for HAProxy: {rule.match_type}")


def emit_haproxy_cache_rules(
    cache_config,
    cache_name: str,
    acl_prefix: str,
    extra_condition: Optional[str] = None,
    emit_acls: bool = True,
    indent: str = "    ",
) -> Tuple[List[str], bool]:
    """Emit ACLs and ordered `http-request cache-use` lines for the memory cache.

    HAProxy has no "do not cache" action, so first-match-wins is expressed by
    emitting one `cache-use` per `cache` rule, in priority order, guarded by the
    negation of every *earlier* `bypass` rule. HAProxy applies the first
    matching `cache-use`, which reproduces the ordered semantics exactly.

    Only processes rules with tier="memory" and request-phase match types.
    Response-phase rules (content_type, status_code) are handled separately
    in cache-store conditions.

    Args:
        emit_acls: If True (default), emit ACL declarations. Set to False if ACLs
                   are emitted separately via emit_cache_rule_acls().

    Returns (lines, any_cache_rule). When `any_cache_rule` is False the caller
    should skip `filter cache` / `cache-store` entirely, since nothing would
    ever be served from the cache.
    """
    all_rules = active_rules(cache_config)
    # Filter for memory tier and request-phase match types only
    rules = [r for r in all_rules if r.tier == "memory" and r.match_type in REQUEST_PHASE_TYPES]
    
    if not rules:
        return ([f"{indent}# No cacheability rules for memory tier — memory cache stores nothing"], False)

    acl_names = {}
    lines: List[str] = []
    
    # Emit ACLs if requested
    if emit_acls:
        for rule in rules:
            acl_name = f"{acl_prefix}_{rule.id}"
            acl_names[rule.id] = acl_name
            lines.append(f"{indent}acl {acl_name} {haproxy_acl_criterion(rule)}")
    else:
        # Just build the ACL name mapping
        for rule in rules:
            acl_names[rule.id] = f"{acl_prefix}_{rule.id}"

    use_lines: List[str] = []
    preceding_bypass: List[str] = []
    for rule in rules:
        if rule.action == "bypass":
            preceding_bypass.append(acl_names[rule.id])
            continue
        conditions = [acl_names[rule.id]] + [f"!{name}" for name in preceding_bypass]
        if extra_condition:
            conditions.append(extra_condition)
        use_lines.append(f"{indent}http-request cache-use {cache_name} if {' '.join(conditions)}")

    if not use_lines:
        comment = f"{indent}# All memory tier cacheability rules are bypass rules — memory cache stores nothing"
        return (lines + [comment] if emit_acls else [comment], False)

    return (lines + use_lines, True)


def emit_response_phase_cache_store_condition(
    cache_config,
    cache_name: str,
    indent: str = "    ",
) -> Optional[str]:
    """Emit conditional http-response cache-store for response-phase rules.
    
    Returns cache-store line with conditions if there are response-phase rules,
    or None if only request-phase rules exist (unconditional cache-store).
    
    Response-phase rules (content_type, status_code) add conditions to cache-store
    to filter what gets cached based on the response.
    """
    all_rules = active_rules(cache_config)
    # Filter for memory tier and response-phase match types
    response_rules = [r for r in all_rules if r.tier == "memory" and r.match_type in RESPONSE_PHASE_TYPES]
    
    if not response_rules:
        # No response-phase rules - return unconditional cache-store
        return None
    
    # Build condition from response-phase rules (first-match-wins, with bypass negation)
    conditions = []
    preceding_bypass = []
    
    for rule in response_rules:
        if rule.action == "bypass":
            # Track bypass conditions to negate in later cache rules
            preceding_bypass.append(haproxy_response_condition(rule))
            continue
        
        # Cache rule - add condition with negation of earlier bypasses
        rule_cond = haproxy_response_condition(rule)
        if preceding_bypass:
            # Negate all preceding bypass conditions
            negated = " && ".join([f"!({cond})" for cond in preceding_bypass])
            conditions.append(f"({rule_cond} && {negated})")
        else:
            conditions.append(f"({rule_cond})")
    
    if not conditions:
        # All response rules are bypasses - don't cache anything
        return f"{indent}# All response-phase rules are bypass rules — nothing cached"
    
    # Combine all cache conditions with OR
    combined = " || ".join(conditions)
    return f"{indent}http-response cache-store {cache_name} if {combined}"


def emit_cache_rule_acls(
    cache_config,
    acl_prefix: str,
    indent: str = "    ",
) -> List[str]:
    """Emit ACL declarations for request-phase cache rules.
    
    Only emits ACLs for rules that can be evaluated in the request phase.
    Response-phase rules (content_type, status_code) are handled inline
    in cache-store conditions.
    
    Returns list of ACL declaration lines.
    """
    rules = active_rules(cache_config)
    if not rules:
        return []
    
    lines: List[str] = []
    for rule in rules:
        # Skip response-phase rules - they don't get ACLs
        if rule.match_type in RESPONSE_PHASE_TYPES:
            continue
        acl_name = f"{acl_prefix}_{rule.id}"
        lines.append(f"{indent}acl {acl_name} {haproxy_acl_criterion(rule)}")
    
    return lines


def haproxy_response_condition(rule) -> str:
    """Return HAProxy condition for response-phase rules (content_type, status_code).
    
    These are used in http-response cache-store conditions.
    """
    pattern = rule.pattern
    if rule.match_type == "content_type":
        if pattern.endswith("/*"):
            # Wildcard match (e.g., "image/*")
            prefix = pattern[:-2]
            return f"res.hdr(Content-Type) -m beg {prefix}/"
        # Exact match
        return f"res.hdr(Content-Type) -m beg {pattern}"
    
    if rule.match_type == "status_code":
        if "," in pattern:
            # Multiple codes: 200,301,404
            codes = pattern.split(",")
            conditions = []
            for code in codes:
                if code.endswith("xx"):
                    first_digit = code[0]
                    conditions.append(f"{{ status {first_digit}00:599 }}")
                else:
                    conditions.append(f"{{ status {code} }}")
            return " || ".join(conditions)
        if pattern.endswith("xx"):
            # Range: 2xx, 4xx, 5xx
            first_digit = pattern[0]
            return f"{{ status {first_digit}00:599 }}"
        # Specific code
        return f"{{ status {pattern} }}"
    
    raise ValueError(f"Not a response-phase match type: {rule.match_type}")


def emit_disk_cache_use_server_directives(
    cache_config,
    varnish_server_name: str,
    acl_prefix: str,
    indent: str = "    ",
) -> Tuple[List[str], List[str]]:
    """Emit `use-server` directives for disk cache routing to Varnish.

    Routes cache-eligible requests to the Varnish server based on cache rules.
    Uses the same ACLs generated by `emit_cache_rule_acls()`, so this
    function only emits the `use-server` directives, not the ACL declarations.

    Only processes rules with tier="disk" and request-phase match types.
    Response-phase rules (content_type, status_code) would need to be evaluated
    in Varnish VCL, not in HAProxy routing decisions.

    Returns (use_server_lines, acl_condition_list). The use_server_lines are
    the `use-server` directives. The acl_condition_list contains the OR'd ACL
    conditions for use in setting the X-Cache-Backend header conditionally.

    Example output:
        use-server disk_cache if cacherule_1
        use-server disk_cache if cacherule_2 !cacherule_3
    """
    all_rules = active_rules(cache_config)
    # Filter for disk tier and request-phase match types only
    rules = [r for r in all_rules if r.tier == "disk" and r.match_type in REQUEST_PHASE_TYPES]
    
    if not rules:
        return ([], [])

    # Build ACL names mapping (must match emit_haproxy_cache_rules naming)
    acl_names = {}
    for rule in rules:
        acl_names[rule.id] = f"{acl_prefix}_{rule.id}"

    use_server_lines: List[str] = []
    acl_conditions: List[str] = []
    preceding_bypass: List[str] = []
    
    for rule in rules:
        acl_name = acl_names[rule.id]
        
        if rule.action == "bypass":
            # Bypass rules don't generate use-server directives, but they
            # negate later cache rules
            preceding_bypass.append(acl_name)
            continue
        
        # Cache rule: generate use-server directive with negation of earlier bypass rules
        conditions = [acl_name] + [f"!{name}" for name in preceding_bypass]
        use_server_lines.append(f"{indent}use-server {varnish_server_name} if {' '.join(conditions)}")
        
        # Track conditions for X-Cache-Backend header (OR'd together)
        acl_conditions.append(' '.join(conditions))

    return (use_server_lines, acl_conditions)
