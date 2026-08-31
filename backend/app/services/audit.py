"""Audit event helpers: action derivation, payload truncation, config-change classification."""
import json
import re
from typing import Any, Dict, Optional, Tuple

from ..core.config import get_settings

settings = get_settings()

# Paths whose request bodies contain secrets and must NOT be captured.
_PAYLOAD_SKIP_PATHS = {
    "/auth/token",
    "/auth/totp/setup",
    "/auth/totp/verify",
    "/auth/totp/disable",
    "/auth/logout",
    "/auth/refresh",
    "/certificates",  # POST /certificates — contains fullchain/key/dns_credentials
    # MCP Gateway — server secrets and PAT issuance
    "/mcp/servers",
    "/mcp/identities",
}

# Special-case action mapping for non-REST or ambiguous paths.
# Maps (method, path_pattern) -> (action, resource_type, resource_id_group_index)
# resource_id_group_index is the regex group index to use for resource_id, or None.
_SPECIAL_CASES = [
    # Auth events
    (r"^/auth/token$", "POST", "login", None, None),
    (r"^/auth/logout$", "POST", "logout", None, None),
    (r"^/auth/refresh$", "POST", "refresh_token", None, None),
    (r"^/auth/totp/setup$", "POST", "totp_setup", None, None),
    (r"^/auth/totp/verify$", "POST", "totp_verify", None, None),
    (r"^/auth/totp/disable$", "POST", "totp_disable", None, None),
    # Config lifecycle
    (r"^/config/apply$", "POST", "apply_config", "config", None),
    (r"^/config/revert$", "POST", "revert_config", "config", None),
    (r"^/config/snapshots/max$", "PUT", "update_max_snapshots", "setting", None),
    (r"^/config/snapshots/(\d+)/rollback$", "POST", "rollback_snapshot", "config_snapshot", 1),
    # Certificate actions
    (r"^/certificates/(\d+)/issue$", "POST", "issue_certificate", "certificate", 1),
    (r"^/certificates/(\d+)/upload$", "POST", "upload_certificate", "certificate", 1),
    (r"^/certificates/renew$", "POST", "renew_certificates", "certificate", None),
    # WAF rule lifecycle
    (r"^/waf/rules/import$", "POST", "import_waf_rules", "waf_rule", None),
    (r"^/waf/rules/(\d+)/snapshot$", "POST", "snapshot_waf_rule", "waf_rule", 1),
    (r"^/waf/rules/(\d+)/restore/\d+$", "POST", "restore_waf_rule", "waf_rule", 1),
    (r"^/waf/rule-versions/(\d+)$", "DELETE", "delete_waf_rule_version", "waf_rule_version", 1),
    (r"^/waf/rule-versions/max$", "PUT", "update_waf_rule_version_max", "setting", None),
    (r"^/waf/verify-captcha$", "POST", "verify_captcha", None, None),
    # Security list feed refresh
    (r"^/security-lists/feeds/(\d+)/refresh$", "POST", "refresh_feed", "dynamic_feed", 1),
    # Security rules
    (r"^/security-rules/reorder$", "PUT", "reorder_security_rules", "security_rule", None),
    (r"^/security-rules/validate$", "POST", "validate_security_rule", None, None),
    # Risk rules
    (r"^/risk-rules/reorder$", "PUT", "reorder_risk_rules", "risk_rule", None),
    (r"^/risk-rules/validate$", "POST", "validate_risk_rule", None, None),
    (r"^/risk-rules/seed-baseline$", "POST", "seed_baseline_risk_rules", "risk_rule", None),
    # Risk rulesets

    # Response transforms
    (r"^/resp-transforms/reorder$", "PUT", "reorder_response_transforms", "response_transform", None),
    (r"^/resp-transforms/validate$", "POST", "validate_response_transform", None, None),
    # Settings
    (r"^/settings/geoip/download$", "POST", "download_geoip", "setting", None),
    (r"^/settings/maxmind/license-key$", "PUT", "set_maxmind_license_key", "setting", None),
    # HAProxy global options
    (r"^/haproxy/global-options$", "PUT", "update_global_options", "haproxy", None),
    # API Armor
    (r"^/api-armor/settings$", "PUT", "update_api_armor_settings", "api_armor", None),
    (r"^/api-armor/presets/apply$", "POST", "apply_api_armor_presets", "api_armor", None),
    (r"^/api-armor/specs$", "POST", "import_openapi_spec", "openapi_spec", None),
    (r"^/api-armor/specs/(\d+)$", "DELETE", "delete_openapi_spec", "openapi_spec", 1),
    (r"^/api-armor/schemas/(\d+)$", "PUT", "update_api_schema", "api_schema", 1),
    (r"^/api-armor/auth-policies$", "POST", "create_auth_policy", "auth_policy", None),
    (r"^/api-armor/auth-policies/(\d+)$", "PUT", "update_auth_policy", "auth_policy", 1),
    (r"^/api-armor/auth-policies/(\d+)$", "DELETE", "delete_auth_policy", "auth_policy", 1),
    (r"^/api-armor/api-key-lists$", "POST", "create_api_key_list", "api_key_list", None),
    (r"^/api-armor/api-key-lists/(\d+)$", "DELETE", "delete_api_key_list", "api_key_list", 1),
    (r"^/api-armor/profiles/(\d+)/finalize$", "POST", "finalize_api_profile", "api_profile", 1),
    (r"^/api-armor/profiles/(\d+)$", "DELETE", "delete_api_profile", "api_profile", 1),
    (r"^/api-armor/anomalies$", "DELETE", "clear_api_anomalies", "api_anomaly", None),
    # MCP Gateway
    (r"^/mcp/identities/(\d+)/tokens$", "POST", "issue_pat", "mcp_identity", 1),
    (r"^/mcp/skills/(\d+)/publish$", "POST", "publish_skill", "mcp_skill", 1),
    (r"^/mcp/skills/(\d+)/rollback$", "POST", "rollback_skill", "mcp_skill", 1),
    # SSL Labs scans
    (r"^/certificates/(\d+)/ssllabs/scans$", "POST", "start_ssllabs_scan", "ssllabs_scan", None),
    (r"^/certificates/(\d+)/ssllabs/scans/(\d+)/poll$", "POST", "poll_ssllabs_scan", "ssllabs_scan", 2),
    (r"^/certificates/(\d+)/ssllabs/scans/(\d+)$", "DELETE", "delete_ssllabs_scan", "ssllabs_scan", 2),
    (r"^/certificates/(\d+)/ssllabs/settings$", "PUT", "update_ssllabs_settings", "setting", None),
]

# Mutating paths that do NOT affect any generated config file
# (HAProxy/Coraza/Varnish/MCP bundle/security-list files/risk-rules data).
# Each entry is (method, regex) matched against the path with /api/v1 stripped.
# Events matching these are marked config_change=False so they don't appear in
# the audit log "Pending Changes" section (they don't require a config apply).
_NON_CONFIG_PATHS: list[tuple[str, str]] = [
    # --- Auth (no config impact) ---
    ("POST", r"^/auth/token$"),
    ("POST", r"^/auth/logout$"),
    ("POST", r"^/auth/refresh$"),
    ("POST", r"^/auth/totp/setup$"),
    ("POST", r"^/auth/totp/verify$"),
    ("POST", r"^/auth/totp/disable$"),
    ("POST", r"^/auth/change-password$"),
    # User preferences (theme / custom themes / language) — UI-only
    ("PUT", r"^/auth/preferences$"),
    # --- User management (no config impact) ---
    ("POST", r"^/users$"),
    ("PUT", r"^/users/\d+$"),
    ("DELETE", r"^/users/\d+$"),
    # --- Task cancellation (operational, no config impact) ---
    ("POST", r"^/tasks/\d+/cancel$"),
    # --- Config lifecycle actions (apply/revert/rollback) ---
    # These are the actions that APPLY or REVERT pending changes — they are
    # not themselves pending changes. Without this, apply_config events can
    # show as "pending" due to timing issues with background task snapshot
    # stamping.
    ("POST", r"^/config/apply$"),
    ("POST", r"^/config/revert$"),
    ("POST", r"^/config/snapshots/\d+/rollback$"),
    # --- Config lifecycle: max snapshots setting (not read by any generator) ---
    ("PUT", r"^/config/snapshots/max$"),
    # --- Captcha keys (proxy to external Cap service, no DB/config change) ---
    ("POST", r"^/captcha/keys$"),
    ("PUT", r"^/captcha/keys/[^/]+/config$"),
    ("DELETE", r"^/captcha/keys/[^/]+$"),
    ("POST", r"^/captcha/keys/[^/]+/rotate-secret$"),
    # --- WAF operational / metadata (not config-generating) ---
    ("POST", r"^/waf/verify-captcha$"),
    ("POST", r"^/waf/siem-integrations$"),
    ("PUT", r"^/waf/siem-integrations/\d+$"),
    ("DELETE", r"^/waf/siem-integrations/\d+$"),
    ("POST", r"^/waf/rules/\d+/snapshot$"),
    ("PUT", r"^/waf/rule-versions/max$"),
    ("DELETE", r"^/waf/rule-versions/\d+$"),
    # --- Validation-only endpoints (no DB write) ---
    ("POST", r"^/security-rules/validate$"),
    ("POST", r"^/risk-rules/validate$"),
    ("POST", r"^/resp-transforms/validate$"),
    # --- Cache flush (operational, no config change) ---
    ("POST", r"^/cache/\d+/clear$"),
    ("POST", r"^/cache/clear-all$"),
    # --- API Armor runtime / observational data (not consumed by generators) ---
    ("POST", r"^/api-armor/specs$"),
    ("DELETE", r"^/api-armor/specs/\d+$"),
    ("PUT", r"^/api-armor/schemas/\d+$"),
    ("POST", r"^/api-armor/auth-policies$"),
    ("PUT", r"^/api-armor/auth-policies/\d+$"),
    ("DELETE", r"^/api-armor/auth-policies/\d+$"),
    ("POST", r"^/api-armor/api-key-lists$"),
    ("DELETE", r"^/api-armor/api-key-lists/\d+$"),
    ("POST", r"^/api-armor/profiles/\d+/finalize$"),
    ("DELETE", r"^/api-armor/profiles/\d+$"),
    ("DELETE", r"^/api-armor/anomalies$"),
    # --- Page protect observational data (not emitted by HAProxy/Varnish) ---
    ("PUT", r"^/page-protect/scripts/\d+$"),
    ("DELETE", r"^/page-protect/scripts/\d+$"),
    ("POST", r"^/page-protect/scripts/\d+/check$"),
    ("POST", r"^/page-protect/scripts/check-all$"),
    ("POST", r"^/page-protect/sample$"),
    ("POST", r"^/page-protect/baseline/start$"),
    ("POST", r"^/page-protect/baseline/stop$"),
    ("DELETE", r"^/page-protect/baseline$"),
    ("DELETE", r"^/page-protect/reports$"),
    # --- MaxMind license key (key only; DB files downloaded separately) ---
    ("PUT", r"^/settings/maxmind/license-key$"),
    # --- MCP operational / non-bundle-affecting endpoints ---
    ("POST", r"^/mcp/marketplace/discover-env-vars$"),
    ("POST", r"^/mcp/servers/\d+/oauth/discover$"),
    ("POST", r"^/mcp/servers/\d+/oauth/authorize$"),
    ("POST", r"^/mcp/skills/\d+/export$"),
    ("DELETE", r"^/mcp/sessions/[^/]+$"),
    ("POST", r"^/mcp/identities/\d+/revoke$"),
    ("POST", r"^/mcp/config/regenerate$"),
    ("PUT", r"^/mcp/alerts/config$"),
    ("POST", r"^/mcp/teams/\d+/members$"),
    ("DELETE", r"^/mcp/teams/\d+/members/\d+$"),
    ("POST", r"^/mcp/skills/\d+/versions$"),
    # --- SSL Labs scans (external API, no HAProxy/Coraza config impact) ---
    ("POST", r"^/certificates/\d+/ssllabs/scans$"),
    ("POST", r"^/certificates/\d+/ssllabs/scans/\d+/poll$"),
    ("DELETE", r"^/certificates/\d+/ssllabs/scans/\d+$"),
    ("PUT", r"^/certificates/\d+/ssllabs/settings$"),
]


def is_config_change(method: str, path: str) -> bool:
    """Return True if the mutating request affects generated config.

    Checks the (method, path) against a denylist of non-config-affecting
    paths. Returns False for matches (non-config), True otherwise
    (conservative default — treat unknown paths as config-affecting).
    """
    clean = path
    if clean.startswith("/api/v1"):
        clean = clean[len("/api/v1"):]
    if not clean.startswith("/"):
        clean = "/" + clean
    for sc_method, pattern in _NON_CONFIG_PATHS:
        if sc_method != method:
            continue
        if re.match(pattern, clean):
            return False
    return True

# Simple pluralization rules for singularizing resource names.
_SINGULAR_OVERRIDES = {
    "asns": "asn",
    "ips": "ip",
    "fcgi-apps": "fcgi_app",
    "waf-rules": "waf_rule",
    "waf-exceptions": "waf_exception",
    "waf-siem-integrations": "waf_siem_integration",
    "rule-versions": "waf_rule_version",
    "backend-rules": "backend_rule",
    "rate-limits": "rate_limit",
    "log-destinations": "log_destination",
    "logged-fields": "logged_field",
    "response-headers": "response_header",
    "error-pages": "error_page",
    "security-lists": "security_list",
    "security-rules": "security_rule",
    "risk-rules": "risk_rule",
    "risk-rulesets": "risk_ruleset",
    "cipher-suites": "cipher_suite",
    "ciphers": "cipher",
    "certificates": "certificate",
    "backends": "backend",
    "listeners": "listener",
    "servers": "server",
    "redirects": "redirect",
    "rewrites": "rewrite",
    "resp-transforms": "response_transform",
    "users": "user",
    "feeds": "dynamic_feed",
    "entries": "entry",
    "snapshots": "config_snapshot",
    "network": "network_list",
    "asn": "asn_list",
    "geo": "geo_list",
    "ja4": "ja4_list",
    # MCP Gateway
    "identities": "mcp_identity",
    "policies": "mcp_policy",
    "dlp-rules": "mcp_dlp_rule",
    "guardrails": "mcp_guardrail",
    "skills": "mcp_skill",
    "teams": "team",
}

_VERB_MAP = {
    "POST": "create",
    "PUT": "update",
    "PATCH": "patch",
    "DELETE": "delete",
}


def _singularize(segment: str) -> str:
    """Convert a plural URL segment to a singular resource type string."""
    if segment in _SINGULAR_OVERRIDES:
        return _SINGULAR_OVERRIDES[segment]
    # Generic rules
    if segment.endswith("ies"):
        return segment[:-3] + "y"
    if segment.endswith("es") and not segment.endswith("ses"):
        return segment[:-2]
    if segment.endswith("s") and not segment.endswith("ss"):
        return segment[:-1]
    return segment


def derive_action(method: str, path: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Derive a semantic action label, resource_type, and resource_id from method + path.

    Returns (action, resource_type, resource_id).
    resource_id may be None for POST creates (filled later from response body).
    """
    # Strip /api/v1/ prefix if present
    clean = path
    if clean.startswith("/api/v1"):
        clean = clean[len("/api/v1"):]
    if not clean.startswith("/"):
        clean = "/" + clean

    # Check special cases first
    for pattern, sc_method, action, rtype, rid_group in _SPECIAL_CASES:
        if sc_method != method:
            continue
        m = re.match(pattern, clean)
        if m:
            rid = m.group(rid_group) if rid_group else None
            return action, rtype, rid

    # Generic REST fallback
    parts = [p for p in clean.strip("/").split("/") if p]
    verb = _VERB_MAP.get(method, method.lower())

    # Find the resource segment (last non-numeric segment) and any id after it
    resource_segment = None
    resource_id = None
    for i, seg in enumerate(parts):
        if re.match(r"^\d+$", seg):
            # This is a numeric id; the resource is the previous segment
            if i > 0:
                resource_segment = parts[i - 1]
                resource_id = seg
        elif seg not in ("api", "v1"):
            resource_segment = seg

    # For POST to a collection (e.g. /backends), resource_segment is the collection
    # For nested like /backends/{bid}/servers, the last non-numeric segment is "servers"
    if resource_segment:
        resource_type = _singularize(resource_segment)
        action = f"{verb}_{resource_type}"
    else:
        resource_type = None
        action = f"{verb}_unknown"

    return action, resource_type, resource_id


def should_capture_payload(path: str, content_type: Optional[str]) -> bool:
    """Return True if the request payload should be captured for this path."""
    if not content_type:
        return False
    ct = content_type.lower()
    if not ct.startswith("application/json"):
        return False
    # Strip /api/v1 prefix
    clean = path
    if clean.startswith("/api/v1"):
        clean = clean[len("/api/v1"):]
    if not clean.startswith("/"):
        clean = "/" + clean
    # Check exact skip paths
    for skip in _PAYLOAD_SKIP_PATHS:
        if clean == skip:
            return False
    # Skip all /auth/* paths
    if clean.startswith("/auth/"):
        return False
    return True


def truncate_payload(body_bytes: bytes, max_bytes: int) -> Optional[Dict[str, Any]]:
    """Parse and optionally truncate a request body for audit storage.

    Returns a dict (parsed JSON or raw preview), or None if the body is empty.
    """
    if not body_bytes:
        return None
    # Try to parse as JSON
    try:
        text = body_bytes.decode("utf-8")
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            if len(body_bytes) <= max_bytes:
                return parsed
            return {
                "_truncated": True,
                "_size": len(body_bytes),
                "_preview": text[:max_bytes],
            }
        if isinstance(parsed, list):
            if len(body_bytes) <= max_bytes:
                return {"_list": parsed}
            return {
                "_truncated": True,
                "_size": len(body_bytes),
                "_preview": text[:max_bytes],
            }
        # Other JSON types
        if len(body_bytes) <= max_bytes:
            return {"_value": parsed}
        return {
            "_truncated": True,
            "_size": len(body_bytes),
            "_preview": text[:max_bytes],
        }
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    # Not JSON — store raw preview
    preview = body_bytes[:max_bytes].decode("utf-8", errors="replace")
    return {
        "_raw": preview,
        "_truncated": len(body_bytes) > max_bytes,
        "_size": len(body_bytes),
    }
