"""Terraform configuration export for coreX Manager.

Queries all resource tables from the database and generates a structured,
module-based Terraform project compatible with the terraform-provider-corex
provider. The output is a ZIP archive containing:

  main.tf                  — root module composing all submodules
  provider.tf              — provider configuration with variable refs
  variables.tf             — root-level variable declarations
  terraform.tfvars.example — placeholder variable values
  outputs.tf               — root outputs
  README.md                — setup and usage instructions
  modules/<name>/          — one directory per domain (routing, ssl, etc.)
    main.tf                — resource blocks
    variables.tf           — module-level variables (cross-module inputs)
    outputs.tf             — module outputs (for cross-module wiring)
    README.md              — module documentation

The primary use case is exporting a dev environment config as a starting
point for building a robust Terraform config for production environments.
"""
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from ..core.config import get_settings

from ..models.proxy import Backend, BackendRule, Certificate, CipherSuite, FcgiApp, Listener, Server
from ..models.security import (
    AsnList, DynamicFeed, GeoList,
    Ja4List, NetworkList,
    PatternList, RiskRule, RiskRuleset, SecurityRule,
)
from ..models.waf import WafException, WafRule
from ..models.routing import (
    RateLimit, Redirect, RequestHeader, ResponseHeader, ResponseTransform, Rewrite,
)
from ..models.logging import CustomErrorPage, LogDestination, LoggedField
from ..models.cache import CacheConfig, CacheRule
from ..models.page_protect import PageProtectPolicy, PageProtectScript
from ..services.page_protect import get_page_protect_settings
from ..services.settings import get_setting, get_maxmind_license_key
from ..services.ha import get_ha_config
from ..models.api_armor import ApiKeyList, ApiKeyListEntry, ApiSchema, AuthPolicy, OpenApiSpec
from ..models.auth import Setting, User
from ..models.mcp import (
    McpDlpRule, McpGuardrail, McpIdentity, McpPolicy, McpServer,
    McpServerReplica, McpSkill, McpSkillVersion, Team, UserTeam,
)
from .provider_schema import get_computed_fields, get_provider_field_names

# ─── Configuration ──────────────────────────────────────────────────────────

# Provider field overrides — maps resource_type to field-level corrections
# so the exporter emits only attributes the provider actually supports.
# The provider schema is the source of truth; the DB may have extra columns.
#
# Each entry can have:
#   'skip':   set of DB fields to NOT emit (not in provider schema)
#   'rename': {db_field: provider_field} for name mismatches
#   'raw_int': set of FK fields that should stay as raw ints (no resource ref)
#
# This is a short-term bridge until the exporter reads the provider schema
# directly (option 1) or shares Go structs (option 2).
PROVIDER_FIELD_OVERRIDES: Dict[str, Dict[str, Any]] = {
    'user': {
        'skip': {'hashed_password', 'totp_secret', 'totp_enabled', 'is_admin'},
    },
    'waf_exception': {
        'skip': {'update_action', 'update_target',
                 'condition_variable', 'condition_operator', 'condition_value'},
    },
    'waf_rule': {
        'skip': {'rule_set_plugins', 'sec_rules', 'captcha_valid_seconds',
                 'content_types', 'export_rule_ids',
                 'rate_enabled', 'rate_events', 'rate_window_seconds',
                 'rate_key', 'rate_header', 'rate_action', 'rate_duration_seconds'},
    },
    'cache_config': {
        'skip': {'name', 'haproxy_max_object_size', 'haproxy_max_secondary_entries',
                 'haproxy_cache_condition', 'haproxy_process_vary',
                 'disk_cache_grace', 'disk_cache_purge_enabled'},
        'rename': {
            'haproxy_total_max_size': 'haproxy_cache_size',
            'haproxy_max_age': 'haproxy_cache_max_age',
            'haproxy_rfc7234_compliance': 'rfc7234_compliance',
            'disk_cache_ttl': 'disk_cache_max_age',
        },
    },
    'mcp_identity': {
        'skip': {'pat_hash'},
    },
    'mcp_skill_version': {
        'skip': {'name', 'created_by'},
        # version is computed-only in the provider
        'raw_int_skip': {'version'},
    },
    'mcp_policy': {
        # priority is computed-only in the provider
        'skip': {'priority'},
    },
    'security_rule': {
        # priority is computed-only in the provider — don't set it
        'skip': {'priority'},
    },
    'certificate': {
        # dns_credentials is a map in the provider, not a string
        # The type fix is handled in the variable type builder
        # 'provider' is a reserved Terraform word; the provider uses 'provider_name'
        'rename': {'provider': 'provider_name'},
    },
    'backend': {
        'skip': {'health_check_expect_status', 'health_check_expect_body',
                 'timeout_connect', 'timeout_server', 'timeout_queue',
                 'timeout_check', 'timeout_tunnel',
                 'http_reuse', 'fullconn',
                 'fcgi_app_id', 'options', 'http2_enabled', 'http2_npn',
                 'max_connections', 'max_queue', 'max_queue_time',
                 'connect_timeout', 'tfo_enabled', 'dynamic_cookie_key',
                 'cookie_domain', 'cookie_path', 'cookie_type',
                 'health_check_rise', 'health_check_fall',
                 'health_check_port', 'health_check_ssl',
                 'health_check_check_ssl', 'health_check_send_proxy',
                 'health_check_enabled_tls'},
    },
    'listener': {
        'skip': {'options', 'haproxy_options'},
    },
    'server': {
        'skip': {'options', 'ca_certificate_id', 'client_certificate_id'},
    },
    'mcp_server': {
        'skip': {'has_secret', 'has_env_vars', 'env_var_names',
                 'health_status', 'last_seen_at', 'last_error', 'last_catalog_at',
                 'installed_version', 'oauth_auth_status'},
        'rename': {
            'auth_secret_enc': 'auth_secret',
            'oauth_client_secret_enc': 'oauth_client_secret',
            'args_json': 'args',
            'env_vars_json': 'env_vars',
        },
    },
    'mcp_team_member': {
        'skip': {'name'},
    },
    'page_protect_script': {
        # Skip runtime/computed fields — provider only has url, resource_type, notes, fetch_method, ignored
        'skip': {'first_seen', 'last_seen', 'occurrence_count', 'domain',
                 'first_hash', 'first_hash_at', 'last_hash', 'last_hash_at',
                 'hash_checked_at', 'hash_changed', 'content', 'has_content',
                 'source', 'last_fetch_method'},
    },
    'mcp_server_replica': {
        # Provider schema is only: server_id, url, enabled, verify_tls
        'skip': {'name'},
    },
    'mcp_dlp_rule': {
        # priority is computed-only (assigned by server)
        'skip': {'priority'},
    },
    'mcp_guardrail': {
        # priority is computed-only (assigned by server)
        'skip': {'priority'},
    },
    'mcp_skill': {
        # enable_when_ast is computed-only (server-generated JSON AST)
        'skip': {'enable_when_ast'},
    },
}


def _resolve_provider_overrides(resource_type: str, model_cls=None) -> Dict[str, Any]:
    """Merge manual PROVIDER_FIELD_OVERRIDES with schema-derived overrides.

    Returns a dict with keys: skip, rename, raw_int, raw_int_skip.

    Schema-derived additions (on top of manual overrides):
      - Computed-only attributes from the provider schema are added to 'skip'
        so the exporter never writes them.
      - DB fields not present in the provider schema (after applying renames)
        are added to 'skip' so the exporter never emits unsupported attributes.

    This is the single entry point for provider-aware field handling.
    Both the module builder and the tfvars builder should call this instead
    of reading PROVIDER_FIELD_OVERRIDES directly.
    """
    overrides = PROVIDER_FIELD_OVERRIDES.get(resource_type, {})
    skip = set(overrides.get('skip', set()))
    rename = dict(overrides.get('rename', {}))
    raw_int = set(overrides.get('raw_int', set()))
    raw_int_skip = set(overrides.get('raw_int_skip', set()))

    # Schema-derived: skip computed-only attributes
    schema_computed = get_computed_fields(resource_type)
    skip |= schema_computed

    # Schema-derived: skip DB fields that have no corresponding provider attribute.
    # A DB field 'foo' maps to provider attribute rename.get('foo', 'foo').
    # If that provider attribute doesn't exist in the schema, skip it.
    if model_cls is not None:
        schema_attrs = get_provider_field_names(resource_type)
        if schema_attrs:  # only if we have a schema for this resource
            from sqlalchemy import inspect as sa_inspect
            mapper = sa_inspect(model_cls)
            for col in mapper.columns:
                col_key = col.key
                if col_key in skip or col_key in raw_int or col_key in raw_int_skip:
                    continue
                provider_attr = rename.get(col_key, col_key)
                if provider_attr not in schema_attrs:
                    skip.add(col_key)

    return {
        'skip': skip,
        'rename': rename,
        'raw_int': raw_int,
        'raw_int_skip': raw_int_skip,
    }


# Fields that are runtime/computed and should never be exported.
SKIP_FIELDS: Set[str] = {
    "id", "created_at", "updated_at",
    "expression_ast",          # computed from expression
    "health_status", "last_seen_at", "last_error", "last_catalog_at",
    "last_updated_at", "last_entry_count",
    "rule_set_last_updated_at", "rule_set_last_error",
    "not_before", "not_after", "subject_cn", "sans",
    "pat_prefix", "last_used_at",
    "published_version_id",
    "oauth_auth_status", "oauth_token_enc", "oauth_refresh_token_enc", "oauth_token_expires_at",
    "last_login_at", "password_changed_at",
    "last_hash", "last_hash_at", "hash_checked_at", "hash_changed",
    "occurrence_count", "first_seen", "last_seen", "has_content",
    "installer_user_id", "installed_version",
    "spec_json",               # computed from spec text
    "files",                   # base64-encoded file content in MCP skill versions
    "sample_count", "learned", "status_codes", "first_seen", "last_seen",  # api_profiles (excluded)
    "cert_path", "key_path", "chain_path",  # system paths — export PEM files instead
}

# Sensitive fields per table — when include_secrets=False, these become var.xxx.
# NOTE: users no longer have sensitive fields here. The provider's user resource
# has a write-only `password` field, but existing password hashes cannot be
# round-tripped. Users are import-only for identity fields; set passwords
# out-of-band after import.
# NOTE: mcp_identities no longer have pat_hash here. The provider has
# pat_prefix (computed) but not pat_hash. PATs cannot be round-tripped.
SENSITIVE_FIELDS: Dict[str, Set[str]] = {
    "certificates": {"dns_credentials"},
    "mcp_servers": {"auth_secret_enc", "oauth_client_secret_enc", "env_vars_json"},
}

# Map (table_name, field_name) → secret category for granular inline control.
# When include_secrets=False, the category flag determines whether
# sensitive fields are inlined or become var placeholders.
SECRET_CATEGORIES: Dict[str, str] = {
    "users": "users_identities",
    "mcp_identities": "users_identities",
    "mcp_servers": "system_secrets",
}

# Setting keys that are sensitive.
SENSITIVE_SETTING_KEYS: Set[str] = {
    "maxmind_license_key", "recaptcha_secret",
    "cap_secret", "turnstile_secret", "keepalived_auth_password",
}

# Setting keys that are runtime/internal and should be skipped.
SKIP_SETTING_KEYS: Set[str] = {
    "haproxy_global_options",  # exported as corex_global_options separately
    "last_applied_at",        # runtime state set by config apply
    "geoip_download_last_run_at",  # runtime state set by geoip download
    "rule_set_download_poll_last_run_at",  # runtime state
    "auto_renew_last_run_at",  # runtime state
    "security_list_feeds_poll_last_run_at",  # runtime state
    # Auto-generated secrets/tokens (regenerated on first boot, not user config)
    "captcha_cookie_secret", "pp_hasher_bypass_token",
    "page_protect_monitoring_enabled", "page_protect_change_detection_enabled",
    "page_protect_change_detection_interval_hours", "page_protect_report_retention_days",
    "page_protect_report_path", "page_protect_baseline_start", "page_protect_baseline_end",
    "page_protect_baseline_note", "page_protect_beacon_injection_enabled",
    "page_protect_beacon_trust_enabled", "page_protect_beacon_path",
    "page_protect_beacon_script_path", "page_protect_beacon_content_types",
    "page_protect_beacon_path_patterns", "page_protect_beacon_backend_ids",
    "page_protect_auto_prune_stale_days",
    # Runtime state: auto-disabled rule IDs (set when ja4/req_fp toggled off)
    "ja4_auto_disabled_rule_ids", "ja4_risk_auto_disabled_rule_ids",
    "risk_auto_disabled_rule_ids",
    # Runtime config: internal sampler intervals (not user-facing)
    "api_armor_profiler_interval", "api_armor_schema_learn_interval",
    # Runtime state: CRS version auto-set by downloader (crs_pinned_version is user-configurable)
    "crs_active_version",
    # API Armor settings (exported as corex_api_armor_settings singleton)
    "api_armor_enabled", "api_armor_max_body_bytes", "api_armor_module_enabled",
    "api_armor_schema_learning_enabled", "api_armor_profiling_learning_enabled",
    "api_armor_profile_retention_days", "api_armor_scope", "api_armor_backend_ids",
    "api_armor_path_patterns",
    # Captcha settings (exported as corex_captcha_settings singleton)
    "captcha_provider", "captcha_valid_seconds", "cap_site_key", "cap_secret",
    "recaptcha_site_key", "recaptcha_secret", "recaptcha_version", "recaptcha_min_score",
    "turnstile_site_key", "turnstile_secret",
    # MaxMind license key (exported as corex_maxmind_license_key singleton)
    "maxmind_license_key",
    # HA config (exported as corex_ha_config singleton)
    "ha_enabled", "ha_topology", "haproxy_ha_replicas", "valkey_ha_replicas",
    "coraza_ha_replicas", "haproxy_instances", "haproxy_peer_port",
    "keepalived_vip", "keepalived_virtual_router_id", "keepalived_priority",
    "keepalived_interface", "keepalived_auth_password", "keepalived_peer_addresses",
    "keepalived_advert_int", "keepalived_preempt", "keepalived_track_script",
    "valkey_sentinel_enabled", "valkey_sentinel_hosts", "valkey_sentinel_service",
    # SSL Labs settings (exported as corex_ssl_labs_settings singleton per cert)
    "ssllabs_max_scans_per_host",
    # MCP alert config (exported as corex_mcp_alert_config singleton)
    "mcp_alert_thresholds",
}

# Tables excluded entirely (runtime/metrics).
EXCLUDED_TABLES: Set[str] = {
    "audit_events", "metric_snapshots", "waf_metrics", "tasks",
    "config_snapshots", "challenge_events", "csp_reports", "api_anomalies",
    "mcp_events", "mcp_installations", "ssllabs_scans", "waf_rule_versions",
    "cache_metric_snapshots", "user_preferences", "api_profiles",
}

# Singleton setting keys that the provider expects as bool/int/list (not string).
# Settings are stored as strings in the DB; we coerce them to the right Python
# type so the HCL emitter produces native bool/int/list, not quoted strings.
SINGLETON_BOOL_KEYS: Set[str] = {
    'ha_enabled', 'valkey_sentinel_enabled', 'keepalived_preempt',
    'api_armor_enabled', 'api_armor_module_enabled',
    'api_armor_schema_learning_enabled', 'api_armor_profiling_learning_enabled',
}
SINGLETON_INT_KEYS: Set[str] = {
    'captcha_valid_seconds',
    'haproxy_ha_replicas', 'valkey_ha_replicas', 'coraza_ha_replicas',
    'haproxy_peer_port',
    'keepalived_virtual_router_id', 'keepalived_priority', 'keepalived_advert_int',
    'api_armor_max_body_bytes', 'api_armor_profile_retention_days',
}
SINGLETON_LIST_KEYS: Set[str] = {
    'keepalived_peer_addresses', 'valkey_sentinel_hosts',
    'api_armor_backend_ids', 'api_armor_path_patterns',
}


def _coerce_setting_value(key: str, value):
    """Coerce a string setting value to the Python type the provider expects.

    Settings are stored as strings in the DB. The HCL emitter quotes strings
    but passes bool/int/list natively. Without coercion, "true" becomes a
    string, not a bool, and the provider rejects it.
    """
    if value is None:
        return None
    if key in SINGLETON_BOOL_KEYS:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes')
        return bool(value)
    if key in SINGLETON_INT_KEYS:
        if isinstance(value, int):
            return value
        try:
            return int(value)
        except (ValueError, TypeError):
            return value
    if key in SINGLETON_LIST_KEYS:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else [value]
            except (json.JSONDecodeError, ValueError):
                # Comma-separated fallback
                return [v.strip() for v in value.split(',') if v.strip()] if value else []
        return value
    return value


def _try_json_parse(value):
    """Try to parse a JSON string into a dict/list; return original on failure.

    Used for fields like dns_credentials that are stored as JSON strings
    but the provider expects a map/list.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    if not value:
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, ValueError):
        return value


# ─── HCL Formatting Helpers ─────────────────────────────────────────────────

def _sanitize_name(name: str) -> str:
    """Convert a resource name to a valid Terraform resource name suffix."""
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name or 'unnamed')
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized
    return sanitized.lower() or 'unnamed'


def _hcl_string(val: str, allow_heredoc: bool = True) -> str:
    """Format a string as an HCL quoted string or heredoc for multi-line content."""
    if val is None:
        return 'null'
    if not isinstance(val, str):
        val = str(val)
    # Use heredoc for multi-line or very long strings — more robust for HTML/JSON/code
    if allow_heredoc and ('\n' in val or len(val) > 500):
        return _hcl_heredoc(val)
    # Single-line: escape control characters and special chars
    escaped = (val
               .replace('\\', '\\\\')
               .replace('"', '\\"')
               .replace('\n', '\\n')
               .replace('\t', '\\t')
               .replace('\r', '\\r'))
    # Strip remaining control characters that would break HCL
    escaped = ''.join(c if c >= ' ' or c in '\t' else '' for c in escaped)
    return f'"{escaped}"'


def _hcl_heredoc(val: str) -> str:
    """Format a multi-line string as an HCL heredoc (<<-EOT ... EOT)."""
    # Choose a delimiter that doesn't appear in the content
    delimiter = "EOT"
    while delimiter in val:
        delimiter += "X"
    # Strip null bytes and other control chars that break HCL (except \n, \t, \r)
    cleaned = ''.join(c if c >= ' ' or c in '\n\t\r' else '' for c in val)
    # Escape ${} interpolation sequences that HCL heredocs process
    cleaned = cleaned.replace('${', '$${')
    return f'<<-{delimiter}\n{cleaned}\n{delimiter}'


def _hcl_bool(val: bool) -> str:
    return 'true' if val else 'false'


def _hcl_int(val: int) -> str:
    return str(val)


def _hcl_float(val: float) -> str:
    return str(val)


def _hcl_list(val: list) -> str:
    if not val:
        return '[]'
    items = ', '.join(_hcl_value(v, allow_heredoc=False) for v in val)
    return f'[{items}]'


def _hcl_map(val: dict) -> str:
    if not val:
        return '{}'
    items = ', '.join(f'{_hcl_string(k, allow_heredoc=False)} = {_hcl_value(v, allow_heredoc=False)}' for k, v in val.items())
    return f'{{{items}}}'


def _hcl_value(val: Any, allow_heredoc: bool = True) -> str:
    """Format any Python value as an HCL literal."""
    if val is None:
        return 'null'
    if isinstance(val, bool):
        return _hcl_bool(val)
    if isinstance(val, int):
        return _hcl_int(val)
    if isinstance(val, float):
        return _hcl_float(val)
    if isinstance(val, str):
        return _hcl_string(val, allow_heredoc=allow_heredoc)
    if isinstance(val, list):
        return _hcl_list(val)
    if isinstance(val, dict):
        return _hcl_map(val)
    return _hcl_string(str(val), allow_heredoc=allow_heredoc)


def _format_resource_block(resource_type: str, name: str, attributes: List[Tuple[str, str]], indent: str = '  ') -> str:
    """Generate a Terraform resource block.

    attributes is a list of (key, hcl_value_string) tuples in insertion order.
    """
    lines = [f'{indent}resource "corex_{resource_type}" "{name}" {{']
    for key, value_str in attributes:
        lines.append(f'{indent}  {key} = {value_str}')
    lines.append(f'{indent}}}')
    return '\n'.join(lines)


def _row_to_dict(row) -> Dict[str, Any]:
    """Convert a SQLAlchemy model instance to a dict, excluding SKIP_FIELDS."""
    if row is None:
        return {}
    mapper = sa_inspect(type(row))
    result = {}
    for attr in mapper.column_attrs:
        if attr.key in SKIP_FIELDS:
            continue
        val = getattr(row, attr.key)
        result[attr.key] = val
    return result


def _build_attributes(
    row_dict: Dict[str, Any],
    table_name: str,
    should_inline: 'Callable[[str, str], bool]',
    secret_vars: Dict[str, str],
    resource_name: str = None,
) -> List[Tuple[str, str]]:
    """Build a list of (key, hcl_value) tuples from a row dict.

    Handles sensitive fields by either inlining them or creating variable references.
    should_inline(table_name, field_name) returns True if the field should be inlined.
    When resource_name is provided, variable names are unique per resource
    so each resource gets its own placeholder.
    """
    sensitive = SENSITIVE_FIELDS.get(table_name, set())
    attrs = []
    for key, val in row_dict.items():
        if val is None:
            continue
        if key in sensitive and not should_inline(table_name, key):
            if resource_name:
                var_name = f"{table_name}_{resource_name}_{key}"
            else:
                var_name = f"{table_name}_{key}"
            if var_name not in secret_vars:
                secret_vars[var_name] = f"Secret value for {table_name}.{key}"
            attrs.append((key, f'var.{var_name}'))
        else:
            attrs.append((key, _hcl_value(val)))
    return attrs


# ─── Module Container ───────────────────────────────────────────────────────

class Module:
    """Represents a Terraform module directory."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.blocks: List[str] = []
        self.locals_blocks: List[str] = []
        self.variables: List[str] = []
        self.outputs: List[str] = []

    def add_section(self, comment: str):
        self.blocks.append(f'\n# {"=" * 60}\n# {comment}\n# {"=" * 60}\n')

    def add_resource(self, resource_type: str, name: str, attributes: List[Tuple[str, str]]):
        self.blocks.append(_format_resource_block(resource_type, name, attributes))

    def add_variable(self, name: str, var_type: str, description: str, default: str = 'null', sensitive: bool = False):
        sens = '\n  sensitive = true' if sensitive else ''
        self.variables.append(
            f'variable "{name}" {{\n'
            f'  type        = {var_type}\n'
            f'  description = {_hcl_string(description)}\n'
            f'  default     = {default}{sens}\n'
            f'}}'
        )

    def add_output(self, name: str, value: str, description: str = ''):
        desc = f'  description = {_hcl_string(description)}\n' if description else ''
        self.outputs.append(
            f'output "{name}" {{\n'
            f'{desc}'
            f'  value = {value}\n'
            f'}}'
        )

    @property
    def has_content(self) -> bool:
        return bool(self.blocks) or bool(self.locals_blocks)

    def main_tf(self) -> str:
        header = f'# {self.description}\n# Auto-generated by coreX Manager Terraform Export\n'
        return header + '\n'.join(self.blocks) + '\n'

    def locals_tf(self) -> str:
        if not self.locals_blocks:
            return f'# Locals for {self.name} module\n# (none)\n'
        header = f'# Locals for {self.name} module\n# Auto-generated by coreX Manager Terraform Export\n'
        return header + '\n'.join(self.locals_blocks) + '\n'

    def variables_tf(self) -> str:
        if not self.variables:
            return f'# Variables for {self.name} module\n# (none — this module has no cross-module inputs)\n'
        return f'# Variables for {self.name} module\n\n' + '\n\n'.join(self.variables) + '\n'

    def outputs_tf(self) -> str:
        if not self.outputs:
            return f'# Outputs for {self.name} module\n# (none)\n'
        return f'# Outputs for {self.name} module\n\n' + '\n\n'.join(self.outputs) + '\n'

    def readme(self) -> str:
        return f'# Module: {self.name}\n\n{self.description}\n\n## Resources\n\nSee `main.tf` for all managed resources.\n'

    @property
    def has_real_readme(self) -> bool:
        """Whether the README has useful content beyond the stub.

        The default README just says 'See main.tf' — skip emitting it.
        Subclasses or callers can set a richer README to enable emission.
        """
        return False

    def add_collection_variable(self, var_name: str, description: str, var_type: str = 'any'):
        """Add a collection variable for reusable modules.

        Args:
            var_name: variable name
            description: human-readable description
            var_type: HCL type (default 'any'; use map(object({...})) for typed vars)
        """
        self.variables.append(
            f'variable "{var_name}" {{\n'
            f'  type        = {var_type}\n'
            f'  description = {_hcl_string(description)}\n'
            f'  default     = {{}}\n'
            f'}}'
        )

    def add_secret_map_variable(self, var_name: str, description: str, var_type: str = None):
        """Add a secret map variable (map(string), sensitive)."""
        actual_type = var_type or 'map(string)'
        self.variables.append(
            f'variable "{var_name}" {{\n'
            f'  type        = {actual_type}\n'
            f'  description = {_hcl_string(description)}\n'
            f'  default     = {{}}\n'
            f'  sensitive   = true\n'
            f'}}'
        )

    def add_map_output(self, output_name: str, resource_type: str, description: str):
        """Add a map output that exports resource IDs keyed by name."""
        self.outputs.append(
            f'output "{output_name}" {{\n'
            f'  description = {_hcl_string(description)}\n'
            f'  value       = {{ for k, v in corex_{resource_type}.this : k => v.id }}\n'
            f'}}'
        )

    def add_local_output(self, output_name: str, local_name: str, description: str):
        """Add an output that exports a local variable (e.g. merged ID maps)."""
        self.outputs.append(
            f'output "{output_name}" {{\n'
            f'  description = {_hcl_string(description)}\n'
            f'  value       = local.{local_name}\n'
            f'}}'
        )

    def add_for_each_resource(
        self,
        resource_type: str,
        var_name: str,
        fields: List[str],
        same_module_fks: Dict[str, Tuple[str, bool]] = None,
        cross_module_fks: Dict[str, str] = None,
        optional_cross_module_fks: Dict[str, str] = None,
        fk_lists: Dict[str, str] = None,
        secret_maps: Dict[str, str] = None,
        polymorphic_fks: Dict[str, List[Tuple[str, str]]] = None,
        name_field: str = 'name',
        provider_rename: Dict[str, str] = None,
        provider_raw_int: Set[str] = None,
        provider_skip: Set[str] = None,
    ):
        """Generate a for_each resource block for reusable modules.
        
        Args:
            resource_type: e.g., 'backend', 'listener'
            var_name: variable name to iterate over, e.g., 'backends'
            fields: list of field names to copy from each.value
            same_module_fks: {field: (resource_type, nullable)} for same-module FK resolution
            cross_module_fks: {field: var_name} for required cross-module FK resolution (fail loud)
            optional_cross_module_fks: {field: var_name} for nullable cross-module FK resolution (try null)
            fk_lists: {field: var_name} for list FK resolution
            secret_maps: {field: var_name} for secret map resolution
            polymorphic_fks: {field: [(type, resource_type), ...]} for polymorphic FK resolution
        """
        same_module_fks = same_module_fks or {}
        cross_module_fks = cross_module_fks or {}
        optional_cross_module_fks = optional_cross_module_fks or {}
        fk_lists = fk_lists or {}
        secret_maps = secret_maps or {}
        polymorphic_fks = polymorphic_fks or {}
        provider_rename = provider_rename or {}
        provider_raw_int = provider_raw_int or set()
        provider_skip = provider_skip or set()

        lines = [f'resource "corex_{resource_type}" "this" {{']
        lines.append(f'  for_each = var.{var_name}')
        lines.append('')
        # Use the original name from tfvars if present (preserves hyphens,
        # dots, spaces that are sanitized out of the Terraform map key).
        # name_field defaults to 'name' but can be 'username' (User resource).
        # Skip the name_field line if the provider doesn't have a name attribute.
        if name_field not in provider_skip:
            lines.append(f'  {name_field} = try(each.value.{name_field}, each.key)')
        
        for field in fields:
            if field == name_field:
                continue  # already set
            
            # Determine the provider-facing attribute name (after rename).
            # The tfvars and variable type use the renamed key, so the
            # right-hand side must reference each.value.{attr_name} too.
            attr_name = provider_rename.get(field, field)
            
            # Raw int fields: just pass the value through (no FK resolution)
            if field in provider_raw_int:
                lines.append(f'  {attr_name} = try(each.value.{attr_name}, null)')
                continue
            
            # Secret map resolution
            if field in secret_maps:
                secret_var = secret_maps[field]
                lines.append(f'  {attr_name} = try(var.{secret_var}[each.key], null)')
            
            # Same-module FK resolution
            elif field in same_module_fks:
                ref_type, nullable = same_module_fks[field]
                if nullable:
                    lines.append(f'  {attr_name} = try(corex_{ref_type}.this[each.value.{attr_name}].id, null)')
                else:
                    # Non-nullable FK: fail loud if the key doesn't match.
                    # A silent null would create a resource with a dangling FK.
                    lines.append(f'  {attr_name} = corex_{ref_type}.this[each.value.{attr_name}].id')
            
            # Cross-module FK resolution — fail loud on required refs.
            # A typo'd key should error, not silently produce null.
            elif field in cross_module_fks:
                var = cross_module_fks[field]
                lines.append(f'  {attr_name} = var.{var}[each.value.{attr_name}]')

            # Optional cross-module FK resolution — nullable, use try().
            elif field in optional_cross_module_fks:
                var = optional_cross_module_fks[field]
                lines.append(f'  {attr_name} = try(var.{var}[each.value.{attr_name}], null)')
            
            # FK list resolution
            elif field in fk_lists:
                var = fk_lists[field]
                lines.append(f'  {attr_name} = try([for k in each.value.{attr_name} : var.{var}[k]], [])')
            
            # Polymorphic FK resolution using coalesce() with per-type try()
            # Each type is wrapped in its own try() so that missing resources
            # of a given type don't cause parse errors. coalesce() picks the
            # first non-null match.
            # The FK value in tfvars is a string (the resource name), not an
            # object with .key.
            # Uses local.{type_key}_list_ids which merges .this and .feed_managed
            # maps so feed-managed lists are found correctly.
            # All 5 list types are always in the coalesce — the resource blocks
            # and locals always exist for every type.
            elif field in polymorphic_fks:
                type_attempts = polymorphic_fks[field]
                if not type_attempts:
                    lines.append(f'  {attr_name} = null')
                else:
                    coalesce_args = ', '.join(
                        f'try(local.{type_key}_list_ids[each.value.{attr_name}], null)'
                        for type_key, _ in type_attempts
                    )
                    lines.append(f'  {attr_name} = coalesce({coalesce_args})')
            
            # Simple field copy — wrap in try() because the field may be
            # absent from the tfvars object when it was None in the database.
            else:
                lines.append(f'  {attr_name} = try(each.value.{attr_name}, null)')
        
        lines.append('}')
        self.blocks.append('\n'.join(lines))

    def add_singleton_resource(self, resource_type: str, var_name: str, fields: List[str]):
        """Generate a singleton resource block (no for_each)."""
        lines = [f'resource "corex_{resource_type}" "this" {{']
        for field in fields:
            lines.append(f'  {field} = var.{var_name}.{field}')
        lines.append('}')
        self.blocks.append('\n'.join(lines))


# ─── Exporter ───────────────────────────────────────────────────────────────

class TerraformExporter:
    def __init__(self, db: Session, include_secrets: bool = False,
                 include_certs: bool = False, include_users_identities: bool = False,
                 include_system_secrets: bool = False):
        self.db = db
        self.include_secrets = include_secrets
        self.include_certs = include_certs
        self.include_users_identities = include_users_identities
        self.include_system_secrets = include_system_secrets
        self.secret_vars: Dict[str, str] = {}
        # Track whether each secret var is a map (per-resource) or string (singleton)
        self.secret_var_types: Dict[str, str] = {}
        # Map secret var name → HCL type override (e.g. map(map(string)) for dns_credentials)
        self.secret_var_hcl_types: Dict[str, str] = {}
        # Map secret var name → name_maps key, so tfvars can pre-populate per-resource keys
        self.secret_var_name_maps: Dict[str, str] = {}
        # ID → sanitized name maps per resource type (for cross-module refs)
        self.name_maps: Dict[str, Dict[int, str]] = {}
        # Extra files to include in the ZIP (e.g. error page HTML files)
        self.extra_files: Dict[str, str] = {}
        # Typed variable schemas: var_name → HCL type string (e.g. map(object({...})))
        self.collection_types: Dict[str, str] = {}

    def _should_inline_secret(self, table_name: str, field_name: str = None) -> bool:
        """Decide whether sensitive fields for a table should be inlined or var placeholders.

        When include_secrets=True, all secrets are inlined (master override).
        Otherwise, the category-specific flag controls the behavior.
        """
        if self.include_secrets:
            return True
        # dns_credentials on certificates is a system secret, not a cert secret
        if table_name == "certificates" and field_name == "dns_credentials":
            return self.include_system_secrets
        category = SECRET_CATEGORIES.get(table_name)
        if category == "certs":
            return self.include_certs
        if category == "users_identities":
            return self.include_users_identities
        if category == "system_secrets":
            return self.include_system_secrets
        return False

    def _resolve_id_ref(self, attrs: List[Tuple[str, str]], field_name: str,
                        id_val, var_name: str, name_map: Dict[int, str]) -> List[Tuple[str, str]]:
        """Resolve a singular ID field to var.<var_name>["<name>"]."""
        if id_val is None:
            return attrs
        name = name_map.get(id_val)
        if name:
            return [(k, f'var.{var_name}[{_hcl_string(name)}]' if k == field_name else v) for k, v in attrs]
        return attrs

    def _resolve_id_list_ref(self, attrs: List[Tuple[str, str]], field_name: str,
                             id_list, var_name: str, name_map: Dict[int, str]) -> List[Tuple[str, str]]:
        """Resolve a JSON-array ID list field to [var.<var_name>["name1"], ...]."""
        if not id_list:
            return attrs
        resolved = []
        for id_val in id_list:
            name = name_map.get(id_val)
            if name:
                resolved.append(f'var.{var_name}[{_hcl_string(name)}]')
        if resolved:
            return [(k, f'[{", ".join(resolved)}]' if k == field_name else v) for k, v in attrs]
        return attrs

    def _register_names(self, resource_key: str, rows, name_col: str = 'name'):
        """Build a map of id → sanitized_name for a set of rows."""
        mapping = {}
        for row in rows:
            name = getattr(row, name_col, None) or f'id_{row.id}'
            mapping[row.id] = _sanitize_name(str(name))
        self.name_maps[resource_key] = mapping

    def _add_secret_map_var(self, mod: 'Module', var_name: str, description: str,
                            name_map_key: str = None, var_type: str = None):
        """Register a secret map variable on both the module and the exporter.

        This ensures the variable is declared in the module's variables.tf,
        declared in the root variables.tf, and wired in the root main.tf.

        If name_map_key is provided, the exporter tracks which name map
        corresponds to this secret var so the tfvars generator can pre-populate
        per-resource placeholder keys.

        var_type overrides the default map(string) type (e.g. map(map(string))
        for dns_credentials).
        """
        mod.add_secret_map_variable(var_name, description, var_type=var_type)
        if var_name not in self.secret_vars:
            self.secret_vars[var_name] = description
            self.secret_var_types[var_name] = 'map'
            if var_type:
                self.secret_var_hcl_types[var_name] = var_type
        if name_map_key:
            self.secret_var_name_maps[var_name] = name_map_key

    def _add_secret_string_var(self, mod: 'Module', var_name: str, description: str):
        """Register a singleton secret string variable on both the module and the exporter.

        Unlike _add_secret_map_var, this is for singleton secrets (not per-resource maps).
        The variable is declared as type = string (not map(string)).
        """
        mod.add_variable(var_name, 'string', description, '""', sensitive=True)
        if var_name not in self.secret_vars:
            self.secret_vars[var_name] = description
            self.secret_var_types[var_name] = 'string'

    def _query_all(self, model_cls) -> list:
        return self.db.query(model_cls).order_by(model_cls.id).all()

    @staticmethod
    def _get_model_fields(model_cls) -> list:
        """Get all exportable column names from a model class (excluding SKIP_FIELDS)."""
        mapper = sa_inspect(model_cls)
        return [attr.key for attr in mapper.column_attrs if attr.key not in SKIP_FIELDS]

    @staticmethod
    def _sqlalchemy_type_to_hcl(column) -> str:
        """Map a SQLAlchemy column type to an HCL type string."""
        from sqlalchemy import Integer, BigInteger, Boolean, String, Text, DateTime, JSON
        col_type = column.type
        if isinstance(col_type, (Integer, BigInteger)):
            return 'number'
        if isinstance(col_type, Boolean):
            return 'bool'
        if isinstance(col_type, (String, Text)):
            return 'string'
        if isinstance(col_type, DateTime):
            return 'string'  # ISO 8601 format
        if isinstance(col_type, JSON):
            return 'any'
        return 'any'

    def _build_object_type(
        self,
        model_cls,
        same_module_fks: Dict[str, Tuple[str, bool]] = None,
        cross_module_fks: Dict[str, str] = None,
        optional_cross_module_fks: Dict[str, str] = None,
        fk_list_fields: Dict[str, str] = None,
        polymorphic_fks: Dict[str, list] = None,
        skip_fields: set = None,
        extra_fields: Dict[str, str] = None,
        resource_type: str = None,
        type_overrides: Dict[str, str] = None,
    ) -> str:
        """Build a map(object({...})) HCL type string from a SQLAlchemy model.

        All fields are optional() so missing fields become null, not plan errors.
        FK fields are typed as string (they hold logical keys, not integer IDs).
        When resource_type is provided, PROVIDER_FIELD_OVERRIDES is consulted
        to skip/rename fields to match the provider schema.
        type_overrides: {field_name: hcl_type} to override inferred types
        (e.g. dns_credentials should be map(string), not string).
        """
        same_module_fks = same_module_fks or {}
        cross_module_fks = cross_module_fks or {}
        optional_cross_module_fks = optional_cross_module_fks or {}
        fk_list_fields = fk_list_fields or {}
        polymorphic_fks = polymorphic_fks or {}
        skip_fields = skip_fields or set()
        extra_fields = extra_fields or {}

        # Apply provider field overrides (manual + schema-derived)
        provider_skip = set()
        provider_rename = {}
        provider_raw_int_skip = set()
        if resource_type:
            overrides = _resolve_provider_overrides(resource_type, model_cls)
            provider_skip = overrides['skip']
            provider_rename = overrides['rename']
            provider_raw_int_skip = overrides['raw_int_skip']
        skip_fields = skip_fields | provider_skip | provider_raw_int_skip

        mapper = sa_inspect(model_cls)
        all_fk_fields = set(same_module_fks.keys()) | set(cross_module_fks.keys()) | set(optional_cross_module_fks.keys()) | set(polymorphic_fks.keys())
        all_fk_list_fields = set(fk_list_fields.keys())
        type_overrides = type_overrides or {}

        fields = []
        for attr in mapper.column_attrs:
            if attr.key in SKIP_FIELDS or attr.key in skip_fields:
                continue
            name = provider_rename.get(attr.key, attr.key)
            # Check for explicit type override first
            if attr.key in type_overrides:
                fields.append(f'    {name} = optional({type_overrides[attr.key]})')
            elif attr.key in all_fk_fields:
                # FK fields hold logical keys (strings), not integer IDs
                fields.append(f'    {name} = optional(string)')
            elif name in all_fk_list_fields:
                fields.append(f'    {name} = optional(list(string))')
            else:
                column = attr.columns[0]
                hcl_type = self._sqlalchemy_type_to_hcl(column)
                fields.append(f'    {name} = optional({hcl_type})')

        # Add extra fields (e.g. nested rules, entries)
        for name, hcl_type in sorted(extra_fields.items()):
            # Properly indent multi-line HCL types (e.g. nested objects).
            # The field is at 4 spaces; nested content at 6; closing braces
            # back at 4. Strip existing whitespace and re-indent.
            if '\n' in hcl_type:
                lines = [line.strip() for line in hcl_type.split('\n')]
                indented = lines[0]
                for line in lines[1:]:
                    if line.startswith('}'):
                        indented += '\n    ' + line
                    else:
                        indented += '\n      ' + line
                fields.append(f'    {name} = optional({indented})')
            else:
                fields.append(f'    {name} = optional({hcl_type})')

        return 'map(object({\n' + '\n'.join(fields) + '\n  }))'

    def _add_for_each_collection(
        self,
        mod: Module,
        resource_type: str,
        var_name: str,
        model_cls,
        description: str,
        name_attr: str = 'name',
        name_fn=None,
        cross_module_fks: Dict[str, str] = None,
        optional_cross_module_fks: Dict[str, str] = None,
        same_module_fks: Dict[str, Tuple[str, bool]] = None,
        fk_list_fields: Dict[str, str] = None,
        secret_fields: Dict[str, str] = None,
        polymorphic_fks: Dict[str, list] = None,
        skip_fields: set = None,
        add_output: bool = True,
        filter_fn=None,
        type_overrides: Dict[str, str] = None,
    ):
        """Generic helper: build a complete for_each collection with ALL model fields.
        
        Args:
            resource_type: e.g. 'backend', 'listener'
            var_name: collection variable name, e.g. 'backends'
            model_cls: SQLAlchemy model class
            description: human-readable description
            name_attr: attribute to use as the map key (default 'name')
            name_fn: optional fn(row) -> str to compute the map key
            cross_module_fks: {col_name: var_name} for required FKs resolved via var.xxx_ids (fail loud)
            optional_cross_module_fks: {col_name: var_name} for nullable FKs (try null)
            same_module_fks: {col_name: (resource_type, nullable)} for same-module FKs
            fk_list_fields: {col_name: var_name} for list-of-FKs
            secret_fields: {col_name: secret_var_name} for secret map resolution
            polymorphic_fks: {col_name: [(type_key, resource_type), ...]}
            skip_fields: additional fields to skip beyond SKIP_FIELDS
            add_output: whether to add a map output for IDs
            filter_fn: optional fn(row) -> bool to filter rows
        """
        cross_module_fks = cross_module_fks or {}
        optional_cross_module_fks = optional_cross_module_fks or {}
        same_module_fks = same_module_fks or {}
        fk_list_fields = fk_list_fields or {}
        secret_fields = secret_fields or {}
        polymorphic_fks = polymorphic_fks or {}
        skip_fields = skip_fields or set()

        rows = self._query_all(model_cls)
        if filter_fn:
            rows = [r for r in rows if filter_fn(r)]

        # Always declare the collection variable, even when empty,
        # so the root module can pass it without "argument not declared" errors.
        # Build a typed map(object({...})) so typos in tfvars fail at validate
        # and missing optional fields become null instead of plan errors.
        obj_type = self._build_object_type(
            model_cls,
            same_module_fks=same_module_fks,
            cross_module_fks=cross_module_fks,
            optional_cross_module_fks=optional_cross_module_fks,
            fk_list_fields=fk_list_fields,
            polymorphic_fks=polymorphic_fks,
            skip_fields=skip_fields | set(secret_fields.keys()),
            resource_type=resource_type,
            type_overrides=type_overrides,
        )
        self.collection_types[var_name] = obj_type
        mod.add_collection_variable(var_name, description, var_type=obj_type)

        # Register names - use name_fn if provided, else name_attr.
        # Always register (even when empty) so name_maps has an entry.
        if name_fn:
            mapping = {}
            for row in rows:
                key = _sanitize_name(str(name_fn(row)))
                mapping[row.id] = key
            self.name_maps[var_name] = mapping
        else:
            self._register_names(var_name, rows, name_attr)

        all_fields = self._get_model_fields(model_cls)
        # Categorize fields - include ALL fields (FKs and non-FKs) so add_for_each_resource
        # can generate the appropriate reference for each
        if name_attr in all_fields and not name_fn:
            all_fields_minus_name = [f for f in all_fields if f != name_attr]
        else:
            all_fields_minus_name = list(all_fields)
        # Remove skip_fields + provider skip
        provider_skip = set()
        provider_rename = {}
        provider_raw_int = set()
        provider_raw_int_skip = set()
        if resource_type:
            overrides = _resolve_provider_overrides(resource_type, model_cls)
            provider_skip = overrides['skip']
            provider_rename = overrides['rename']
            provider_raw_int = overrides['raw_int']
            provider_raw_int_skip = overrides['raw_int_skip']
        ordered_fields = [f for f in all_fields_minus_name if f not in skip_fields and f not in provider_skip and f not in provider_raw_int_skip]

        mod.add_section(description)
        mod.add_for_each_resource(
            resource_type=resource_type,
            var_name=var_name,
            fields=ordered_fields,
            cross_module_fks=cross_module_fks,
            optional_cross_module_fks=optional_cross_module_fks,
            same_module_fks=same_module_fks,
            fk_lists=fk_list_fields,
            secret_maps=secret_fields,
            polymorphic_fks=polymorphic_fks,
            name_field=name_attr if not name_fn else 'name',
            provider_rename=provider_rename,
            provider_raw_int=provider_raw_int,
            provider_skip=provider_skip,
        )
        if add_output:
            mod.add_map_output(f'{resource_type}_ids', resource_type, f'Map of {resource_type} name to ID')

    def _add_tfvars_collection(
        self,
        tfvars: dict,
        var_name: str,
        model_cls,
        name_attr: str = 'name',
        name_fn=None,
        cross_module_fks: Dict[str, str] = None,
        fk_list_fields: Dict[str, str] = None,
        same_module_fk_maps: Dict[str, str] = None,
        skip_fields: set = None,
        secret_fields: set = None,
        filter_fn=None,
        resource_type: str = None,
        value_transforms: Dict[str, Callable] = None,
    ):
        """Generic helper: build tfvars data for a collection with ALL model fields.
        
        FK fields are resolved to logical keys. None values are skipped.
        Secret fields are skipped (they're referenced via var placeholders in the module).
        
        Args:
            var_name: tfvars key, e.g. 'backends'
            model_cls: SQLAlchemy model class
            name_attr: attribute to use as the map key
            name_fn: optional fn(row) -> str to compute the map key
            cross_module_fks: {col_name: name_map_key} for cross-module FK resolution
            fk_list_fields: {col_name: name_map_key} for list-of-FKs
            same_module_fk_maps: {col_name: name_map_key} for same-module FK resolution
            skip_fields: additional fields to skip
            secret_fields: set of field names to skip (secrets referenced via var placeholders)
            filter_fn: optional fn(row) -> bool to filter rows
            resource_type: provider resource type for field override lookup
        """
        cross_module_fks = cross_module_fks or {}
        fk_list_fields = fk_list_fields or {}
        same_module_fk_maps = same_module_fk_maps or {}
        skip_fields = skip_fields or set()
        secret_fields = secret_fields or set()

        # Apply provider field overrides (manual + schema-derived)
        provider_skip = set()
        provider_rename = {}
        if resource_type:
            overrides = _resolve_provider_overrides(resource_type, model_cls)
            provider_skip = overrides['skip'] | overrides['raw_int_skip']
            provider_rename = overrides['rename']
        value_transforms = value_transforms or {}

        rows = self._query_all(model_cls)
        if filter_fn:
            rows = [r for r in rows if filter_fn(r)]
        if not rows:
            return

        data = {}
        for row in rows:
            row_dict = _row_to_dict(row)
            if name_fn:
                key = str(name_fn(row))
            else:
                key = _sanitize_name(str(getattr(row, name_attr)))
            entry = {}
            # Include the name field in tfvars so resource blocks can use the
            # original (unsanitized) name. The Terraform map key is sanitized
            # (e.g. "asn_hosting"), but the API name may differ (e.g. "asn-hosting").
            effective_skip = set(skip_fields) | set(secret_fields) | provider_skip
            for k, v in row_dict.items():
                if v is None:
                    continue
                if k in effective_skip:
                    continue
                # Determine the provider-facing key (after rename)
                tfvars_key = provider_rename.get(k, k)
                if k in cross_module_fks:
                    map_name = cross_module_fks[k]
                    name_map = self.name_maps.get(map_name, {})
                    if v in name_map:
                        entry[tfvars_key] = name_map[v]
                elif k in fk_list_fields:
                    map_name = fk_list_fields[k]
                    name_map = self.name_maps.get(map_name, {})
                    if isinstance(v, list):
                        resolved = [name_map[vid] for vid in v if vid in name_map]
                        if resolved:
                            entry[tfvars_key] = resolved
                elif k in same_module_fk_maps:
                    map_name = same_module_fk_maps[k]
                    name_map = self.name_maps.get(map_name, {})
                    if v in name_map:
                        entry[tfvars_key] = name_map[v]
                else:
                    if k in value_transforms:
                        v = value_transforms[k](v)
                    entry[tfvars_key] = v
            data[key] = entry
        tfvars[var_name] = data

    @staticmethod
    def _read_file(path: str) -> Optional[str]:
        """Read a file from disk, returning None if it doesn't exist or is empty."""
        import os
        if not path or not os.path.isfile(path):
            return None
        try:
            with open(path, 'r') as f:
                return f.read()
        except (OSError, IOError):
            return None

    def _list_cap_keys_sync(self) -> list:
        """List Cap captcha keys synchronously from the Cap service."""
        import os
        try:
            import httpx
        except ImportError:
            return []
        admin_key = os.environ.get("CAP_ADMIN_KEY", "")
        if not admin_key:
            return []
        base_url = get_settings().CAPTCHA_SERVICE_URL.rstrip("/")
        if not base_url:
            return []
        try:
            with httpx.Client(timeout=10) as client:
                # Login
                res = client.post(f"{base_url}/auth/login", json={"admin_key": admin_key})
                if res.status_code != 200:
                    return []
                token = res.json().get("token", "")
                if not token:
                    return []
                # List keys
                res = client.get(
                    f"{base_url}/server/keys",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if res.status_code != 200:
                    return []
                data = res.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and 'keys' in data:
                    return data['keys']
                return []
        except Exception:
            return []

    def generate(self) -> bytes:
        """Generate the full Terraform project as a ZIP archive."""
        modules = self._build_modules()
        self._wire_module_secret_vars(modules)
        root_files = self._build_root_files(modules)
        return self._create_zip(modules, root_files)

    def _wire_module_secret_vars(self, modules: Dict[str, 'Module']) -> None:
        """Detect var.xxx references in module blocks and wire them through.

        Secret variables referenced inside a module need to be:
        1. Declared in the module's variables.tf
        2. Passed as inputs from the root main.tf module block

        Variables already declared by the module builder (via _add_secret_map_var
        or _add_secret_string_var) are skipped to avoid duplicates.
        """
        import re
        self.module_secret_vars: Dict[str, Set[str]] = {}
        for mod_name, mod in modules.items():
            # Scan all blocks for var.xxx references
            referenced = set()
            for block in mod.blocks:
                for m in re.finditer(r'var\.(\w+)', block):
                    var_name = m.group(1)
                    if var_name in self.secret_vars:
                        referenced.add(var_name)
            if not referenced:
                continue
            self.module_secret_vars[mod_name] = referenced
            # Check which secret vars are already declared in the module
            already_declared = set()
            for v in mod.variables:
                m = re.search(r'variable "(\w+)"', v)
                if m:
                    already_declared.add(m.group(1))
            # Add variable declarations only for vars not already declared
            for var_name in sorted(referenced):
                if var_name in already_declared:
                    continue
                desc = self.secret_vars[var_name]
                vtype = self.secret_var_types.get(var_name, 'map')
                hcl_type = self.secret_var_hcl_types.get(var_name)
                if vtype == 'string':
                    mod.add_variable(var_name, 'string', desc, 'null', sensitive=True)
                elif hcl_type:
                    mod.add_secret_map_variable(var_name, desc, var_type=hcl_type)
                else:
                    mod.add_secret_map_variable(var_name, desc)

    def _pre_register_name_maps(self) -> None:
        """Pre-register all name maps before building modules.

        This ensures cross-module references work regardless of build order.
        All maps must be populated upfront so that same-module and cross-module
        FK resolution can find resource names during module construction.
        """
        # SSL module resources
        self._register_names('certificates', self._query_all(Certificate))
        self._register_names('cipher_suites', self._query_all(CipherSuite))

        # Routing module resources (FCGI apps moved here to avoid circular dep)
        self._register_names('fcgi_apps', self._query_all(FcgiApp))
        # Error pages use raw code as key (e.g. "403") to match file names
        self.name_maps['error_pages'] = {ep.id: str(ep.code) for ep in self._query_all(CustomErrorPage)}

        # Routing module resources
        self._register_names('backends', self._query_all(Backend))
        self._register_names('listeners', self._query_all(Listener))

        # Security lists
        for list_cls, key in [
            (NetworkList, 'network_lists'), (AsnList, 'asn_lists'),
            (GeoList, 'geo_lists'), (Ja4List, 'ja4_lists'),
            (PatternList, 'pattern_lists'),
        ]:
            self._register_names(key, self._query_all(list_cls))

        # WAF rules
        self._register_names('waf_rules', self._query_all(WafRule))

        # Risk scoring
        self._register_names('risk_rulesets', self._query_all(RiskRuleset))

        # Management
        self._register_names('users', self._query_all(User), 'username')

    def _build_modules(self) -> Dict[str, Module]:
        modules: Dict[str, Module] = {}

        # Pre-register all name maps so cross-module references work
        # regardless of module build order.
        self._pre_register_name_maps()

        # ── SSL Module ──
        modules['ssl'] = self._build_ssl_module()

        # ── Traffic Module ──
        modules['traffic'] = self._build_traffic_module()

        # ── Routing Module (depends on ssl + traffic) ──
        modules['routing'] = self._build_routing_module()

        # ── Security Lists Module ──
        modules['security-lists'] = self._build_security_lists_module()

        # ── Security Rules Module ──
        modules['security-rules'] = self._build_security_rules_module()

        # ── WAF Module ──
        modules['waf'] = self._build_waf_module()

        # ── Cache Module (depends on routing) ──
        modules['cache'] = self._build_cache_module()

        # ── Observability Module ──
        modules['observability'] = self._build_observability_module()

        # ── Page Protect Module ──
        modules['page-protect'] = self._build_page_protect_module()

        # ── API Armor Module ──
        modules['api-armor'] = self._build_api_armor_module()

        # ── Risk Scoring Module ──
        modules['risk-scoring'] = self._build_risk_scoring_module()

        # ── Management Module ──
        modules['management'] = self._build_management_module()

        # ── MCP Gateway Module (depends on management) ──
        modules['mcp-gateway'] = self._build_mcp_gateway_module()

        # Remove empty modules
        return {k: v for k, v in modules.items() if v.has_content}

    def _build_ssl_module(self) -> Module:
        mod = Module('ssl', 'SSL/TLS certificates and cipher suites')

        # Certificates - special handling for PEM files and dns_credentials secret
        certs = self._query_all(Certificate)
        self._register_names('certificates', certs)
        # Always declare collection and file content variables so the root module can pass them
        cert_type = self._build_object_type(
            Certificate,
            skip_fields={'dns_credentials'} if not (self.include_secrets or self.include_certs) else set(),
            type_overrides={'dns_credentials': 'map(string)'},
            resource_type='certificate',
        )
        self.collection_types['certificates'] = cert_type
        mod.add_collection_variable('certificates', 'Map of certificate name to configuration', var_type=cert_type)
        mod.add_variable('cert_fullchains', 'map(string)', 'Map of cert name to fullchain PEM content', '{}')
        mod.add_variable('cert_keys', 'map(string)', 'Map of cert name to private key PEM content', '{}')
        if certs:
            # Export PEM files to environments/dev/files/ssl/ (environment-specific).
            # Only generate PEM files for custom-provider certs — Let's Encrypt
            # certs are managed by the provider and don't need PEM content.
            for cert in certs:
                if cert.provider != 'custom':
                    continue
                cert_slug = _sanitize_name(cert.name)
                if self.include_certs:
                    if cert.cert_path:
                        pem = self._read_file(cert.cert_path)
                        if pem:
                            self.extra_files[f'environments/dev/files/ssl/{cert_slug}_fullchain.pem'] = pem
                    if cert.key_path:
                        pem = self._read_file(cert.key_path)
                        if pem:
                            self.extra_files[f'environments/dev/files/ssl/{cert_slug}_key.pem'] = pem
                    if cert.chain_path:
                        pem = self._read_file(cert.chain_path)
                        if pem:
                            self.extra_files[f'environments/dev/files/ssl/{cert_slug}_chain.pem'] = pem
                else:
                    self.extra_files[f'environments/dev/files/ssl/{cert_slug}_fullchain.pem'] = (
                        "-----BEGIN CERTIFICATE-----\n"
                        "PLACEHOLDER-REPLACE-WITH-REAL-CERTIFICATE\n"
                        "-----END CERTIFICATE-----\n"
                    )
                    self.extra_files[f'environments/dev/files/ssl/{cert_slug}_key.pem'] = (
                        "-----BEGIN PRIVATE KEY-----\n"
                        "PLACEHOLDER-REPLACE-WITH-REAL-KEY\n"
                        "-----END PRIVATE KEY-----\n"
                    )

            # Get all fields and handle dns_credentials as secret
            cert_fields = self._get_model_fields(Certificate)
            # dns_credentials is sensitive - handle via secret map
            secret_fields = {}
            if 'dns_credentials' in cert_fields and not (self.include_secrets or self.include_certs):
                secret_fields = {'dns_credentials': 'certificates_dns_credentials'}
                self._add_secret_map_var(mod, 'certificates_dns_credentials', 'Certificate DNS credentials',
                                         name_map_key='certificates',
                                         var_type='map(map(string))')

            mod.add_section('Certificates')
            # Build the for_each block with ALL fields + PEM content from variables
            # Include secret fields so add_for_each_resource can emit var.xxx[each.key] references
            simple_fields = [f for f in cert_fields if f != 'name']
            # Apply provider overrides (rename 'provider' -> 'provider_name')
            cert_overrides = _resolve_provider_overrides('certificate', Certificate)
            cert_fields_filtered = [f for f in simple_fields
                                     if f not in cert_overrides['skip']
                                     and f not in cert_overrides['raw_int_skip']]
            mod.add_for_each_resource(
                resource_type='certificate',
                var_name='certificates',
                fields=cert_fields_filtered,
                secret_maps=secret_fields,
                provider_rename=cert_overrides['rename'],
            )
            # Append PEM content references from variables (environment-independent module).
            # Only pass fullchain/key for provider="custom" — Let's Encrypt certs
            # are managed by the provider, and passing PEM would fight state on
            # every renewal.
            pem_lines = [
                '',
                '  # PEM content from environment-specific variables',
                '  # Only for custom-provider certs; LE certs are provider-managed.',
                '  fullchain = each.value.provider_name == "custom" ? var.cert_fullchains[each.key] : null',
                '  key       = each.value.provider_name == "custom" ? var.cert_keys[each.key] : null',
            ]
            # Insert before the closing brace of the last block
            last_block = mod.blocks[-1]
            mod.blocks[-1] = last_block.replace('}', '\n'.join(pem_lines) + '\n}')
            mod.add_map_output('certificate_ids', 'certificate', 'Map of certificate name to ID')

        # Cipher suites - tls_options is a list in the provider but a string in the DB
        self._add_for_each_collection(
            mod, 'cipher_suite', 'cipher_suites', CipherSuite,
            'Map of cipher suite name to configuration',
            type_overrides={'tls_options': 'list(string)'},
        )

        # SSL Labs settings — singleton per certificate.
        # The provider expects cert_id (int, RequiresReplace) and max_scans_per_host (int).
        # The setting is stored as ssllabs_max_scans_per_host in the settings table.
        from ..services.ssllabs import get_max_scans_per_host
        max_scans = get_max_scans_per_host(self.db)
        ssl_labs_data = {}
        for cert in certs:
            cert_slug = _sanitize_name(cert.name)
            ssl_labs_data[cert_slug] = {
                'max_scans_per_host': max_scans,
            }
        # Always declare the variable so the root module can pass it.
        # Typed as map(object({...})) so typos in tfvars fail at validate.
        # cert_id is NOT in the type — it's wired to the local cert resource.
        ssl_labs_type = (
            'map(object({\n'
            '    max_scans_per_host = optional(number)\n'
            '  }))'
        )
        self.collection_types['ssl_labs_settings'] = ssl_labs_type
        mod.add_variable('ssl_labs_settings', ssl_labs_type,
                        'SSL Labs settings per certificate (singleton per cert)', '{}')
        if ssl_labs_data:
            mod.add_section('SSL Labs Settings')
            # cert_id is wired to the local certificate resource's ID,
            # not a snapshot integer. This avoids the classic "snapshot ID"
            # bug where the integer becomes stale after import/recreate.
            mod.blocks.append(
                'resource "corex_ssl_labs_settings" "this" {\n'
                '  for_each = var.ssl_labs_settings\n'
                '\n'
                '  cert_id            = corex_certificate.this[each.key].id\n'
                '  max_scans_per_host = try(each.value.max_scans_per_host, null)\n'
                '}'
            )

        return mod

    def _build_traffic_module(self) -> Module:
        mod = Module('traffic', 'Traffic management: rate limits, headers, redirects, rewrites, transforms, error pages')
        mod.add_variable('listener_ids', 'map(number)', 'Map of listener name to ID from the routing module', '{}')
        mod.add_variable('backend_ids', 'map(number)', 'Map of backend name to ID from the routing module', '{}')

        # Error pages - special: content exported as files, keyed by code
        error_pages = self._query_all(CustomErrorPage)
        # Use raw code as the map key (e.g. "403") so file paths match:
        # file is error_403.html, key is "403", root reads error_${k}.html
        self.name_maps['error_pages'] = {ep.id: str(ep.code) for ep in error_pages}
        # Always declare collection and content variables so the root module can pass them
        ep_type = self._build_object_type(
            CustomErrorPage,
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            fk_list_fields={'listener_ids': 'listener_ids'},
            skip_fields={'content'},
        )
        self.collection_types['error_pages'] = ep_type
        mod.add_collection_variable('error_pages', 'Map of error page key to configuration', var_type=ep_type)
        mod.add_variable('error_page_contents', 'map(string)', 'Map of error page code to HTML content', '{}')
        if error_pages:
            for ep in error_pages:
                row = _row_to_dict(ep)
                if row.get('content'):
                    ext = 'html' if (row.get('content_type') or 'text/html') == 'text/html' else 'txt'
                    filename = f'error_{ep.code}.{ext}'
                    self.extra_files[f'environments/dev/files/traffic/{filename}'] = row['content']

            ep_fields = self._get_model_fields(CustomErrorPage)
            # Remove 'content' from simple fields - it's handled via variable
            # Keep listener_id and listener_ids in the list so FK resolution can handle them
            ep_simple = [f for f in ep_fields if f not in ('content', 'name', 'code')]
            mod.add_section('Custom Error Pages')
            mod.add_for_each_resource(
                resource_type='error_page',
                var_name='error_pages',
                fields=ep_simple,
                optional_cross_module_fks={'listener_id': 'listener_ids'},
                fk_lists={'listener_ids': 'listener_ids'},
            )
            # Override the name line to use code as the key.
            # Use try(each.value.code, each.key) to preserve the original
            # integer code from tfvars (the map key may be sanitized).
            last_block = mod.blocks[-1]
            mod.blocks[-1] = last_block.replace(
                '  name = try(each.value.name, each.key)',
                '  code = try(each.value.code, each.key)'
            )
            # Append content from variable (environment-independent module)
            content_lines = [
                '',
                '  # Content from environment-specific variable',
                '  content = var.error_page_contents[each.key]',
            ]
            last_block = mod.blocks[-1]
            mod.blocks[-1] = last_block.replace('}', '\n'.join(content_lines) + '\n}')

        # Rate limits - listener_id cross-module FK (nullable)
        self._add_for_each_collection(
            mod, 'rate_limit', 'rate_limits', RateLimit,
            'Map of rate limit name to configuration',
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            add_output=False,
        )

        # Response headers - listener_id cross-module FK, listener_ids list FK
        self._add_for_each_collection(
            mod, 'response_header', 'response_headers', ResponseHeader,
            'Map of response header rule name to configuration',
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            fk_list_fields={'listener_ids': 'listener_ids'},
            add_output=False,
        )

        # Request headers - backend_id cross-module FK, backend_ids list FK
        self._add_for_each_collection(
            mod, 'request_header', 'request_headers', RequestHeader,
            'Map of request header rule name to configuration',
            optional_cross_module_fks={'backend_id': 'backend_ids'},
            fk_list_fields={'backend_ids': 'backend_ids'},
            add_output=False,
        )

        # Redirects - listener_id cross-module FK, listener_ids list FK
        self._add_for_each_collection(
            mod, 'redirect', 'redirects', Redirect,
            'Map of redirect rule name to configuration',
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            fk_list_fields={'listener_ids': 'listener_ids'},
            add_output=False,
        )

        # Rewrites - listener_id cross-module FK, listener_ids list FK
        self._add_for_each_collection(
            mod, 'rewrite', 'rewrites', Rewrite,
            'Map of rewrite rule name to configuration',
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            fk_list_fields={'listener_ids': 'listener_ids'},
            add_output=False,
        )

        # Response transforms - backend_id cross-module FK, backend_ids list FK
        self._add_for_each_collection(
            mod, 'response_transform', 'response_transforms', ResponseTransform,
            'Map of response transform rule name to configuration',
            optional_cross_module_fks={'backend_id': 'backend_ids'},
            fk_list_fields={'backend_ids': 'backend_ids'},
            add_output=False,
        )

        return mod

    def _build_routing_module(self) -> Module:
        mod = Module('routing', 'Core routing: backends, servers, backend rules, listeners, FCGI apps')

        # Variables for cross-module inputs
        mod.add_variable('certificate_ids', 'map(number)', 'Map of certificate name to ID from the ssl module', '{}')

        # FCGI apps - no FKs, but backends reference them via same-module FK
        self._add_for_each_collection(
            mod, 'fcgi_app', 'fcgi_apps', FcgiApp,
            'Map of FastCGI application name to configuration',
        )

        # Backends - fcgi_app_id is a same-module FK (FCGI apps are in this module)
        self._add_for_each_collection(
            mod, 'backend', 'backends', Backend,
            'Map of backend name to configuration',
            same_module_fks={'fcgi_app_id': ('fcgi_app', True)},
        )

        # Servers - backend_id is a same-module FK (non-nullable: servers belong to a backend)
        self._add_for_each_collection(
            mod, 'server', 'servers', Server,
            'Map of server name to configuration',
            same_module_fks={'backend_id': ('backend', False)},
            add_output=False,
        )

        # Listeners - certificate_id is cross-module, default_backend_id is same-module,
        # certificate_ids is a list FK
        self._add_for_each_collection(
            mod, 'listener', 'listeners', Listener,
            'Map of listener name to configuration',
            optional_cross_module_fks={'certificate_id': 'certificate_ids'},
            same_module_fks={'default_backend_id': ('backend', True)},
            fk_list_fields={'certificate_ids': 'certificate_ids'},
        )
        # Production safety: prevent accidental listener destruction
        if mod.blocks and 'corex_listener' in mod.blocks[-1]:
            prevent_destroy_lines = [
                '  lifecycle {',
                '    prevent_destroy = true',
                '  }',
            ]
            last_block = mod.blocks[-1]
            mod.blocks[-1] = last_block.replace('}', '\n'.join(prevent_destroy_lines) + '\n}')

        # Backend rules - listener_id and backend_id are same-module FKs
        self._add_for_each_collection(
            mod, 'backend_rule', 'backend_rules', BackendRule,
            'Map of backend rule name to configuration',
            same_module_fks={
                'listener_id': ('listener', False),
                'backend_id': ('backend', False),
            },
            add_output=False,
        )

        return mod

    def _build_security_lists_module(self) -> Module:
        mod = Module('security-lists', 'Security lists: network, ASN, geo, JA4, pattern lists with inline entries and dynamic feeds')

        list_types = [
            ('Network', NetworkList, 'network'),
            ('ASN', AsnList, 'asn'),
            ('Geo', GeoList, 'geo'),
            ('JA4', Ja4List, 'ja4'),
            ('Pattern', PatternList, 'pattern'),
        ]

        # Track which list types have resources in this module.
        # Only those can be referenced in polymorphic FK resolution —
        # referencing a resource type that doesn't exist in the module
        # is a parse error that try() cannot hide.
        active_list_types = []

        # Track which list types have feed-managed lists (separate resource block).
        # The polymorphic FK resolution must merge .this and .feed_managed maps
        # via locals, otherwise feeds targeting feed-managed lists get null.
        types_with_feed_managed = set()

        # Build a set of (list_type, list_id) pairs that are managed by a
        # dynamic feed. Feed-backed lists should NOT ship entry snapshots —
        # the feed keeps them updated, and shipping 75KB+ snapshots fights
        # the feed. Instead, split them into a separate resource block with
        # lifecycle { ignore_changes = [entries] }.
        feed_managed_list_ids = set()
        for feed in self._query_all(DynamicFeed):
            feed_managed_list_ids.add((feed.list_type, feed.target_list_id))

        for label, list_cls, type_key in list_types:
            lists = self._query_all(list_cls)

            # Always declare the collection variable and entries variable,
            # even when empty, so the root module can pass them without errors.
            # Add feed_managed field to the object type so we can split.
            list_obj_type = self._build_object_type(
                list_cls,
                extra_fields={'feed_managed': 'bool'},
            )
            self.collection_types[f'{type_key}_lists'] = list_obj_type
            mod.add_collection_variable(f'{type_key}_lists', f'Map of {label.lower()} list name to configuration', var_type=list_obj_type)
            mod.add_variable(f'{type_key}_list_entries', 'any', f'Map of {label.lower()} list name to entries list', '{}')

            if not lists:
                # Always emit the .this resource block, even when empty, so the
                # variable is not silently ignored. The for_each on an empty
                # map produces zero instances.
                list_fields = self._get_model_fields(list_cls)
                mod.add_section(f'{label} Lists')
                mod.add_for_each_resource(
                    resource_type=f'{type_key}_list',
                    var_name=f'{type_key}_lists',
                    fields=list_fields,
                )
                entries_lines = [
                    '',
                    '  # Entries from environment-specific variable',
                    f'  entries = try(var.{type_key}_list_entries[each.key], [])',
                ]
                last_block = mod.blocks[-1]
                mod.blocks[-1] = last_block.replace('}', '\n'.join(entries_lines) + '\n}')
                # Exclude feed-managed from .this (they go to .feed_managed below)
                mod.blocks[-1] = mod.blocks[-1].replace(
                    f'for_each = var.{type_key}_lists',
                    f'for_each = {{ for k, v in var.{type_key}_lists : k => v if !try(v.feed_managed, false) }}'
                )
                # Always emit .feed_managed resource block (empty for_each = no instances)
                feed_block_lines = [
                    f'\n# {"=" * 60}',
                    f'# Feed-managed {label} lists (entries controlled by dynamic feeds)',
                    f'# {"=" * 60}',
                    '',
                    f'resource "corex_{type_key}_list" "feed_managed" {{',
                    f'  for_each = {{ for k, v in var.{type_key}_lists : k => v if try(v.feed_managed, false) }}',
                    '',
                    '  name = try(each.value.name, each.key)',
                ]
                for field in list_fields:
                    if field == 'name':
                        continue
                    feed_block_lines.append(f'  {field} = try(each.value.{field}, null)')
                feed_block_lines.extend([
                    '',
                    '  # Entries are managed by the feed, not Terraform',
                    f'  entries = try(var.{type_key}_list_entries[each.key], [])',
                    '',
                    '  lifecycle {',
                    '    ignore_changes = [entries]',
                    '  }',
                    '}',
                ])
                mod.blocks.append('\n'.join(feed_block_lines))
                continue
            self._register_names(f'{type_key}_lists', lists)
            active_list_types.append(type_key)

            # Determine which lists are feed-managed vs owned
            feed_managed_keys = set()
            for lst in lists:
                if (type_key, lst.id) in feed_managed_list_ids:
                    feed_managed_keys.add(_sanitize_name(lst.name))

            # Export entries JSON files only for lists you own (not feed-managed).
            # Feed-managed lists get entries from the feed, not from Terraform.
            for lst in lists:
                if (type_key, lst.id) in feed_managed_list_ids:
                    continue  # Feed-managed: skip the snapshot file
                entries_data = [{"value": ent.value, "note": ent.note} for ent in lst.entries]
                filename = f'{type_key}_{_sanitize_name(lst.name)}.json'
                self.extra_files[f'environments/dev/files/security-lists/{filename}'] = json.dumps(entries_data, indent=2)

            # Build for_each with ALL fields + entries from variable
            list_fields = self._get_model_fields(list_cls)
            mod.add_section(f'{label} Lists')
            mod.add_for_each_resource(
                resource_type=f'{type_key}_list',
                var_name=f'{type_key}_lists',
                fields=list_fields,
            )
            # Append entries from variable (environment-independent module)
            entries_lines = [
                '',
                '  # Entries from environment-specific variable',
                f'  entries = try(var.{type_key}_list_entries[each.key], [])',
            ]
            last_block = mod.blocks[-1]
            mod.blocks[-1] = last_block.replace('}', '\n'.join(entries_lines) + '\n}')

            # Always split .this vs .feed_managed and always emit the
            # .feed_managed resource block (empty for_each = no instances).
            # This ensures the merged ID local is always valid, even if a
            # feed is later attached to a geo/ja4/pattern list.
            if feed_managed_keys:
                types_with_feed_managed.add(type_key)
                # Replace the for_each in the main block to exclude feed-managed lists
                last_block = mod.blocks[-1]
                mod.blocks[-1] = last_block.replace(
                    f'for_each = var.{type_key}_lists',
                    f'for_each = {{ for k, v in var.{type_key}_lists : k => v if !try(v.feed_managed, false) }}'
                )
            else:
                # No feed-managed lists currently, but still exclude them from
                # .this for consistency (the filter is a no-op when none exist)
                last_block = mod.blocks[-1]
                mod.blocks[-1] = last_block.replace(
                    f'for_each = var.{type_key}_lists',
                    f'for_each = {{ for k, v in var.{type_key}_lists : k => v if !try(v.feed_managed, false) }}'
                )

            # Always emit .feed_managed resource block (empty for_each = no instances)
            feed_block_lines = [
                f'\n# {"=" * 60}',
                f'# Feed-managed {label} lists (entries controlled by dynamic feeds)',
                f'# {"=" * 60}',
                '',
                f'resource "corex_{type_key}_list" "feed_managed" {{',
                f'  for_each = {{ for k, v in var.{type_key}_lists : k => v if try(v.feed_managed, false) }}',
                '',
                '  name = try(each.value.name, each.key)',
            ]
            for field in list_fields:
                if field == 'name':
                    continue
                feed_block_lines.append(f'  {field} = try(each.value.{field}, null)')
            feed_block_lines.extend([
                '',
                '  # Entries are managed by the feed, not Terraform',
                f'  entries = try(var.{type_key}_list_entries[each.key], [])',
                '',
                '  lifecycle {',
                '    ignore_changes = [entries]',
                '  }',
                '}',
            ])
            mod.blocks.append('\n'.join(feed_block_lines))

        # All 5 list types always get resource blocks (even when empty),
        # so locals can always reference all 5. This ensures feeds targeting
        # any list type resolve correctly, even if that type had no rows
        # at export time.
        all_list_types = [
            ('network', 'network_list'),
            ('asn', 'asn_list'),
            ('geo', 'geo_list'),
            ('ja4', 'ja4_list'),
            ('pattern', 'pattern_list'),
        ]

        # Locals: always merge .this and .feed_managed ID maps for ALL list
        # types, not just active ones. Since we always emit resource blocks
        # for all 5 types, the merge() is always valid (empty maps = no-op).
        local_lines = ['locals {']
        for type_key, res_type in all_list_types:
            local_lines.append(
                f'  {type_key}_list_ids = merge('
            )
            local_lines.append(
                f'    {{ for k, v in corex_{res_type}.this : k => v.id }},'
            )
            local_lines.append(
                f'    {{ for k, v in corex_{res_type}.feed_managed : k => v.id }}'
            )
            local_lines.append('  )')
        local_lines.append('}')
        mod.locals_blocks.append('\n'.join(local_lines))

        # Export merged ID maps as outputs for all list types
        for type_key, _ in all_list_types:
            mod.add_local_output(f'{type_key}_list_ids', f'{type_key}_list_ids',
                                 f'Merged {type_key} list IDs (this + feed_managed)')

        # Dynamic feeds with polymorphic FK resolution.
        # All 5 list types are always in the coalesce — the resource blocks
        # always exist, so local.xxx_list_ids is always defined.
        self._add_for_each_collection(
            mod, 'dynamic_feed', 'dynamic_feeds', DynamicFeed,
            'Map of dynamic feed name to configuration',
            polymorphic_fks={
                'target_list_id': all_list_types,
            },
            add_output=False,
        )

        return mod

    def _build_security_rules_module(self) -> Module:
        mod = Module('security-rules', 'Security rules for request filtering and access control')
        mod.add_variable('listener_ids', 'map(number)', 'Map of listener name to ID from the routing module', '{}')

        self._add_for_each_collection(
            mod, 'security_rule', 'security_rules', SecurityRule,
            'Map of security rule name to configuration',
            fk_list_fields={'listener_ids': 'listener_ids'},
            add_output=False,
        )

        return mod

    def _build_waf_module(self) -> Module:
        mod = Module('waf', 'Web Application Firewall rules and exceptions')
        mod.add_variable('listener_ids', 'map(number)', 'Map of listener name to ID from the routing module', '{}')
        mod.add_variable('backend_ids', 'map(number)', 'Map of backend name to ID from the routing module', '{}')

        # WAF rules - listener_id and backend_id are nullable cross-module FKs.
        # http_methods is a comma-separated string in the DB but a list in the provider.
        self._add_for_each_collection(
            mod, 'waf_rule', 'waf_rules', WafRule,
            'Map of WAF rule name to configuration',
            optional_cross_module_fks={
                'listener_id': 'listener_ids',
                'backend_id': 'backend_ids',
            },
            type_overrides={'http_methods': 'list(string)'},
        )

        self._add_for_each_collection(
            mod, 'waf_exception', 'waf_exceptions', WafException,
            'Map of WAF exception name to configuration',
            same_module_fks={'waf_rule_id': ('waf_rule', True)},
            add_output=False,
        )

        # Export WAF rule IDs as a module output for cross-module reference
        mod.add_map_output('waf_rule_ids', 'waf_rule', 'Map of WAF rule name to ID')

        return mod

    def _build_cache_module(self) -> Module:
        mod = Module('cache', 'Cache configuration and rules per backend')
        mod.add_variable('backend_ids', 'map(number)', 'Map of backend name to ID from the routing module', '{}')

        backend_map = self.name_maps.get('backends', {})

        # Cache configs with nested rules (instead of a sibling cache_rules map).
        # Rules are nested under their config in tfvars for readability:
        #   cache_configs = {
        #     "cache_web" = {
        #       backend_id = "web"
        #       haproxy_enabled = true
        #       rules = [
        #         { priority = 0, match_type = "path", pattern = "/static/*", action = "cache", tier = "memory" },
        #       ]
        #     }
        #   }
        # The module flattens them into separate corex_cache_rule resources.
        cache_rule_obj_type = (
            'object({\n'
            '    priority     = optional(number)\n'
            '    enabled      = optional(bool)\n'
            '    match_type   = optional(string)\n'
            '    pattern      = optional(string)\n'
            '    action       = optional(string)\n'
            '    tier         = optional(string)\n'
            '  })'
        )
        cache_config_type = self._build_object_type(
            CacheConfig,
            cross_module_fks={'backend_id': 'backend_ids'},
            extra_fields={
                'rules': f'list({cache_rule_obj_type})',
                # Provider-only fields not in the DB model; optional so they
                # default to null when unset.
                'haproxy_cache_vary': 'list(string)',
                'disk_cache_max_size': 'number',
            },
            resource_type='cache_config',
        )
        self.collection_types['cache_configs'] = cache_config_type
        mod.add_collection_variable('cache_configs', 'Map of cache config name to configuration', var_type=cache_config_type)

        cache_configs = self._query_all(CacheConfig)
        if cache_configs:
            self._register_names('cache_configs', cache_configs,
                                 name_col='backend_id')
            # Override name map to use cache_<backend_name> keys
            mapping = {}
            for cc in cache_configs:
                mapping[cc.id] = f"cache_{backend_map.get(cc.backend_id, 'unknown')}"
            self.name_maps['cache_configs'] = mapping

            # Build cache_config resource block
            config_fields = self._get_model_fields(CacheConfig)
            # Apply provider overrides (manual + schema-derived) to match provider schema
            cc_overrides = _resolve_provider_overrides('cache_config', CacheConfig)
            cc_provider_skip = cc_overrides['skip']
            cc_provider_rename = cc_overrides['rename']
            cc_provider_raw_int = cc_overrides['raw_int']
            cc_provider_raw_int_skip = cc_overrides['raw_int_skip']
            # Filter out skipped/raw_int_skip fields from the resource block
            cc_fields = [f for f in config_fields
                         if f not in cc_provider_skip and f not in cc_provider_raw_int_skip]
            mod.add_section('Cache Configs')
            mod.add_for_each_resource(
                resource_type='cache_config',
                var_name='cache_configs',
                fields=cc_fields,
                cross_module_fks={'backend_id': 'backend_ids'},
                provider_rename=cc_provider_rename,
                provider_raw_int=cc_provider_raw_int,
                provider_skip=cc_provider_skip,
            )
            # Append provider-only fields not in the DB model (optional, null when unset)
            block = mod.blocks[-1]
            block = block.replace(
                '}',
                '  haproxy_cache_vary = try(each.value.haproxy_cache_vary, null)\n'
                '  disk_cache_max_size = try(each.value.disk_cache_max_size, null)\n'
                '}',
            )
            mod.blocks[-1] = block

            # Build cache_rule resource block — flatten nested rules into
            # separate resources keyed by "<config_key>_<priority>".
            rule_fields = ['priority', 'enabled', 'match_type', 'pattern', 'action', 'tier']
            rule_lines = [
                '',
                f'# {"=" * 60}',
                f'# Cache Rules (flattened from nested config.rules)',
                f'# {"=" * 60}',
                '',
                'resource "corex_cache_rule" "this" {',
                '  for_each = merge([',
                '    for config_key, config in var.cache_configs : {',
                '      for rule in try(config.rules, []) :',
                '        "${config_key}_${rule.priority}" => {',
                '          config_key = config_key',
                '          priority    = rule.priority',
                '          match_type  = rule.match_type',
                '          pattern     = rule.pattern',
                '          action      = rule.action',
                '          tier        = rule.tier',
                '          enabled     = try(rule.enabled, true)',
                '        }',
                '    }',
                '  ]...)',
                '',
                '  cache_config_id = corex_cache_config.this[each.value.config_key].id',
            ]
            for f in rule_fields:
                if f == 'priority':
                    rule_lines.append(f'  {f} = each.value.{f}')
                else:
                    rule_lines.append(f'  {f} = try(each.value.{f}, null)')
            rule_lines.append('}')
            mod.blocks.append('\n'.join(rule_lines))

        return mod

    def _build_observability_module(self) -> Module:
        mod = Module('observability', 'Log destinations and logged fields')
        mod.add_variable('listener_ids', 'map(number)', 'Map of listener name to ID from the routing module', '{}')

        self._add_for_each_collection(
            mod, 'log_destination', 'log_destinations', LogDestination,
            'Map of log destination name to configuration',
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            add_output=False,
        )

        self._add_for_each_collection(
            mod, 'logged_field', 'logged_fields', LoggedField,
            'Map of logged field name to configuration',
            optional_cross_module_fks={'listener_id': 'listener_ids'},
            add_output=False,
        )

        return mod

    def _build_page_protect_module(self) -> Module:
        mod = Module('page-protect', 'Page protection: CSP policies, settings, and scripts')
        mod.add_variable('backend_ids', 'map(number)', 'Map of backend name to ID from the routing module', '{}')

        self._add_for_each_collection(
            mod, 'page_protect_policy', 'page_protect_policies', PageProtectPolicy,
            'Map of page protect policy name to configuration',
            fk_list_fields={'backend_ids': 'backend_ids'},
            add_output=False,
        )

        # Page protect scripts — provider has url, resource_type, notes, fetch_method, ignored
        # Only export manually-added scripts (source='manual'). Auto-detected scripts
        # (csp/beacon) are inventory, not user configuration.
        self._add_for_each_collection(
            mod, 'page_protect_script', 'page_protect_scripts', PageProtectScript,
            'Map of page protect script URL to configuration',
            name_attr='url',
            add_output=False,
            filter_fn=lambda s: (s.source or '').lower() == 'manual',
        )

        # Page protect settings — singleton with flat attributes
        mod.add_variable('page_protect_settings', 'any', 'Page protection configuration (singleton)', '{}')

        db = self.db
        pp_settings = get_page_protect_settings(db)
        # Map DB setting names to provider field names and coerce types
        pp_data = {}
        pp_data['monitoring_enabled'] = pp_settings.get('monitoring_enabled', False)
        pp_data['change_detection_enabled'] = pp_settings.get('change_detection_enabled', False)
        pp_data['change_detection_interval_hours'] = pp_settings.get('change_detection_interval_hours', 24)
        pp_data['report_retention_days'] = pp_settings.get('report_retention_days', 7)
        pp_data['report_path'] = pp_settings.get('report_path', '')
        pp_data['beacon_injection_enabled'] = pp_settings.get('beacon_injection_enabled', False)
        pp_data['beacon_trust_enabled'] = pp_settings.get('beacon_trust_enabled', False)
        # beacon_path (string) → beacon_paths (list)
        beacon_path = pp_settings.get('beacon_path', '')
        pp_data['beacon_paths'] = [beacon_path] if beacon_path else []
        # beacon_content_types (comma-separated) → list
        ct = pp_settings.get('beacon_content_types', '')
        pp_data['beacon_content_types'] = [c.strip() for c in ct.split(',') if c.strip()] if ct else []
        # beacon_path_patterns (comma-separated) → beacon_patterns (list)
        pp_patterns = pp_settings.get('beacon_path_patterns', '')
        pp_data['beacon_patterns'] = [p.strip() for p in pp_patterns.split(',') if p.strip()] if pp_patterns else []
        # beacon_backend_ids (JSON list) → backend_ids (list of int)
        pp_data['backend_ids'] = pp_settings.get('beacon_backend_ids', [])
        pp_data['auto_prune_stale_days'] = pp_settings.get('auto_prune_stale_days', 7)

        if pp_data:
            mod.add_section('Page Protect Settings')
            pp_lines = ['resource "corex_page_protect_settings" "this" {']
            for k in ['monitoring_enabled', 'change_detection_enabled',
                      'change_detection_interval_hours', 'report_retention_days',
                      'report_path', 'beacon_injection_enabled', 'beacon_trust_enabled',
                      'beacon_paths', 'beacon_content_types', 'beacon_patterns',
                      'backend_ids', 'auto_prune_stale_days']:
                pp_lines.append(f'  {k} = try(var.page_protect_settings["{k}"], null)')
            pp_lines.append('}')
            mod.blocks.append('\n'.join(pp_lines))

        return mod

    def _build_api_armor_module(self) -> Module:
        mod = Module('api-armor', 'API Armor: settings, auth policies, API key lists, OpenAPI specs, schemas')
        mod.add_variable('listener_ids', 'map(number)', 'Map of listener name to ID from the routing module', '{}')
        mod.add_variable('backend_ids', 'map(number)', 'Map of backend name to ID from the routing module', '{}')

        # API Armor settings — singleton with flat attributes (lives in api-armor, not management)
        mod.add_variable('api_armor_settings', 'any', 'API Armor configuration (singleton)', '{}')
        db = self.db
        api_armor_keys = [
            'api_armor_enabled', 'api_armor_max_body_bytes', 'api_armor_module_enabled',
            'api_armor_schema_learning_enabled', 'api_armor_profiling_learning_enabled',
            'api_armor_profile_retention_days', 'api_armor_scope', 'api_armor_backend_ids',
            'api_armor_path_patterns',
        ]
        api_armor_data = {}
        for k in api_armor_keys:
            v = get_setting(db, k)
            if v is not None:
                api_armor_data[k] = v
        if api_armor_data:
            mod.add_section('API Armor Settings')
            aa_lines = ['resource "corex_api_armor_settings" "this" {']
            for k in api_armor_keys:
                if k in api_armor_data:
                    aa_lines.append(f'  {k} = try(var.api_armor_settings["{k}"], null)')
            aa_lines.append('}')
            mod.blocks.append('\n'.join(aa_lines))

        self._add_for_each_collection(
            mod, 'api_armor_auth_policy', 'auth_policies', AuthPolicy,
            'Map of auth policy name to configuration',
            fk_list_fields={
                'listener_ids': 'listener_ids',
                'backend_ids': 'backend_ids',
            },
            same_module_fks={'api_key_list_id': ('api_armor_api_key_list', True)},
            add_output=False,
        )

        # API key lists - with entries as nested blocks
        api_key_lists = self._query_all(ApiKeyList)
        list_fields = self._get_model_fields(ApiKeyList)
        ak_simple = [f for f in list_fields if f not in SKIP_FIELDS and f != 'name']
        # Include name and entries in the variable type so the resource can
        # read each.value.name and each.value.entries
        akl_type = self._build_object_type(
            ApiKeyList,
            skip_fields={'name'},
            extra_fields={
                'name': 'string',
                'entries': 'list(object({\n      value = string\n      note = optional(string)\n    }))',
            },
        )
        self.collection_types['api_key_lists'] = akl_type
        # Always declare the collection variable, even when empty
        mod.add_collection_variable('api_key_lists', 'Map of API key list name to configuration', var_type=akl_type)
        if api_key_lists:
            self._register_names('api_key_lists', api_key_lists)
        mod.add_section('API Key Lists')
        mod.add_for_each_resource(
            resource_type='api_armor_api_key_list',
            var_name='api_key_lists',
            fields=ak_simple,
        )
        # Append nested entries block
        entries_lines = [
            '',
            '  # Entries from the api_key_list_entries variable',
            '  entries = try(each.value.entries, [])',
        ]
        last_block = mod.blocks[-1]
        mod.blocks[-1] = last_block.replace('}', '\n'.join(entries_lines) + '\n}')

        # API key list entries - exported as nested entries inside each list
        # They're included in the api_key_lists tfvars as a nested "entries" list
        # (handled in _build_tfvars_data)

        # OpenAPI specs
        self._add_for_each_collection(
            mod, 'api_armor_openapi_spec', 'openapi_specs', OpenApiSpec,
            'Map of OpenAPI spec name to configuration',
            fk_list_fields={
                'listener_ids': 'listener_ids',
                'backend_ids': 'backend_ids',
            },
            add_output=False,
        )

        # API schemas - spec_id is same-module FK to openapi_spec
        self._add_for_each_collection(
            mod, 'api_armor_api_schema', 'api_schemas', ApiSchema,
            'Map of API schema name to configuration',
            same_module_fks={'spec_id': ('api_armor_openapi_spec', True)},
            add_output=False,
        )

        return mod

    def _build_risk_scoring_module(self) -> Module:
        mod = Module('risk-scoring', 'Risk scoring: rulesets and rules')

        self._add_for_each_collection(
            mod, 'risk_ruleset', 'risk_rulesets', RiskRuleset,
            'Map of risk ruleset name to configuration',
        )

        self._add_for_each_collection(
            mod, 'risk_rule', 'risk_rules', RiskRule,
            'Map of risk rule name to configuration',
            same_module_fks={'ruleset_id': ('risk_ruleset', False)},
            add_output=False,
        )

        return mod

    def _build_management_module(self) -> Module:
        mod = Module('management', 'Management: users, settings, and singleton configurations')

        # Users — the provider's user resource has a write-only `password` field
        # but no `hashed_password` or `totp_secret`. Existing password hashes
        # cannot be round-tripped. Users are import-only for identity fields;
        # set passwords out-of-band after import.
        self._add_for_each_collection(
            mod, 'user', 'users', User,
            'Map of username to user configuration',
            name_attr='username',
        )

        # Settings (key-value pairs)
        settings = self._query_all(Setting)
        exportable = [s for s in settings if s.key not in SKIP_SETTING_KEYS]
        # Always declare the collection variable so the root module can pass it
        mod.add_collection_variable('settings', 'Map of setting key to value')
        if exportable:
            mod.add_section('Settings')
            lines = [
                'resource "corex_setting" "this" {',
                '  for_each = var.settings',
                '',
                '  key   = each.key',
                '  value = each.value',
                '}',
            ]
            mod.blocks.append('\n'.join(lines))

        # Singleton resources: global_options, captcha, maxmind, ha_config, api_armor_settings
        # These are stored as settings (key-value pairs) and exported as singleton resources.
        self._export_singleton_settings(mod, self.db)

        return mod

    def _add_singleton_tfvars(self, tfvars: dict, db) -> None:
        """Add singleton configuration data to tfvars."""
        # HAProxy global options — stored as a JSON string in the DB,
        # but the provider expects a list of objects. Parse it here so
        # the tfvars contains a real list, not a JSON string.
        global_opts = get_setting(db, 'haproxy_global_options')
        if global_opts:
            parsed = _try_json_parse(global_opts)
            if isinstance(parsed, list):
                tfvars['haproxy_global_options'] = parsed
            else:
                tfvars['haproxy_global_options'] = []

        # Captcha settings — split non-secret and secret keys when secrets excluded.
        # Non-secret keys go in captcha_settings (dev.tfvars).
        # Secret keys go in captcha_secrets (dev.secrets.tfvars).
        # When secrets are included, all keys go in captcha_settings.
        captcha_nonsecret_keys = [
            'captcha_provider', 'captcha_valid_seconds',
            'cap_site_key', 'recaptcha_site_key',
            'turnstile_site_key',
            'challenge_url', 'proxy_path',
        ]
        captcha_secret_keys = [
            'cap_secret', 'recaptcha_secret', 'turnstile_secret',
        ]
        captcha_data = {}
        for k in captcha_nonsecret_keys:
            v = get_setting(db, k)
            if v is not None:
                captcha_data[k] = _coerce_setting_value(k, v)
        if self.include_secrets or self.include_system_secrets:
            # Include all keys in captcha_settings
            for k in captcha_secret_keys:
                v = get_setting(db, k)
                if v is not None:
                    captcha_data[k] = v
            if captcha_data:
                tfvars['captcha_settings'] = captcha_data
        else:
            # Split: non-secret in captcha_settings, secret in captcha_secrets
            if captcha_data:
                tfvars['captcha_settings'] = captcha_data
            captcha_secret_data = {}
            for k in captcha_secret_keys:
                v = get_setting(db, k)
                if v is not None:
                    captcha_secret_data[k] = "change-me"
            if captcha_secret_data:
                tfvars['captcha_secrets'] = captcha_secret_data

        # MaxMind license key
        maxmind_key = get_maxmind_license_key(db)
        if maxmind_key:
            if self.include_secrets or self.include_system_secrets:
                tfvars['maxmind_license_key'] = maxmind_key

        # HA config — nest keepalived fields under keepalived key
        ha_config_keys = [
            'ha_enabled', 'ha_topology', 'haproxy_ha_replicas', 'valkey_ha_replicas',
            'coraza_ha_replicas', 'haproxy_instances', 'haproxy_peer_port',
            'valkey_sentinel_enabled', 'valkey_sentinel_hosts', 'valkey_sentinel_service',
        ]
        keepalived_keys = [
            'keepalived_vip', 'keepalived_virtual_router_id', 'keepalived_priority',
            'keepalived_interface', 'keepalived_auth_password', 'keepalived_peer_addresses',
            'keepalived_advert_int', 'keepalived_preempt', 'keepalived_track_script',
        ]
        ha_data = {}
        keepalived_data = {}
        for k in ha_config_keys:
            v = get_setting(db, k)
            if v is not None:
                is_sensitive = k in SENSITIVE_SETTING_KEYS
                if not is_sensitive or self.include_secrets or self.include_system_secrets:
                    ha_data[k] = _coerce_setting_value(k, v)
                else:
                    ha_data[k] = "change-me"
        for k in keepalived_keys:
            v = get_setting(db, k)
            if v is not None:
                is_sensitive = k in SENSITIVE_SETTING_KEYS
                if not is_sensitive or self.include_secrets or self.include_system_secrets:
                    keepalived_data[k.replace('keepalived_', '')] = _coerce_setting_value(k, v)
                else:
                    keepalived_data[k.replace('keepalived_', '')] = "change-me"
        if keepalived_data:
            ha_data['keepalived'] = keepalived_data
        if ha_data:
            tfvars['ha_config'] = ha_data

        # API Armor settings
        api_armor_keys = [
            'api_armor_enabled', 'api_armor_max_body_bytes', 'api_armor_module_enabled',
            'api_armor_schema_learning_enabled', 'api_armor_profiling_learning_enabled',
            'api_armor_profile_retention_days', 'api_armor_scope', 'api_armor_backend_ids',
            'api_armor_path_patterns',
        ]
        api_armor_data = {}
        for k in api_armor_keys:
            v = get_setting(db, k)
            if v is not None:
                api_armor_data[k] = _coerce_setting_value(k, v)
        if api_armor_data:
            tfvars['api_armor_settings'] = api_armor_data

    def _export_singleton_settings(self, mod: Module, db) -> None:
        """Export singleton configurations as singleton Terraform resources.

        These are NOT for_each collections — the provider defines them as
        singleton resources (corex_captcha_settings, corex_ha_config, etc.)
        with flat attributes, not key/value maps.
        """
        # HAProxy global options — provider expects a list of objects
        # with target/directive/value/enabled fields. The setting is stored
        # as JSON in the DB; the tfvars builder parses it to a real list,
        # so the module variable is list(object({...})) and the resource
        # block passes it through directly (no jsondecode()).
        global_opts = get_setting(db, 'haproxy_global_options')
        global_opts_type = ('list(object({ target = optional(string) '
                            'directive = optional(string) '
                            'value = optional(string) '
                            'enabled = optional(bool) }))')
        # Register the type so the root variables.tf uses it instead of `any`
        self.collection_types['haproxy_global_options'] = global_opts_type
        mod.add_variable('haproxy_global_options', global_opts_type,
                       'HAProxy global options (list of objects)', '[]')
        if global_opts:
            mod.add_section('HAProxy Global Options')
            mod.blocks.append(
                'resource "corex_global_options" "this" {\n'
                '  options = var.haproxy_global_options\n'
                '}'
            )

        # Captcha settings — singleton with flat attributes.
        # When secrets are excluded, secret keys (cap_secret, recaptcha_secret,
        # turnstile_secret) are split into a separate captcha_secrets map so they
        # can live in *.secrets.tfvars. When secrets are included, all keys go
        # in captcha_settings.
        captcha_nonsecret_keys = [
            'captcha_provider', 'captcha_valid_seconds',
            'cap_site_key', 'recaptcha_site_key',
            'turnstile_site_key',
            'challenge_url', 'proxy_path',
        ]
        captcha_secret_keys = ['cap_secret', 'recaptcha_secret', 'turnstile_secret']
        captcha_data = {}
        for k in captcha_nonsecret_keys:
            v = get_setting(db, k)
            if v is not None:
                captcha_data[k] = _coerce_setting_value(k, v)
        # Always declare singleton setting variables so the root module can pass them
        mod.add_variable('captcha_settings', 'any', 'Captcha configuration (singleton)', '{}')
        mod.add_variable('ha_config', 'any', 'HA configuration (singleton)', '{}')
        # api_armor_settings lives in the api-armor module, not management.

        if not (self.include_secrets or self.include_system_secrets):
            # Split secrets into a separate map variable
            self._add_secret_map_var(mod, 'captcha_secrets',
                'Captcha secret keys (cap_secret, recaptcha_secret, turnstile_secret)')
            if captcha_data:
                mod.add_section('Captcha Settings')
                captcha_lines = ['resource "corex_captcha_settings" "this" {']
                for k in captcha_nonsecret_keys:
                    if k in captcha_data:
                        captcha_lines.append(f'  {k} = try(var.captcha_settings["{k}"], null)')
                for k in captcha_secret_keys:
                    captcha_lines.append(f'  {k} = try(var.captcha_secrets["{k}"], null)')
                captcha_lines.append('}')
                mod.blocks.append('\n'.join(captcha_lines))
        else:
            # Include all keys (secrets too) in captcha_settings
            for k in captcha_secret_keys:
                v = get_setting(db, k)
                if v is not None:
                    captcha_data[k] = v
            if captcha_data:
                mod.add_section('Captcha Settings')
                captcha_lines = ['resource "corex_captcha_settings" "this" {']
                for k in captcha_nonsecret_keys + captcha_secret_keys:
                    if k in captcha_data:
                        captcha_lines.append(f'  {k} = try(var.captcha_settings["{k}"], null)')
                captcha_lines.append('}')
                mod.blocks.append('\n'.join(captcha_lines))

        # MaxMind license key
        maxmind_key = get_maxmind_license_key(db)
        if maxmind_key:
            if self.include_secrets or self.include_system_secrets:
                mod.add_variable('maxmind_license_key', 'string', 'MaxMind license key', '""')
                mod.add_section('MaxMind License Key')
                mod.blocks.append(
                    'resource "corex_maxmind_license_key" "this" {\n'
                    '  value = var.maxmind_license_key\n'
                    '}'
                )
            else:
                self._add_secret_string_var(mod, 'maxmind_license_key', 'MaxMind license key')
                mod.add_section('MaxMind License Key')
                mod.blocks.append(
                    'resource "corex_maxmind_license_key" "this" {\n'
                    '  value = var.maxmind_license_key\n'
                    '}'
                )

        # HA config — singleton with flat attributes + nested keepalived block
        ha_config_keys = [
            'ha_enabled', 'ha_topology', 'haproxy_ha_replicas', 'valkey_ha_replicas',
            'coraza_ha_replicas', 'haproxy_instances', 'haproxy_peer_port',
            'valkey_sentinel_enabled', 'valkey_sentinel_hosts', 'valkey_sentinel_service',
        ]
        keepalived_keys = [
            'keepalived_vip', 'keepalived_virtual_router_id', 'keepalived_priority',
            'keepalived_interface', 'keepalived_auth_password', 'keepalived_peer_addresses',
            'keepalived_advert_int', 'keepalived_preempt', 'keepalived_track_script',
        ]
        ha_data = {}
        keepalived_data = {}
        for k in ha_config_keys:
            v = get_setting(db, k)
            if v is not None:
                is_sensitive = k in SENSITIVE_SETTING_KEYS
                if not is_sensitive or self.include_secrets or self.include_system_secrets:
                    ha_data[k] = _coerce_setting_value(k, v)
                else:
                    ha_data[k] = "change-me"
        for k in keepalived_keys:
            v = get_setting(db, k)
            if v is not None:
                is_sensitive = k in SENSITIVE_SETTING_KEYS
                if not is_sensitive or self.include_secrets or self.include_system_secrets:
                    keepalived_data[k.replace('keepalived_', '')] = _coerce_setting_value(k, v)
                else:
                    keepalived_data[k.replace('keepalived_', '')] = "change-me"
        if keepalived_data:
            ha_data['keepalived'] = keepalived_data
        if ha_data:
            mod.add_section('HA Configuration')
            # Singleton resource — no for_each, flat attributes from var
            ha_lines = ['resource "corex_ha_config" "this" {']
            for k in ha_config_keys:
                if k in ha_data:
                    ha_lines.append(f'  {k} = try(var.ha_config["{k}"], null)')
            if 'keepalived' in ha_data:
                # keepalived is a SingleNestedAttribute (assignment, not a block)
                ha_lines.append('  keepalived = try(var.ha_config["keepalived"], null)')
            ha_lines.append('}')
            mod.blocks.append('\n'.join(ha_lines))

        # API Armor settings singleton lives in the api-armor module, not management.

    def _build_mcp_gateway_module(self) -> Module:
        mod = Module('mcp-gateway', 'MCP Gateway: teams, servers, identities, policies, DLP, guardrails, skills')
        mod.add_variable('user_ids', 'map(number)', 'Map of username to user ID from the management module', '{}')

        SELF_REGISTERED_SERVER_NAMESPACE = "corex-manager"
        SELF_REGISTERED_SKILL_NAME = "corex-manager"

        # Teams - export all teams (including platform). The self-registered
        # server (namespace "corex-manager") and skill (name "corex-manager")
        # are filtered individually below.
        #
        # NOTE: The "platform" team is created by coreX's self-registration
        # process (mcp_self_register.py). It is a real team in the DB, and
        # user-created servers/identities may belong to it. The import uses
        # the team name "platform" — if the target appliance does not have a
        # team with that name, the import will fail (which is the correct
        # safety behavior: it prevents creating a duplicate team and
        # orphaning resources onto it). Verify the team exists on the target
        # before applying.
        self._add_for_each_collection(
            mod, 'mcp_team', 'mcp_teams', Team,
            'Map of team name to configuration',
        )

        # Export MCP team IDs as a module output for cross-module reference
        mod.add_map_output('mcp_team_ids', 'mcp_team', 'Map of MCP team name to ID')

        # All teams are valid now (no team-level filter).
        mcp_team_map = self.name_maps.get('mcp_teams', {})
        valid_team_ids = set(mcp_team_map.keys())

        # Team members - team_id same-module FK, user_id cross-module FK
        user_map = self.name_maps.get('users', {})
        self._add_for_each_collection(
            mod, 'mcp_team_member', 'mcp_team_members', UserTeam,
            'Map of team member to configuration',
            name_fn=lambda ut: f"member_{mcp_team_map.get(ut.team_id, 'unknown')}_{user_map.get(ut.user_id, 'unknown')}",
            same_module_fks={'team_id': ('mcp_team', False)},
            cross_module_fks={'user_id': 'user_ids'},
            filter_fn=lambda ut: ut.team_id in valid_team_ids,
            add_output=False,
        )

        # Servers - exclude self-registered, team_id same-module FK, sensitive fields
        srv_secret_fields = {}
        if not (self.include_secrets or self.include_system_secrets):
            srv_secret_fields = {
                'auth_secret_enc': 'mcp_servers_auth_secrets',
                'oauth_client_secret_enc': 'mcp_servers_oauth_secrets',
                'env_vars_json': 'mcp_servers_env_vars',
            }
            self._add_secret_map_var(mod, 'mcp_servers_auth_secrets', 'MCP server auth secrets',
                                     name_map_key='mcp_servers')
            self._add_secret_map_var(mod, 'mcp_servers_oauth_secrets', 'MCP server OAuth client secrets',
                                     name_map_key='mcp_servers')
            # env_vars is a map in the provider (mapAttrSensitive), so the
            # secret var must be map(map(string)) — each server has a map of env vars.
            self._add_secret_map_var(mod, 'mcp_servers_env_vars', 'MCP server environment variables',
                                     name_map_key='mcp_servers',
                                     var_type='map(map(string))')

        self._add_for_each_collection(
            mod, 'mcp_server', 'mcp_servers', McpServer,
            'Map of MCP server name to configuration',
            same_module_fks={'team_id': ('mcp_team', False)},
            secret_fields=srv_secret_fields,
            filter_fn=lambda s: s.namespace != SELF_REGISTERED_SERVER_NAMESPACE and s.team_id in valid_team_ids,
            type_overrides={'args_json': 'list(string)', 'env_vars_json': 'map(string)'},
        )

        # Server replicas - server_id same-module FK
        mcp_server_map = self.name_maps.get('mcp_servers', {})
        self._add_for_each_collection(
            mod, 'mcp_server_replica', 'mcp_server_replicas', McpServerReplica,
            'Map of server replica to configuration',
            name_fn=lambda r: f"replica_{mcp_server_map.get(r.server_id, 'unknown')}_{r.id}",
            same_module_fks={'server_id': ('mcp_server', False)},
            filter_fn=lambda r: r.server_id in set(mcp_server_map.keys()),
            add_output=False,
        )

        # Identities - team_id same-module FK.
        # The provider has idp_user_info (non-sensitive) but not pat_hash.
        # pat_hash is in PROVIDER_FIELD_OVERRIDES skip set.
        # idp_user_info is NOT sensitive in the provider, so it's exported as
        # a regular field (not a secret).
        self._add_for_each_collection(
            mod, 'mcp_identity', 'mcp_identities', McpIdentity,
            'Map of MCP identity name to configuration',
            same_module_fks={'team_id': ('mcp_team', False)},
            filter_fn=lambda i: i.team_id in valid_team_ids,
        )

        # Policies - team_id same-module FK
        self._add_for_each_collection(
            mod, 'mcp_policy', 'mcp_policies', McpPolicy,
            'Map of MCP policy name to configuration',
            same_module_fks={'team_id': ('mcp_team', False)},
            filter_fn=lambda p: p.team_id in valid_team_ids,
            add_output=False,
        )

        # DLP rules - team_id same-module FK
        self._add_for_each_collection(
            mod, 'mcp_dlp_rule', 'mcp_dlp_rules', McpDlpRule,
            'Map of MCP DLP rule name to configuration',
            same_module_fks={'team_id': ('mcp_team', False)},
            filter_fn=lambda r: r.team_id in valid_team_ids,
            add_output=False,
        )

        # Guardrails - team_id same-module FK
        self._add_for_each_collection(
            mod, 'mcp_guardrail', 'mcp_guardrails', McpGuardrail,
            'Map of MCP guardrail name to configuration',
            same_module_fks={'team_id': ('mcp_team', False)},
            filter_fn=lambda g: g.team_id in valid_team_ids,
            add_output=False,
        )

        # Skills - exclude self-registered, team_id same-module FK
        self._add_for_each_collection(
            mod, 'mcp_skill', 'mcp_skills', McpSkill,
            'Map of MCP skill name to configuration',
            same_module_fks={'team_id': ('mcp_team', False)},
            filter_fn=lambda s: s.name != SELF_REGISTERED_SKILL_NAME and s.team_id in valid_team_ids,
        )

        # Skill versions - skill_id same-module FK, body/frontmatter exported as files
        # Filter out self-registered skill versions (they're managed by coreX, not Terraform)
        self_reg_skill_ids = {s.id for s in self._query_all(McpSkill) if s.name == SELF_REGISTERED_SKILL_NAME}
        # Always declare skill content variables so the root module can pass them
        mod.add_variable('mcp_skill_bodies', 'map(string)', 'Map of skill version key to body content', '{}')
        mod.add_variable('mcp_skill_frontmatters', 'any', 'Map of skill version key to frontmatter', '{}')
        # Always declare the collection variable, even when empty, so the root
        # module can pass it without "Unexpected argument" errors.
        skill_map = self.name_maps.get('mcp_skills', {})
        self._add_for_each_collection(
            mod, 'mcp_skill_version', 'mcp_skill_versions', McpSkillVersion,
            'Map of MCP skill version to configuration',
            name_fn=lambda sv: f"version_{skill_map.get(sv.skill_id, 'unknown')}_v{sv.version}",
            same_module_fks={'skill_id': ('mcp_skill', False)},
            skip_fields={'body', 'frontmatter'},
            # Filter out self-registered skill versions (same filter as tfvars)
            filter_fn=lambda sv: sv.skill_id not in self_reg_skill_ids,
            add_output=False,
        )

        # Always append body/frontmatter references from variables to the
        # skill_version resource block, even when empty. The provider requires
        # body (non-null) and optionally frontmatter.
        file_lines = [
            '',
            '  # Body and frontmatter from environment-specific variables',
            '  body        = try(var.mcp_skill_bodies[each.key], null)',
            '  frontmatter = try(var.mcp_skill_frontmatters[each.key], null)',
        ]
        last_block = mod.blocks[-1]
        mod.blocks[-1] = last_block.replace('}', '\n'.join(file_lines) + '\n}')

        # Export skill version body/frontmatter as files (only for non-self-registered)
        skill_versions = [sv for sv in self._query_all(McpSkillVersion)
                         if sv.skill_id not in self_reg_skill_ids]
        if skill_versions:
            for sv in skill_versions:
                row = _row_to_dict(sv)
                skill_name = skill_map.get(sv.skill_id, 'unknown')
                skill_slug = _sanitize_name(skill_name)
                # Use the same key as tfvars: version_{skill_slug}_v{version}
                sv_key = f"version_{skill_slug}_v{sv.version}"
                if row.get('body'):
                    fname = f'skills/{sv_key}.md'
                    self.extra_files[f'environments/dev/files/mcp-gateway/{fname}'] = row['body']
                if row.get('frontmatter'):
                    fname = f'skills/{sv_key}.json'
                    self.extra_files[f'environments/dev/files/mcp-gateway/{fname}'] = json.dumps(row['frontmatter'], indent=2)

        # MCP alert config — singleton with webhook_url and thresholds map
        mod.add_variable('mcp_alert_config', 'any', 'MCP alert configuration (singleton)', '{}')
        mod.add_section('MCP Alert Config')
        mod.blocks.append(
            'resource "corex_mcp_alert_config" "this" {\n'
            '  webhook_url = try(var.mcp_alert_config["webhook_url"], null)\n'
            '  thresholds  = try(var.mcp_alert_config["thresholds"], null)\n'
            '}'
        )

        return mod

    # ─── Root Files ─────────────────────────────────────────────────────────

    def _build_root_files(self, modules: Dict[str, Module]) -> Dict[str, str]:
        files = {}

        # Build tfvars data first (needed for variables.tf)
        tfvars_data = self._build_tfvars_data()

        # backend.tf — partial remote state config (key supplied per-env)
        files['backend.tf'] = self._generate_backend_tf()

        # Per-environment backend config with state key
        files['environments/dev.backend.tfvars'] = self._generate_backend_env_tfvars()

        # versions.tf — Terraform version + provider requirements
        files['versions.tf'] = self._generate_versions_tf()

        # providers.tf — provider configuration
        files['providers.tf'] = self._generate_providers_tf()

        # variables.tf (root-level: provider credentials + collection variables + secrets)
        files['variables.tf'] = self._generate_variables_tf(tfvars_data, modules)

        # main.tf (root module composition)
        files['main.tf'] = self._generate_main_tf(modules)

        # locals.tf (root file-content locals — only emitted if non-empty)
        root_locals = self._generate_root_locals_tf(modules)
        if root_locals:
            files['locals.tf'] = root_locals

        # outputs.tf
        files['outputs.tf'] = self._generate_outputs_tf(modules)

        # README.md
        files['README.md'] = self._generate_readme(modules)

        # .gitignore — standard Terraform ignores
        files['.gitignore'] = self._generate_gitignore()

        # environments/dev.tfvars — non-secret config (committable)
        files['environments/dev.tfvars'] = self._generate_environments_tfvars(tfvars_data)

        # environments/dev.secrets.tfvars — secret values (gitignored)
        files['environments/dev.secrets.tfvars'] = self._generate_environments_secrets_tfvars(tfvars_data)

        # environments/README.md — instructions for prod.tfvars
        files['environments/README.md'] = self._generate_environments_readme()

        # terraform.tfvars.example — placeholder values for secrets (gitignored)
        files['terraform.tfvars.example'] = self._generate_tfvars_example()

        # imports.tf — import blocks for existing resources (generated from DB state)
        files['imports.tf'] = self._generate_imports_tf(modules)

        return files

    def _generate_backend_tf(self) -> str:
        """Generate backend.tf with partial remote state config.

        The `key` is intentionally omitted — it's supplied per-environment via
        `terraform init -backend-config=environments/<env>.backend.tfvars`.
        This prevents two environments from sharing the same state file.
        """
        return '''# Remote state backend configuration
# Auto-generated by coreX Manager Terraform Export
#
# The `key` is omitted here — it is supplied per-environment via:
#   terraform init -backend-config=environments/dev.backend.tfvars
#
# This ensures dev and prod use separate state files:
#   corex/dev/terraform.tfstate  vs  corex/prod/terraform.tfstate
#
# Uncomment ONE backend block below and configure it for your environment.

# S3 + DynamoDB backend (AWS)
# terraform {
#   backend "s3" {
#     bucket         = "my-terraform-state"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "terraform-state-lock"
#     # key is supplied via -backend-config=environments/<env>.backend.tfvars
#   }
# }

# GCS backend (Google Cloud)
# terraform {
#   backend "gcs" {
#     bucket = "my-terraform-state"
#     # key is supplied via -backend-config=environments/<env>.backend.tfvars
#   }
# }
# Note: GCS buckets should have CMEK encryption enabled at the bucket level.

# Azure RM backend (Azure)
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "terraform-state-rg"
#     storage_account_name = "tfstate"
#     container_name       = "tfstate"
#     # key is supplied via -backend-config=environments/<env>.backend.tfvars
#   }
# }
# Note: Azure storage accounts should have encryption enabled (default in most regions).
'''

    def _generate_backend_env_tfvars(self) -> str:
        """Generate per-environment backend config with state key."""
        return (
            '# Per-environment backend configuration\n'
            '# Auto-generated by coreX Manager Terraform Export\n'
            '#\n'
            '# Usage: terraform init -backend-config=environments/dev.backend.tfvars\n'
            '#\n'
            '# This ensures dev state is separate from prod state.\n'
            '# Copy this file for other environments and change the key:\n'
            '#   environments/prod.backend.tfvars → key = "corex/prod/terraform.tfstate"\n'
            '\n'
            'key = "corex/dev/terraform.tfstate"\n'
        )

    def _generate_versions_tf(self) -> str:
        """Generate versions.tf with Terraform version and provider requirements.

        The provider is installed locally via `make install` (VERSION=dev by
        default). The version constraint accepts any version so the local
        dev build is picked up. Once published to the Terraform Registry,
        pin to a real version constraint (e.g. ~> 0.1).
        """
        return '''# Terraform and provider version constraints
# Auto-generated by coreX Manager Terraform Export

terraform {
  required_version = ">= 1.5"

  required_providers {
    corex = {
      source  = "ne4u/corex"
      # The provider is installed locally via `make install` (VERSION=dev).
      # Once published to the Terraform Registry, pin to a real version
      # (e.g. ~> 0.1) and remove the dev_overrides entry from ~/.terraformrc.
      version = ">= 0.0.1"
    }
  }
}
'''

    def _generate_providers_tf(self) -> str:
        """Generate providers.tf with provider configuration."""
        return '''# Provider configuration
# Auto-generated by coreX Manager Terraform Export

provider "corex" {
  host     = var.corex_host
  username = var.corex_username
  password = var.corex_password
}
'''

    def _generate_environments_readme(self) -> str:
        """Generate environments/README.md with instructions for creating prod.tfvars."""
        return '''# Environment Configuration

This directory contains environment-specific variable files for Terraform.

## File Structure

Each environment has two files:

- **`<env>.tfvars`** — Non-secret configuration. Safe to commit to version control.
- **`<env>.secrets.tfvars`** — Secret values (passwords, tokens, keys). Gitignored via `*.secrets.tfvars`.

## Development Environment

`dev.tfvars` contains the exported configuration from your development coreX Manager instance.
`dev.secrets.tfvars` contains secret placeholders (e.g. `"admin" = "change-me"`) keyed by
resource name so you know exactly which resources need secrets.

**Usage:**
```bash
terraform plan  -var-file=environments/dev.tfvars -var-file=environments/dev.secrets.tfvars
terraform apply -var-file=environments/dev.tfvars -var-file=environments/dev.secrets.tfvars
```

## Production Environment

1. **Copy dev files as a starting point:**
   ```bash
   cp environments/dev.tfvars         environments/prod.tfvars
   cp environments/dev.secrets.tfvars environments/prod.secrets.tfvars
   ```

2. **Review and modify `prod.tfvars` for production:**
   - Remove dev-only resources (test backends, debug listeners, etc.)
   - Update hostnames, ports, and domains for production
   - Adjust rate limits, timeouts, and thresholds
   - Review WAF rules and security policies
   - Ensure certificate references point to production certs

3. **Fill in `prod.secrets.tfvars` with real secret values** — or replace
   the file entirely with secrets manager references (see below).

4. **Apply to production:**
   ```bash
   terraform plan  -var-file=environments/prod.tfvars -var-file=environments/prod.secrets.tfvars
   terraform apply -var-file=environments/prod.tfvars -var-file=environments/prod.secrets.tfvars
   ```

## Secret Management

### Option 1: secrets.tfvars file (simplest)

Fill in `dev.secrets.tfvars` (or `prod.secrets.tfvars`) with real values.
The file is gitignored via `*.secrets.tfvars` so it won't be committed.

### Option 2: Secrets manager (recommended for production)

Replace the secrets tfvars file with a Terraform data source that pulls
secrets from your secrets manager at plan/apply time:

```hcl
# secrets.tf — data sources for secrets (commit this)
data "vault_generic_secret" "corex" {
  path = "secret/corex"
}

# Then pass values via -var-file or terraform.tfvars:
# dev.tfvars (non-secret, committable):
#   corex_host = "https://corex.prod.example.com"
#
# dev.secrets.tfvars (gitignored, or use TF_VAR_ env vars):
#   corex_password                = data.vault_generic_secret.corex.data["password"]
#   certificates_dns_credentials  = jsondecode(data.vault_generic_secret.corex.data["cert_dns_credentials"])
```

### Option 3: Environment variables

```bash
export TF_VAR_corex_password="..."
export TF_VAR_certificates_dns_credentials='{"wildcard":{"api_key":"..."}}'
terraform apply -var-file=environments/dev.tfvars
```

### Sensitive keys inside map variables

Some secrets are embedded inside map variables (`captcha_settings`, `ha_config`)
and shown as `"change-me"` placeholders in `dev.tfvars`. These can't be split into
a separate file because Terraform maps are single variables. For production,
replace the `"change-me"` values with real secrets or secrets manager references.
'''

    def _build_tfvars_data(self) -> Dict[str, Any]:
        """Build tfvars data structure from database for environments/dev.tfvars.
        
        Uses the generic _add_tfvars_collection helper to include ALL model fields
        with FK IDs replaced by resource keys.
        """
        tfvars = {}
        
        # SSL module
        cert_secret_fields = set()
        if not (self.include_secrets or self.include_certs):
            cert_secret_fields = {'dns_credentials'}
        self._add_tfvars_collection(tfvars, 'certificates', Certificate,
            secret_fields=cert_secret_fields,
            resource_type='certificate',
            value_transforms={
                'dns_credentials': lambda v: _try_json_parse(v),
            })
        self._add_tfvars_collection(tfvars, 'cipher_suites', CipherSuite,
            value_transforms={'tls_options': lambda v: v.split() if v else []})
        
        # SSL Labs settings — singleton per certificate.
        # cert_id is NOT included in tfvars — it's wired to the local
        # certificate resource ID in the module (corex_certificate.this[each.key].id).
        from ..services.ssllabs import get_max_scans_per_host
        max_scans = get_max_scans_per_host(self.db)
        ssl_labs_data = {}
        for cert in self._query_all(Certificate):
            cert_slug = _sanitize_name(cert.name)
            ssl_labs_data[cert_slug] = {
                'max_scans_per_host': max_scans,
            }
        if ssl_labs_data:
            tfvars['ssl_labs_settings'] = ssl_labs_data
        
        # Routing module
        self._add_tfvars_collection(tfvars, 'fcgi_apps', FcgiApp)
        self._add_tfvars_collection(tfvars, 'backends', Backend,
            same_module_fk_maps={'fcgi_app_id': 'fcgi_apps'},
            resource_type='backend')
        self._add_tfvars_collection(tfvars, 'servers', Server,
            same_module_fk_maps={'backend_id': 'backends'},
            resource_type='server')
        self._add_tfvars_collection(tfvars, 'listeners', Listener,
            cross_module_fks={'certificate_id': 'certificates'},
            same_module_fk_maps={'default_backend_id': 'backends'},
            fk_list_fields={'certificate_ids': 'certificates'},
            resource_type='listener')
        self._add_tfvars_collection(tfvars, 'backend_rules', BackendRule,
            same_module_fk_maps={'listener_id': 'listeners', 'backend_id': 'backends'})
        
        # Traffic module
        self._add_tfvars_collection(tfvars, 'error_pages', CustomErrorPage,
            name_fn=lambda ep: str(ep.code), skip_fields={'content'})
        self._add_tfvars_collection(tfvars, 'rate_limits', RateLimit,
            cross_module_fks={'listener_id': 'listeners'})
        self._add_tfvars_collection(tfvars, 'response_headers', ResponseHeader,
            cross_module_fks={'listener_id': 'listeners'},
            fk_list_fields={'listener_ids': 'listeners'})
        self._add_tfvars_collection(tfvars, 'request_headers', RequestHeader,
            cross_module_fks={'backend_id': 'backends'},
            fk_list_fields={'backend_ids': 'backends'})
        self._add_tfvars_collection(tfvars, 'redirects', Redirect,
            cross_module_fks={'listener_id': 'listeners'},
            fk_list_fields={'listener_ids': 'listeners'})
        self._add_tfvars_collection(tfvars, 'rewrites', Rewrite,
            cross_module_fks={'listener_id': 'listeners'},
            fk_list_fields={'listener_ids': 'listeners'})
        self._add_tfvars_collection(tfvars, 'response_transforms', ResponseTransform,
            cross_module_fks={'backend_id': 'backends'},
            fk_list_fields={'backend_ids': 'backends'})
        
        # Security lists
        self._add_tfvars_collection(tfvars, 'network_lists', NetworkList)
        self._add_tfvars_collection(tfvars, 'asn_lists', AsnList)
        self._add_tfvars_collection(tfvars, 'geo_lists', GeoList)
        self._add_tfvars_collection(tfvars, 'ja4_lists', Ja4List)
        self._add_tfvars_collection(tfvars, 'pattern_lists', PatternList)
        # Mark feed-managed lists so the module can split them into a
        # separate resource block with lifecycle { ignore_changes = [entries] }.
        feed_managed_map = {
            'network_lists': 'network',
            'asn_lists': 'asn',
            'geo_lists': 'geo',
            'ja4_lists': 'ja4',
            'pattern_lists': 'pattern',
        }
        for feed in self._query_all(DynamicFeed):
            lt = (feed.list_type or '').strip().lower()
            for var_name, type_key in feed_managed_map.items():
                if lt == type_key and var_name in tfvars:
                    # Find the sanitized key for this list
                    for list_cls in [NetworkList, AsnList, GeoList, Ja4List, PatternList]:
                        # Match by type_key and target_list_id
                        pass
                    # We need to find the list name by (type_key, target_list_id)
                    # and mark it feed_managed in tfvars.
                    list_cls_map = {
                        'network': NetworkList, 'asn': AsnList,
                        'geo': GeoList, 'ja4': Ja4List, 'pattern': PatternList,
                    }
                    cls = list_cls_map.get(type_key)
                    if cls:
                        lst = self.db.query(cls).filter(cls.id == feed.target_list_id).first()
                        if lst:
                            skey = _sanitize_name(lst.name)
                            if skey in tfvars[var_name]:
                                tfvars[var_name][skey]['feed_managed'] = True
        # Dynamic feeds: target_list_id is polymorphic — use list_type to resolve
        # against the correct list type's name map. Without this, IDs from
        # different tables would collide (each table has its own auto-increment).
        df_rows = self._query_all(DynamicFeed)
        if df_rows:
            df_data = {}
            # Map list_type values to name map keys.
            # Include both canonical and common variant forms.
            list_type_to_map = {
                'network': 'network_lists',
                'asn': 'asn_lists',
                'geo': 'geo_lists',
                'ja4': 'ja4_lists',
                'pattern': 'pattern_lists',
            }
            for row in df_rows:
                row_dict = _row_to_dict(row)
                key = _sanitize_name(str(getattr(row, 'name')))
                # Get list_type from row_dict (more reliable than row attribute
                # in case the object is detached from the session).
                # Normalize to lowercase for case-insensitive matching.
                feed_list_type = (row_dict.get('list_type') or '').strip().lower()
                entry = {}
                for k, v in row_dict.items():
                    if v is None:
                        continue
                    if k == 'name':
                        continue
                    if k == 'target_list_id':
                        # Use list_type to resolve against the correct name map.
                        # This is critical because each list type table has its
                        # own auto-increment, so ID 1 in network_lists is a
                        # different list from ID 1 in asn_lists.
                        map_name = list_type_to_map.get(feed_list_type)
                        if map_name:
                            name_map = self.name_maps.get(map_name, {})
                            if v in name_map:
                                entry[k] = name_map[v]
                            else:
                                # ID not found in the expected map — leave as-is
                                # (the module's coalesce() will handle it)
                                entry[k] = v
                        else:
                            # Unknown list_type — try all maps as fallback,
                            # but prefer the map that matches list_type prefix.
                            resolved = None
                            for mn in list_type_to_map.values():
                                name_map = self.name_maps.get(mn, {})
                                if v in name_map:
                                    resolved = name_map[v]
                                    break
                            if resolved is not None:
                                entry[k] = resolved
                    else:
                        entry[k] = v
                df_data[key] = entry
            tfvars['dynamic_feeds'] = df_data
        
        # Security rules
        self._add_tfvars_collection(tfvars, 'security_rules', SecurityRule,
            fk_list_fields={'listener_ids': 'listeners'},
            resource_type='security_rule')
        
        # WAF
        self._add_tfvars_collection(tfvars, 'waf_rules', WafRule,
            cross_module_fks={'listener_id': 'listeners', 'backend_id': 'backends'},
            resource_type='waf_rule',
            value_transforms={'http_methods': lambda v: [m for m in str(v).split(',') if m] if v else v})
        self._add_tfvars_collection(tfvars, 'waf_exceptions', WafException,
            same_module_fk_maps={'waf_rule_id': 'waf_rules'},
            resource_type='waf_exception')
        
        # Cache — nest rules under their config for readability
        backend_map = self.name_maps.get('backends', {})
        cc_overrides = _resolve_provider_overrides('cache_config', CacheConfig)
        cc_provider_skip = cc_overrides['skip']
        cc_provider_rename = cc_overrides['rename']
        cc_rows = self._query_all(CacheConfig)
        if cc_rows:
            cc_data = {}
            # Build a map of config_id → rules list
            rules_by_config = {}
            for cr in self._query_all(CacheRule):
                rules_by_config.setdefault(cr.cache_config_id, []).append({
                    'priority': cr.priority,
                    'enabled': cr.enabled,
                    'match_type': cr.match_type,
                    'pattern': cr.pattern,
                    'action': cr.action,
                    'tier': cr.tier,
                })
            for cc in cc_rows:
                row_dict = _row_to_dict(cc)
                key = f"cache_{backend_map.get(cc.backend_id, 'unknown')}"
                entry = {}
                for k, v in row_dict.items():
                    if v is None or k == 'name' or k in cc_provider_skip:
                        continue
                    tfvars_key = cc_provider_rename.get(k, k)
                    if k == 'backend_id':
                        name_map = self.name_maps.get('backends', {})
                        if v in name_map:
                            entry[tfvars_key] = name_map[v]
                    else:
                        entry[tfvars_key] = v
                # Nest rules under the config
                rules = rules_by_config.get(cc.id, [])
                if rules:
                    entry['rules'] = sorted(rules, key=lambda r: r.get('priority', 0))
                cc_data[key] = entry
            tfvars['cache_configs'] = cc_data
        
        # Observability
        self._add_tfvars_collection(tfvars, 'log_destinations', LogDestination,
            cross_module_fks={'listener_id': 'listeners'})
        self._add_tfvars_collection(tfvars, 'logged_fields', LoggedField,
            cross_module_fks={'listener_id': 'listeners'})
        
        # Page protect
        self._add_tfvars_collection(tfvars, 'page_protect_policies', PageProtectPolicy,
            fk_list_fields={'backend_ids': 'backends'})
        self._add_tfvars_collection(tfvars, 'page_protect_scripts', PageProtectScript,
            name_attr='url',
            filter_fn=lambda s: (s.source or '').lower() == 'manual',
            resource_type='page_protect_script')
        
        # Page protect settings (singleton)
        pp_settings = get_page_protect_settings(self.db)
        pp_data = {}
        pp_data['monitoring_enabled'] = pp_settings.get('monitoring_enabled', False)
        pp_data['change_detection_enabled'] = pp_settings.get('change_detection_enabled', False)
        pp_data['change_detection_interval_hours'] = pp_settings.get('change_detection_interval_hours', 24)
        pp_data['report_retention_days'] = pp_settings.get('report_retention_days', 7)
        pp_data['report_path'] = pp_settings.get('report_path', '')
        pp_data['beacon_injection_enabled'] = pp_settings.get('beacon_injection_enabled', False)
        pp_data['beacon_trust_enabled'] = pp_settings.get('beacon_trust_enabled', False)
        beacon_path = pp_settings.get('beacon_path', '')
        pp_data['beacon_paths'] = [beacon_path] if beacon_path else []
        ct = pp_settings.get('beacon_content_types', '')
        pp_data['beacon_content_types'] = [c.strip() for c in ct.split(',') if c.strip()] if ct else []
        pp_patterns = pp_settings.get('beacon_path_patterns', '')
        pp_data['beacon_patterns'] = [p.strip() for p in pp_patterns.split(',') if p.strip()] if pp_patterns else []
        pp_data['backend_ids'] = pp_settings.get('beacon_backend_ids', [])
        pp_data['auto_prune_stale_days'] = pp_settings.get('auto_prune_stale_days', 7)
        tfvars['page_protect_settings'] = pp_data
        
        # API Armor
        self._add_tfvars_collection(tfvars, 'auth_policies', AuthPolicy,
            fk_list_fields={'listener_ids': 'listeners', 'backend_ids': 'backends'},
            same_module_fk_maps={'api_key_list_id': 'api_key_lists'})
        # API key lists - with nested entries
        self._add_tfvars_collection(tfvars, 'api_key_lists', ApiKeyList)
        # Add entries as nested data inside each api_key_list
        api_key_entries = self._query_all(ApiKeyListEntry)
        if api_key_entries:
            list_map = self.name_maps.get('api_key_lists', {})
            entries_by_list = {}
            for ent in api_key_entries:
                list_key = list_map.get(ent.list_id)
                if list_key:
                    entries_by_list.setdefault(list_key, []).append(
                        {'value': ent.value, 'note': ent.note}
                    )
            if 'api_key_lists' in tfvars and entries_by_list:
                for lk, entries in entries_by_list.items():
                    if lk in tfvars['api_key_lists']:
                        tfvars['api_key_lists'][lk]['entries'] = entries
        self._add_tfvars_collection(tfvars, 'openapi_specs', OpenApiSpec,
            fk_list_fields={'listener_ids': 'listeners', 'backend_ids': 'backends'})
        self._add_tfvars_collection(tfvars, 'api_schemas', ApiSchema,
            same_module_fk_maps={'spec_id': 'openapi_specs'})
        
        # Risk scoring
        self._add_tfvars_collection(tfvars, 'risk_rulesets', RiskRuleset)
        self._add_tfvars_collection(tfvars, 'risk_rules', RiskRule,
            same_module_fk_maps={'ruleset_id': 'risk_rulesets'})
        
        # Management - users
        user_secret_fields = set()
        if not (self.include_secrets or self.include_users_identities):
            user_secret_fields = {'hashed_password', 'totp_secret'}
        self._add_tfvars_collection(tfvars, 'users', User, name_attr='username',
            secret_fields=user_secret_fields,
            resource_type='user')
        
        # Management - settings (key-value pairs)
        settings = self._query_all(Setting)
        exportable = [s for s in settings if s.key not in SKIP_SETTING_KEYS]
        if exportable:
            settings_data = {}
            for s in exportable:
                is_sensitive = s.key in SENSITIVE_SETTING_KEYS
                if not is_sensitive or self.include_secrets or self.include_system_secrets:
                    settings_data[s.key] = s.value or ''
            if settings_data:
                tfvars['settings'] = settings_data

        # Singleton configurations (global_options, captcha, maxmind, ha_config, api_armor_settings)
        self._add_singleton_tfvars(tfvars, self.db)
        
        # MCP Gateway — export all teams (including platform). Self-registered
        # server/skill are filtered individually by namespace/name.
        self._add_tfvars_collection(tfvars, 'mcp_teams', Team)
        mcp_team_map = self.name_maps.get('mcp_teams', {})
        valid_team_ids = set(mcp_team_map.keys())
        user_map = self.name_maps.get('users', {})
        self._add_tfvars_collection(tfvars, 'mcp_team_members', UserTeam,
            name_fn=lambda ut: f"member_{mcp_team_map.get(ut.team_id, 'unknown')}_{user_map.get(ut.user_id, 'unknown')}",
            same_module_fk_maps={'team_id': 'mcp_teams'},
            cross_module_fks={'user_id': 'users'},
            filter_fn=lambda ut: ut.team_id in valid_team_ids,
            resource_type='mcp_team_member')
        # MCP servers - secret fields: auth_secret_enc, oauth_client_secret_enc, env_vars_json
        srv_secret_fields = set()
        if not (self.include_secrets or self.include_system_secrets):
            srv_secret_fields = {'auth_secret_enc', 'oauth_client_secret_enc', 'env_vars_json'}
        self._add_tfvars_collection(tfvars, 'mcp_servers', McpServer,
            same_module_fk_maps={'team_id': 'mcp_teams'},
            secret_fields=srv_secret_fields,
            filter_fn=lambda s: s.namespace != 'corex-manager' and s.team_id in valid_team_ids,
            resource_type='mcp_server',
            value_transforms={
                'args_json': _try_json_parse,
                'env_vars_json': _try_json_parse,
            })
        mcp_server_map = self.name_maps.get('mcp_servers', {})
        self._add_tfvars_collection(tfvars, 'mcp_server_replicas', McpServerReplica,
            name_fn=lambda r: f"replica_{mcp_server_map.get(r.server_id, 'unknown')}_{r.id}",
            same_module_fk_maps={'server_id': 'mcp_servers'},
            filter_fn=lambda r: r.server_id in set(mcp_server_map.keys()),
            resource_type='mcp_server_replica')
        # MCP identities - secret fields: pat_hash, idp_user_info
        ident_secret_fields = set()
        if not (self.include_secrets or self.include_users_identities):
            ident_secret_fields = {'pat_hash', 'idp_user_info'}
        self._add_tfvars_collection(tfvars, 'mcp_identities', McpIdentity,
            same_module_fk_maps={'team_id': 'mcp_teams'},
            secret_fields=ident_secret_fields,
            filter_fn=lambda i: i.team_id in valid_team_ids,
            resource_type='mcp_identity')
        self._add_tfvars_collection(tfvars, 'mcp_policies', McpPolicy,
            same_module_fk_maps={'team_id': 'mcp_teams'},
            filter_fn=lambda p: p.team_id in valid_team_ids,
            resource_type='mcp_policy')
        self._add_tfvars_collection(tfvars, 'mcp_dlp_rules', McpDlpRule,
            same_module_fk_maps={'team_id': 'mcp_teams'},
            filter_fn=lambda r: r.team_id in valid_team_ids,
            resource_type='mcp_dlp_rule')
        self._add_tfvars_collection(tfvars, 'mcp_guardrails', McpGuardrail,
            same_module_fk_maps={'team_id': 'mcp_teams'},
            filter_fn=lambda g: g.team_id in valid_team_ids,
            resource_type='mcp_guardrail')
        self._add_tfvars_collection(tfvars, 'mcp_skills', McpSkill,
            same_module_fk_maps={'team_id': 'mcp_teams'},
            filter_fn=lambda s: s.name != 'corex-manager' and s.team_id in valid_team_ids,
            resource_type='mcp_skill')
        skill_map = self.name_maps.get('mcp_skills', {})
        # Filter out self-registered skill versions (same filter as the module builder)
        self_reg_skill_ids = {s.id for s in self._query_all(McpSkill) if s.name == 'corex-manager'}
        self._add_tfvars_collection(tfvars, 'mcp_skill_versions', McpSkillVersion,
            name_fn=lambda sv: f"version_{skill_map.get(sv.skill_id, 'unknown')}_v{sv.version}",
            same_module_fk_maps={'skill_id': 'mcp_skills'},
            skip_fields={'body', 'frontmatter'},
            filter_fn=lambda sv: sv.skill_id not in self_reg_skill_ids,
            resource_type='mcp_skill_version')
        
        # MCP alert config — singleton
        import os as _os
        alert_webhook = _os.environ.get('MCP_ALERT_WEBHOOK_URL', '')
        alert_thresholds = {}
        alert_row = self.db.query(Setting).filter(Setting.key == 'mcp_alert_thresholds').first()
        if alert_row and alert_row.value:
            try:
                alert_thresholds = json.loads(alert_row.value)
            except (json.JSONDecodeError, ValueError):
                pass
        tfvars['mcp_alert_config'] = {
            'webhook_url': alert_webhook,
            'thresholds': alert_thresholds,
        }
        
        return tfvars

    def _generate_environments_tfvars(self, tfvars_data: Dict[str, Any]) -> str:
        """Generate environments/dev.tfvars — non-secret config only.

        Secret map vars and singleton secret string vars are emitted to a
        separate dev.secrets.tfvars file (see _generate_environments_secrets_tfvars).
        Sensitive keys embedded inside map variables (ha_config) get 'change-me'
        placeholders here since the map can't be split across files. Captcha
        secrets are split into a separate captcha_secrets map in secrets.tfvars.
        """
        lines = [
            '# Development environment configuration',
            '# Auto-generated by coreX Manager Terraform Export',
            '# This file contains non-secret configuration and can be committed to git.',
            '# Secret values are in dev.secrets.tfvars (gitignored).',
            '',
            '# Environment name — must match the environments/<name>/files/ directory.',
            '# When copying to prod.tfvars, update this to "prod" so file() calls',
            '# read from environments/prod/files/ instead of environments/dev/files/.',
            'environment = "dev"',
            '',
            '# Provider connection (corex_password is in dev.secrets.tfvars)',
            'corex_host     = "https://corex.example.com:8000"  # Update with your coreX Manager URL',
            'corex_username = "admin"',
            '',
        ]

        # Emit each collection (secret vars are excluded — they go to secrets.tfvars)
        for key, value in sorted(tfvars_data.items()):
            # Skip secret vars — they go to dev.secrets.tfvars
            if key in self.secret_vars:
                continue
            if isinstance(value, dict):
                lines.append(f'{key} = {{')
                for k, v in value.items():
                    lines.append(f'  {_hcl_string(k)} = {_hcl_value(v)}')
                lines.append('}')
                lines.append('')
            else:
                lines.append(f'{key} = {_hcl_value(value)}')
                lines.append('')

        return '\n'.join(lines)

    def _generate_environments_secrets_tfvars(self, tfvars_data: Dict[str, Any] = None) -> str:
        """Generate environments/dev.secrets.tfvars — secret values only.

        This file is gitignored and intended to be replaced by a secrets manager
        in production (Vault, AWS Secrets Manager, etc.).
        Contains:
          - corex_password (provider credential)
          - Standalone secret map vars (mcp_servers_auth_secrets, etc.) with
            per-resource keys pre-populated
          - Singleton secret string vars (maxmind_license_key)
          - captcha_secrets map (cap_secret, recaptcha_secret, turnstile_secret)
        """
        tfvars_data = tfvars_data or {}
        lines = [
            '# Development environment secrets',
            '# Auto-generated by coreX Manager Terraform Export',
            '#',
            '# WARNING: This file contains sensitive values.',
            '# This file is gitignored — do NOT commit real secrets to version control.',
            '#',
            '# For production, replace this file with secrets manager references, e.g.:',
            '#   corex_password = data.vault_generic_secret.corex.data["password"]',
            '#   certificates_dns_credentials = jsondecode(data.vault_generic_secret.corex.data["cert_dns_credentials"])',
            '',
            '# Provider connection',
            'corex_password = "change-me"',
            '',
        ]

        if not self.include_secrets and self.secret_vars:
            lines.extend([
                '# ───────────────────────────────────────────────────────────',
                '# Secrets — fill in real values or replace with secrets manager',
                '# Map variables are keyed by resource name; string variables are singleton',
                '# ───────────────────────────────────────────────────────────',
                '',
            ])
            for var_name in sorted(self.secret_vars.keys()):
                vtype = self.secret_var_types.get(var_name, 'map')
                if vtype == 'string':
                    lines.append(f'{var_name} = "change-me"')
                elif var_name in tfvars_data and isinstance(tfvars_data[var_name], dict):
                    # Secret map with pre-populated keys (e.g. captcha_secrets)
                    lines.append(f'{var_name} = {{')
                    for k, v in sorted(tfvars_data[var_name].items()):
                        lines.append(f'  {_hcl_string(k)} = {_hcl_value(v)}')
                    lines.append('}')
                else:
                    lines.append(f'{var_name} = {{')
                    # Pre-populate with actual resource names from the name map
                    name_map_key = self.secret_var_name_maps.get(var_name)
                    name_map = self.name_maps.get(name_map_key, {}) if name_map_key else {}
                    hcl_type = self.secret_var_hcl_types.get(var_name)
                    if name_map:
                        for resource_name in sorted(name_map.values()):
                            if hcl_type == 'map(map(string))':
                                # dns_credentials is a map per cert, not a string
                                lines.append(f'  {_hcl_string(resource_name)} = {{}}')
                            else:
                                lines.append(f'  {_hcl_string(resource_name)} = "change-me"')
                    else:
                        lines.append(f'  # "<resource_name>" = "<secret_value>"')
                    lines.append('}')
                lines.append('')

        return '\n'.join(lines)

    def _generate_provider_tf(self) -> str:
        return '''# Terraform provider configuration for coreX Manager
# Auto-generated by coreX Manager Terraform Export

terraform {
  required_providers {
    corex = {
      source  = "ne4u/corex"
      version = ">= 0.0.1"
    }
  }
}

provider "corex" {
  host     = var.corex_host
  username = var.corex_username
  password = var.corex_password
}
'''

    def _generate_variables_tf(self, tfvars_data: Dict[str, Any], modules: Dict[str, 'Module']) -> str:
        lines = [
            '# Root-level variables',
            '# Auto-generated by coreX Manager Terraform Export',
            '',
            '# ───────────────────────────────────────────────────────────',
            '# Provider connection',
            '# ───────────────────────────────────────────────────────────',
            '',
            'variable "corex_host" {',
            '  type        = string',
            '  description = "coreX Manager API URL (e.g. https://corex.example.com:8000)"',
            '}',
            '',
            'variable "corex_username" {',
            '  type        = string',
            '  description = "coreX Manager admin username"',
            '}',
            '',
            'variable "corex_password" {',
            '  type        = string',
            '  description = "coreX Manager admin password"',
            '  sensitive   = true',
            '}',
            '',
            '# ───────────────────────────────────────────────────────────',
            '# Environment (used to locate environment-specific files)',
            '# ───────────────────────────────────────────────────────────',
            '',
            'variable "environment" {',
            '  type        = string',
            '  description = "Environment name (matches environments/<name>.tfvars and environments/<name>/files/)"',
            '  default     = "dev"',
            '}',
            '',
        ]

        # Build the complete set of collection variables that need to be declared.
        # This includes ALL collections referenced by any generated module,
        # not just the ones with data in tfvars. This ensures Terraform doesn't
        # fail with "variable not declared" when a collection is empty in one
        # environment but has data in another.
        all_collection_vars = {
            # SSL module
            'certificates': 'SSL/TLS certificates',
            'cipher_suites': 'TLS cipher suites',
            # Routing module
            'fcgi_apps': 'FastCGI applications',
            'backends': 'HAProxy backends',
            'servers': 'Backend servers',
            'listeners': 'HAProxy listeners',
            'backend_rules': 'Backend routing rules',
            # Traffic module
            'error_pages': 'Custom error pages',
            'rate_limits': 'Rate limiting rules',
            'response_headers': 'Response header modifications',
            'request_headers': 'Request header modifications',
            'redirects': 'HTTP redirects',
            'rewrites': 'URL rewrites',
            'response_transforms': 'Response transformations',
            # Security lists module
            'network_lists': 'Network IP/CIDR lists',
            'asn_lists': 'ASN lists',
            'geo_lists': 'Geolocation country code lists',
            'ja4_lists': 'JA4 TLS fingerprint lists',
            'pattern_lists': 'Pattern match lists',
            'dynamic_feeds': 'Dynamic security list feeds',
            # Security rules module
            'security_rules': 'Security filtering rules',
            # WAF module
            'waf_rules': 'WAF ruleset configurations',
            'waf_exceptions': 'WAF rule exceptions',
            # Cache module
            'cache_configs': 'Cache configurations per backend',
            # Observability module
            'log_destinations': 'Log destinations',
            'logged_fields': 'Custom logged fields',
            # Page protect module
            'page_protect_policies': 'Page protect CSP policies',
            'page_protect_scripts': 'Page protect scripts',
            'page_protect_settings': 'Page protect settings (singleton)',
            # API Armor module
            'auth_policies': 'API authentication policies',
            'api_key_lists': 'API key lists',
            'openapi_specs': 'OpenAPI specifications',
            'api_schemas': 'API schemas',
            # Risk scoring module
            'risk_rulesets': 'Risk scoring rulesets',
            'risk_rules': 'Risk scoring rules',
            # Management module
            'users': 'User accounts',
            'settings': 'System settings',
            'haproxy_global_options': 'HAProxy global options (list of objects)',
            'captcha_settings': 'Captcha configuration',
            'captcha_secrets': 'Captcha secret keys (cap_secret, recaptcha_secret, turnstile_secret)',
            'maxmind_license_key': 'MaxMind license key',
            'ha_config': 'HA configuration',
            'api_armor_settings': 'API Armor global settings',
            # MCP Gateway module
            'mcp_teams': 'MCP Gateway teams',
            'mcp_team_members': 'MCP Gateway team members',
            'mcp_servers': 'MCP Gateway servers',
            'mcp_server_replicas': 'MCP Gateway server replicas',
            'mcp_identities': 'MCP Gateway identities',
            'mcp_policies': 'MCP Gateway policies',
            'mcp_dlp_rules': 'MCP Gateway DLP rules',
            'mcp_guardrails': 'MCP Gateway guardrails',
            'mcp_skills': 'MCP Gateway skills',
            'mcp_skill_versions': 'MCP Gateway skill versions',
            'mcp_alert_config': 'MCP alert configuration (singleton)',
            # SSL module extras
            'ssl_labs_settings': 'SSL Labs settings per certificate',
        }

        # Determine which modules were generated, and only declare variables
        # for collections belonging to those modules.
        module_collections_map = {
            'ssl': ['certificates', 'cipher_suites', 'ssl_labs_settings'],
            'routing': ['fcgi_apps', 'backends', 'servers', 'listeners', 'backend_rules'],
            'traffic': ['error_pages', 'rate_limits', 'response_headers',
                       'request_headers', 'redirects', 'rewrites', 'response_transforms'],
            'security-lists': ['network_lists', 'asn_lists', 'geo_lists', 'ja4_lists',
                              'pattern_lists', 'dynamic_feeds'],
            'security-rules': ['security_rules'],
            'waf': ['waf_rules', 'waf_exceptions'],
            'cache': ['cache_configs'],
            'observability': ['log_destinations', 'logged_fields'],
            'page-protect': ['page_protect_policies', 'page_protect_scripts', 'page_protect_settings'],
            'api-armor': ['api_armor_settings', 'auth_policies', 'api_key_lists', 'openapi_specs', 'api_schemas'],
            'risk-scoring': ['risk_rulesets', 'risk_rules'],
            'management': ['users', 'settings', 'haproxy_global_options', 'captcha_settings',
                          'captcha_secrets', 'ha_config'],
            'mcp-gateway': ['mcp_teams', 'mcp_team_members', 'mcp_servers', 'mcp_server_replicas',
                          'mcp_identities', 'mcp_policies', 'mcp_dlp_rules', 'mcp_guardrails',
                          'mcp_skills', 'mcp_skill_versions', 'mcp_alert_config'],
        }

        # Collect all variable names that belong to generated modules
        declared_vars = set()
        for mod_name, col_list in module_collections_map.items():
            if mod_name in modules:
                declared_vars.update(col_list)

        # Also include any variables that have data in tfvars (covers singleton
        # variables that are conditionally generated)
        declared_vars.update(tfvars_data.keys())

        # Remove vars that are declared as secret vars (they're declared separately)
        declared_vars -= set(self.secret_vars.keys())

        if declared_vars:
            lines.extend([
                '# ───────────────────────────────────────────────────────────',
                '# Resource collections (environment-specific)',
                '# ───────────────────────────────────────────────────────────',
                '',
            ])

            for key in sorted(declared_vars):
                desc = all_collection_vars.get(key, f'{key.replace("_", " ").title()} configuration')
                # Special-case variables that are not map(object) collections.
                # maxmind_license_key is a plain string.
                if key == 'maxmind_license_key':
                    lines.extend([
                        f'variable "{key}" {{',
                        f'  type        = string',
                        f'  description = "{desc}"',
                        f'  default     = ""',
                        f'}}',
                        '',
                    ])
                else:
                    var_type = self.collection_types.get(key, 'any')
                    # Lists default to [], maps default to {}
                    default_val = '[]' if var_type.startswith('list(') else '{}'
                    lines.extend([
                        f'variable "{key}" {{',
                        f'  type        = {var_type}',
                        f'  description = "{desc}"',
                        f'  default     = {default_val}',
                        f'}}',
                        '',
                    ])

        # Add environment-specific file content variables (read from environments/<env>/files/)
        file_content_var_types = {
            'cert_fullchains': ('map(string)', 'Map of cert name to fullchain PEM content'),
            'cert_keys': ('map(string)', 'Map of cert name to private key PEM content'),
            'error_page_contents': ('map(string)', 'Map of error page code to HTML content'),
            'network_list_entries': ('any', 'Map of network list name to entries'),
            'asn_list_entries': ('any', 'Map of ASN list name to entries'),
            'geo_list_entries': ('any', 'Map of geo list name to entries'),
            'ja4_list_entries': ('any', 'Map of JA4 list name to entries'),
            'pattern_list_entries': ('any', 'Map of pattern list name to entries'),
            'mcp_skill_bodies': ('map(string)', 'Map of skill version key to body content'),
            'mcp_skill_frontmatters': ('any', 'Map of skill version key to frontmatter'),
        }
        # Only declare variables for modules that exist
        active_file_vars = set()
        for mod_name in modules:
            active_file_vars.update(self._get_module_file_content_vars(mod_name, modules).keys())
        if active_file_vars:
            lines.extend([
                '# ───────────────────────────────────────────────────────────',
                '# Environment-specific file content (read from environments/<env>/files/)',
                '# ───────────────────────────────────────────────────────────',
                '',
            ])
            for var_name in sorted(active_file_vars):
                vtype, desc = file_content_var_types.get(var_name, ('any', var_name))
                lines.extend([
                    f'variable "{var_name}" {{',
                    f'  type        = {vtype}',
                    f'  description = "{desc}"',
                    f'  default     = {{}}',
                    f'}}',
                    '',
                ])

        # Add secret variables
        if not self.include_secrets and self.secret_vars:
            lines.extend([
                '# ───────────────────────────────────────────────────────────',
                '# Secrets (variable placeholders)',
                '# ───────────────────────────────────────────────────────────',
                '',
            ])
            for var_name, desc in sorted(self.secret_vars.items()):
                vtype = self.secret_var_types.get(var_name, 'map')
                hcl_type = self.secret_var_hcl_types.get(var_name)
                vtype_hcl = hcl_type or ('string' if vtype == 'string' else 'map(string)')
                lines.extend([
                    f'variable "{var_name}" {{',
                    f'  type        = {vtype_hcl}',
                    f'  description = {_hcl_string(desc)}',
                    f'  sensitive   = true',
                    f'}}',
                    '',
                ])

        return '\n'.join(lines)

    def _generate_tfvars_example(self) -> str:
        lines = [
            '# Example terraform.tfvars — copy to terraform.tfvars and fill in real values',
            '# Auto-generated by coreX Manager Terraform Export',
            '',
            '# Provider connection',
            'corex_host     = "https://corex.example.com:8000"',
            'corex_username = "admin"',
            'corex_password = "change-me"',
            '',
        ]

        if not self.include_secrets:
            for var_name in sorted(self.secret_vars.keys()):
                vtype = self.secret_var_types.get(var_name, 'map')
                if vtype == 'string':
                    lines.append(f'{var_name} = "change-me"')
                else:
                    lines.append(f'{var_name} = {{')
                    name_map_key = self.secret_var_name_maps.get(var_name)
                    name_map = self.name_maps.get(name_map_key, {}) if name_map_key else {}
                    if name_map:
                        for resource_name in sorted(name_map.values()):
                            lines.append(f'  {_hcl_string(resource_name)} = "change-me"')
                    else:
                        lines.append(f'  # "<resource_name>" = "<secret_value>"')
                    lines.append('}')
            if self.secret_vars:
                lines.append('')

        return '\n'.join(lines)

    def _get_module_file_content_vars(self, mod_name: str, modules: Dict[str, Module]) -> Dict[str, str]:
        """Return {var_name: expression} for environment-specific file content
        that needs to be read from environments/<env>/files/ and passed to a module.

        The expression uses file() with path.module so it resolves relative to
        the root module, where environments/<env>/files/ lives.
        """
        # Only generate file content vars if the module exists and has data
        if mod_name not in modules:
            return {}

        # Map of module_name → {var_name: (file_subdir, file_pattern, decoder)}
        # file_pattern uses ${each.key} or ${k} which we translate to Terraform for expressions
        file_var_map: Dict[str, Dict[str, str]] = {
            'ssl': {
                'cert_fullchains': '{ for k, v in var.certificates : k => v.provider_name == "custom" ? try(file("${path.module}/environments/${var.environment}/files/ssl/${k}_fullchain.pem"), "") : "" }',
                'cert_keys': '{ for k, v in var.certificates : k => v.provider_name == "custom" ? try(file("${path.module}/environments/${var.environment}/files/ssl/${k}_key.pem"), "") : "" }',
            },
            'traffic': {
                'error_page_contents': '{ for k, v in var.error_pages : k => try(file("${path.module}/environments/${var.environment}/files/traffic/error_${k}.html"), "") }',
            },
            'security-lists': {
                'network_list_entries': '{ for k, v in var.network_lists : k => try(v.feed_managed, false) ? [] : try(jsondecode(file("${path.module}/environments/${var.environment}/files/security-lists/network_${k}.json")), []) }',
                'asn_list_entries': '{ for k, v in var.asn_lists : k => try(v.feed_managed, false) ? [] : try(jsondecode(file("${path.module}/environments/${var.environment}/files/security-lists/asn_${k}.json")), []) }',
                'geo_list_entries': '{ for k, v in var.geo_lists : k => try(v.feed_managed, false) ? [] : try(jsondecode(file("${path.module}/environments/${var.environment}/files/security-lists/geo_${k}.json")), []) }',
                'ja4_list_entries': '{ for k, v in var.ja4_lists : k => try(v.feed_managed, false) ? [] : try(jsondecode(file("${path.module}/environments/${var.environment}/files/security-lists/ja4_${k}.json")), []) }',
                'pattern_list_entries': '{ for k, v in var.pattern_lists : k => try(v.feed_managed, false) ? [] : try(jsondecode(file("${path.module}/environments/${var.environment}/files/security-lists/pattern_${k}.json")), []) }',
            },
            'mcp-gateway': {
                'mcp_skill_bodies': '{ for k, v in var.mcp_skill_versions : k => try(file("${path.module}/environments/${var.environment}/files/mcp-gateway/skills/${k}.md"), "") }',
                # Provider wants frontmatter as a JSON string, not a decoded object.
                # Pass the raw file content (which is JSON) as a string.
                'mcp_skill_frontmatters': '{ for k, v in var.mcp_skill_versions : k => try(file("${path.module}/environments/${var.environment}/files/mcp-gateway/skills/${k}.json"), null) }',
            },
        }
        return file_var_map.get(mod_name, {})

    def _generate_root_locals_tf(self, modules: Dict[str, Module]) -> str:
        """Generate root locals.tf with file-content expressions.

        Environment-specific file content (certs, error pages, list entries,
        skill bodies) is read from environments/<env>/files/ and exposed as
        locals so module arguments stay clean and missing files are skipped.
        """
        all_file_locals: Dict[str, str] = {}
        for mod_name in modules:
            file_content_vars = self._get_module_file_content_vars(mod_name, modules)
            for var_name, expr in file_content_vars.items():
                all_file_locals[var_name] = expr

        if not all_file_locals:
            return ''

        lines = [
            '# Root locals — file content expressions',
            '# Auto-generated by coreX Manager Terraform Export',
            '',
            '# Environment-specific file content (certs, error pages, list entries,',
            '# skill bodies) is read from environments/<env>/files/ and exposed as',
            '# locals so module arguments stay clean and missing files are skipped.',
            'locals {',
        ]
        for var_name, expr in sorted(all_file_locals.items()):
            lines.append(f'  {var_name} = {expr}')
        lines.append('}')
        return '\n'.join(lines) + '\n'

    def _generate_main_tf(self, modules: Dict[str, Module]) -> str:
        lines = [
            '# Root module — composes all submodules',
            '# Auto-generated by coreX Manager Terraform Export',
            '',
            '# Module dependency graph:',
            '#   ssl → (no cross-module deps)',
            '#   routing ← ssl (cert IDs)',
            '#   traffic ← routing (listener IDs, backend IDs)',
            '#   waf ← routing (listener IDs, backend IDs)',
            '#   security-rules ← routing (listener IDs)',
            '#   security-lists → (internal list refs only)',
            '#   observability ← routing (listener IDs)',
            '#   page-protect ← routing (backend IDs)',
            '#   api-armor ← routing (listener IDs, backend IDs)',
            '#   cache ← routing (backend IDs)',
            '#   mcp-gateway ← management (user IDs)',
            '#   management, risk-scoring → (no cross-module deps)',
            '',
        ]

        # Map module names to their collection variables
        module_collections = {
            'ssl': ['certificates', 'cipher_suites', 'ssl_labs_settings'],
            'routing': ['fcgi_apps', 'backends', 'servers', 'listeners', 'backend_rules'],
            'traffic': ['error_pages', 'rate_limits', 'response_headers', 
                       'request_headers', 'redirects', 'rewrites', 'response_transforms'],
            'security-lists': ['network_lists', 'asn_lists', 'geo_lists', 'ja4_lists', 
                              'pattern_lists', 'dynamic_feeds'],
            'security-rules': ['security_rules'],
            'waf': ['waf_rules', 'waf_exceptions'],
            'cache': ['cache_configs'],
            'observability': ['log_destinations', 'logged_fields'],
            'page-protect': ['page_protect_policies', 'page_protect_scripts', 'page_protect_settings'],
            'api-armor': ['api_armor_settings', 'auth_policies', 'api_key_lists', 'openapi_specs', 'api_schemas'],
            'risk-scoring': ['risk_rulesets', 'risk_rules'],
            'management': ['users', 'settings', 'haproxy_global_options', 'captcha_settings',
                          'captcha_secrets', 'ha_config'],
            'mcp-gateway': ['mcp_teams', 'mcp_team_members', 'mcp_servers', 'mcp_server_replicas',
                          'mcp_identities', 'mcp_policies', 'mcp_dlp_rules', 'mcp_guardrails',
                          'mcp_skills', 'mcp_skill_versions', 'mcp_alert_config'],
        }

        # Cross-module dependencies (ID maps passed between modules)
        module_dependencies = {
            'ssl': {},
            'traffic': {
                'listener_ids': 'module.routing.listener_ids',
                'backend_ids': 'module.routing.backend_ids',
            },
            'security-lists': {},
            'security-rules': {
                'listener_ids': 'module.routing.listener_ids',
            },
            'waf': {
                'listener_ids': 'module.routing.listener_ids',
                'backend_ids': 'module.routing.backend_ids',
            },
            'observability': {
                'listener_ids': 'module.routing.listener_ids',
            },
            'page-protect': {
                'backend_ids': 'module.routing.backend_ids',
            },
            'api-armor': {
                'listener_ids': 'module.routing.listener_ids',
                'backend_ids': 'module.routing.backend_ids',
            },
            'risk-scoring': {},
            'management': {},
            'routing': {
                'certificate_ids': 'module.ssl.certificate_ids',
            },
            'cache': {
                'backend_ids': 'module.routing.backend_ids',
            },
            'mcp-gateway': {
                'user_ids': 'module.management.user_ids',
            },
        }

        for mod_name in sorted(module_collections.keys()):
            if mod_name not in modules:
                continue
            
            lines.append(f'module "{mod_name.replace("-", "_")}" {{')
            lines.append(f'  source = "./modules/{mod_name}"')
            lines.append('')
            
            # Pass collection variables
            passed_vars = set()
            for col_var in module_collections[mod_name]:
                lines.append(f'  {col_var} = var.{col_var}')
                passed_vars.add(col_var)
            
            # Pass cross-module dependencies
            if mod_name in module_dependencies and module_dependencies[mod_name]:
                lines.append('')
                lines.append('  # Cross-module dependencies')
                for var_name, value in module_dependencies[mod_name].items():
                    # Only wire if the source module exists
                    src_module = value.split('.')[1]
                    if src_module.replace('_', '-') in modules:
                        lines.append(f'  {var_name} = {value}')
            
            # Pass secret map variables referenced by this module.
            # Skip any already passed as collection vars to avoid duplicates.
            secret_vars = sorted(getattr(self, 'module_secret_vars', {}).get(mod_name, set()))
            secret_vars = [v for v in secret_vars if v not in passed_vars]
            if secret_vars:
                lines.append('')
                lines.append('  # Secrets')
                for var_name in secret_vars:
                    lines.append(f'  {var_name} = var.{var_name}')

            # Pass environment-specific file content variables (from root locals)
            file_content_vars = self._get_module_file_content_vars(mod_name, modules)
            if file_content_vars:
                lines.append('')
                lines.append('  # Environment-specific file content (from root locals)')
                for var_name in file_content_vars:
                    lines.append(f'  {var_name} = local.{var_name}')

            lines.append('}')
            lines.append('')

        return '\n'.join(lines)

    def _generate_imports_tf(self, modules: Dict[str, Module]) -> str:
        """Generate import blocks for existing resources.

        Import blocks allow `terraform plan` to show the diff between the
        current state and the configuration, rather than trying to create
        duplicates. Each block maps a Terraform resource address (using the
        sanitized for_each key) to the provider import ID.

        Import ID formats (verified against provider ImportState implementations):
        - 'name':      provider tries name first, then numeric ID (most resources)
        - 'numeric':   provider accepts numeric row ID only (server, backend_rule,
                       cache_rule, waf_exception, error_page, response_header,
                       request_header, response_transform, logged_field,
                       mcp_skill_version, mcp_server_replica)
        - 'backend_id': cache_config imported by backend name (provider resolves
                       via ListBackends, falls back to numeric backend_id)
        - 'cache_rule': cache_rule keyed by "{config_key}_{priority}", ID is numeric row ID
        - 'composite':  mcp_team_member uses "{team_name}:{user_username}" (provider
                       resolves via ListMcpTeams/ListUsers, falls back to numeric IDs)
        - 'key':        setting uses the setting key string
        - 'username':   user uses the username string
        - 'feed_managed': feed-managed lists target .feed_managed, not .this
        - 'singleton':   singleton resources (global_options, captcha_settings,
                         ha_config, api_armor_settings)
                         use a fixed identifier; import ID is arbitrary

        Singleton resources now have ImportState in the provider and can be
        imported. The import ID is arbitrary (the provider sets the fixed
        singleton ID on Read).
        """
        tfvars = self._build_tfvars_data()

        # (var_name, resource_type, mod_name, id_mode, model_cls_or_None)
        # id_mode: 'name' = use 'name' field from tfvars
        #          'username' = use 'username' field from tfvars
        #          'key' = use the tfvars map key directly
        #          'numeric' = query DB for row.id
        #          'backend_id' = query DB for backend name (portable; provider resolves via ListBackends)
        #          'composite' = query DB, build "{team_name}:{user_username}" (portable; provider resolves via API)
        #          'feed_managed' = target .feed_managed, use name from tfvars
        #          'singleton' = fixed identifier; import ID is arbitrary (provider sets ID on Read)
        import_specs = [
            # SSL — by name
            ('certificates', 'certificate', 'ssl', 'name', None),
            ('cipher_suites', 'cipher_suite', 'ssl', 'name', None),
            # Routing
            ('fcgi_apps', 'fcgi_app', 'routing', 'name', None),
            ('backends', 'backend', 'routing', 'name', None),
            ('servers', 'server', 'routing', 'numeric', Server),
            ('listeners', 'listener', 'routing', 'name', None),
            ('backend_rules', 'backend_rule', 'routing', 'numeric', BackendRule),
            # Traffic
            ('error_pages', 'error_page', 'traffic', 'numeric', CustomErrorPage),
            ('rate_limits', 'rate_limit', 'traffic', 'name', None),
            ('response_headers', 'response_header', 'traffic', 'numeric', ResponseHeader),
            ('request_headers', 'request_header', 'traffic', 'numeric', RequestHeader),
            ('redirects', 'redirect', 'traffic', 'name', None),
            ('rewrites', 'rewrite', 'traffic', 'name', None),
            ('response_transforms', 'response_transform', 'traffic', 'numeric', ResponseTransform),
            # Security lists — by name (feed-managed handled separately)
            ('network_lists', 'network_list', 'security-lists', 'name', None),
            ('asn_lists', 'asn_list', 'security-lists', 'name', None),
            ('geo_lists', 'geo_list', 'security-lists', 'name', None),
            ('ja4_lists', 'ja4_list', 'security-lists', 'name', None),
            ('pattern_lists', 'pattern_list', 'security-lists', 'name', None),
            ('dynamic_feeds', 'dynamic_feed', 'security-lists', 'name', None),
            # Security rules — by name
            ('security_rules', 'security_rule', 'security-rules', 'name', None),
            # WAF
            ('waf_rules', 'waf_rule', 'waf', 'name', None),
            ('waf_exceptions', 'waf_exception', 'waf', 'numeric', WafException),
            # Cache
            ('cache_configs', 'cache_config', 'cache', 'backend_id', CacheConfig),
            ('cache_rules', 'cache_rule', 'cache', 'cache_rule', CacheRule),
            # Observability
            ('log_destinations', 'log_destination', 'observability', 'name', None),
            ('logged_fields', 'logged_field', 'observability', 'numeric', LoggedField),
            # Page protect — by name/URL
            ('page_protect_policies', 'page_protect_policy', 'page-protect', 'name', None),
            ('page_protect_scripts', 'page_protect_script', 'page-protect', 'url', None),
            # API armor — by name
            ('auth_policies', 'api_armor_auth_policy', 'api-armor', 'name', None),
            ('api_key_lists', 'api_armor_api_key_list', 'api-armor', 'name', None),
            ('openapi_specs', 'api_armor_openapi_spec', 'api-armor', 'name', None),
            # Risk scoring
            ('risk_rulesets', 'risk_ruleset', 'risk-scoring', 'name', None),
            ('risk_rules', 'risk_rule', 'risk-scoring', 'name', None),
            # Management
            ('users', 'user', 'management', 'username', None),
            ('settings', 'setting', 'management', 'key', None),
            # MCP gateway
            ('mcp_teams', 'mcp_team', 'mcp-gateway', 'name', None),
            ('mcp_team_members', 'mcp_team_member', 'mcp-gateway', 'composite', UserTeam),
            ('mcp_servers', 'mcp_server', 'mcp-gateway', 'name', None),
            ('mcp_server_replicas', 'mcp_server_replica', 'mcp-gateway', 'numeric', McpServerReplica),
            ('mcp_identities', 'mcp_identity', 'mcp-gateway', 'name', None),
            ('mcp_policies', 'mcp_policy', 'mcp-gateway', 'name', None),
            ('mcp_dlp_rules', 'mcp_dlp_rule', 'mcp-gateway', 'name', None),
            ('mcp_guardrails', 'mcp_guardrail', 'mcp-gateway', 'name', None),
            ('mcp_skills', 'mcp_skill', 'mcp-gateway', 'name', None),
            ('mcp_skill_versions', 'mcp_skill_version', 'mcp-gateway', 'numeric', McpSkillVersion),
            # Singletons — importable via fixed identifier (provider ImportState
            # accepts any ID and sets the fixed singleton ID on Read)
            ('haproxy_global_options', 'global_options', 'management', 'singleton', None),
            ('captcha_settings', 'captcha_settings', 'management', 'singleton', None),
            ('ha_config', 'ha_config', 'management', 'singleton', None),
            ('api_armor_settings', 'api_armor_settings', 'api-armor', 'singleton', None),
            ('page_protect_settings', 'page_protect_settings', 'page-protect', 'singleton', None),
            ('mcp_alert_config', 'mcp_alert_config', 'mcp-gateway', 'singleton', None),
            # SSL Labs settings — singleton per cert, import by cert ID (string)
            ('ssl_labs_settings', 'ssl_labs_settings', 'ssl', 'ssl_labs_cert_id', None),
        ]

        lines = [
            '# Import blocks for existing coreX resources',
            '# Auto-generated by coreX Manager Terraform Export',
            '#',
            '# These blocks tell Terraform about resources that already exist in coreX',
            '# so `terraform plan`/`apply` can adopt them into state without recreating.',
            '# The generated config (modules/*.tf) defines the desired state; these',
            '# import blocks map existing coreX objects to Terraform addresses so the',
            '# first plan shows in-place/no-op updates instead of creating duplicates.',
            '#',
            '# After a successful import (resources are in state), you can remove this',
            '# file or keep it — Terraform 1.5+ import blocks are no-ops once the',
            '# resource is in state.',
            '#',
            '# Import ID formats:',
            '#   name       — provider resolves by resource name (most resources)',
            '#   numeric    — provider requires the numeric row ID',
            '#   backend_id — cache_config imported by backend name (portable)',
            '#   cache_rule — cache_rule keyed by "{config_key}_{priority}", numeric row ID',
            '#   composite  — mcp_team_member uses "{team_name}:{user_username}" (portable)',
            '#   key        — settings use the setting key string',
            '#   singleton  — fixed identifier; import ID is arbitrary (provider sets ID on Read)',
            '#   url        — page protect scripts use the script URL as import ID',
            '#   ssl_labs_cert_id — SSL Labs settings use the certificate ID as import ID',
            '#',
            '# Singleton resources (captcha_settings, ha_config,',
            '# api_armor_settings, global_options, page_protect_settings,',
            '# mcp_alert_config) now have ImportState',
            '# in the provider and are imported above.',
            '',
        ]

        mod_keys = {m.replace('-', '_'): m for m in modules}
        import_count = 0

        for var_name, resource_type, mod_name, id_mode, model_cls in import_specs:
            if mod_name.replace('-', '_') not in mod_keys:
                continue

            mod_addr = mod_name.replace('-', '_')

            # ── Feed-managed lists: target .feed_managed, not .this ──
            if id_mode == 'name' and var_name in (
                'network_lists', 'asn_lists', 'geo_lists',
                'ja4_lists', 'pattern_lists',
            ):
                # Get feed-managed keys from tfvars
                col_data = tfvars.get(var_name, {})
                if not col_data:
                    continue
                for key, entry in col_data.items():
                    if not isinstance(entry, dict) or not entry.get('feed_managed'):
                        continue
                    import_id = entry.get('name', key)
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.feed_managed["{key}"]')
                    lines.append(f'  id = "{import_id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1
                # Continue to also generate .this imports for non-feed-managed below

            # ── Name-based imports (from tfvars) ──
            if id_mode in ('name', 'username'):
                col_data = tfvars.get(var_name, {})
                if not col_data:
                    continue
                id_field = 'username' if id_mode == 'username' else 'name'
                for key, entry in col_data.items():
                    # Skip feed-managed lists (handled above)
                    if isinstance(entry, dict) and entry.get('feed_managed'):
                        continue
                    if isinstance(entry, dict) and id_field in entry:
                        import_id = entry[id_field]
                    else:
                        import_id = key
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{key}"]')
                    lines.append(f'  id = "{import_id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── Key-based imports (settings) ──
            elif id_mode == 'key':
                col_data = tfvars.get(var_name, {})
                if not col_data:
                    continue
                for key in col_data:
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{key}"]')
                    lines.append(f'  id = "{key}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── Numeric ID imports (query DB for row.id) ──
            elif id_mode == 'numeric':
                if model_cls is None:
                    continue
                name_map = self.name_maps.get(var_name, {})
                if not name_map:
                    continue
                rows = self._query_all(model_cls)
                for row in rows:
                    tf_key = name_map.get(row.id)
                    if not tf_key:
                        continue
                    # Skip keys that indicate a filtered-out parent (e.g. "unknown"
                    # skill name for self-registered skill versions).
                    if '_unknown_' in tf_key or tf_key.endswith('_unknown'):
                        continue
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{tf_key}"]')
                    lines.append(f'  id = "{row.id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── Backend name imports (cache_config keyed by backend name) ──
            # The provider resolves the backend name to a numeric backend_id
            # via ListBackends, making the import portable across instances.
            elif id_mode == 'backend_id':
                if model_cls is None:
                    continue
                name_map = self.name_maps.get(var_name, {})
                if not name_map:
                    continue
                # Build backend_id → original backend name map for portable imports
                backend_name_by_id = {
                    b.id: b.name for b in self._query_all(Backend)
                }
                rows = self._query_all(model_cls)
                for row in rows:
                    tf_key = name_map.get(row.id)
                    if not tf_key:
                        continue
                    if '_unknown_' in tf_key or tf_key.endswith('_unknown'):
                        continue
                    import_id = backend_name_by_id.get(row.backend_id, str(row.backend_id))
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{tf_key}"]')
                    lines.append(f'  id = "{import_id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── Composite name imports (mcp_team_member: "{team_name}:{user_username}") ──
            # The provider resolves team name/slug and username to numeric IDs
            # via ListMcpTeams and ListUsers, making the import portable.
            elif id_mode == 'composite':
                if model_cls is None:
                    continue
                name_map = self.name_maps.get(var_name, {})
                if not name_map:
                    continue
                # Build team_id → name and user_id → username maps for portable imports
                team_name_by_id = {
                    t.id: t.name for t in self._query_all(Team)
                }
                user_username_by_id = {
                    u.id: u.username for u in self._query_all(User)
                }
                rows = self._query_all(model_cls)
                for row in rows:
                    tf_key = name_map.get(row.id)
                    if not tf_key:
                        continue
                    if '_unknown_' in tf_key or tf_key.endswith('_unknown'):
                        continue
                    team_name = team_name_by_id.get(row.team_id, str(row.team_id))
                    user_username = user_username_by_id.get(row.user_id, str(row.user_id))
                    composite_id = f'{team_name}:{user_username}'
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{tf_key}"]')
                    lines.append(f'  id = "{composite_id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── Cache rule imports (keyed by "{config_key}_{priority}") ──
            # Cache rules are nested inside cache_configs in tfvars and flattened
            # by the module into corex_cache_rule.this["{config_key}_{priority}"].
            # The import ID is the numeric row ID.
            elif id_mode == 'cache_rule':
                if model_cls is None:
                    continue
                # Build a map of cache_config_id → config_key from tfvars
                cc_data = tfvars.get('cache_configs', {})
                if not isinstance(cc_data, dict) or not cc_data:
                    continue
                # Reverse map: config_id (from DB) → config_key (from tfvars)
                # We need to query CacheConfig to get the backend_id → config_key mapping
                backend_map = self.name_maps.get('backends', {})
                cc_rows = self._query_all(CacheConfig)
                cc_id_to_key = {}
                for cc in cc_rows:
                    cc_key = f"cache_{backend_map.get(cc.backend_id, 'unknown')}"
                    cc_id_to_key[cc.id] = cc_key
                rows = self._query_all(model_cls)
                for row in rows:
                    config_key = cc_id_to_key.get(row.cache_config_id)
                    if not config_key:
                        continue
                    tf_key = f"{config_key}_{row.priority}"
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{tf_key}"]')
                    lines.append(f'  id = "{row.id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── Singleton imports (fixed identifier, no for_each) ──
            # Singletons use a fixed ID in the provider; the import ID is
            # arbitrary (the provider sets the correct ID on Read).
            elif id_mode == 'singleton':
                # Only emit if the singleton has data in tfvars
                col_data = tfvars.get(var_name, {})
                if not col_data:
                    continue
                lines.append(f'import {{')
                lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this')
                lines.append(f'  id = "{var_name}"')
                lines.append(f'}}')
                lines.append('')
                import_count += 1

            # ── URL-based imports (page_protect_script: import by URL) ──
            elif id_mode == 'url':
                col_data = tfvars.get(var_name, {})
                if not col_data:
                    continue
                for key, entry in col_data.items():
                    import_id = entry.get('url', key) if isinstance(entry, dict) else key
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{key}"]')
                    lines.append(f'  id = "{import_id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

            # ── SSL Labs settings imports (singleton per cert, import by numeric cert ID) ──
            # The provider's Read parses state.ID as the cert ID (integer).
            # The resource block wires cert_id to corex_certificate.this[each.key].id,
            # so the import ID must be the numeric cert ID from the DB.
            elif id_mode == 'ssl_labs_cert_id':
                col_data = tfvars.get(var_name, {})
                if not col_data:
                    continue
                # Build cert_slug → cert_id map from DB
                cert_id_by_slug = {
                    _sanitize_name(c.name): c.id for c in self._query_all(Certificate)
                }
                for key in col_data:
                    cert_id = cert_id_by_slug.get(key)
                    if cert_id is None:
                        continue
                    lines.append(f'import {{')
                    lines.append(f'  to = module.{mod_addr}.corex_{resource_type}.this["{key}"]')
                    lines.append(f'  id = "{cert_id}"')
                    lines.append(f'}}')
                    lines.append('')
                    import_count += 1

        if import_count == 0:
            lines.append('# No importable resources found in the current configuration.')
            lines.append('')

        lines.append(f'# Total: {import_count} import block(s)')
        lines.append('')

        return '\n'.join(lines)

    def _generate_outputs_tf(self, modules: Dict[str, Module]) -> str:
        lines = [
            '# Root outputs — expose key resource IDs for downstream use',
            '# Auto-generated by coreX Manager Terraform Export',
            '',
        ]

        # Re-export key module outputs at root level
        root_outputs = {
            'routing': ['backend_ids', 'listener_ids'],
            'ssl': ['certificate_ids'],
            'management': ['user_ids'],
            'security-lists': ['network_list_ids', 'asn_list_ids', 'geo_list_ids',
                              'ja4_list_ids', 'pattern_list_ids'],
            'waf': ['waf_rule_ids'],
            'mcp-gateway': ['mcp_team_ids'],
        }

        for mod_name, output_names in root_outputs.items():
            if mod_name not in modules:
                continue
            mod = modules[mod_name]
            mod_var = mod_name.replace('-', '_')
            for out_name in output_names:
                if any(out_name in o for o in mod.outputs):
                    lines.append(f'output "{mod_var}_{out_name}" {{')
                    lines.append(f'  description = "{mod_name} module: {out_name}"')
                    lines.append(f'  value       = module.{mod_var}.{out_name}')
                    lines.append('}')
                    lines.append('')

        return '\n'.join(lines)

    @staticmethod
    def _generate_gitignore() -> str:
        return """\
.terraform/
*.tfstate
*.tfstate.*
crash.log
terraform.tfvars
*.secrets.tfvars
override.tf
override.tf.json
# Real certificate/key files — placeholder PEMs under environments/*/files/ssl/
# are safe to commit. Add real cert paths here if you export with include_certs.
# *.real.pem
# *.real.key
"""

    def _generate_readme(self, modules: Dict[str, Module]) -> str:
        mod_list = '\n'.join(f'- **{m.name}** — {m.description}' for m in modules.values())
        # Build the tree from actual generated modules
        mod_tree = '\n'.join(f'    ├── {m.name}/' for m in modules.values())
        return f'''# coreX Terraform Configuration

Auto-generated by coreX Manager Terraform Export on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}.

## Overview

This project manages coreX Manager resources via the
[terraform-provider-corex](https://github.com/ne4u/terraform-provider-corex)
provider. It is structured as reusable modules that use `for_each` to iterate over
resource collections, enabling the same configuration to be deployed to multiple
environments (dev, prod, staging) with different `.tfvars` files.

## Structure

```
.
├── backend.tf                 # remote state config (key supplied per-env)
├── versions.tf                # Terraform + provider version constraints
├── providers.tf               # provider configuration
├── main.tf                    # module composition (no resources)
├── variables.tf               # root variable declarations
├── outputs.tf                 # root outputs
├── .gitignore
├── README.md                  # this file
├── environments/
│   ├── dev.tfvars             # dev environment values (auto-generated from DB)
│   ├── dev.secrets.tfvars     # dev secret values (gitignored)
│   ├── dev.backend.tfvars     # dev state key for remote backend
│   ├── dev/                   # dev environment files (certs, error pages, etc.)
│   │   └── files/
│   └── (copy for prod.tfvars, prod.secrets.tfvars, prod.backend.tfvars, prod/)
└── modules/
{mod_tree}
```

## Modules

{mod_list}

## Usage

### Development Environment

Apply the auto-generated dev configuration:

```bash
# Initialize Terraform (with per-environment state key)
terraform init -backend-config=environments/dev.backend.tfvars

# Review the plan
terraform plan -var-file=environments/dev.tfvars -var-file=environments/dev.secrets.tfvars

# Apply
terraform apply -var-file=environments/dev.tfvars -var-file=environments/dev.secrets.tfvars
```

### Production Environment

1. **Create `environments/prod.tfvars`** from dev (see below)
2. **Create `environments/prod.backend.tfvars`** with `key = "corex/prod/terraform.tfstate"`
3. **Create `environments/prod.secrets.tfvars`** with production secret values
4. **Configure remote state** — uncomment a backend in `backend.tf`
5. **Apply to production:**

```bash
terraform init -backend-config=environments/prod.backend.tfvars
terraform plan -var-file=environments/prod.tfvars -var-file=environments/prod.secrets.tfvars
terraform apply -var-file=environments/prod.tfvars -var-file=environments/prod.secrets.tfvars
```

## Reusable Module Architecture

Each module uses `for_each` to iterate over resource collections. For example:

```hcl
# modules/routing/main.tf
resource "corex_backend" "this" {{
  for_each = var.backends
  name     = try(each.value.name, each.key)
  mode     = try(each.value.mode, null)
  # ...
}}
```

```hcl
# environments/dev.tfvars
backends = {{
  web_backend = {{ name = "web-backend", mode = "http" }}
  api_backend = {{ name = "api-backend", mode = "http" }}
}}
```

This enables:
- **Multiple environments** — same modules, different `.tfvars`
- **Multiple instances** — instantiate modules multiple times
- **Clean separation** — resource logic in modules, data in environment files

## Notes & Limitations

### Users (import-only for identity fields)

The provider's `corex_user` resource has a write-only `password` field but no
`hashed_password` or `totp_secret` field. Existing password hashes and TOTP
secrets cannot be round-tripped through the provider. Users are imported with
their current identity attributes (username, role, email, etc.), but
**passwords must be set out-of-band** after import (e.g. via the UI or the
password reset flow).

### MCP identities (PATs cannot be round-tripped)

The provider's `corex_mcp_identity` resource has a computed `pat_prefix` field
but no `pat_hash` field. Existing PAT hashes cannot be round-tripped. Identities
are imported with their current attributes, but **PATs must be regenerated**
after import if you need new tokens.

### CAPTCHA keys (not exported)

`corex_captcha_key` resources are not exported because Cap site keys are managed
by the external Cap service (a separate HTTP API at `CAP_SERVICE_URL`), not by
the coreX Manager backend database. There is no backend table or model
representing Cap keys. To manage Cap keys, use the Cap service API directly or
the coreX Manager UI (System → CAPTCHA → Cap Keys).

### Page protect settings (field name mapping)

The backend stores page protect settings with different field names than the
provider expects. The exporter maps these automatically:
- `beacon_path` (string) → `beacon_paths` (list)
- `beacon_content_types` (comma-separated string) → `beacon_content_types` (list)
- `beacon_path_patterns` (comma-separated string) → `beacon_patterns` (list)
- `beacon_backend_ids` (JSON list) → `backend_ids` (list of int)

## Importing Existing Resources

If coreX already has resources configured (e.g. via the UI or API), the export
includes an `imports.tf` file with `import` blocks for every existing resource.
Run `terraform plan` — Terraform will adopt the existing objects into state and
show in-place/no-op updates instead of trying to create duplicates. After a
successful apply, the resources are in state and the import blocks become no-ops
(Terraform 1.5+); you can keep or delete `imports.tf`.

You can also import resources manually with `terraform import`:

```bash
# Import a backend by name (matches the for_each key)
terraform import module.routing.corex_backend.this["web_backend"] web-backend

# Import a listener
terraform import module.routing.corex_listener.this["https"] https

# Import a certificate
terraform import module.ssl.corex_certificate.this["example_com"] example.com
```

## Customizing for Production

This export is a starting point from a dev environment. To adapt for production:

1. **Copy dev.tfvars → prod.tfvars** and update values
2. **Remove dev-only resources** — test backends, debug listeners, etc.
3. **Update values** — production hostnames, ports, rate limits, WAF policies
4. **Review secrets** — use Vault, AWS Secrets Manager, or `TF_VAR_*` env vars
5. **Configure remote state** — uncomment a backend in `backend.tf`
6. **Run `terraform fmt -recursive`** to ensure consistent formatting

## Managing Secrets

Secrets are exported as `sensitive` variable placeholders. **Never commit real
secret values to version control.** Choose one of these approaches for production:

### Option 1: Separate secrets tfvars (gitignored)

Fill in `environments/dev.secrets.tfvars` (already in `.gitignore`):

```hcl
certificates_dns_credentials = {{
  "wildcard" = {{
    api_key = "..."
  }}
}}
```

### Option 2: Environment variables (CI/CD)

Set `TF_VAR_*` environment variables in your CI/CD pipeline:

```bash
export TF_VAR_certificates_dns_credentials='{{"wildcard":{{"api_key":"..."}}}}'
export TF_VAR_mcp_servers_auth_secrets='{{"tools":"secret-token"}}'
terraform apply
```

### Option 3: Secret manager (recommended for production)

Replace variable references with `data` sources from your secret manager.

### State file security

Regardless of approach, the **Terraform state file** will contain secret values.
Protect it by:

- Using **remote state** with encryption at rest (S3 + KMS, Terraform Cloud, etc.)
- Restricting state access to authorized CI/CD and users only
- **Never committing `.tfstate`** to version control (ensure `.tfstate` is gitignored)
'''

    # ─── ZIP Creation ───────────────────────────────────────────────────────

    def _create_zip(self, modules: Dict[str, Module], root_files: Dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Root files
            for filename, content in root_files.items():
                zf.writestr(filename, content)

            # Module files
            for mod_name, mod in modules.items():
                prefix = f'modules/{mod_name}/'
                zf.writestr(f'{prefix}main.tf', mod.main_tf())
                # Only emit locals.tf if the module has actual locals
                if mod.locals_blocks:
                    zf.writestr(f'{prefix}locals.tf', mod.locals_tf())
                zf.writestr(f'{prefix}variables.tf', mod.variables_tf())
                zf.writestr(f'{prefix}outputs.tf', mod.outputs_tf())
                # Only emit README.md if the module has real content
                if mod.has_real_readme:
                    zf.writestr(f'{prefix}README.md', mod.readme())

            # Extra files (error page HTML, etc.)
            for filename, content in self.extra_files.items():
                zf.writestr(filename, content)

        return buf.getvalue()


# ─── Public API ─────────────────────────────────────────────────────────────

def generate_terraform_export(
    db: Session,
    include_secrets: bool = False,
    include_certs: bool = False,
    include_users_identities: bool = False,
    include_system_secrets: bool = False,
) -> bytes:
    """Generate a Terraform configuration ZIP from the current coreX database state.

    Args:
        db: SQLAlchemy session
        include_secrets: If True, all sensitive values are included inline (master override).
        include_certs: If True, cert PEM files and dns credentials are included inline.
        include_users_identities: If True, user passwords and MCP identity secrets are included inline.
        include_system_secrets: If True, system secrets (MaxMind key, captcha secrets,
                               MCP server auth secrets, HA passwords) are included inline.
        When a category flag is False, those secrets become variable placeholders.

    Returns:
        ZIP archive bytes containing the Terraform project.
    """
    exporter = TerraformExporter(
        db,
        include_secrets=include_secrets,
        include_certs=include_certs,
        include_users_identities=include_users_identities,
        include_system_secrets=include_system_secrets,
    )
    return exporter.generate()
