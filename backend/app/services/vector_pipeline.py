"""Vector log-pipeline service.

Generates ``vector.toml`` for the managed Vector sidecar/service from the
``vector_sinks`` table (1-to-1 source-per-sink model), and drives the
file lifecycle (write, .applied snapshot, container restart).

Sources are auto-enabled when at least one enabled sink references them —
no separate source toggles needed. The source is selected when creating
a sink, and ``get_vector_sources()`` derives the active set from enabled
sinks.

Secrets (API keys, passwords, tokens) are stored Fernet-encrypted inside the
``options`` JSON column (values prefixed ``enc:``), decrypted at render time
and inlined into the generated TOML on the shared data volume. The plaintext
is collected and returned so API surfaces can redact it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.logging import VectorSink
from ..schemas.vector import REQUIRED_OPTIONS, SECRET_MASK, SECRET_OPTIONS, VALID_SOURCES
from .settings import get_setting, set_setting

logger = logging.getLogger(__name__)
settings = get_settings()

DEFAULT_SOURCES = {"corex": False, "waf": False, "mcp": False}

# Terminal transform per source — sinks consume these.
TERMINAL_TRANSFORMS = {
    "corex": "haproxy_finalize",
    "waf": "waf_parse_json",
    "mcp": "mcp_parse_json",
}

DEFAULT_INDEX = {
    "corex": "corex-log-%Y.%m.%d",
    "waf": "waf-logs-%Y.%m.%d",
    "mcp": "mcp-events-%Y.%m.%d",
}

ENC_PREFIX = "enc:"


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

_fernet: Optional[Fernet] = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    key = settings.VECTOR_SECRETS_KEY or os.environ.get("VECTOR_SECRETS_KEY") or settings.SECRET_KEY
    if not key:
        raise RuntimeError(
            "No secret key material available for vector sink secrets. "
            'Set VECTOR_SECRETS_KEY (python -c "import secrets; print(secrets.token_urlsafe(32))")'
        )
    derived = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), b"corex-vector-secrets", 100_000, dklen=32)
    _fernet = Fernet(base64.urlsafe_b64encode(derived))
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Vector sink secret decryption failed")


def is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(ENC_PREFIX)


def encrypt_sink_options(sink_type: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt secret option fields in-place-safe; returns a new dict.

    Values that are already ``enc:``-prefixed or equal to the mask sentinel
    are left untouched (mask is resolved against the stored row by the API).
    """
    out = dict(options or {})
    for key in SECRET_OPTIONS.get(sink_type, []):
        v = out.get(key)
        if isinstance(v, str) and v and not is_encrypted(v) and v != SECRET_MASK:
            out[key] = ENC_PREFIX + encrypt_secret(v)
    return out


def decrypt_sink_options(sink_type: str, options: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Return (options with decrypted secret fields, [decrypted plaintexts])."""
    out = dict(options or {})
    plaintexts: List[str] = []
    for key in SECRET_OPTIONS.get(sink_type, []):
        v = out.get(key)
        if is_encrypted(v):
            plain = decrypt_secret(v[len(ENC_PREFIX):])
            out[key] = plain
            plaintexts.append(plain)
    return out, plaintexts


def mask_sink_options(sink_type: str, options: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(options or {})
    for key in SECRET_OPTIONS.get(sink_type, []):
        v = out.get(key)
        if isinstance(v, str) and v:
            out[key] = SECRET_MASK
    return out


def redact_text(text: str, secrets: List[str]) -> str:
    out = text
    for s in secrets:
        if s:
            out = out.replace(s, SECRET_MASK)
    return out


# Vector TOML option names that carry secrets — masked in diffs/previews so
# credentials never appear in API responses (covers previously-applied files
# whose plaintext may differ from the current DB values).
_TOML_SECRET_KEYS = (
    "default_api_key", "secret_access_key", "session_token",
    "client_secret", "password", "api_key", "license_key",
    "default_token", "token",
)
_TOML_SECRET_RE = re.compile(
    r'(?m)^(\s*(?:' + "|".join(_TOML_SECRET_KEYS) + r')\s*=\s*)"[^"]*"'
)


def redact_vector_text(text: str) -> str:
    """Mask secret option values in a rendered vector.toml."""
    return _TOML_SECRET_RE.sub(rf'\1"{SECRET_MASK}"', text or "")


# ---------------------------------------------------------------------------
# Sources setting
# ---------------------------------------------------------------------------

def get_vector_sources(db: Session) -> Dict[str, bool]:
    """Derive the active sources from enabled sinks.

    A source is 'active' when at least one enabled sink references it.
    This eliminates the need for separate source toggles — the source is
    selected and auto-enabled when a sink is configured for it.
    """
    from ..models.logging import VectorSink
    try:
        active = {s.source for s in db.query(VectorSink).filter(
            VectorSink.enabled == True  # noqa: E712
        ).all() if s.source}
    except Exception:
        active = set()
    return {k: (k in active) for k in VALID_SOURCES}


def vector_syslog_target() -> str:
    """HAProxy log target for the managed coreX source (e.g. vector:601).

    Uses plain UDP syslog (HAProxy's default) so Docker service names resolve
    at runtime. HAProxy 3.4's tcp@ protocol prefix requires an IP address,
    not a hostname — set VECTOR_SYSLOG_TARGET to tcp@<ip>:601 if you need TCP
    transport and know the IP ahead of time.
    """
    return getattr(settings, "VECTOR_SYSLOG_TARGET", "vector:601")


def corex_source_enabled(db: Optional[Session]) -> bool:
    if db is None:
        return False
    try:
        return get_vector_sources(db).get("corex", False)
    except Exception:
        return False


def vector_pipeline_active(db: Optional[Session]) -> bool:
    """True when the pipeline is configured (any source enabled or sinks exist).

    Used to decide whether vector.toml participates in config status/diff so
    installs that never use Vector don't get a permanent 'unapplied' flag.
    """
    if db is None:
        return False
    try:
        if any(get_vector_sources(db).values()):
            return True
        from ..models.logging import VectorSink
        return db.query(VectorSink).count() > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# TOML helpers
# ---------------------------------------------------------------------------

def _toml_str(v: str) -> str:
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{s}"'


def _toml_val(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_val(x) for x in v) + "]"
    return _toml_str(str(v))


def _component_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", str(name).strip())
    if not safe or safe[0].isdigit():
        safe = f"s_{safe}"
    return safe


def _opt(options: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        v = options.get(k)
        if v is not None and v != "":
            return v
    return default


def _opt_bool(options: Dict[str, Any], key: str) -> Optional[bool]:
    v = options.get(key)
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# VRL transforms (ported verbatim from the corex-logging reference vector.toml)
# ---------------------------------------------------------------------------

_HAPROXY_PARSE_JSON = r'''
# The syslog source puts the HAProxy JSON log line in .message
parsed, err = parse_json(.message)
if err == null {
  . = merge!(., parsed)
} else {
  # Not JSON — likely an HAProxy internal log message (e.g. SSL handshake
  # errors, connection errors). These have the format:
  #   <client_ip>:<client_port> [<timestamp>] <backend>/<conn>: <message>
  # Parse them into structured fields so they don't get dropped.
  raw = to_string(.message) ?? ""
  # Extract client_ip:client_port (before the first space)
  ip_port_match, ip_port_err = parse_regex(raw, r'^(?P<client>[0-9a-fA-F:.]+):(?P<client_port>\d+)\s+')
  if ip_port_err == null {
    .client = ip_port_match.client
    .client_port = to_int(ip_port_match.client_port) ?? null
  }
  # Extract [timestamp] (HAProxy's %t format: 13/Sep/2026:01:55:49.531)
  ts_match, ts_err = parse_regex(raw, r'\[(?P<ts>[^\]]+)\]')
  if ts_err == null {
    ts_raw = to_string(ts_match.ts) ?? ""
    parsed_ts, pt_err = parse_timestamp(ts_raw, format: "%d/%b/%Y:%H:%M:%S%.3f")
    if pt_err == null {
      .@timestamp = to_string(parsed_ts)
    }
  }
  # Extract backend/conn and message (after the timestamp)
  be_match, be_err = parse_regex(raw, r'\]\s+(?P<backend>[^\s]+):\s+(?P<message>.+)$')
  if be_err == null {
    .backend = be_match.backend
    .message = to_string(be_match.message) ?? ""
  }
  # Mark as an internal HAProxy log (not a request log)
  .haproxy_internal = true
}
# Preserve syslog metadata under _syslog_ prefix for debugging
._syslog_facility = to_string(.facility) ?? ""
._syslog_severity = to_string(.severity) ?? ""
._syslog_hostname = to_string(.hostname) ?? ""
._syslog_version = to_string(.version) ?? ""
# Drop the raw syslog metadata fields so they don't clutter the sink output
del(.facility)
del(.severity)
del(.hostname)
del(.version)

# HAProxy sends "-" for numeric fields when no value is available (e.g. WAF
# fields when no WAF rules matched, timing fields for error responses).
# Structured sinks reject "-" for integer/long-mapped fields, so convert to null.
if (to_string(.waf_anomaly_score) ?? "") == "-" { .waf_anomaly_score = null }
if (to_string(.waf_rule_id) ?? "") == "-" { .waf_rule_id = null }
if (to_string(.risk_score) ?? "") == "-" { .risk_score = null }
if (to_string(.risk_rules_hit_count) ?? "") == "-" { .risk_rules_hit_count = null }
if (to_string(.be_response_time) ?? "") == "-" { .be_response_time = null }
if (to_string(.be_connect_time) ?? "") == "-" { .be_connect_time = null }
if (to_string(.total_time) ?? "") == "-" { .total_time = null }
if (to_string(.bytes_out) ?? "") == "-" { .bytes_out = null }
if (to_string(.status) ?? "") == "-" { .status = null }
if (to_string(.client_port) ?? "") == "-" { .client_port = null }
if (to_string(.unique_id_client_port) ?? "") == "-" { .unique_id_client_port = null }
if (to_string(.unique_id_timestamp) ?? "") == "-" { .unique_id_timestamp = null }
if (to_string(.unique_id_request_counter) ?? "") == "-" { .unique_id_request_counter = null }
if (to_string(.unique_id_pid) ?? "") == "-" { .unique_id_pid = null }
if (to_string(.ja4_cipher_count) ?? "") == "-" { .ja4_cipher_count = null }
if (to_string(.ja4_ext_count) ?? "") == "-" { .ja4_ext_count = null }
if (to_string(.req_fp_path_depth) ?? "") == "-" { .req_fp_path_depth = null }
if (to_string(.req_fp_hdr_count) ?? "") == "-" { .req_fp_hdr_count = null }
if (to_string(.req_fp_status) ?? "") == "-" { .req_fp_status = null }
if (to_string(.req_fp_body_bytes) ?? "") == "-" { .req_fp_body_bytes = null }

# xff (X-Forwarded-For) is a string; the json converter emits "-" when missing.
if (to_string(.xff) ?? "") == "-" { .xff = null }

# referer is a string; the json converter emits "-" when missing.
if (to_string(.referer) ?? "") == "-" { .referer = null }

# Common timestamp field for cross-index correlation (combined index pattern).
# HAProxy's ts field is in format "03/Sep/2026:01:28:04.092" — parse to ISO 8601,
# then drop the redundant source time fields.
# Skip for internal logs (already parsed above) — only parse for request logs.
if !exists(.haproxy_internal) || .haproxy_internal != true {
  ts_raw = to_string(.ts) ?? ""
  if ts_raw != "" {
    parsed_ts, parse_err = parse_timestamp(ts_raw, format: "%d/%b/%Y:%H:%M:%S%.3f")
    if parse_err == null {
      .@timestamp = to_string(parsed_ts)
    } else {
      .@timestamp = now()
    }
  } else {
    .@timestamp = now()
  }
  # Drop redundant source time fields; @timestamp is the canonical one.
  del(.ts)
  del(.timestamp)
}
'''

_DECODE_JA4 = r'''
if !exists(.ja4) || .ja4 == null || .ja4 == "" || .ja4 == "-" {
  .ja4 = ""
} else {
  parts = split!(.ja4, "_")
  if length(parts) >= 3 {
    a = to_string(parts[0])
    .ja4_a = a
    .ja4_b = to_string(parts[1])
    .ja4_c = to_string(parts[2])

    # Split JA4_a into its 6 components (only if long enough)
    if length(a) >= 10 {
      .ja4_proto = slice!(a, start: 0, end: 1)
      .ja4_version = slice!(a, start: 1, end: 3)
      .ja4_sni = slice!(a, start: 3, end: 4)
      .ja4_cipher_count = to_int(slice!(a, start: 4, end: 6)) ?? 0
      .ja4_ext_count = to_int(slice!(a, start: 6, end: 8)) ?? 0
      .ja4_alpn = slice!(a, start: 8, end: 10)
      .ja4_cipher_hash = parts[1]
      .ja4_ext_hash = parts[2]
    }
  }

  # Decode proto to human-readable protocol name
  if .ja4_proto == "t" {
    .ja4_protocol = "TLS"
  } else if .ja4_proto == "d" {
    .ja4_protocol = "DTLS"
  } else if .ja4_proto == "q" {
    .ja4_protocol = "QUIC"
  } else {
    .ja4_protocol = .ja4_proto
  }

  # Decode version to human-readable TLS version
  if .ja4_version == "13" {
    .ja4_tls_version = "TLSv1.3"
  } else if .ja4_version == "12" {
    .ja4_tls_version = "TLSv1.2"
  } else if .ja4_version == "11" {
    .ja4_tls_version = "TLSv1.1"
  } else if .ja4_version == "10" {
    .ja4_tls_version = "TLSv1.0"
  } else if .ja4_version == "s3" {
    .ja4_tls_version = "SSLv3"
  } else if .ja4_version == "s2" {
    .ja4_tls_version = "SSLv2"
  } else if .ja4_version == "d1" {
    .ja4_tls_version = "DTLSv1.0"
  } else if .ja4_version == "d2" {
    .ja4_tls_version = "DTLSv1.2"
  } else if .ja4_version == "d3" {
    .ja4_tls_version = "DTLSv1.3"
  } else {
    .ja4_tls_version = .ja4_version
  }

  # Decode SNI presence
  if .ja4_sni == "d" {
    .ja4_sni_present = "domain"
  } else if .ja4_sni == "i" {
    .ja4_sni_present = "ip"
  } else {
    .ja4_sni_present = .ja4_sni
  }

  # Decode ALPN
  if .ja4_alpn == "00" {
    .ja4_alpn_decoded = "none"
  } else {
    .ja4_alpn_decoded = .ja4_alpn
  }
}
'''

_DECODE_REQ_FP = r'''
# --- req_fp decode ---
if !exists(.req_fp) || .req_fp == null || .req_fp == "" {
  .req_fp = ""
} else if .req_fp != "err" {
  parts = split!(.req_fp, "_")
  if length(parts) >= 17 {

    # 1. path_b62 — kept as raw keyword for fingerprint matching/comparison.
    #    Not decoded — the `path` field from HAProxy %HP already has the
    #    human-readable request path.
    .req_fp_path_b62 = parts[0]

    # 2. method2 -> full HTTP method name
    .req_fp_method_raw = parts[1]
    if .req_fp_method_raw == "ge" { .req_fp_method = "GET" }
    else if .req_fp_method_raw == "po" { .req_fp_method = "POST" }
    else if .req_fp_method_raw == "pu" { .req_fp_method = "PUT" }
    else if .req_fp_method_raw == "de" { .req_fp_method = "DELETE" }
    else if .req_fp_method_raw == "pa" { .req_fp_method = "PATCH" }
    else if .req_fp_method_raw == "he" { .req_fp_method = "HEAD" }
    else if .req_fp_method_raw == "op" { .req_fp_method = "OPTIONS" }
    else if .req_fp_method_raw == "co" { .req_fp_method = "CONNECT" }
    else if .req_fp_method_raw == "tr" { .req_fp_method = "TRACE" }
    else { .req_fp_method = .req_fp_method_raw }

    # 3. http_ver -> full HTTP version string
    .req_fp_http_ver_raw = parts[2]
    if .req_fp_http_ver_raw == "09" { .req_fp_http_ver = "HTTP/0.9" }
    else if .req_fp_http_ver_raw == "10" { .req_fp_http_ver = "HTTP/1.0" }
    else if .req_fp_http_ver_raw == "11" { .req_fp_http_ver = "HTTP/1.1" }
    else if .req_fp_http_ver_raw == "20" { .req_fp_http_ver = "HTTP/2.0" }
    else if .req_fp_http_ver_raw == "30" { .req_fp_http_ver = "HTTP/3.0" }
    else { .req_fp_http_ver = .req_fp_http_ver_raw }

    # 4. path_depth (integer — count of "/" in path)
    .req_fp_path_depth = to_int(parts[3]) ?? 0

    # 5-7. param_keys / param_types / param_lens
    .req_fp_param_keys = parts[4]
    .req_fp_param_types_raw = parts[5]
    # param_types stored as raw — mapping: i=int f=float s=string c=char
    # b=bool t=time d=date z=datetime+tz e=empty o=object l=list
    .req_fp_param_lens = parts[6]

    # 8. req_ctype (4-char content-type subtype, "0000" = absent)
    .req_fp_ctype = parts[7]

    # 9-10. hdr_count / hdr_list
    .req_fp_hdr_count = to_int(parts[8]) ?? 0
    .req_fp_hdr_list = parts[9]

    # 11. accept_lang (4-char language code, "0000" = absent)
    .req_fp_accept_lang = parts[10]

    # 12. auth_type
    .req_fp_auth_type_raw = parts[11]
    if .req_fp_auth_type_raw == "n" { .req_fp_auth_type = "none" }
    else if .req_fp_auth_type_raw == "b" { .req_fp_auth_type = "basic" }
    else if .req_fp_auth_type_raw == "t" { .req_fp_auth_type = "bearer" }
    else if .req_fp_auth_type_raw == "d" { .req_fp_auth_type = "digest" }
    else if .req_fp_auth_type_raw == "o" { .req_fp_auth_type = "other" }
    else { .req_fp_auth_type = .req_fp_auth_type_raw }

    # 13. cookie (c=present, n=absent)
    .req_fp_cookie_raw = parts[12]
    if .req_fp_cookie_raw == "c" { .req_fp_cookie = "present" }
    else if .req_fp_cookie_raw == "n" { .req_fp_cookie = "absent" }
    else { .req_fp_cookie = .req_fp_cookie_raw }

    # 14. cookie_fields (sorted first-char initials, "nil" = none)
    .req_fp_cookie_fields = parts[13]

    # 15. referer (n=none, s=same-origin, x=cross-origin)
    .req_fp_referer_raw = parts[14]
    if .req_fp_referer_raw == "n" { .req_fp_referer = "none" }
    else if .req_fp_referer_raw == "s" { .req_fp_referer = "same-origin" }
    else if .req_fp_referer_raw == "x" { .req_fp_referer = "cross-origin" }
    else { .req_fp_referer = .req_fp_referer_raw }

    # 16. status (HTTP response status code)
    .req_fp_status = to_int(parts[15]) ?? 0

    # 17. body_bytes (response body size in bytes)
    .req_fp_body_bytes = to_int(parts[16]) ?? 0
  }
}

# --- unique_id decode ---
# Format: {client_ip_hex}:{client_port_hex}_{timestamp_hex}_{req_counter_hex}:{pid_hex}
# Example: 4A07F20E:8C04_6A9889FC_14FD:0012
#   -> client_ip 74.7.242.14, client_port 35844, timestamp 1788420092,
#      req_counter 5373, pid 18
if exists(.unique_id) && .unique_id != null && .unique_id != "" {
  uid_parts = split!(.unique_id, "_")
  if length(uid_parts) >= 3 {
    # Part 1: client_ip:client_port (both hex)
    ip_port = split!(uid_parts[0], ":")
    ip_hex = to_string(ip_port[0])
    if length(ip_hex) >= 8 {
      .unique_id_client_ip = to_string(parse_int(slice!(ip_hex, start: 0, end: 2), 16) ?? 0) + "." + to_string(parse_int(slice!(ip_hex, start: 2, end: 4), 16) ?? 0) + "." + to_string(parse_int(slice!(ip_hex, start: 4, end: 6), 16) ?? 0) + "." + to_string(parse_int(slice!(ip_hex, start: 6, end: 8), 16) ?? 0)
    }
    port_hex = to_string(ip_port[1])
    if port_hex != "" {
      .unique_id_client_port = parse_int(port_hex, 16) ?? 0
    }

    # Part 2: timestamp (hex Unix epoch seconds)
    ts_hex = uid_parts[1]
    if ts_hex != "" {
      ts_val = parse_int(ts_hex, 16) ?? 0
      .unique_id_timestamp = ts_val
      ts_conv = from_unix_timestamp(ts_val) ?? null
      if ts_conv != null {
        .unique_id_timestamp_iso = to_string(ts_conv)
      }
    }

    # Part 3: req_counter:pid (both hex)
    counter_pid = split!(uid_parts[2], ":")
    counter_hex = to_string(counter_pid[0])
    if counter_hex != "" {
      .unique_id_request_counter = parse_int(counter_hex, 16) ?? 0
    }
    pid_hex = to_string(counter_pid[1])
    if pid_hex != "" {
      .unique_id_pid = parse_int(pid_hex, 16) ?? 0
    }
  }
}
'''

_HAPROXY_FINALIZE = r'''
if exists(.unique_id) && .unique_id != null && .unique_id != "" {
  ._doc_id = .unique_id
} else {
  ._doc_id = uuid_v4()
}
.corex_source = "corex"
'''

_WAF_PARSE_JSON = r'''
parsed, err = parse_json(.message)
if err == null {
  . = merge!(., parsed)
}

# Flatten match.* fields to top-level
if exists(.match) {
  m = .match
  .rule_id = to_string(m.rule_id) ?? ""
  .severity = to_string(m.severity) ?? ""
  .msg = to_string(m.msg) ?? ""
  .client_ip = m.client
  .uri = to_string(m.uri) ?? ""
  .unique_id = to_string(m.unique_id) ?? ""
  .action = if m.disruptive == true { "blocked" } else { "allowed" }
  .tags = m.tags
  # Keep the nested match object for full detail downstream
}

# Normalize high-cardinality WAF messages that only differ by a numeric score
# so dashboards can group them. The full original message remains in match.msg.
if is_string(.msg) {
  .msg = replace!(.msg, r'^Inbound Anomaly Score Exceeded \(Total Score: [0-9]+\)$', "Inbound Anomaly Score Exceeded")
}

# Common timestamp field for cross-index correlation. Coraza SPOA emits the
# event time as either "time" or "timestamp" at the top level (different
# versions / log formats). Prefer "time", fall back to "timestamp", and
# finally use the Vector ingestion time as a last resort.
ts_str = to_string(.time) ?? ""
if ts_str == "" {
  ts_str = to_string(.timestamp) ?? ""
}
if ts_str != "" {
  .@timestamp = ts_str
} else {
  .@timestamp = now()
}
# Drop the redundant raw source time fields; @timestamp is the canonical one.
del(.time)
del(.timestamp)

._doc_id = uuid_v4()
.corex_source = "waf"
'''

_MCP_PARSE_JSON = r'''
# MCP Gateway event log — one JSON object per line (events.ndjson).
parsed, err = parse_json(.message)
if err == null {
  . = merge!(., parsed)
} else {
  ._parse_error = to_string(err)
}

# The event struct emits "ts" as an ISO-8601/RFC3339 string.
ts_str = to_string(.ts) ?? ""
if ts_str != "" {
  .@timestamp = ts_str
} else {
  .@timestamp = now()
}
del(.ts)

if exists(.request_id) && .request_id != null && .request_id != "" {
  ._doc_id = to_string(.request_id)
} else {
  ._doc_id = uuid_v4()
}
.corex_source = "mcp"
'''


# ---------------------------------------------------------------------------
# Source blocks
# ---------------------------------------------------------------------------

def _source_blocks(sources: Dict[str, bool]) -> str:
    parts: List[str] = []
    if sources.get("corex"):
        parts.append(
            "# coreX (HAProxy) request logs via TCP syslog.\n"
            "# HAProxy emits a managed `log backend@vector_logs` line in the\n"
            "# global section when this source is enabled. The `backend vector_logs`\n"
            "# section uses `mode log` with `server vector vector:601` — HAProxy's\n"
            "# `mode log` backends use TCP by default for server lines (and the\n"
            "# `udp@` prefix requires an IP, not a hostname), so the Vector source\n"
            "# listens on TCP to match.\n"
            "[sources.corex_syslog]\n"
            'type = "syslog"\n'
            'address = "0.0.0.0:601"\n'
            'mode = "tcp"\n'
        )
    if sources.get("waf"):
        parts.append(
            "# WAF (Coraza SPOA) logs via file tailing — one JSON event per line.\n"
            "# The WAF metrics sampler prunes this file in-place (ftruncate), so\n"
            "# the inode is preserved and checksum fingerprinting stays valid.\n"
            "[sources.waf_file]\n"
            'type = "file"\n'
            'include = ["/app/data/coraza-spoa.log"]\n'
            'read_from = "beginning"\n'
            'fingerprint.strategy = "checksum"\n'
            "fingerprint.lines = 1\n"
        )
    if sources.get("mcp"):
        parts.append(
            "# MCP Gateway events — one JSON object per line (events.ndjson),\n"
            "# plus the rotated .1 file written by the gateway's 8MB rotation.\n"
            "[sources.mcp_file]\n"
            'type = "file"\n'
            'include = ["/app/data/mcp/events.ndjson", "/app/data/mcp/events.ndjson.1"]\n'
            'read_from = "beginning"\n'
            'fingerprint.strategy = "checksum"\n'
            "fingerprint.lines = 1\n"
        )
    return "\n".join(parts)


def _transform_blocks(sources: Dict[str, bool]) -> str:
    parts: List[str] = []
    if sources.get("corex"):
        parts.append(
            "[transforms.haproxy_parse_json]\n"
            'type = "remap"\n'
            'inputs = ["corex_syslog"]\n'
            f"source = '''{_HAPROXY_PARSE_JSON}'''\n"
        )
        parts.append(
            "[transforms.decode_ja4]\n"
            'type = "remap"\n'
            'inputs = ["haproxy_parse_json"]\n'
            f"source = '''{_DECODE_JA4}'''\n"
        )
        parts.append(
            "[transforms.decode_req_fp]\n"
            'type = "remap"\n'
            'inputs = ["decode_ja4"]\n'
            f"source = '''{_DECODE_REQ_FP}'''\n"
        )
        parts.append(
            "[transforms.haproxy_finalize]\n"
            'type = "remap"\n'
            'inputs = ["decode_req_fp"]\n'
            f"source = '''{_HAPROXY_FINALIZE}'''\n"
        )
    if sources.get("waf"):
        parts.append(
            "[transforms.waf_parse_json]\n"
            'type = "remap"\n'
            'inputs = ["waf_file"]\n'
            f"source = '''{_WAF_PARSE_JSON}'''\n"
        )
    if sources.get("mcp"):
        parts.append(
            "[transforms.mcp_parse_json]\n"
            'type = "remap"\n'
            'inputs = ["mcp_file"]\n'
            f"source = '''{_MCP_PARSE_JSON}'''\n"
        )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Sink block renderers
# ---------------------------------------------------------------------------

def _emit(lines: List[str], key: str, val: Any) -> None:
    if val is None or val == "":
        return
    lines.append(f"{key} = {_toml_val(val)}")


def _render_sink_block(sink_name: str, source: str, sink_type: str,
                       options: Dict[str, Any], secrets: List[str],
                       input_name: Optional[str] = None) -> str:
    """Render one [sinks.<name>_<source>] block. ``options`` already decrypted."""
    inputs = [input_name or TERMINAL_TRANSFORMS[source]]
    block = f"{sink_name}_{source}"
    lines = [f"[sinks.{block}]", f'type = "{sink_type}"', f"inputs = {_toml_val(inputs)}"]
    sub: List[str] = []  # [sinks.<block>.<sub>] tables emitted after

    if sink_type == "aws_s3":
        _emit(lines, "bucket", options.get("bucket"))
        _emit(lines, "region", options.get("region"))
        prefix = _opt(options, f"key_prefix_{source}", "key_prefix",
                      default=f"corex/{source}/%Y/%m/%d/")
        _emit(lines, "key_prefix", str(prefix).replace("{source}", source))
        _emit(lines, "compression", options.get("compression", "gzip"))
        _emit(lines, "endpoint", options.get("endpoint"))
        sub.append(f"[sinks.{block}.encoding]\n" + 'codec = "ndjson"')
        if options.get("access_key_id") or options.get("secret_access_key"):
            auth = [f"[sinks.{block}.auth]"]
            _emit(auth, "access_key_id", options.get("access_key_id"))
            _emit(auth, "secret_access_key", options.get("secret_access_key"))
            _emit(auth, "session_token", options.get("session_token"))
            _emit(auth, "assume_role", options.get("assume_role"))
            sub.append("\n".join(auth))

    elif sink_type == "azure_logs_ingestion":
        _emit(lines, "endpoint", options.get("endpoint"))
        _emit(lines, "dcr_immutable_id", options.get("dcr_immutable_id"))
        _emit(lines, "stream_name", _opt(options, f"stream_name_{source}", "stream_name"))
        _emit(lines, "timestamp_field", options.get("timestamp_field", "@timestamp"))
        auth_kind = options.get("azure_credential_kind", "client_secret")
        auth = [f"[sinks.{block}.auth]", f'azure_credential_kind = "{auth_kind}"']
        if auth_kind == "client_secret":
            _emit(auth, "tenant_id", options.get("tenant_id"))
            _emit(auth, "client_id", options.get("client_id"))
            _emit(auth, "client_secret", options.get("client_secret"))
        sub.append("\n".join(auth))

    elif sink_type == "datadog_logs":
        _emit(lines, "default_api_key", options.get("api_key"))
        _emit(lines, "site", options.get("site", "datadoghq.com"))
        _emit(lines, "endpoint", options.get("endpoint"))
        _emit(lines, "compression", options.get("compression", "zstd"))

    elif sink_type == "elasticsearch":
        endpoints = options.get("endpoints")
        if isinstance(endpoints, str):
            endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
        _emit(lines, "endpoints", endpoints or [])
        # Use api_version (v8) instead of the deprecated suppress_type_name.
        # The `type` field was removed in ES 8.x; api_version=v8 omits it.
        _emit(lines, "api_version", "v8")
        idx = _opt(options, f"index_{source}", "index", default=DEFAULT_INDEX[source])
        _emit(lines, "bulk.index", str(idx).replace("{source}", source))
        _emit(lines, "id_key", "_doc_id")
        _emit(lines, "opensearch_service_type", options.get("opensearch_service_type"))
        vc = _opt_bool(options, "tls_verify_certificate")
        vh = _opt_bool(options, "tls_verify_hostname")
        if vc is not None:
            _emit(lines, "tls.verify_certificate", vc)
        if vh is not None:
            _emit(lines, "tls.verify_hostname", vh)
        except_fields = ["_doc_id", "_syslog_facility", "_syslog_severity",
                         "_syslog_hostname", "corex_source"]
        _emit(lines, "encoding.except_fields", except_fields)
        strategy = options.get("auth_strategy", "none")
        if strategy in ("basic", "api_key"):
            auth = [f"[sinks.{block}.auth]", f'strategy = "{strategy}"']
            if strategy == "basic":
                _emit(auth, "user", options.get("user"))
                _emit(auth, "password", options.get("password"))
            else:
                _emit(auth, "api_key", options.get("api_key"))
            sub.append("\n".join(auth))

    elif sink_type == "http":
        _emit(lines, "uri", options.get("uri"))
        _emit(lines, "method", options.get("method", "post"))
        _emit(lines, "compression", options.get("compression", "none"))
        vc = _opt_bool(options, "tls_verify_certificate")
        if vc is not None:
            _emit(lines, "tls.verify_certificate", vc)
        sub.append(f"[sinks.{block}.encoding]\n" +
                   f'codec = {_toml_str(options.get("encoding", "ndjson"))}')
        strategy = options.get("auth_strategy", "none")
        if strategy in ("basic", "bearer"):
            auth = [f"[sinks.{block}.auth]", f'strategy = "{strategy}"']
            if strategy == "basic":
                _emit(auth, "user", options.get("user"))
                _emit(auth, "password", options.get("password"))
            else:
                _emit(auth, "token", options.get("token"))
            sub.append("\n".join(auth))
        headers = options.get("headers")
        if isinstance(headers, dict) and headers:
            hdr = [f"[sinks.{block}.headers]"]
            for hk, hv in headers.items():
                hdr.append(f"{_toml_str(str(hk))} = {_toml_str(str(hv))}")
            sub.append("\n".join(hdr))

    elif sink_type == "new_relic":
        _emit(lines, "account_id", options.get("account_id"))
        _emit(lines, "license_key", options.get("license_key"))
        _emit(lines, "api", "logs")
        _emit(lines, "region", options.get("region"))
        _emit(lines, "compression", options.get("compression", "gzip"))

    elif sink_type == "splunk_hec_logs":
        _emit(lines, "endpoint", options.get("endpoint"))
        _emit(lines, "default_token", options.get("token"))
        _emit(lines, "index", options.get("index"))
        _emit(lines, "sourcetype", options.get("sourcetype"))
        _emit(lines, "source", options.get("source"))
        _emit(lines, "host_key", options.get("host_key"))
        _emit(lines, "endpoint_target", options.get("endpoint_target", "event"))
        vc = _opt_bool(options, "tls_verify_certificate")
        if vc is not None:
            _emit(lines, "tls.verify_certificate", vc)
        sub.append(f"[sinks.{block}.encoding]\n" + 'codec = "json"')

    else:
        raise ValueError(f"unsupported sink type: {sink_type}")

    out = "\n".join(lines) + "\n"
    if sub:
        out += "\n" + "\n".join(sub) + "\n"
    return out


def _enabled_sinks(db: Session) -> List[VectorSink]:
    return db.query(VectorSink).filter(VectorSink.enabled == True).all()  # noqa: E712


def generate_vector_toml(db: Session) -> Tuple[str, List[str]]:
    """Generate vector.toml; returns (toml_text, secret_plaintexts)."""
    sources = get_vector_sources(db)
    secrets: List[str] = []
    parts = [
        "# Generated by coreX Manager — do not edit",
        "# Vector log pipeline (sources: coreX/HAProxy, WAF/Coraza, MCP Gateway)",
        'data_dir = "/vector-data"',
        "",
    ]

    sinks = _enabled_sinks(db)
    active_sources = {s: v for s, v in sources.items() if v}

    if not active_sources or not sinks:
        # Emit a minimal valid config so the vector container starts cleanly
        # even before any sources/sinks are configured.
        parts.append(
            "# No sources or sinks configured — emitting a no-op pipeline so\n"
            "# Vector runs healthily until the pipeline is configured.\n"
            "[sources.internal_metrics]\n"
            'type = "internal_metrics"\n'
            "\n"
            "[sinks.blackhole]\n"
            'type = "blackhole"\n'
            'inputs = ["internal_metrics"]\n'
        )
        return "\n".join(parts) + "\n", secrets

    parts.append(_source_blocks(sources))
    parts.append(_transform_blocks(sources))

    for sink in sinks:
        try:
            options, plaintexts = decrypt_sink_options(sink.type, sink.options or {})
            secrets.extend(plaintexts)
        except Exception as exc:
            logger.error("Failed to decrypt secrets for vector sink %s: %s", sink.name, exc)
            continue
        name = _component_name(sink.name)
        source = sink.source
        if source not in active_sources:
            continue
        parts.append(_render_sink_block(name, source, sink.type, options, secrets))

    return "\n".join(parts) + "\n", secrets


def generate_vector_toml_text(db: Session) -> str:
    """Text-only variant for config-status comparison."""
    return generate_vector_toml(db)[0]


def generate_vector_toml_redacted(db: Session) -> str:
    text, secrets = generate_vector_toml(db)
    return redact_text(text, secrets)


# ---------------------------------------------------------------------------
# Staging config for sink testing
# ---------------------------------------------------------------------------

def generate_staging_sink_toml(db: Session, sink_type: str, sink_source: str,
                               options: Dict[str, Any], send_test_event: bool) -> Tuple[str, List[str]]:
    """Build a standalone vector.toml that exercises a single candidate sink.

    Wired to the enabled source transforms when available; otherwise (and for
    ``send_test_event``) a demo_logs source is used so the check works before
    the pipeline is fully configured.
    """
    secrets: List[str] = []
    options = dict(options or {})
    for key in SECRET_OPTIONS.get(sink_type, []):
        v = options.get(key)
        if isinstance(v, str) and v and not is_encrypted(v):
            # Candidate payload plaintext — collect for output redaction.
            secrets.append(v)

    parts = [
        "# Generated by coreX Manager — staging config for sink check",
        'data_dir = "/vector-data"',
        "",
    ]

    sources = get_vector_sources(db)
    if send_test_event or not any(sources.values()):
        test_input = "test_events"
        parts.append(
            "[sources.test_events]\n"
            'type = "demo_logs"\n'
            'format = "json"\n'
            'interval = 0.5\n'
            'count = 5\n'
        )
    else:
        parts.append(_source_blocks(sources))
        parts.append(_transform_blocks(sources))
        # Feed the sink from the candidate's source transform if that source
        # is active; otherwise fall back to any enabled source's transform.
        src = sink_source if sink_source in TERMINAL_TRANSFORMS and sources.get(sink_source) else next(
            (s for s in VALID_SOURCES if sources.get(s)), "corex")
        test_input = TERMINAL_TRANSFORMS[src]

    # Render with the candidate source for per-source option resolution
    # (index naming etc.), overridden to consume the staging input.
    src_for_options = sink_source if sink_source in VALID_SOURCES else "corex"
    block = _render_sink_block(
        "check", src_for_options, sink_type, options, secrets,
        input_name=test_input)
    parts.append(block)

    return "\n".join(parts) + "\n", secrets


# ---------------------------------------------------------------------------
# File lifecycle
# ---------------------------------------------------------------------------

def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_vector_config(db: Session, restart: bool = True, only_if_missing: bool = False) -> bool:
    """Write vector.toml + .applied snapshot; restart Vector on change.

    The container runs with ``--watch-config`` so the write alone is usually
    sufficient; the restart call is an idempotent fallback. Returns True if
    the on-disk config changed. ``only_if_missing`` is used at startup so a
    restart doesn't silently apply pending DB changes (the unapplied banner
    should keep showing them until the user applies).
    """
    path = settings.VECTOR_CONFIG_PATH
    text, _secrets = generate_vector_toml(db)
    existing = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read()
        except OSError:
            existing = None
    if only_if_missing and existing is not None:
        return False
    if existing == text and os.path.exists(f"{path}.applied"):
        return False

    _write_file(path, text)
    _write_file(f"{path}.applied", text)
    logger.info("vector.toml written to %s", path)

    if restart:
        try:
            from .runtime import get_runtime
            get_runtime().restart_vector()
        except Exception as exc:
            logger.warning("vector restart failed (config written): %s", exc)
    return True
