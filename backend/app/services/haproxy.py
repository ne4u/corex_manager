import difflib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import DateTime, JSON, Table, text
from ..core.database import Base

try:
    import docker
except ImportError:  # pragma: no cover
    docker = None  # type: ignore
from sqlalchemy.orm import Session, joinedload
from ..core.config import get_settings
from . import coraza_config, dataplane
from ..models.models import (
    Listener, Backend, Server, Certificate, CipherSuite,
    WafRule, WafException, RateLimit, Redirect, Rewrite,
    ResponseHeader, RequestHeader, LogDestination, LoggedField, CustomErrorPage, BackendRule,
    FcgiApp, ConfigSnapshot, PageProtectPolicy, CacheConfig, NetworkList
)

settings = get_settings()

import logging
logger = logging.getLogger(__name__)

# Dedicated backend name for ACME HTTP-01 challenge passthrough.
# acme.sh --standalone binds port 80 in the api container during issuance;
# HAProxy routes /.well-known/acme-challenge/ here so Let's Encrypt validators
# can reach the challenge response without interfering with normal traffic.
ACME_CHALLENGE_BACKEND_NAME = "acme_challenge_backend"

# Cap CAPTCHA proxy backends — emitted when any listener has a challenge-action
# rule (WAF, security rule, or rate limit). cap_api_proxy serves the challenge
# HTML page and verify endpoint from the backend API; cap_service_proxy
# forwards widget API calls (challenge/redeem) to the Cap service.
CAP_API_PROXY_BACKEND_NAME = "cap_api_proxy"
CAP_SERVICE_PROXY_BACKEND_NAME = "cap_service_proxy"

CIPHER_BASELINES = {
    "fips": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256",
    "fedramp": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
    "pci": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384",
    "modern": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305",
}

QUANTUM_SAFE_CURVES = "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:secp256r1:secp384r1"

_ERROR_TEMPLATE_VARS = {
    "request_id": "unique-id",
    "waf_unique_id": "var(txn.coraza.id)",
    "client_ip": "src",
    "client_port": "src_port",
    "frontend_ip": "dst",
    "frontend_port": "dst_port",
    "method": "method",
    "uri": "url",
    "path": "path",
    "query": "query",
    "host": "req.hdr(host)",
    "user_agent": 'req.fhdr("user-agent")',
    "referer": 'req.hdr("referer")',
    "timestamp": "date",
    "timeout": "var(txn.timeout)",
    "haproxy_server": "srv_name",
    "backend_name": "be_name",
    "frontend_name": "fe_name",
    "rate_limit_window": "var(txn.rate_limit_window)",
    "rate_limit_duration": "var(txn.rate_limit_duration)",
}

_PREVIEW_VALUES = {
    "request_id": "0A010170:E18D_6A721294_1274:006A",
    "waf_unique_id": "0A010170:E18D_6A721294_1274:006A",
    "client_ip": "203.0.113.10",
    "client_port": "54321",
    "frontend_ip": "198.51.100.5",
    "frontend_port": "443",
    "method": "GET",
    "uri": "/path?query=1",
    "path": "/path",
    "query": "query=1",
    "host": "example.com",
    "user_agent": "Mozilla/5.0 (compatible; Browser/1.0)",
    "referer": "https://example.com/",
    "timestamp": "2024-01-01T12:00:00Z",
    "timeout": "50s",
    "haproxy_server": "web1",
    "backend_name": "ne4u.com_be",
    "frontend_name": "http_in",
    "rate_limit_window": "60",
    "rate_limit_duration": "300",
}

_TEMPLATE_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


# Whitelist for HAProxy identifiers (section/acl/server names and filesystem directory names)
_NAME_RE = re.compile(r"[^A-Za-z0-9_.:-]")
_PATH_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]")
# Characters that could terminate a HAProxy statement or start a shell/command injection
_TOKEN_RE = re.compile(r"[\r\n;#|&`$\\]")
_REGEX_SANITIZE_RE = re.compile(r"[\r\n;]")
_FCGI_PARAM_RE = re.compile(r"[\r\n;]")
# Characters that could break a HAProxy log-format query string or inject config
_QUERY_RE = re.compile(r"[\r\n;#|\"'`$\\]")


def _safe_name(name: str) -> str:
    """Sanitize a value used as a HAProxy identifier."""
    if not isinstance(name, str):
        name = str(name)
    return _NAME_RE.sub("_", name).strip("_") or "unnamed"


def _unique_section_name(base: str, used: set, suffix: Optional[str] = None) -> str:
    """Return a unique HAProxy section name, optionally appending a backend suffix."""
    if base not in used:
        used.add(base)
        return base
    if suffix and not base.endswith(f"_{suffix}"):
        candidate = f"{base}_{suffix}"
        if candidate not in used:
            used.add(candidate)
            return candidate
    i = 2
    while True:
        candidate = f"{base}_{i}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        i += 1


def _get_section_names(db: Session) -> Tuple[Dict[int, str], Dict[int, str], str, str]:
    """Build unique frontend and backend section names that avoid HAProxy 3.3+ name conflicts."""
    listeners = [l for l in db.query(Listener).all() if l.enabled]
    backends = db.query(Backend).all()
    used: set = set()
    frontend_names: Dict[int, str] = {}
    for listener in listeners:
        base = _safe_name(listener.name)
        frontend_names[listener.id] = _unique_section_name(base, used)
    stats_name = _unique_section_name("stats", used)
    backend_names: Dict[int, str] = {}
    for backend in backends:
        base = _safe_name(backend.name)
        backend_names[backend.id] = _unique_section_name(base, used, suffix="be")
    coraza_name = _unique_section_name("coraza-spoa", used, suffix="be")
    return frontend_names, backend_names, stats_name, coraza_name


def _safe_path_name(name: str) -> str:
    """Sanitize a value used in a filesystem path."""
    if not isinstance(name, str):
        name = str(name)
    return _PATH_NAME_RE.sub("_", name).strip("_.-").strip() or "unnamed"


def _safe_token(value: str) -> str:
    """Remove characters that could break HAProxy config or inject shell commands."""
    if not isinstance(value, str):
        value = str(value)
    return _TOKEN_RE.sub("", value).strip()


def _rate_key_track_expr(rate_key: str, rate_header: Optional[str] = None) -> str:
    """Return the HAProxy track expression for a rate-limit counter key.

    Supported keys:
      - src       → src (source IP, tracked on the ip-type frontend stick-table)
      - user_id   → req.hdr(<rate_header or X-User-ID>)
      - header    → req.hdr(<rate_header or X-API-Key>)
      - path      → path
      - asn       → src,map_ip(<asn_map>) or src,lua.geoip2-lookup-asn(...)
                    (falls back to src if no ASN lookup is available)

    Returns "src" for unknown/empty keys so callers can treat non-"src"
    expressions as requiring a string-type stick table.
    """
    rk = _safe_token(rate_key or "src")
    if rk == "user_id":
        hdr = _safe_token(rate_header) if rate_header else "X-User-ID"
        return f"req.hdr({hdr})"
    if rk == "header":
        hdr = _safe_token(rate_header) if rate_header else "X-API-Key"
        return f"req.hdr({hdr})"
    if rk == "path":
        return "path"
    if rk == "asn":
        # Tier 1: Rust Lua module (covers all fields, no geoip2 build dep)
        if _geoip_lua_module_available():
            return 'src,lua.geoip2-lookup-asn("autonomous_system_number")'
        # Tier 2: native geoip2 converter
        if _haproxy_supports_geoip2() and os.path.exists(settings.ASN_DB_PATH):
            asn_db = os.path.abspath(settings.ASN_DB_PATH)
            return f"src,geoip2({asn_db},autonomous_system_number)"
        # Tier 3: map_ip fallback file
        if os.path.exists(settings.GEOIP_ASN_MAP_PATH):
            asn_map = os.path.abspath(settings.GEOIP_ASN_MAP_PATH)
            return f"src,map_ip({asn_map})"
        # No ASN lookup available — fall back to source IP
        return "src"
    return "src"


def _safe_regex(value: str) -> str:
    """Sanitize a regex value while preserving regex metacharacters."""
    if not isinstance(value, str):
        value = str(value)
    return _REGEX_SANITIZE_RE.sub("", value).strip()


def _safe_fcgi_param_value(value: str) -> str:
    """Sanitize a FCGI set-param value while preserving spaces and sample-fetch syntax."""
    if not isinstance(value, str):
        value = str(value)
    return _FCGI_PARAM_RE.sub("", value).strip()


def _safe_query(value: str) -> str:
    """Sanitize a query string used with http-request set-query.

    Preserves URL encoding, sample-fetch syntax, and parameter separators while
    removing characters that could break HAProxy config parsing. Spaces are
    replaced with '+' so they are valid in a query string.
    """
    if not isinstance(value, str):
        value = str(value)
    value = _QUERY_RE.sub("", value)
    value = re.sub(r"\s", "+", value)
    return value.strip("&+").strip()


def _read_file(path: str) -> str:
    """Return the contents of a file, or an empty string if it doesn't exist."""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return ""


def _haproxy_action(action: Optional[str]) -> str:
    """Map a UI ACL action to a valid HAProxy http-request action."""
    if not action or action == "block":
        return "deny"
    if action == "log":
        return "set-log-level notice"
    return _safe_token(action)


def _backend_condition_expression(condition_type: str, condition_name: Optional[str], operator: str, value: Optional[str]) -> str:
    """Build an inline HAProxy ACL fetch expression for a backend rule condition."""
    op = _safe_token(operator)
    if op == "eq":
        op = "str"
    name = _safe_token(condition_name or "")
    raw_value = value or ""
    if op == "reg":
        value = _safe_regex(raw_value)
    else:
        value = _safe_token(raw_value)

    if condition_type == "path":
        fetch = "path"
    elif condition_type == "host":
        fetch = "req.hdr(host)"
    elif condition_type == "hdr":
        fetch = f"req.hdr({name})" if name else "req.hdr"
    elif condition_type == "cookie":
        fetch = f"req.cook({name})" if name else "req.cook"
    elif condition_type == "url_param":
        fetch = f"url_param({name})" if name else "url_param"
    elif condition_type == "src":
        return f"src {value}" if value else "src -m found"
    else:
        fetch = "path"

    if op == "found":
        return f"{fetch} -m found"
    if op in ("eq", "len"):
        if not value:
            return f"{fetch} -m found"
        return f"{fetch} -m {op} {value}"
    if op == "reg":
        return f"{fetch} -m reg {value}"
    if op in ("beg", "end", "sub", "dir"):
        return f"{fetch} -m {op} {value}"
    return f"{fetch} -m beg {value}"


def _backend_rule_condition(rule: BackendRule) -> str:
    """Build an inline HAProxy ACL fetch expression for the first backend rule condition."""
    return _backend_condition_expression(rule.condition_type, rule.condition_name, rule.operator, rule.value)


def _render_haproxy_options(options: Optional[List[dict]], scope: str) -> tuple[list[str], list[str]]:
    """Return (extra_bind_opts, extra_section_lines) from a list of haproxy options."""
    bind_opts: list[str] = []
    section_lines: list[str] = []
    if not options:
        return bind_opts, section_lines
    for opt in options:
        if not opt.get("enabled", True):
            continue
        directive = _safe_token(str(opt.get("directive", "")))
        value = _safe_token(str(opt.get("value", "")))
        if not directive:
            continue
        target = opt.get("target", "section")
        line = f"    {directive} {value}".rstrip()
        if scope == "listener" and target == "bind":
            bind_opts.append(f"{directive} {value}".strip())
        else:
            section_lines.append(line)
    return bind_opts, section_lines


def _safe_header_value(value: str) -> str:
    """Quote header values, preserving semicolons and spaces.

    Semicolons are valid in HTTP header values (e.g. Content-Type params,
    Cookie attributes) but would start a HAProxy comment if unquoted.
    Always quote the value and escape inner double quotes so HAProxy treats
    the entire string as a single token.
    """
    if not isinstance(value, str):
        value = str(value)
    # Strip only truly dangerous chars (newlines, backticks, $, backslash,
    # pipe, ampersand, #) but preserve semicolons and spaces.
    value = re.sub(r"[\r\n#|&`$\\]", "", value).strip()
    value = value.replace('"', "'")
    return f'"{value}"'


def _format_condition(raw_condition: Optional[str]) -> str:
    """Format a header rule condition for HAProxy emission.

    Strips a leading 'if ' that the user may have included (HAProxy syntax is
    ``http-request add-header ... if <cond>``, so the code prepends ``if``).
    Returns ``" if <cond>"`` or empty string.
    """
    if not raw_condition or not raw_condition.strip():
        return ""
    cond = raw_condition.strip()
    # Strip leading "if " that the user may have included.
    if cond.lower().startswith("if "):
        cond = cond[3:].strip()
    elif cond.lower() == "if":
        return ""
    cond = _safe_token(cond)
    if not cond:
        return ""
    return f" if {cond}"


def _indent(lines: str, width: int = 4) -> str:
    pad = " " * width
    return "\n".join(pad + line for line in lines.splitlines() if line.strip())


def _block(title: str, body: str) -> str:
    return f"{title}\n{_indent(body)}\n"


_geoip2_support_cache: Optional[bool] = None


def _haproxy_supports_geoip2() -> bool:
    """Check whether the HAProxy binary supports the geoip2 converter.

    Runs `haproxy -vv` in the haproxy container (or locally) and looks for
    'geoip2' in the built features. The result is cached for the process
    lifetime.
    """
    global _geoip2_support_cache
    if _geoip2_support_cache is not None:
        return _geoip2_support_cache

    _geoip2_support_cache = False
    try:
        output = ""
        if docker is not None:
            try:
                client = docker.from_env()
                container_name = os.environ.get("HAPROXY_CONTAINER_NAME", "haproxy")
                container = client.containers.get(container_name)
                ec, out = container.exec_run("haproxy -vv")
                output = (out or b"").decode("utf-8", errors="replace")
            except Exception:
                pass
        if not output:
            haproxy_bin = shutil.which("haproxy")
            if haproxy_bin:
                result = subprocess.run(
                    [haproxy_bin, "-vv"],
                    capture_output=True, text=True
                )
                output = (result.stdout or "") + (result.stderr or "")
        if output and "geoip2" in output.lower():
            _geoip2_support_cache = True
    except Exception:
        pass
    return _geoip2_support_cache


def _geoip_lua_module_available() -> bool:
    """Check whether the haproxy-geoip2 Rust Lua module can be used.

    Requires the module to be enabled in settings AND both the City and ASN
    MMDB files to exist (the module reads them directly at runtime).
    """
    return (
        getattr(settings, "GEOIP_LUA_MODULE_ENABLED", True)
        and os.path.exists(settings.GEOIP_CITY_DB_PATH)
        and os.path.exists(settings.ASN_DB_PATH)
    )


def _api_armor_module_available() -> bool:
    """Check whether the haproxy-api-armor Rust Lua module can be used.

    Requires the module to be enabled in settings (API_ARMOR_MODULE_ENABLED).
    The .so file is installed by the Dockerfile's api-armor-builder stage.
    """
    return getattr(settings, "API_ARMOR_MODULE_ENABLED", True)


def _req_fp_module_available() -> bool:
    """Check whether the haproxy-req-fp Rust Lua module can be used.

    Requires the module to be enabled in settings (REQ_FP_MODULE_ENABLED).
    The .so file is installed by the Dockerfile's req-fp-builder stage.
    Set to False for dev environments where the .so is not built.
    """
    return getattr(settings, "REQ_FP_MODULE_ENABLED", True)


def _generate_geoip2_loader() -> str:
    """Generate the geoip2.lua loader script content.

    The loader is written to the data directory at config-write time so the
    DB paths and reload_interval always match the current settings. It is
    loaded via ``lua-load-per-thread`` in the global section.
    """
    city_db = os.path.abspath(settings.GEOIP_CITY_DB_PATH)
    asn_db = os.path.abspath(settings.ASN_DB_PATH)
    interval = getattr(settings, "GEOIP_LUA_RELOAD_INTERVAL_SECONDS", 3600)
    return (
        "-- Auto-generated by haproxy.py. Do not edit; regenerated on each config write.\n"
        "-- Loads the haproxy-geoip2 Rust Lua module and registers GeoIP converters.\n"
        'local geoip2 = require("haproxy_geoip2_module")\n'
        "geoip2.register({\n"
        "    db = {\n"
        f'        city = "{city_db}",\n'
        f'        asn = "{asn_db}",\n'
        "    },\n"
        f"    reload_interval = {interval},\n"
        "})\n"
    )


def _generate_combined_lua_loader(include_geoip: bool, include_compress: bool, include_resp_transform: bool = False, include_img_2_webp: bool = False, include_api_armor: bool = False, include_req_fp: bool = False) -> str:
    """Generate a combined Lua loader script for all Rust modules.

    The haproxy-geoip2, haproxy-compression, haproxy-resp-transform,
    haproxy-img-2-webp, haproxy-api-armor, and haproxy-req-fp modules are
    Rust cdylib (.so) files that link against the same crates (mlua,
    haproxy-api, std). Loading them via separate ``lua-load-per-thread``
    directives causes ``dlopen`` symbol conflicts (RTLD_GLOBAL) that can
    corrupt the Lua state and unregister converters from the first-loaded
    module.

    This combined loader loads all modules in a single script execution,
    using ``pcall`` to isolate failures so a load error in one module doesn't
    break the others.
    """
    parts = [
        "-- Auto-generated by haproxy.py. Do not edit; regenerated on each config write.\n"
        "-- Combined loader for haproxy-geoip2, haproxy-compression, haproxy-resp-transform,\n"
        "-- haproxy-img-2-webp, haproxy-api-armor, and haproxy-req-fp Rust Lua modules.\n"
        "-- All modules are loaded in a single lua-load-per-thread to avoid dlopen symbol\n"
        "-- conflicts between the cdylib .so files.\n",
    ]
    if include_req_fp:
        parts.append(
            "-- Request fingerprint (lua.req_fp_capture + lua.req_fp actions)\n"
            'local ok, req_fp = pcall(require, "haproxy_req_fp_module")\n'
            "if ok then\n"
            "    local rok, rerr = pcall(req_fp.register)\n"
            "    if not rok then\n"
            '        core.Alert("modules.lua: req_fp register failed: " .. tostring(rerr))\n'
            "    end\n"
            "else\n"
            '    core.Alert("modules.lua: req_fp module load failed: " .. tostring(req_fp))\n'
            "end\n"
        )
    if include_geoip:
        city_db = os.path.abspath(settings.GEOIP_CITY_DB_PATH)
        asn_db = os.path.abspath(settings.ASN_DB_PATH)
        interval = getattr(settings, "GEOIP_LUA_RELOAD_INTERVAL_SECONDS", 3600)
        parts.append(
            "-- GeoIP2 converters (lua.geoip2-lookup-city, lua.geoip2-lookup-asn)\n"
            'local ok, geoip2 = pcall(require, "haproxy_geoip2_module")\n'
            "if ok then\n"
            "    geoip2.register({\n"
            "        db = {\n"
            f'            city = "{city_db}",\n'
            f'            asn = "{asn_db}",\n'
            "        },\n"
            f"        reload_interval = {interval},\n"
            "    })\n"
            "else\n"
            '    core.Alert("modules.lua: geoip2 module load failed: " .. tostring(geoip2))\n'
            "end\n"
        )
    if include_compress:
        parts.append(
            "-- Compression filter (lua.compress for brotli/zstd)\n"
            'local ok, compress = pcall(require, "haproxy_compression_module")\n'
            "if ok then\n"
            "    local rok, rerr = pcall(compress.register)\n"
            "    if not rok then\n"
            '        core.Alert("modules.lua: compression register failed: " .. tostring(rerr))\n'
            "    end\n"
            "else\n"
            '    core.Alert("modules.lua: compression module load failed: " .. tostring(compress))\n'
            "end\n"
        )
    if include_resp_transform:
        # Inject Valkey connection params from settings so the Rust module's
        # TCP client connects to the right Valkey. The password is escaped
        # for Lua string literals to prevent injection. The fallback_key_env
        # is the env var name the Rust module reads for the AES-256 key used
        # when Valkey is unreachable (fail-to-encrypt fallback).
        vk_host = _escape_lua_string(str(settings.VALKEY_HOST))
        vk_port = int(settings.VALKEY_PORT)
        vk_db = int(settings.VALKEY_DB)
        vk_pass = _escape_lua_string(str(settings.VALKEY_PASSWORD or ""))
        fb_key_env = _escape_lua_string(str(settings.RESP_TRANSFORM_FALLBACK_KEY_ENV))
        parts.append(
            "-- Response transform filter (lua.resp_transform for replace/inject/mask)\n"
            'local ok, rt = pcall(dofile, "/etc/haproxy/resp_transform.lua")\n'
            "if ok and type(rt) == \"table\" and type(rt.init) == \"function\" then\n"
            "    local rok, rerr = pcall(rt.init, {\n"
            f'        valkey_host = "{vk_host}",\n'
            f"        valkey_port = {vk_port},\n"
            f"        valkey_db = {vk_db},\n"
            f'        valkey_password = "{vk_pass}",\n'
            f'        fallback_key_env = "{fb_key_env}",\n'
            "    })\n"
            "    if not rok then\n"
            '        core.Alert("modules.lua: resp_transform init failed: " .. tostring(rerr))\n'
            "    end\n"
            "else\n"
            '    core.Alert("modules.lua: resp_transform load failed: " .. tostring(rt))\n'
            "end\n"
        )
    if include_img_2_webp:
        parts.append(
            "-- Image conversion filter (lua.img_2_webp for JPEG/PNG/GIF to WebP)\n"
            'local ok, img_2_webp = pcall(require, "haproxy_img_2_webp_module")\n'
            "if ok then\n"
            "    local rok, rerr = pcall(img_2_webp.register)\n"
            "    if not rok then\n"
            '        core.Alert("modules.lua: img_2_webp register failed: " .. tostring(rerr))\n'
            "    end\n"
            "else\n"
            '    core.Alert("modules.lua: img_2_webp module load failed: " .. tostring(img_2_webp))\n'
            "end\n"
        )
    if include_api_armor:
        parts.append(
            "-- API Armor (body parsing, GraphQL, schema validation, JWT, profiling)\n"
            'local ok, api_armor = pcall(require, "haproxy_api_armor_module")\n'
            "if ok then\n"
            "    local rok, rerr = pcall(api_armor.register)\n"
            "    if not rok then\n"
            '        core.Alert("modules.lua: api_armor register failed: " .. tostring(rerr))\n'
            "    end\n"
            "else\n"
            '        core.Alert("modules.lua: api_armor module load failed: " .. tostring(api_armor))\n'
            "end\n"
        )
    return "".join(parts)


def _escape_lua_string(s: str) -> str:
    """Escape a string for safe embedding in a Lua double-quoted string literal."""
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    return s


def _default_json_log_format(ja4_enabled: bool, page_protect_enabled: bool = False) -> str:
    """Build the default JSON log-format string.

    Includes request metadata, security-rule/rate-limit/WAF action vars, and
    enrichment fields (country, ASN, JA4, req_fp) when their backing resources
    are available. The result is a single-quoted HAProxy log-format string
    containing a JSON object.
    """
    fields = [
        '"ts":"%t"',
        '"client":"%[src]"',
        '"client_port":"%cp"',
        '"frontend":"%f"',
        '"backend":"%b"',
        '"host":"%[var(txn.host)]"',
        '"method":"%HM"',
        '"path":"%HP"',
        '"query":"%HQ"',
        '"user_agent":"%[capture.req.hdr(1),json]"',
        '"status":"%ST"',
        '"status_source":"%[var(txn.status_source)]"',
        '"bytes_out":"%B"',
        '"rt":"%Tr"',
        '"ct":"%Tc"',
        '"tt":"%Tt"',
        '"termination":"%ts"',
        '"sec_action":"%[var(txn.sec.action)]"',
        '"sec_rule":"%[var(txn.sec.rule)]"',
        '"risk_score":"%[var(txn.risk.score)]"',
        '"risk_rules_hit":"%[var(txn.risk.rules_hit)]"',
        '"risk_rules_hit_count":"%[var(txn.risk.rules_hit_count)]"',
        '"risk_hit_density":"%[var(txn.risk.hit_density)]"',
        '"rl_action":"%[var(txn.ratelimit.action)]"',
        '"rl_name":"%[var(txn.ratelimit.name)]"',
        '"waf_action":"%[var(txn.coraza.action)]"',
        '"waf_status":"%[var(txn.coraza.status)]"',
        '"waf_anomaly_score":"%[var(txn.coraza.anomaly_score)]"',
        '"waf_rules_hit":"%[var(txn.coraza.rules_hit)]"',
        '"waf_rule_ids":"%[var(txn.coraza.rule_ids)]"',
        '"server":"%s"',
        '"unique_id":"%ID"',
    ]

    # GeoIP enrichment — three tiers:
    #   1. Rust Lua module (primary) — covers all fields, no geoip2 build dep
    #   2. Native geoip2 converter — when HAProxy is built with geoip2 support
    #   3. map_ip fallback files — legacy last resort
    if _geoip_lua_module_available():
        fields.append('"country":"%[src,lua.geoip2-lookup-city(\\"country\\",\\"iso_code\\")]"')
        fields.append('"asn":"%[src,lua.geoip2-lookup-asn(\\"autonomous_system_number\\")]"')
        fields.append('"city":"%[src,lua.geoip2-lookup-city(\\"city\\",\\"names\\",\\"en\\")]"')
    elif _haproxy_supports_geoip2() and os.path.exists(settings.GEOIP_DB_PATH):
        geo_db = os.path.abspath(settings.GEOIP_DB_PATH)
        fields.append(f'"country":"%[src,geoip2({geo_db},country.iso_code)]"')
        if os.path.exists(settings.ASN_DB_PATH):
            asn_db = os.path.abspath(settings.ASN_DB_PATH)
            fields.append(f'"asn":"%[src,geoip2({asn_db},autonomous_system_number)]"')
    elif not _haproxy_supports_geoip2() and os.path.exists(settings.GEOIP_COUNTRY_MAP_PATH):
        country_map = os.path.abspath(settings.GEOIP_COUNTRY_MAP_PATH)
        fields.append(f'"country":"%[src,map_ip({country_map})]"')
        if os.path.exists(settings.GEOIP_ASN_MAP_PATH):
            asn_map = os.path.abspath(settings.GEOIP_ASN_MAP_PATH)
            fields.append(f'"asn":"%[src,map_ip({asn_map})]"')

    # JA4 — only if the JA4 Lua script is loaded (ja4_enabled)
    if ja4_enabled:
        fields.append('"ja4":"%[lua.ja4_fp]"')

    # req_fp — always safe to reference. var(txn.req_fp) returns empty when
    # the per-frontend http-response lua.req_fp action isn't emitted.
    fields.append('"req_fp":"%[var(txn.req_fp)]"')

    # Page Protect — CSP report body captured in txn.csp_report for report POSTs.
    # Empty for normal requests. The sampler filters for non-empty values.
    # The json converter escapes special characters in the CSP report body (which
    # is itself JSON) but does NOT wrap the output in quotes. We must wrap it
    # ourselves: "csp_report":"%[var(txn.csp_report),json]" so the log line is
    # valid JSON. When empty, the json converter outputs "-" inside our quotes,
    # producing "csp_report":"-" which is valid JSON (treated as "no report").
    if page_protect_enabled:
        fields.append('"csp_report":"%[var(txn.csp_report),json]"')
        fields.append('"asset_beacon":"%[var(txn.asset_beacon),json]"')

    return "'{" + ",".join(fields) + "}'"


def _default_nbthread() -> int:
    """Return a sensible default for HAProxy's nbthread.

    Prefer os.sched_getaffinity() because it respects Linux container CPU
    limits (cgroups cpuset). Fall back to os.cpu_count() on other platforms.
    Always return at least 1.
    """
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except AttributeError:
        return max(1, os.cpu_count() or 1)


def generate_global_section(
    ciphers: Optional[List[CipherSuite]] = None,
    logs: Optional[List[LogDestination]] = None,
    logged_fields: Optional[List[LoggedField]] = None,
    global_options: Optional[List[dict]] = None,
    ja4_enabled: bool = True,
    compression_enabled: bool = False,
    disk_cache_enabled: bool = False,
    resp_transform_enabled: bool = False,
    img_2_webp_enabled: bool = False,
    captcha_challenge_enabled: bool = False,
    api_armor_enabled: bool = False,
    req_fp_enabled: bool = False,
) -> str:
    lines = ["global"]
    lines.append(f"    maxconn {settings.HAPROXY_MAXCONN}")
    lines.append("    pidfile /var/run/haproxy.pid")
    lines.append("    stats socket " + settings.HAPROXY_SOCKET_PATH + " mode 600 expose-fd listeners level admin")
    lines.append("    stats timeout 30s")
    lines.append("    user haproxy")
    lines.append("    group haproxy")

    # Stick counters: HAProxy defaults to 3 (sc0–sc2). Response-code rate
    # limiting uses sc3 (a dedicated stick-table backend), so require at least
    # 4. A user-supplied tune.stick-counters value is respected when valid and
    # >= 4, then deduped below.
    tune_stick_counters_value = 4
    for opt in (global_options or []):
        if not opt.get("enabled", True):
            continue
        if _safe_token(str(opt.get("directive", ""))).strip().lower() != "tune.stick-counters":
            continue
        raw_value = _safe_token(str(opt.get("value", ""))).strip()
        try:
            user_value = int(raw_value)
        except (TypeError, ValueError):
            user_value = 4
        tune_stick_counters_value = max(4, user_value)
        break
    lines.append(f"    tune.stick-counters {tune_stick_counters_value}")

    # Buffer size for image conversion. The img_2_webp filter must buffer the
    # whole response body and re-insert the converted WebP in a single
    # `msg:set()` call, which HAProxy caps at `htx_free_data_space()`. Above that
    # cap msg:set() returns -1 and copies nothing, producing a silently empty
    # response body. HAProxy's 16384 default only leaves ~14 KB once
    # tune.maxrewrite and the response headers are accounted for, so the largest
    # convertible image would be smaller than most real images.
    #
    # This is OPT-IN (IMG_2_WEBP_BUFSIZE defaults to 0 = don't emit) because
    # tune.bufsize is GLOBAL and HAProxy allocates ~2 buffers per connection:
    # worst-case buffer memory is `maxconn * 2 * tune.bufsize`. With a large
    # maxconn, raising it silently would multiply memory use dramatically. When
    # left at 0 the filter assumes HAProxy's 16384 default and simply serves
    # larger images unconverted — a safe, working fallback.
    #
    # Only emitted when a user-supplied tune.bufsize is absent, so an explicit
    # value in Global Options always wins. `max_buffer` on the filter line is
    # derived from the same setting (see _img_2_webp_max_buffer) and the two
    # always move together.
    if img_2_webp_enabled and settings.IMG_2_WEBP_BUFSIZE:
        user_set_bufsize = any(
            opt.get("enabled", True)
            and _safe_token(str(opt.get("directive", ""))).strip().lower() == "tune.bufsize"
            for opt in (global_options or [])
        )
        if not user_set_bufsize:
            lines.append(f"    tune.bufsize {settings.IMG_2_WEBP_BUFSIZE}")

    # When 3+ Lua response filters are active simultaneously (resp_transform +
    # compression + img_2_webp), HAProxy's default 16KB buffer is too small.
    # Each filter buffers response data, and compress's offload mode buffers
    # the entire response before dispatching to the compression thread pool.
    # Combined with large response headers (CSP, HSTS, etc.) and a fast origin
    # (e.g. Varnish cache hit) that delivers 32KB+ in one shot, the 16KB
    # buffer overflows during response header processing, producing PH
    # (proxy header) termination → 500. This is automatically emitted when
    # the user has not set tune.bufsize explicitly (via Global Options or
    # IMG_2_WEBP_BUFSIZE above). See HAPROXY_MULTI_FILTER_BUFSIZE in config.py.
    lua_response_filter_count = sum([
        bool(resp_transform_enabled),
        bool(compression_enabled),
        bool(img_2_webp_enabled),
    ])
    if lua_response_filter_count >= 3:
        user_set_bufsize = any(
            opt.get("enabled", True)
            and _safe_token(str(opt.get("directive", ""))).strip().lower() == "tune.bufsize"
            for opt in (global_options or [])
        )
        if not user_set_bufsize and not settings.IMG_2_WEBP_BUFSIZE:
            lines.append(f"    tune.bufsize {settings.HAPROXY_MULTI_FILTER_BUFSIZE}")

    # Log destinations (global).
    # If no enabled LogDestination rows exist, emit a default stdout target so
    # `docker compose logs haproxy` shows request logs out of the box.
    # For stdout/stderr targets, use `format raw` to emit the log-format string
    # as-is (no syslog framing) — ideal for JSON logging in containers.
    # `len` is raised above HAProxy's 1024 default so CSP report bodies are not
    # truncated in the log line before the sampler can parse them.
    log_max_len = getattr(settings, "HAPROXY_LOG_MAX_LEN", 65535)
    enabled_logs = [log for log in (logs or []) if log.enabled]
    if enabled_logs:
        for log in enabled_logs:
            target = _safe_token(log.target)
            facility = _safe_token(log.facility)
            level = _safe_token(log.level)
            if target in ("stdout", "stderr"):
                lines.append(f"    log {target} len {log_max_len} format raw {facility}")
            else:
                lines.append(f"    log {target} len {log_max_len} {facility} {level}")
    elif getattr(settings, "HAPROXY_LOG_DEFAULT_STDOUT", True):
        lines.append(f"    log stdout len {log_max_len} format raw daemon")

    # TLS session cache
    lines.append("    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    lines.append("    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets")

    # HAProxy 3.1+ requires tune.lua.bool-sample-conversion to be set before any
    # lua-load or lua-load-per-thread directive. Since req_fp and acme Lua scripts
    # are always loaded below, emit this unconditionally near the top of the global
    # section. A user-supplied value in global_options is respected and deduped.
    tune_bool_value = "normal"
    for opt in (global_options or []):
        if opt.get("enabled", True) and _safe_token(str(opt.get("directive", ""))).strip().lower() == "tune.lua.bool-sample-conversion":
            tune_bool_value = _safe_token(str(opt.get("value", ""))).strip() or "normal"
            break
    lines.append(f"    tune.lua.bool-sample-conversion {tune_bool_value}")

    # GeoIP + Response compression + Response transforms — all use Rust Lua modules
    # (cdylib .so files). When any are enabled, they MUST be loaded via a single
    # combined loader script and a single lua-load-per-thread directive. Loading
    # separate .so files via separate lua-load-per-thread directives causes Rust
    # cdylib symbol conflicts (all export mlua/haproxy-api/std symbols via dlopen
    # RTLD_GLOBAL), which can corrupt the Lua state and unregister converters from
    # the first-loaded module.
    geoip_available = _geoip_lua_module_available()
    need_geoip = geoip_available
    need_compress = compression_enabled
    need_resp_transform = resp_transform_enabled
    need_img_2_webp = img_2_webp_enabled
    need_api_armor = api_armor_enabled and _api_armor_module_available()
    need_req_fp = req_fp_enabled and _req_fp_module_available()

    if need_geoip or need_compress or need_resp_transform or need_img_2_webp or need_api_armor or need_req_fp:
        lines.append("    lua-prepend-path /etc/haproxy/?.so cpath")
        # Generate a combined loader script that loads all modules in sequence
        # with pcall error isolation, so a failure in one doesn't break the others.
        loader_path = os.path.join(
            os.path.dirname(os.path.abspath(settings.HAPROXY_CONFIG_PATH)),
            "modules.lua",
        )
        try:
            with open(loader_path, "w") as f:
                f.write(_generate_combined_lua_loader(
                    include_geoip=need_geoip,
                    include_compress=need_compress,
                    include_resp_transform=need_resp_transform,
                    include_img_2_webp=need_img_2_webp,
                    include_api_armor=need_api_armor,
                    include_req_fp=need_req_fp,
                ))
        except OSError:
            pass  # config generation should not fail on loader write
        lines.append(f"    lua-load-per-thread {loader_path}")
        if need_geoip:
            # insecure-fork-wanted is required for non-blocking MMDB reload in workers.
            lines.append("    insecure-fork-wanted")
    elif _haproxy_supports_geoip2():
        if os.path.exists(settings.GEOIP_DB_PATH):
            lines.append(f"    # geoip Country DB available at {settings.GEOIP_DB_PATH}")
        if os.path.exists(settings.ASN_DB_PATH):
            lines.append(f"    # geoip ASN DB available at {settings.ASN_DB_PATH}")
        else:
            lines.append("    # geoip2 converter not available; country/ASN use map_ip fallback files")

    # User-defined global HAProxy options
    _, extra_global = _render_haproxy_options(global_options, "global")
    # Avoid duplicating tune.lua.bool-sample-conversion and tune.stick-counters;
    # they are already emitted at the top of the global section.
    extra_global = [
        line for line in extra_global
        if not line.strip().startswith("tune.lua.bool-sample-conversion")
        and not line.strip().startswith("tune.stick-counters")
    ]
    lines.extend(extra_global)

    # Coraza WAF spoa module reference (optional, user should place binary)
    lines.append("    # coraza-spoa configuration loaded per frontend")

    # JA4 fingerprint Lua script (for security rules referencing http.request.ja4)
    # tune.ssl.capture-buffer-size must be set so ssl_fc_cipherlist_bin /
    # ssl_fc_extlist_bin / ssl_fc_sigalgs_bin return ClientHello data for JA4.
    # tune.lua.bool-sample-conversion is emitted near the top of global before
    # any lua-load/lua-load-per-thread directive (HAProxy 3.1+).
    # Gated by the ja4_enabled setting (toggled via Global Options GUI).
    if ja4_enabled:
        lines.append("    tune.ssl.capture-buffer-size 336")
        lines.append("    lua-load /etc/haproxy/ja4.lua")

    # HTTP request fingerprint is now a Rust cdylib module (haproxy-req-fp),
    # loaded via the combined modules.lua loader above when req_fp_enabled and
    # the module is available. The per-frontend http-request lua.req_fp_capture
    # and http-response lua.req_fp actions are emitted only when req_fp_enabled.

    # ACME HTTP-01 challenge file server (reads from shared webroot volume).
    # Always loaded; the lua.acme_challenge_file fetch is invoked per-frontend
    # only for exact /.well-known/acme-challenge/<token> paths.
    lines.append("    lua-load /etc/haproxy/acme.lua")

    # Risk Scoring engine: pure-Lua script providing risk_capture + risk_compute
    # actions. Loaded when req_fp is enabled (risk_capture reads txn.req_fp.*
    # vars set by the Rust module). The script is safe to load even with no
    # risk rules configured (risk_compute sets txn.risk.score and
    # per-ruleset vars to "0").
    if req_fp_enabled:
        lines.append("    lua-load /etc/haproxy/risk_score.lua")

    # Captcha context store: stores challenge rule context in Valkey (server-side)
    # and returns an opaque token. Loaded when any challenge-action rule exists.
    # We write a generated init script that loads the static captcha_ctx.lua
    # module and calls its init() with Valkey connection params from settings.
    if captcha_challenge_enabled:
        # HAProxy's Lua core.tcp():connect() does NOT support DNS hostnames,
        # only IP addresses. Resolve the Valkey hostname to an IP here.
        import socket as _socket
        try:
            vk_host = _socket.gethostbyname(str(settings.VALKEY_HOST))
        except Exception:
            vk_host = str(settings.VALKEY_HOST)  # might already be an IP
        vk_port = int(settings.VALKEY_PORT)
        vk_pass = _escape_lua_string(str(settings.VALKEY_PASSWORD or ""))
        init_script = (
            "-- Auto-generated: loads captcha_ctx.lua and injects Valkey params.\n"
            "-- Valkey hostname resolved to IP because HAProxy Lua sockets don't\n"
            "-- support DNS resolution.\n"
            'local ok, mod = pcall(dofile, "/etc/haproxy/captcha_ctx.lua")\n'
            "if ok and type(mod) == \"table\" and type(mod.init) == \"function\" then\n"
            f'    mod.init({{valkey_host = "{vk_host}", valkey_port = {vk_port}, valkey_password = "{vk_pass}"}})\n'
            "else\n"
            '    core.Alert("captcha_ctx init: load failed: " .. tostring(mod))\n'
            "end\n"
        )
        init_path = os.path.join(os.path.dirname(settings.HAPROXY_CONFIG_PATH), "captcha_ctx_init.lua")
        try:
            with open(init_path, "w") as f:
                f.write(init_script)
        except Exception:
            # Fallback: just lua-load the static script (uses default params)
            pass
        lines.append(f"    lua-load {init_path}")

    # Dynamic nbthread default based on the CPU count. Users can still override
    # by adding an explicit nbthread row in the Global HAProxy Options UI.
    has_user_nbthread = any(
        opt.get("enabled", True)
        and _safe_token(str(opt.get("directive", ""))).lower() == "nbthread"
        for opt in (global_options or [])
    )
    if not has_user_nbthread:
        lines.append(f"    nbthread {_default_nbthread()}")

    # Docker embedded DNS resolver for SPOA/dynamic backend hostnames.
    # Referenced by backend server lines that use hostnames instead of IPs.
    # Emitted when WAF (SPOA) or disk cache (Varnish) is enabled, since both
    # use hostnames that need runtime DNS resolution via Docker's embedded DNS.
    if settings.CORAZA_SPOA_ENABLED or disk_cache_enabled:
        lines.append("")
        lines.append("resolvers docker")
        lines.append("    nameserver docker 127.0.0.11:53")
        lines.append("    resolve_retries 3")
        lines.append("    timeout resolve 1s")
        lines.append("    timeout retry 1s")
        lines.append("    hold other 30s")
        lines.append("    hold refused 30s")
        lines.append("    hold nx 30s")
        lines.append("    hold timeout 30s")
        lines.append("    hold obsolete 30s")
        lines.append("    accepted_payload_size 8192")

    return "\n".join(lines) + "\n\n"


def generate_defaults_section(headers: Optional[List[ResponseHeader]] = None,
                                error_pages: Optional[List[CustomErrorPage]] = None,
                                logged_fields: Optional[List[LoggedField]] = None,
                                ja4_enabled: bool = True,
                                page_protect_enabled: bool = False) -> str:
    lines = ["defaults"]
    lines.append("    mode http")
    # Log format is emitted per-HTTP-frontend (not in defaults) because
    # HAProxy 3.4+ rejects req.hdr sample fetches in the defaults log-format
    # — they need HTTP request headers which aren't guaranteed to be
    # available in all sections inheriting defaults (TCP frontends, etc.).
    # Each HTTP-mode frontend gets its own log-format line; TCP frontends
    # use option tcplog instead.
    lines.append("    timeout connect 5s")
    lines.append("    timeout client 50s")
    lines.append("    timeout server 50s")
    lines.append("    timeout http-keep-alive 10s")
    lines.append("    option http-server-close")
    # No "option forwardfor" here: every HTTP frontend explicitly emits
    # http-request add-header X-Forwarded-For "%[src]" (after the Restore
    # Client IP set-src rules). Having both caused the proxy IP to be
    # appended to the XFF chain twice.
    lines.append("    option http-keep-alive")
    lines.append("    retries 3")
    lines.append("    default-server init-addr last,libc,none")
    lines.append("    option redispatch")
    lines.append('    unique-id-format "%{+X}o %ci:%cp_%Ts_%rt:%pid"')

    # Note: response headers and custom error pages are emitted per-frontend
    # in generate_frontend, not here — HAProxy does not allow http-response
    # or http-error directives in the defaults section.

    # Global custom response pages (not listener-bound)
    if error_pages:
        pages_by_code: Dict[int, CustomErrorPage] = {}
        for ep in sorted(error_pages, key=lambda e: e.id or 0):
            if ep.listener_id is not None or ep.listener_ids:
                continue
            pages_by_code[ep.code] = ep
            path = os.path.join(
                os.path.dirname(settings.HAPROXY_CONFIG_PATH),
                "errorfiles",
                "global",
                f"{ep.code}-{ep.id}.http",
            )
            os.makedirs(os.path.dirname(path), exist_ok=True)
            content_type = _safe_token(ep.content_type) or "text/html"
            _write_error_file(path, ep.content, content_type)
        for ep in pages_by_code.values():
            path = os.path.join(
                os.path.dirname(settings.HAPROXY_CONFIG_PATH),
                "errorfiles",
                "global",
                f"{ep.code}-{ep.id}.http",
            )
            content_type = _safe_token(ep.content_type) or "text/html"
            lines.append(f'    http-error status {ep.code} content-type "{content_type}" lf-file {path}')

    return "\n".join(lines) + "\n\n"


def generate_stats_frontend(name: str = "stats") -> str:
    lines = [
        f"frontend {name}",
        "    bind *:8404",
        "    mode http",
        "    stats enable",
        "    stats uri /",
        "    stats refresh 10s",
    ]
    return "\n".join(lines) + "\n\n"




def generate_dataplane_section() -> str:
    """Generate userlist section for the HAProxy Data Plane API."""
    if not settings.DATAPLANE_API_ENABLED:
        return ""
    user = settings.DATAPLANE_API_USER
    password = settings.DATAPLANE_API_PASSWORD
    if not password:
        import logging
        logging.getLogger(__name__).warning(
            "DATAPLANE_API_ENABLED=true but DATAPLANE_API_PASSWORD is not set. "
            "Skipping Data Plane API userlist — the API will not authenticate. "
            "Set DATAPLANE_API_PASSWORD in your .env file."
        )
        return ""
    return f"""userlist dataplane-api
    user {user} insecure-password {password}

"""


def _write_error_file(path: str, content: str, content_type: str):
    # Remove carriage returns to prevent HTTP response/header injection
    content = content.replace("\r", "") if content else ""
    # Render {{ var }} placeholders to HAProxy sample-fetch expressions.
    # Unknown names are treated as transaction variables: %[var(txn.name)]
    content = _TEMPLATE_RE.sub(
        lambda m: f"%[{_ERROR_TEMPLATE_VARS.get(m.group(1), 'var(txn.' + m.group(1) + ')')}]",
        content,
    )
    # Escape any '%' that is not the start of a sample fetch '%[...]'
    content = re.sub(r"%(?!\[)", "%%", content)
    if not content.endswith("\n"):
        content += "\n"
    with open(path, "w") as f:
        f.write(content)


def render_error_page_preview(content: str) -> str:
    """Render an error page with sample values for browser preview."""
    if not content:
        return ""
    content = _TEMPLATE_RE.sub(
        lambda m: _PREVIEW_VALUES.get(m.group(1), f"[{m.group(1)}]"),
        content,
    )
    content = re.sub(r"%\[([^\]]+)\]", lambda m: f"[{m.group(1)}]", content)
    return content


def _build_ssl_bind_options(listener: Listener, certs: List[Certificate],
                             cipher: Optional[CipherSuite], quic: bool = False) -> str:
    opts = []
    if listener.ssl_enabled:
        opts.append("ssl")
        for cert in certs:
            if cert and cert.cert_path:
                opts.append(f"crt {cert.cert_path}")
        if quic:
            opts.append("alpn h3")
        elif listener.alpn:
            opts.append(f"alpn {_safe_token(listener.alpn)}")
        elif listener.protocol == "grpc":
            opts.append("alpn h2")
        elif listener.http2:
            opts.append("alpn h2,http/1.1")
        if listener.quic:
            opts.append("allow-0rtt")
        if cipher:
            ciphers_str = _safe_token(cipher.ciphers or CIPHER_BASELINES.get(cipher.baseline, ""))
            if ciphers_str:
                opts.append(f"ciphers {ciphers_str}")
            if cipher.quantum_safe and QUANTUM_SAFE_CURVES:
                opts.append(f"curves {QUANTUM_SAFE_CURVES}")
            opts.append(_safe_token(cipher.tls_options or "no-sslv3 no-tlsv10 no-tlsv11"))
            opts.append(f"ssl-min-ver {_safe_token(cipher.min_tls_version)}")
        # Proxy protocol on the listener
        if listener.proxy_protocol:
            opts.append("accept-proxy")
    return " ".join(opts)


def _matches_listener(entity, listener: Listener) -> bool:
    """True if entity is bound to this listener by id list or by frontend name match.

    Entities with no listener binding (listener_id is None, no listener_ids,
    no frontend_match) are considered global and match all listeners.
    """
    listener_ids = getattr(entity, "listener_ids", None)
    if listener_ids:
        return listener.id in listener_ids
    single_id = getattr(entity, "listener_id", None)
    if single_id is not None:
        return single_id == listener.id
    frontend_match = getattr(entity, "frontend_match", None)
    if frontend_match is not None:
        return frontend_match == listener.name
    # No binding at all → global → matches every listener
    return True


def _matches_backend(entity, backend: Backend) -> bool:
    """True if entity is bound to this backend by id list or single backend_id.

    Entities with no backend binding (backend_id is None, no backend_ids) are
    considered global and match all backends.
    """
    backend_ids = getattr(entity, "backend_ids", None)
    if backend_ids:
        return backend.id in backend_ids
    single_id = getattr(entity, "backend_id", None)
    if single_id is not None:
        return single_id == backend.id
    # No binding at all → global → matches every backend
    return True


def _emit_compression_filter(
    backend: Backend,
    compression_enabled: bool,
    has_fcgi: bool = False,
) -> List[str]:
    """Emit HAProxy filter directives for per-backend response compression.

    Reads compression settings from ``backend.options``:
      - ``compression_algorithm``: ``none`` | ``gzip`` | ``deflate`` | ``raw-deflate`` | ``brotli`` | ``zstd``
      - ``compression_quality``: brotli quality 0-11 (default 5)
      - ``compression_level``: zstd level 1-22 (default 3)
      - ``compression_window``: brotli window 10-24 (default 22)
      - ``compression_content_types``: comma-separated MIME prefixes (default all)
      - ``compression_offload``: bool — strip Accept-Encoding from backend request

    ``gzip``/``deflate``/``raw-deflate`` use HAProxy's native ``filter compression``
    (no Rust module needed). ``brotli``/``zstd`` use the ``lua.compress`` filter
    registered by the haproxy-compression Rust Lua module, which must be loaded
    globally (gated by the ``compression_enabled`` flag). Returns an empty list if
    compression is disabled or the requested Lua encoder isn't enabled.

    Emitted in the ``backend`` section so different backends can use different
    algorithms (e.g. zstd for APIs, brotli for static content, none for
    streaming). HAProxy processes filters declared in backend sections for all
    traffic routed to that backend.

    When ``has_fcgi`` is True, brotli/zstd (Lua-based) compression is skipped
    because HAProxy 3.4's fcgi_flt_check rejects Lua filters alongside
    use-fcgi-app (same bug as resp_transform). Native gzip/deflate compression
    is unaffected (it's in HAProxy's allowlist alongside cache).
    """
    opts = backend.options or {}
    algorithm = _safe_token(str(opts.get("compression_algorithm", ""))).lower()
    if algorithm in ("", "none"):
        return []

    content_types = str(opts.get("compression_content_types", "")).strip()
    offload = bool(opts.get("compression_offload", False))
    quality = int(opts.get("compression_quality", 5) or 5)
    level = int(opts.get("compression_level", 3) or 3)
    window = int(opts.get("compression_window", 22) or 22)

    lines: List[str] = []

    if algorithm in ("gzip", "deflate", "raw-deflate"):
        # HAProxy native compression filter (no Lua module required).
        # Allowed alongside use-fcgi-app (http_comp_*_flt_id is in the allowlist).
        lines.append("    filter compression")
        lines.append(f"    compression algo {algorithm}")
        if content_types:
            # Normalize: comma-separated → space-separated MIME tokens
            types = " ".join(_safe_token(t) for t in content_types.split(",") if t.strip())
            if types:
                lines.append(f"    compression type {types}")
        if offload:
            lines.append("    compression offload")
        return lines

    if algorithm in ("brotli", "zstd") and compression_enabled:
        if has_fcgi:
            # Lua-based compression (lua.compress) cannot coexist with
            # use-fcgi-app due to HAProxy 3.4's fcgi_flt_check bug.
            lines.append(
                f"    # compression: {algorithm} skipped for FCGI backend"
                f" (HAProxy 3.4 fcgi_flt_check rejects Lua filters alongside use-fcgi-app)"
            )
            return lines
        if algorithm == "brotli":
            args = ["br", f"quality:{max(0, min(11, quality))}", f"window:{max(10, min(24, window))}"]
        else:
            args = ["zstd", f"level:{max(1, min(22, level))}"]
        if offload:
            args.append("offload")
        if content_types:
            args.append(f"type:{content_types}")
        lines.append(f"    filter lua.compress {' '.join(args)}")
        return lines

    # Algorithm requested but the compression module is not enabled — emit a
    # comment so the config is valid but compression is silently skipped.
    if algorithm in ("brotli", "zstd"):
        lines.append(f"    # compression: {algorithm} requested but compression module not enabled in Global Options")
    return lines


def _img_2_webp_effective_bufsize() -> int:
    """Return the tune.bufsize the img_2_webp filter should assume.

    ``IMG_2_WEBP_BUFSIZE`` of 0 means "don't touch tune.bufsize", so the
    filter must assume HAProxy's built-in default.
    """
    return settings.IMG_2_WEBP_BUFSIZE or settings.HAPROXY_DEFAULT_BUFSIZE


def _img_2_webp_max_buffer() -> int:
    """Initial chunk size the filter uses when handing output back to HAProxy.

    This is a starting hint, NOT a ceiling on convertible image size: the filter
    emits converted output incrementally across ``http_payload`` callbacks and
    halves the chunk automatically whenever the channel refuses it. Sizing it
    near the usable HTX data space just avoids a few wasted probe attempts on
    the first flush. The real limit on image size is ``max_size``.

    Derived from the effective tune.bufsize minus a reserve for tune.maxrewrite
    and the response header block, which share the same buffer. The reserve is
    capped at a quarter of the bufsize so it stays sane for small buffers.
    """
    bufsize = _img_2_webp_effective_bufsize()
    reserve = min(settings.IMG_2_WEBP_BUFFER_RESERVE, bufsize // 4)
    return max(1, bufsize - reserve)


def _emit_img_2_webp_filter(
    backend: Backend,
    img_2_webp_enabled: bool,
    has_fcgi: bool = False,
) -> List[str]:
    """Emit HAProxy filter directives for per-backend image-to-WebP conversion.

    Reads image conversion settings from ``backend.options``:
      - ``img_2_webp_enabled``: bool — enable conversion for this backend
      - ``img_2_webp_quality``: WebP quality 0-100 (default 80)
      - ``img_2_webp_max_size``: max response body size in bytes (default 10MB)
      - ``img_2_webp_max_dim``: max image dimension in pixels (default 4096)
      - ``img_2_webp_source_types``: comma-separated source MIME prefixes
        (default: image/jpeg,image/png,image/gif)

    Uses the ``lua.img_2_webp`` filter registered by the
    haproxy-img-2-webp Rust Lua module, which must be loaded globally
    (gated by the ``img_2_webp_enabled`` flag). Returns an empty list if
    conversion is disabled for this backend or the module is not enabled.

    Emitted in the ``backend`` section so different backends can have
    different conversion settings. The filter performs content negotiation
    based on the Accept header — no rewrite rules or src-link replacement
    needed. Converted responses include ``Vary: Accept`` so HAProxy's native
    memory cache and Varnish disk cache create separate entries for WebP vs
    original.

    When ``has_fcgi`` is True, the Lua filter is skipped because HAProxy 3.4's
    fcgi_flt_check rejects Lua filters alongside use-fcgi-app (same bug as
    compression and resp_transform).
    """
    opts = backend.options or {}
    if not opts.get("img_2_webp_enabled", False):
        return []

    if not img_2_webp_enabled:
        # Per-backend option is set but the global module toggle is off —
        # emit a comment so the config is valid but conversion is skipped.
        lines: List[str] = [
            f"    # img_2_webp: enabled for this backend but module not enabled in Global Options"
        ]
        return lines

    if has_fcgi:
        # Lua-based image conversion cannot coexist with use-fcgi-app due to
        # HAProxy 3.4's fcgi_flt_check bug (same as compression/resp_transform).
        return [
            f"    # img_2_webp: skipped for FCGI backend"
            f" (HAProxy 3.4 fcgi_flt_check rejects Lua filters alongside use-fcgi-app)"
        ]

    quality = int(opts.get("img_2_webp_quality", settings.IMG_2_WEBP_DEFAULT_QUALITY) or settings.IMG_2_WEBP_DEFAULT_QUALITY)
    max_size = int(opts.get("img_2_webp_max_size", settings.IMG_2_WEBP_MAX_FILE_SIZE) or settings.IMG_2_WEBP_MAX_FILE_SIZE)
    max_dim = int(opts.get("img_2_webp_max_dim", settings.IMG_2_WEBP_MAX_DIMENSIONS) or settings.IMG_2_WEBP_MAX_DIMENSIONS)
    source_types = str(opts.get("img_2_webp_source_types", "")).strip()

    # Initial chunk size for incremental output emission. Not a size ceiling —
    # the filter adapts it at runtime (see _img_2_webp_max_buffer).
    max_buffer = _img_2_webp_max_buffer()

    args = [
        f"quality:{max(0, min(100, quality))}",
        f"max_size:{max(1, max_size)}",
        f"max_dim:{max(1, max_dim)}",
        f"max_buffer:{max_buffer}",
    ]
    if source_types:
        args.append(f"type:{source_types}")

    return [f"    filter lua.img_2_webp {' '.join(args)}"]


def generate_cache_sections(db: Session, img_2_webp_enabled: bool = False) -> str:
    """Emit HAProxy `cache` sections for backends with memory cache enabled.

    Each CacheConfig with haproxy_enabled=True produces a `cache <name>` section
    with total-max-size, max-object-size, max-age, process-vary, and
    max-secondary-entries directives. The sections are referenced from
    `generate_backend` via `http-request cache-use` and `http-response cache-store`.

    When img_2_webp is globally enabled and a backend has it enabled in its
    options, ``process-vary on`` is auto-enabled so the cache creates separate
    entries per Accept variant — without this, a single cached raw image would
    be served to all clients and re-converted on every hit.
    """
    sections: List[str] = []
    used: set = set()
    for cc in db.query(CacheConfig).filter(CacheConfig.haproxy_enabled == True).all():  # noqa: E712
        backend = db.get(Backend, cc.backend_id)
        if not backend:
            continue
        if backend.protocol == "tcp":
            continue
        cache_name = _unique_section_name(f"cache_{_safe_name(backend.name)}", used)
        lines = [f"cache {cache_name}"]
        total_max_size = max(1, min(4095, int(cc.haproxy_total_max_size or 100)))
        max_object_size = max(1, int(cc.haproxy_max_object_size or 1000000))
        max_age = max(1, int(cc.haproxy_max_age or 300))
        max_secondary = max(0, int(cc.haproxy_max_secondary_entries or 10))
        lines.append(f"    total-max-size {total_max_size}")
        lines.append(f"    max-object-size {max_object_size}")
        lines.append(f"    max-age {max_age}")
        # Auto-enable process-vary when img_2_webp is active for this backend
        # so the cache creates separate entries per Accept variant.
        backend_opts = backend.options or {}
        backend_has_img_2_webp = backend_opts.get("img_2_webp_enabled", False) and img_2_webp_enabled
        if cc.haproxy_process_vary or backend_has_img_2_webp:
            lines.append("    process-vary on")
        lines.append(f"    max-secondary-entries {max_secondary}")
        sections.append("\n".join(lines) + "\n\n")
    return "".join(sections)


def _emit_cache_directives(
    backend: Backend,
    cache_config: Optional[CacheConfig],
    backend_name: str,
    cache_section_names: Dict[int, str],
    disk_cache_globally_enabled: bool,
) -> List[str]:
    """Emit cache directives for a backend section.

    - Memory cache: `http-request cache-use <name>` and `http-response cache-store <name>`.
    - Disk cache: `use-server` directives route cache-eligible requests to Varnish,
      bypass/no-match requests go directly to origin servers.

    Returns a list of config lines. TCP-mode backends get no cache directives.
    """
    if not cache_config:
        return []
    if backend.protocol == "tcp":
        return []

    lines: List[str] = []
    
    # Generate cache rule ACLs (shared by both memory and disk cache)
    # Emit ACLs once for all enabled rules, then emit tier-specific directives
    acl_prefix = f"cacherule_{_safe_name(backend.name)}"
    either_tier_enabled = cache_config.haproxy_enabled or (cache_config.disk_cache_enabled and disk_cache_globally_enabled)

    # Emit ACLs for ALL enabled rules (both tiers share the same ACLs)
    if either_tier_enabled:
        from .cache_rules import emit_cache_rule_acls
        acl_lines = emit_cache_rule_acls(cache_config, acl_prefix)
        lines.extend(acl_lines)

    # Disk cache ACLs — emitted early (before memory cache directives) so they
    # are available for cache-store guards. is_varnish_fetch detects Varnish's
    # backend fetch (loop prevention); is_cache_purge routes PURGE/BAN to Varnish.
    # Uses req.hdr_cnt (not bare hdr_cnt) because bare hdr_cnt refers to response
    # headers in some contexts.
    disk_cache_active = cache_config.disk_cache_enabled and disk_cache_globally_enabled
    if disk_cache_active:
        lines.append(f"    acl is_cache_purge method PURGE BAN")
        lines.append(f"    acl is_varnish_fetch req.hdr_cnt(X-Varnish-Fetch) gt 0")

    # Memory cache (HAProxy native). Cacheability rules gate `cache-use`:
    # ordered first-match-wins, with nothing cached when no rule matches.
    #
    # When disk cache (Varnish) is active for this backend, the memory cache
    # filter is NOT emitted at all. `filter cache` is a declarative filter —
    # once declared, it's in the pipeline for EVERY response from the backend,
    # including responses from the disk_cache (Varnish) server. Running both
    # caches simultaneously is redundant (Varnish is the superior cache), and
    # the extra filter adds buffer pressure to an already loaded pipeline
    # (resp_transform + compress + img_2_webp). There is no way to
    # conditionally apply a filter declaration in HAProxy, so the memory cache
    # filter is skipped entirely when disk cache is active. Varnish handles
    # all caching in that case.
    if cache_config.haproxy_enabled and not disk_cache_active:
        cache_name = cache_section_names.get(backend.id, "")
        if cache_name:
            from .cache_rules import emit_haproxy_cache_rules
            # haproxy_cache_condition remains supported as an advanced escape
            # hatch, ANDed onto every rule-generated cache-use line.
            extra = (cache_config.haproxy_cache_condition or "").strip() or None
            if extra:
                extra = _REGEX_SANITIZE_RE.sub("", extra)
            # emit_acls=False because we already emitted them above
            rule_lines, any_cacheable = emit_haproxy_cache_rules(
                cache_config, cache_name, acl_prefix, extra_condition=extra, emit_acls=False
            )
            if any_cacheable:
                # RFC 7234 compliance (default off, CDN-style behavior): when
                # disabled, strip request-side Cache-Control/Pragma headers
                # before the cache lookup so a single client's "no-cache"
                # reload does not bypass the shared memory cache for everyone.
                # HAProxy's cache filter otherwise honors these headers per RFC
                # 7234 and skips the cache lookup. The del-header lines must
                # come before `filter cache`/`cache-use` so the filter never
                # sees the headers.
                if not getattr(cache_config, "haproxy_rfc7234_compliance", False):
                    lines.append("    http-request del-header Cache-Control")
                    lines.append("    http-request del-header Pragma")
                # HAProxy 3.x requires an explicit filter declaration before
                # cache-use/cache-store can reference a cache section.
                lines.append(f"    filter cache {cache_name}")
                lines.extend(rule_lines)

                # Check for response-phase rules (content_type, status_code)
                from .cache_rules import emit_response_phase_cache_store_condition
                response_store = emit_response_phase_cache_store_condition(cache_config, cache_name)
                if response_store:
                    # Conditional cache-store based on response attributes
                    lines.append(response_store)
                else:
                    # No response-phase rules - unconditional cache-store
                    lines.append(f"    http-response cache-store {cache_name}")
            else:
                # Nothing can ever be served from this cache, so emitting the
                # filter and cache-store would only add overhead.
                lines.extend(rule_lines)
    elif cache_config.haproxy_enabled and disk_cache_active:
        # Memory cache is enabled but disk cache is also active — skip the
        # memory cache filter to prevent buffer overflow on Varnish responses.
        # Varnish handles all caching. Emit a comment for config readability.
        lines.append("    # memory cache skipped: disk cache is active (filter cache would buffer Varnish responses)")

    # Disk cache — route cache-eligible requests to Varnish via use-server directives
    if cache_config.disk_cache_enabled and disk_cache_globally_enabled:
        from .cache_rules import emit_disk_cache_use_server_directives

        # ACLs (is_cache_purge, is_varnish_fetch) were emitted above, before
        # the memory cache section, so they are available for cache-store guards.
        
        # Generate use-server directives for cache rules
        use_server_lines, acl_conditions = emit_disk_cache_use_server_directives(
            cache_config, "disk_cache", acl_prefix
        )

        # Set X-Cache-Backend header conditionally only for cache-eligible
        # client requests; skip internal Varnish fetches so the backend fetch
        # is not routed back to Varnish (loop prevention). This http-request
        # rule is emitted before the use-server rules because HAProxy processes
        # all http-request rules before use-server at runtime, and emitting it
        # first avoids a config warning about rule ordering.
        if acl_conditions:
            # Combine all cache rule conditions with OR. Each condition is the
            # cache rule's ACL ANDed with any earlier bypass rule negations
            # (space = implicit AND in HAProxy). AND has higher precedence than
            # OR, so the bypass negations bind to their cache rule without
            # needing parentheses, which HAProxy's tokenizer only splits on
            # whitespace and would otherwise include in the ACL name.
            combined_condition = " || ".join(acl_conditions)
            header_condition = f"is_cache_purge || {combined_condition}"
        else:
            # No cache rules, only PURGE/BAN
            header_condition = "is_cache_purge"

        lines.append(f"    http-request set-header X-Cache-Backend {backend_name} if {header_condition} !is_varnish_fetch")

        # Mark cache-eligible client requests so response filters (resp_transform)
        # can skip processing on the Varnish→client delivery path. The response from
        # Varnish has already been transformed on the origin→Varnish fetch path, so
        # re-applying the transform would corrupt the body (double transformation,
        # Content-Length removal, flushing failures → blank response).
        lines.append(f"    http-request set-var(txn.is_disk_cache_eligible) str(1) if {header_condition} !is_varnish_fetch")

        # PURGE/BAN always goes to Varnish (first, so it takes precedence)
        lines.append(f"    use-server disk_cache if is_cache_purge !is_varnish_fetch")

        # Cache rule use-server directives (with loop prevention)
        for line in use_server_lines:
            # Add !is_varnish_fetch negation to each use-server directive
            lines.append(f"{line} !is_varnish_fetch")

    return lines


def _trusted_src_condition(db: Session) -> Optional[str]:
    """Build the HAProxy condition fragment that gates set-src on the
    connection coming from a trusted CDN/proxy edge.

    Reads the ``restore_client_ip_trusted_network_list`` setting (one or more
    Security Lists Network list names, comma-separated). When set, returns
    ``{ src -f <path1> -f <path2> ... }`` — HAProxy ORs multiple ``-f`` files.
    When unset or no named lists still exist, returns None (ungated restore).
    """
    from .settings import get_setting as _get_setting
    from .security_lists import safe_filename

    raw = _get_setting(db, "restore_client_ip_trusted_network_list")
    if not raw:
        return None
    names = [n.strip() for n in raw.split(",") if n.strip()]
    if not names:
        return None

    base = settings.SECURITY_LISTS_DIR
    paths: list = []
    for name in names:
        # Verify each list still exists. Skip deleted lists rather than
        # emitting a broken -f path.
        found = db.query(NetworkList).filter(NetworkList.name == name).first()
        if not found:
            continue
        fname = safe_filename(name) + ".lst"
        path = os.path.abspath(os.path.join(base, "network", fname))
        paths.append(path)

    if not paths:
        return None

    flags = " ".join(f"-f {p}" for p in paths)
    return f"{{ src {flags} }}"


def _cdn_restore_client_ip_rules(
    db: Session,
    listener: Listener,
    backend_default: Optional[Backend],
    rule_combined_exprs: list,
) -> list:
    """Emit http-request set-src rules for CDN-backed backend pools.

    ``rule_combined_exprs`` is a list of ``(BackendRule, Backend, combined_expr)``
    tuples computed by the hoisted ACL block, where ``combined_expr`` is the
    HAProxy condition string (e.g. ``be_rule_1_c1 be_rule_1_c2``) used directly
    in ``if`` clauses. For each rule whose target backend has
    ``restore_client_ip == True``, emit a set-src conditioned on that rule's
    combined expression. If the listener's default_backend has restore_client_ip,
    emit a catch-all set-src with just the header/trusted guards (no rule
    negation — set-src is idempotent, and the trusted-source gate ensures it
    only fires for legitimate CDN traffic).

    Returns a list of HAProxy config lines (may be empty).
    """
    if listener.mode == "tcp" or (getattr(listener, "protocol", "http") == "tcp"):
        return []

    lines: list = []

    # Gather CDN-backed rules and the default backend's restore status.
    cdn_rules = [
        (br, backend, combined_expr)
        for (br, backend, combined_expr) in rule_combined_exprs
        if backend and getattr(backend, "restore_client_ip", False)
    ]
    default_cdn = bool(backend_default and getattr(backend_default, "restore_client_ip", False))

    if not cdn_rules and not default_cdn:
        return []

    trusted = _trusted_src_condition(db)
    trusted_suffix = f" {trusted}" if trusted else ""

    # Per-rule set-src: conditioned on the rule's combined expression.
    # Uses req.hdr_ip(<header>,1) to extract the FIRST IP from the
    # comma-separated XFF header value (the real client IP at the leftmost
    # position of the proxy chain). req.hdr() splits at commas and returns
    # the LAST value (the CDN edge IP), and returns a string type that
    # set-src cannot reliably parse — req.hdr_ip() returns an ip type
    # directly and occurrence 1 selects the first (leftmost) entry.
    # CRITICAL: these set-src rules MUST be emitted BEFORE the
    # add-header X-Forwarded-For "%[src]" line in the frontend, so that
    # req.hdr_ip() reads the original XFF from the CDN (real client IP),
    # not the value HAProxy adds (CDN edge IP). The ordering is enforced
    # in generate_frontend where _cdn_restore_client_ip_rules is called
    # before the add-header directive.
    for br, backend, combined_expr in cdn_rules:
        header = _safe_token(getattr(backend, "client_ip_header", None) or "X-Forwarded-For")
        src_expr = f"req.hdr_ip({header},1)"
        hdr_guard = f"{{ req.hdr_ip({header},1) -m found }}"
        lines.append(
            f"    http-request set-src {src_expr} if {combined_expr} {hdr_guard}{trusted_suffix}"
        )

    # Default-backend catch-all: applies when the default backend is CDN-backed.
    if default_cdn:
        header = _safe_token(getattr(backend_default, "client_ip_header", None) or "X-Forwarded-For")
        src_expr = f"req.hdr_ip({header},1)"
        hdr_guard = f"{{ req.hdr_ip({header},1) -m found }}"
        condition = f"{hdr_guard}{trusted_suffix}"
        lines.append(f"    http-request set-src {src_expr} if {condition}")

    return lines


def _emit_varnish_fetch_routing(
    db: Session,
    listener: Listener,
    backend_names: Dict[int, str],
) -> List[str]:
    """Emit ACLs + use_backend rules from other listeners' BackendRules.

    On a force_https listener (port 80), Varnish fetches skip the HTTPS
    redirect but then have no routing rules (this listener has no
    BackendRules of its own). Query BackendRules from all other enabled
    HTTP-mode listeners, emit their ACLs with a unique prefix, and emit
    use_backend rules conditioned on is_varnish_fetch so they only fire
    for Varnish backend fetches.

    Returns a list of HAProxy config lines (ACLs + use_backend directives).
    """
    # Query BackendRules from all OTHER enabled HTTP-mode listeners.
    other_listeners = [
        l for l in db.query(Listener).filter(Listener.enabled == True).all()  # noqa: E712
        if l.id != listener.id and l.mode == "http"
    ]
    other_listener_ids = [l.id for l in other_listeners]
    if not other_listener_ids:
        return []

    rules = (
        db.query(BackendRule)
        .filter(
            BackendRule.listener_id.in_(other_listener_ids),
            BackendRule.enabled == True,  # noqa: E712
        )
        .order_by(BackendRule.priority)
        .all()
    )
    if not rules:
        return []

    lines: List[str] = []
    seen_backends: set = set()

    for br in rules:
        br_backend = db.query(Backend).filter(Backend.id == br.backend_id).first()
        if not br_backend:
            continue

        # Build the ACL condition expression for this rule.
        cond_list = [br]
        if br.conditions:
            cond_list.extend(br.conditions)
        rule_prefix = f"vfetch_rule_{br.id}"

        # Emit ACL declarations for each condition in the rule.
        combined = ""
        for idx, cond in enumerate(cond_list, start=1):
            if isinstance(cond, dict):
                ct = cond["condition_type"]
                cn = cond.get("condition_name")
                op = cond["operator"]
                val = cond.get("value")
            else:
                ct = cond.condition_type
                cn = cond.condition_name
                op = cond.operator
                val = cond.value
            expr = _backend_condition_expression(ct, cn, op, val)
            acl_name = f"{rule_prefix}_c{idx}"
            lines.append(f"    acl {acl_name} {expr}")
            if idx == 1:
                combined = acl_name
            else:
                join = cond.get("join", "and") if isinstance(cond, dict) else getattr(cond, "join", "and")
                if join == "or":
                    combined = f"{combined} || {acl_name}"
                else:
                    combined = f"{combined} {acl_name}"

        # Emit use_backend conditioned on is_varnish_fetch so it only
        # fires for Varnish backend fetches, not regular HTTP traffic
        # (which was already redirected to HTTPS above).
        backend_name = backend_names.get(br_backend.id, _safe_name(br_backend.name))
        lines.append(f"    use_backend {backend_name} if is_varnish_fetch {combined}")
        seen_backends.add(br_backend.id)

    return lines


def generate_frontend(
    listener: Listener,
    db: Session,
    frontend_names: Optional[Dict[int, str]] = None,
    backend_names: Optional[Dict[int, str]] = None,
    req_fp_enabled: bool = False,
    req_fp_parse_body: bool = False,
    req_fp_max_body_bytes: int = 1048576,
    req_fp_enforce_max_body: bool = False,
    page_protect_enabled: bool = False,
    page_protect_report_path: str = "/_csp-report",
    page_protect_beacon: Optional[Dict[str, Any]] = None,
    api_armor_enabled: bool = False,
    api_armor_max_body_bytes: int = 1048576,
    ja4_enabled: bool = True,
    disk_cache_enabled: bool = False,
    logged_fields: Optional[List[LoggedField]] = None,
) -> str:
    cert_ids = (listener.certificate_ids or []) if listener.certificate_ids else []
    if not cert_ids and listener.certificate_id:
        cert_ids = [listener.certificate_id]
    certs = db.query(Certificate).filter(Certificate.id.in_(cert_ids)).all() if cert_ids else []
    listener_options = listener.options or {}
    cipher = db.query(CipherSuite).filter(CipherSuite.name == _safe_token(listener_options.get("cipher_suite", ""))).first()
    backend_default = db.query(Backend).filter(Backend.id == listener.default_backend_id).first()

    def _backend_name(b: Optional[Backend]) -> str:
        if not b:
            return ""
        if backend_names:
            return backend_names.get(b.id, _safe_name(b.name))
        return _safe_name(b.name)

    listener_name = (frontend_names or {}).get(listener.id, _safe_name(listener.name))
    bind_port = max(1, min(65535, int(listener.bind_port))) if listener.bind_port else 80
    bind_address = _safe_token(listener.bind_address)
    bind_line = f"bind {bind_address}:{bind_port}"
    ssl_opts = _build_ssl_bind_options(listener, certs, cipher)
    if ssl_opts:
        bind_line += " " + ssl_opts
    if listener.protocol == "grpc" and not listener.ssl_enabled:
        bind_line += " proto h2"

    extra_bind, extra_frontend = _render_haproxy_options(listener.haproxy_options, "listener")
    if extra_bind:
        bind_line += " " + " ".join(extra_bind)

    effective_mode = "tcp" if listener.protocol == "tcp" else "http"
    lines = [f"frontend {listener_name}"]
    lines.append(f"    {bind_line}")
    if listener.quic and listener.ssl_enabled:
        quic_bind = f"bind quic4@{bind_address}:{bind_port} {_build_ssl_bind_options(listener, certs, cipher, quic=True)}"
        if extra_bind:
            quic_bind += " " + " ".join(extra_bind)
        lines.append(f"    {quic_bind}")
    lines.append(f"    mode {effective_mode}")

    # Inherit global log destinations (so the default stdout target or any
    # global LogDestination applies to this frontend).
    lines.append("    log global")

    # Per-listener logging destinations (override/augment global)
    log_max_len = getattr(settings, "HAPROXY_LOG_MAX_LEN", 65535)
    for log in db.query(LogDestination).filter(LogDestination.enabled == True).all():
        if _matches_listener(log, listener):
            target = _safe_token(log.target)
            facility = _safe_token(log.facility)
            level = _safe_token(log.level)
            if target in ("stdout", "stderr"):
                lines.append(f"    log {target} len {log_max_len} format raw {facility}")
            else:
                lines.append(f"    log {target} len {log_max_len} {facility} {level}")

    # Log format: TCP listeners emit option tcplog (overrides the defaults
    # log-format with TCP-specific fields). HTTP listeners inherit the
    # defaults log-format (the JSON default or custom override).
    if effective_mode == "tcp":
        lines.append("    option tcplog")
    else:
        # HTTP frontends get a per-frontend log-format (not inherited from
        # defaults) because HAProxy 3.4+ rejects req.hdr sample fetches in
        # the defaults log-format. If any LoggedField rows are enabled,
        # build a custom log-format from them (user override). Otherwise,
        # emit the structured JSON default.
        custom_fields = [f for f in (logged_fields or []) if f.enabled]
        if custom_fields:
            log_format = " ".join(
                f"%{{{_safe_token(f.field)}}}" if not f.field.startswith("%") else f.field
                for f in custom_fields
            )
            lines.append(f"    log-format {log_format}")
        else:
            lines.append(f"    log-format {_default_json_log_format(ja4_enabled, page_protect_enabled=page_protect_enabled)}")

    # Initialized here so it's always defined (TCP listeners skip the HTTP
    # block below but the content-switching section at the end references it).
    rule_combined_acls: list = []  # list of (BackendRule, Backend, combined_acl_name)

    if effective_mode == "http":
        # Standard reverse-proxy headers. X-Forwarded-Proto and Port are only
        # set when absent, so an internal Varnish re-fetch preserves the
        # original client scheme/port instead of overwriting it with the
        # HAProxy-to-Varnish HTTP hop. X-Forwarded-For is appended like a
        # normal proxy chain. These headers sit before per-listener request
        # headers so user-defined rules can override them.
        lines.append("    option http-keep-alive")

        # Stick-table + tcp-request connection tracking — MUST be emitted
        # before any http-request rules. HAProxy processes tcp-request
        # connection rules at the TCP layer (before HTTP) regardless of
        # config position, but emits a warning if they appear after
        # http-request rules in the config. We compute the rate-limit
        # parameters and emit the stick-table + tcp-request connection
        # here, then emit the http-request track-sc1/sc2/sc3 rules later
        # (after the standard http-request headers).
        rules = coraza_config.rules_for_listener(db, listener.id)
        waf_enabled_for_listener = bool(rules)
        waf_rule_rate = None
        if settings.CORAZA_SPOA_ENABLED and waf_enabled_for_listener:
            primary = rules[0]
            if primary.rate_enabled:
                waf_rule_rate = primary

        listener_rate_limits = [
            rl for rl in db.query(RateLimit).all()
            if _matches_listener(rl, listener) and rl.enabled
        ]

        # Response-code rate limits use a dedicated stick-table backend tracked
        # on sc3 (see _generate_resp_code_tables). HAProxy only supports
        # gpc0_rate and gpc1_rate as stick-table rate stores, so gpc2_rate
        # cannot be used on the frontend stick-table.
        has_resp_code_rate = any(rl.limit_type == "response_code" for rl in listener_rate_limits)
        needs_stick_table = any(rl.limit_type in ("basic", "advanced", "waf") for rl in listener_rate_limits) or waf_rule_rate is not None
        # Determine which stores go on the frontend ip stick-table (sc0) vs the
        # string stick-table backend (sc1). Non-src rate keys track on sc1, so
        # their rate stores must be on the string table, not the frontend table.
        # Use the resolved track expression — ASN may fall back to src when no
        # MaxMind DB/map is available.
        def _rl_is_src(rl):
            return _rate_key_track_expr(getattr(rl, "rate_key", "src"), getattr(rl, "rate_header", None)) == "src"
        src_req_windows = [rl.window_seconds for rl in listener_rate_limits
                           if rl.limit_type in ("basic", "advanced") and _rl_is_src(rl)]
        nonsrc_req_windows = [rl.window_seconds for rl in listener_rate_limits
                              if rl.limit_type in ("basic", "advanced") and not _rl_is_src(rl)]
        src_waf_windows = [rl.window_seconds for rl in listener_rate_limits
                           if rl.limit_type == "waf" and _rl_is_src(rl)]
        nonsrc_waf_windows = [rl.window_seconds for rl in listener_rate_limits
                              if rl.limit_type == "waf" and not _rl_is_src(rl)]
        waf_rule_uses_sc1 = False
        if needs_stick_table:
            stores = ["conn_cur"]
            windows = []
            if src_req_windows:
                windows.extend(src_req_windows)
                stores.append(f"http_req_rate({max(src_req_windows)}s)")
            if src_waf_windows:
                windows.extend(src_waf_windows)
                stores.append(f"gpc0_rate({max(src_waf_windows)}s)")
            if waf_rule_rate:
                rule_rate_window = waf_rule_rate.rate_window_seconds or 60
                windows.append(rule_rate_window)
                stores.append(f"gpc1_rate({rule_rate_window}s)")
            expire = max(windows) if windows else 30
            lines.append(f"    stick-table type ip size 1m expire {expire}s store {','.join(stores)}")
            lines.append("    tcp-request connection track-sc0 src")

        # Hoist BackendRule ACL definitions early (before set-src and
        # add-header) so the Restore Client IP set-src rules can reference
        # them. ACL definitions are inert — hoisting does not change runtime
        # behavior. The use_backend lines are emitted later in the
        # content-switching region.
        backend_rules = db.query(BackendRule).filter(
            BackendRule.listener_id == listener.id, BackendRule.enabled == True
        ).order_by(BackendRule.priority).all()
        for br in backend_rules:
            br_backend = db.query(Backend).filter(Backend.id == br.backend_id).first()
            if not br_backend:
                continue
            cond_list = [br]
            if br.conditions:
                cond_list.extend(br.conditions)
            rule_prefix = f"be_rule_{br.id}"
            for idx, cond in enumerate(cond_list, start=1):
                if isinstance(cond, dict):
                    ct, cn, op, val = cond["condition_type"], cond.get("condition_name"), cond["operator"], cond.get("value")
                else:
                    ct, cn, op, val = cond.condition_type, cond.condition_name, cond.operator, cond.value
                expr = _backend_condition_expression(ct, cn, op, val)
                lines.append(f"    acl {rule_prefix}_c{idx} {expr}")

            # Build the combined condition string (used directly in use_backend
            # and set-src if-clauses). HAProxy doesn't allow referencing other
            # ACLs by name inside an acl definition, so we store the expression
            # string and use it inline.
            combined = f"{rule_prefix}_c1"
            for idx in range(1, len(cond_list)):
                join = cond_list[idx].get("join", "and") if isinstance(cond_list[idx], dict) else getattr(cond_list[idx], "join", "and")
                if join == "or":
                    combined = f"{combined} || {rule_prefix}_c{idx+1}"
                else:
                    combined = f"{combined} {rule_prefix}_c{idx+1}"
            rule_combined_acls.append((br, br_backend, combined))

        # Restore Client IP — MUST run BEFORE add-header X-Forwarded-For so
        # that req.hdr_ip(X-Forwarded-For) reads the ORIGINAL XFF header from
        # the CDN (containing the real client IP), not the one HAProxy is
        # about to add. When restore rules exist, the original connection
        # source (the CDN edge IP) is preserved in txn.orig_src BEFORE
        # set-src rewrites it, and the XFF hop appended below uses that
        # original source — per XFF convention each proxy appends the peer
        # address it received the connection from. This yields e.g.
        # "client_ip, cdn_edge_ip" instead of duplicating the client IP.
        restore_lines = _cdn_restore_client_ip_rules(db, listener, backend_default, rule_combined_acls)
        if restore_lines:
            lines.append("    http-request set-var(txn.orig_src) src")
            lines.extend(restore_lines)
            lines.append('    http-request add-header X-Forwarded-For "%[var(txn.orig_src)]"')
        else:
            lines.append('    http-request add-header X-Forwarded-For "%[src]"')
        lines.append('    http-request set-header X-Forwarded-Port "%[dst_port]" if !{ hdr(X-Forwarded-Port) -m found }')
        lines.append('    http-request set-header X-Forwarded-Proto "https" if { ssl_fc } !{ hdr(X-Forwarded-Proto) -m found }')
        lines.append('    http-request set-header X-Forwarded-Proto "http" if !{ ssl_fc } !{ hdr(X-Forwarded-Proto) -m found }')
        # Forward the JA4 TLS fingerprint to backends so the captcha verify
        # endpoint can compute the same client-binding hash that the HAProxy
        # Lua validation action computes. Only emitted when JA4 is enabled
        # (the lua.ja4_fp fetch is only registered when ja4.lua is loaded).
        # Returns empty string for plaintext listeners, which both sides
        # handle as an empty JA4 component in the binding hash.
        if ja4_enabled:
            lines.append('    http-request set-header X-JA4-Fingerprint "%[lua.ja4_fp]"')

        # Varnish fetch requests must not be treated like external clients:
        # they bypass force-HTTPS redirects and any listener-level redirects
        # so the disk-cache fetch can reach the origin backend.
        # Uses req.hdr_cnt (not bare hdr_cnt) because bare hdr_cnt in an
        # http-response context refers to response headers, which never
        # contain X-Varnish-Fetch. However, req.hdr_cnt is ALSO incompatible
        # with http-response rules in HAProxy 3.4+ (request headers aren't
        # available during response processing). So we set a txn var here
        # (during the request phase) and http-response rules check the var
        # instead of the ACL directly.
        lines.append("    acl is_varnish_fetch req.hdr_cnt(X-Varnish-Fetch) gt 0")
        # Stash the varnish-fetch flag in a txn var so http-response rules
        # can check it without referencing req.hdr_cnt (which is incompatible
        # with http-response context in HAProxy 3.4+).
        lines.append("    http-request set-var(txn.is_varnish_fetch) str(1) if is_varnish_fetch")

        # http-request track-sc1 for non-src rate keys. The stick-table
        # declaration and tcp-request connection track-sc0 were emitted
        # earlier (before the http-request rules) to avoid HAProxy's
        # ordering warning. waf_rule_uses_sc1 was initialized to False
        # in that early block.
        if needs_stick_table:
            # For non-src WAF rate keys (user_id/header/path/asn), track on sc1
            # using a separate string-type stick table backend.
            if waf_rule_rate and _safe_token(waf_rule_rate.rate_key) != "src":
                track_expr = _rate_key_track_expr(waf_rule_rate.rate_key, waf_rule_rate.rate_header)
                if track_expr != "src":
                    lines.append(f"    http-request track-sc1 {track_expr} table waf_rate_{_safe_name(listener.name)}")
                    waf_rule_uses_sc1 = True

            # RateLimit-page non-src keys also need sc1 tracking. If the WAF
            # rule already claimed sc1 with a different key expression, the
            # first track-sc1 wins (HAProxy behaviour) — this is a documented
            # limitation. If the WAF rule uses sc1 with the same key, they
            # share the tracking transparently.
            if not waf_rule_uses_sc1:
                for rl in listener_rate_limits:
                    rl_rk = _safe_token(getattr(rl, "rate_key", "src") or "src")
                    if rl_rk != "src" and rl.limit_type in ("basic", "advanced", "waf"):
                        track_expr = _rate_key_track_expr(rl_rk, getattr(rl, "rate_header", None))
                        if track_expr != "src":
                            lines.append(f"    http-request track-sc1 {track_expr} table rl_rate_{_safe_name(listener.name)}")
                        break

        # Block duration (tarpit) tracking on sc2.
        # If any rate limit on this listener has duration > 0, track the client
        # in a block table so they remain blocked for the configured duration
        # even after their rate drops below the threshold.
        has_block_duration = False
        for rl in listener_rate_limits:
            if (rl.duration_seconds or 0) > 0 or (rl.waf_block_duration or 0) > 0:
                has_block_duration = True
                break
        if waf_rule_rate and (waf_rule_rate.rate_duration_seconds or 0) > 0:
            has_block_duration = True
        if has_block_duration:
            lname = _safe_name(listener.name)
            # Determine the sc2 track expression: WAF rules and RateLimits may
            # both have non-src keys. Prefer the WAF rule's key, then check
            # RateLimits. If any non-src key is found, use the string block
            # table; otherwise track src on the ip block table.
            btrack = "src"
            if waf_rule_rate and _safe_token(waf_rule_rate.rate_key) != "src":
                btrack = _rate_key_track_expr(waf_rule_rate.rate_key, waf_rule_rate.rate_header)
            if btrack == "src":
                for rl in listener_rate_limits:
                    rl_rk = _safe_token(getattr(rl, "rate_key", "src") or "src")
                    if rl_rk != "src" and rl.limit_type in ("basic", "advanced", "waf"):
                        btrack = _rate_key_track_expr(rl_rk, getattr(rl, "rate_header", None))
                        break
            if btrack != "src":
                lines.append(f"    http-request track-sc2 {btrack} table block_table_str_{lname}")
            else:
                lines.append(f"    http-request track-sc2 src table block_table_{lname}")

        # Response-code rate limiting tracks on sc3 using a dedicated
        # stick-table backend (resp_code_table_<listener>). This is separate
        # from the frontend stick-table (sc0) because HAProxy only supports
        # gpc0_rate/gpc1_rate as rate stores, and sc0 may already use both
        # for WAF and WAF-rule rate limiting.
        if has_resp_code_rate:
            lname = _safe_name(listener.name)
            lines.append(f"    http-request track-sc3 src table resp_code_table_{lname}")

        lines.append("    http-request capture req.hdr(Host) len 64")
        # Stash the Host header in a txn var so the log-format (evaluated at
        # log time, where req.hdr() is not reliably available) can reference
        # it via %[var(txn.host)]. See _default_json_log_format.
        lines.append("    http-request set-var(txn.host) req.hdr(host)")
        # Default status_source to "haproxy" — overridden to "backend" by the
        # http-response set-var below when a real backend response is received.
        # http-response rules do NOT fire for HAProxy-generated responses (deny,
        # return, redirect, 503 no-backend), so the default correctly marks those
        # as haproxy-sourced. Response-side WAF/security-rule denies override
        # back to "haproxy" before the deny replaces the backend's status.
        lines.append("    http-request set-var(txn.status_source) str(haproxy)")
        lines.append("    http-response set-var(txn.status_source) str(backend)")
        # Capture the User-Agent header into capture slot 1 (Host is slot 0)
        # for inclusion in the log-format via %[capture.req.hdr(1),json].
        # Use req.fhdr() (full header) because req.hdr() splits comma-separated
        # values, which would chop UAs like "KHTML, like Gecko" at the comma.
        # Using capture (not set-var) because the capture buffer explicitly
        # preserves the full header value up to the declared len, whereas
        # set-var can truncate longer header values.
        lines.append("    http-request capture req.fhdr(user-agent) len 512")

        # ACME HTTP-01 challenge — serve challenge files from the shared
        # webroot volume via Lua (reads at request time, no reload needed).
        # Runs BEFORE security rules, rate limiting, WAF, and the force-https
        # redirect so Let's Encrypt validators reach the challenge response
        # unimpeded. The force-https redirect later skips is_acme_challenge so
        # the fallback use_backend to the ACME backend is reachable.
        #
        # Only emitted on plain HTTP listeners (no SSL). ACME HTTP-01
        # validation happens over HTTP (port 80) — Let's Encrypt connects to
        # http://host/.well-known/acme-challenge/<token>, not HTTPS. SSL
        # listeners bind with TLS and can never serve that request, so the
        # ACL and Lua fetch would be dead code on them.
        #
        # Security: only exact token paths (^/.well-known/acme-challenge/<token>$)
        # are served or proxied. The old path_beg match + http-request allow
        # bypassed ALL security controls for any path under the prefix and
        # routed to the API container on port 80 — a security bypass.
        if not listener.ssl_enabled:
            webroot = settings.ACME_WEBROOT_PATH
            lines.append("    acl is_acme_challenge path -m reg '^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$'")
            lines.append("    http-request set-var(txn.acme_file) path,field(3,/) if is_acme_challenge")
            lines.append(f'    http-request set-var(txn.acme_webroot) str("{webroot}") if is_acme_challenge')
            # Read the challenge file via Lua and store content in a variable.
            # If the file doesn't exist, the Lua fetch returns nil → var is empty.
            lines.append("    http-request set-var(txn.acme_content) lua.acme_challenge_file if is_acme_challenge")
            # Serve from webroot if the file exists (primary method).
            lines.append('    http-request return status 200 content-type "application/octet-stream" lf-string "%[var(txn.acme_content)]" if is_acme_challenge { var(txn.acme_content) -m found }')

        # Cap CAPTCHA proxy — route /_cap/ requests through the listener so
        # the browser never talks directly to the Cap service. This fixes
        # cookie-domain mismatches (cv is set for the listener's
        # domain, not localhost:8000) and lets the widget API calls
        # (challenge/redeem) go through the same origin.
        # Bypass ALL security controls for /_cap/ — it's internal captcha
        # infrastructure (the Cap service has its own rate limiting and the
        # verify endpoint has rate_limit_by_ip).
        if _listener_has_challenge_action(db, listener.id):
            cap_path = _safe_token(settings.CAPTCHA_PROXY_PATH)
            lines.append(f"    acl is_cap_proxy path_beg {cap_path}/")
            lines.append(f"    http-request allow if is_cap_proxy")
            # Validate the cv cookie (emitted once per listener, before any
            # challenge-action rules). The cookie is an opaque random token
            # stored in Valkey with a TTL on successful challenge solve. The
            # Lua action looks up cap:_cv:<token> in Valkey and sets
            # txn.captcha_cookie_valid if the key exists (i.e. the user
            # previously solved a challenge and the TTL hasn't expired).
            # Each challenge-action rule then checks txn.captcha_cookie_valid
            # to allow already-challenged users through. This replaces the old
            # "req.cook(cap_valid) -m found" check which was trivially
            # forgeable (any value worked).
            lines.append("    # _cv cookie validation (Valkey-backed opaque token, client-bound)")
            lines.append("    http-request set-var(txn.cap_cv_val) req.cook(_cv) if { req.cook(_cv) -m found }")
            # Set the client-binding context vars (IP, User-Agent, JA4) so the
            # Lua action can recompute the binding hash and compare it with the
            # stored hash. The token is bound to the client that solved the
            # challenge — a leaked cookie cannot be replayed from a different
            # client (different IP / UA / JA4 fingerprint).
            lines.append('    http-request set-var(txn.cap_cv_ip) src if { var(txn.cap_cv_val) -m found }')
            lines.append('    http-request set-var(txn.cap_cv_ua) req.fhdr(user-agent) if { var(txn.cap_cv_val) -m found }')
            if ja4_enabled:
                lines.append('    http-request set-var(txn.cap_cv_ja4) lua.ja4_fp if { var(txn.cap_cv_val) -m found }')
            lines.append("    http-request lua.captcha_validate_cookie if { var(txn.cap_cv_val) -m found }")

        # Page Protect — CSP violation report capture.
        # Browsers POST CSP violation reports to the configured report-uri path.
        # HAProxy buffers the request body, captures it into txn.csp_report,
        # returns 204 (no body needed), and logs the request. The background
        # sampler reads HAProxy logs and extracts the csp_report field.
        # This runs early (before security rules/WAF) so report POSTs are never
        # blocked by security rules or rate limiting.
        if page_protect_enabled:
            report_path = _safe_token(page_protect_report_path) or "/_csp-report"
            lines.append(f"    acl is_csp_report path -m str {report_path}")
            lines.append("    http-request wait-for-body time 5s if is_csp_report")
            lines.append(f"    http-request set-var(txn.csp_report) req.body if is_csp_report")
            lines.append("    http-request return status 204 if is_csp_report")

        # Page Protect — beacon injection capture + static JS serving.
        # When beacon injection is enabled, HAProxy serves the beacon JS file
        # and captures beacon POSTs (resource lists from the browser). The
        # beacon JS uses the Resource Timing API to collect all loaded resources
        # and POSTs them to the beacon endpoint for inventory building.
        beacon = page_protect_beacon or {}
        if page_protect_enabled and beacon.get("enabled"):
            beacon_path = _safe_token(beacon.get("beacon_path") or "/_asset-beacon")
            beacon_script_path = _safe_token(beacon.get("beacon_script_path") or "/_asset-beacon.js")
            # Serve the static beacon JS file
            beacon_js_path = getattr(settings, 'PAGE_PROTECT_BEACON_JS_PATH', '/etc/haproxy/page-protect-beacon.js')
            lines.append(f"    acl is_beacon_script path -m str {beacon_script_path}")
            lines.append(f"    http-request return status 200 content-type application/javascript lf-file {beacon_js_path} hdr Cache-Control public,max-age=86400 if is_beacon_script")
            # Capture beacon POSTs (resource lists from the browser)
            lines.append(f"    acl is_asset_beacon path -m str {beacon_path}")
            lines.append("    http-request wait-for-body time 5s if is_asset_beacon")
            lines.append(f"    http-request set-var(txn.asset_beacon) req.body if is_asset_beacon")
            lines.append("    http-request return status 204 if is_asset_beacon")

        # Body buffering for request fingerprint param extraction.
        # When req_fp_parse_body is enabled (and API Armor is not already
        # handling body buffering for this listener), buffer form/JSON bodies
        # into txn.req_fp_body so req_fp.lua can parse body params. This is
        # independent of API Armor — it only does shallow param extraction
        # (keys/types/lengths), no schema/auth/GraphQL analysis.
        # Must run BEFORE lua.req_fp_capture so the txn var is available.
        # Oversized bodies (> req_fp_max_body_bytes): when req_fp_enforce_max_body
        # is on, the request is rejected with 413. Otherwise the body is not
        # buffered and req_fp.lua falls back to query-only parsing (body params
        # become nil: param_keys/param_types='nil', param_lens='0' when no
        # query params).
        api_armor_on_listener = api_armor_enabled and listener_options.get("api_armor", False)
        if req_fp_enabled and req_fp_parse_body and not api_armor_on_listener:
            lines.append('    acl is_req_fp_body req.hdr(content-type) -m beg application/json application/x-www-form-urlencoded')
            lines.append(f"    acl is_req_fp_body_oversize req.body_len gt {req_fp_max_body_bytes}")
            if req_fp_enforce_max_body:
                lines.append("    http-request deny deny_status 413 if is_req_fp_body is_req_fp_body_oversize")
            lines.append("    http-request wait-for-body time 10s if is_req_fp_body !is_req_fp_body_oversize")
            lines.append("    http-request set-var(txn.req_fp_body) req.body if is_req_fp_body !is_req_fp_body_oversize")

        # API Armor — conditional body buffering.
        # The set-var(txn.api_body) must run BEFORE lua.req_fp_capture so that
        # req_fp.lua can read it during capture. The deeper Rust analysis
        # (lua.api_body_parse) runs AFTER req_fp_capture because it needs req_fp
        # subfields. Both run BEFORE security rules (so rules can reference
        # graphql.*/api.*/auth.*).
        if api_armor_on_listener:
            lines.append('    acl is_api_armor req.hdr(content-type) -m beg application/json application/graphql application/x-www-form-urlencoded')
            lines.append(f"    http-request deny deny_status 413 if is_api_armor {{ req.body_len gt {api_armor_max_body_bytes} }}")
            lines.append("    http-request wait-for-body time 10s if is_api_armor")
            lines.append("    http-request set-var(txn.api_body) req.body if is_api_armor")

        # HTTP request fingerprint (haproxy-req-fp Rust module) — two-phase design:
        #   http-request lua.req_fp_capture  — captures request data (http-req)
        #   http-response lua.req_fp         — builds fingerprint (http-res)
        # The capture must run in http-req because HAProxy frees the request
        # buffer before http-res. The build must run before any response header
        # that references %[var(txn.req_fp)]. Gated by req_fp_enabled AND the
        # Rust module being available (loaded via the combined modules.lua loader).
        # Body buffering (txn.api_body / txn.req_fp_body) must be emitted ABOVE
        # this line so the vars are populated when capture runs.
        if req_fp_enabled and _req_fp_module_available():
            # GeoIP set-vars for risk scoring (geo_lang_mismatch + timezone_mismatch).
            # These must run BEFORE lua.req_fp_capture so txn.geo_country is
            # available to lua.risk_capture (which runs after req_fp_capture).
            if _geoip_lua_module_available():
                lines.append('    http-request set-var(txn.geo_country) src,lua.geoip2-lookup-city("country","iso_code")')
                lines.append('    http-request set-var(txn.geoip_tz) src,lua.geoip2-lookup-city("location","time_zone")')
            elif _haproxy_supports_geoip2():
                geo_db = os.path.abspath(settings.GEOIP_DB_PATH)
                if os.path.exists(geo_db):
                    lines.append(f'    http-request set-var(txn.geo_country) src,geoip2({geo_db},country.iso_code)')
                    lines.append(f'    http-request set-var(txn.geoip_tz) src,geoip2({geo_db},location.time_zone)')
            lines.append("    http-request lua.req_fp_capture")
            lines.append("    http-response lua.req_fp")

        # API Armor deeper analysis — runs AFTER req_fp_capture so req_fp
        # subfields are available for security rules.
        if api_armor_on_listener:
            lines.append("    http-request lua.api_body_parse if is_api_armor")

        # Request headers are emitted ONLY in backend sections (see
        # generate_backend). RequestHeader is backend-scoped (backend_id /
        # backend_ids — it has no listener binding fields), so emitting here
        # made every request header apply to every frontend AND its backend
        # section, duplicating "add" actions (the header value appeared twice
        # at the upstream server).

        # Automatic QUIC Alt-Svc advertisement
        if listener.quic:
            alt_svc = listener.options.get("alt_svc") if listener.options else None
            if not alt_svc:
                alt_svc = f'h3=":{bind_port}"; ma=900'
            else:
                alt_svc = _safe_token(alt_svc)
            # Guard with !is_varnish_fetch so Alt-Svc is not baked into Varnish
            # cache objects (would otherwise be duplicated on cache-hit delivery).
            # Uses the txn var (set during request phase) because the
            # is_varnish_fetch ACL (req.hdr_cnt) is incompatible with
            # http-response rules in HAProxy 3.4+.
            lines.append(f"    http-response set-header Alt-Svc '{alt_svc}' if !{{ var(txn.is_varnish_fetch) -m found }}")

        # Response headers (per listener)
        # Guarded with !{ var(txn.is_varnish_fetch) -m found } so the header
        # is only applied on the Varnish→client (or origin→client when disk
        # cache is off) path, not on the origin→Varnish fetch. Without this,
        # add-header rules fire twice (once when Varnish caches the origin
        # response, again when HAProxy delivers the cached object to the
        # client), producing duplicate header values. set-header rules would
        # silently re-process too. Uses the txn var (set during the request
        # phase) because the is_varnish_fetch ACL (req.hdr_cnt) is
        # incompatible with http-response rules in HAProxy 3.4+.
        for h in db.query(ResponseHeader).all():
            if not _matches_listener(h, listener):
                continue
            header_name = _safe_token(h.header)
            header_value = _safe_header_value(h.value)
            condition = _format_condition(h.condition)
            if condition:
                condition = f"{condition} !{{ var(txn.is_varnish_fetch) -m found }}"
            else:
                condition = " if !{ var(txn.is_varnish_fetch) -m found }"
            if h.action in ("set", "override"):
                lines.append(f"    http-response set-header {header_name} {header_value}{condition}")
            elif h.action == "add":
                lines.append(f"    http-response add-header {header_name} {header_value}{condition}")
            elif h.action == "del":
                lines.append(f"    http-response del-header {header_name}{condition}")

        # Custom response pages (per listener)
        errorfiles_dir = os.path.join(os.path.dirname(settings.HAPROXY_CONFIG_PATH), "errorfiles", _safe_path_name(listener.name))
        pages_by_code: Dict[int, CustomErrorPage] = {}
        for ep in db.query(CustomErrorPage).order_by(CustomErrorPage.id).all():
            if not _matches_listener(ep, listener):
                continue
            pages_by_code[ep.code] = ep
            path = os.path.join(errorfiles_dir, f"{ep.code}-{ep.id}.http")
            os.makedirs(errorfiles_dir, exist_ok=True)
            content_type = _safe_token(ep.content_type) or "text/html"
            _write_error_file(path, ep.content, content_type)
        for ep in pages_by_code.values():
            path = os.path.join(errorfiles_dir, f"{ep.code}-{ep.id}.http")
            content_type = _safe_token(ep.content_type) or "text/html"
            lines.append(f'    http-error status {ep.code} content-type "{content_type}" lf-file {path}')

        # Block deny: deny already-blocked clients before rate checks.
        # This catches clients still within their block duration even if their
        # current rate has dropped below the threshold.
        if has_block_duration:
            lines.append("    http-request deny deny_status 429 default-errorfiles if { sc_get_gpc0(2) gt 0 } !{ var(txn.sec.skip_ratelimit) -m found }")

        # Risk Scoring — runs BEFORE Security Rules so risk.score /
        # risk.rules_hit / risk.rules_hit_count and per-ruleset vars
        # (risk.<slug>.score etc.) are available to Security Rule expressions.
        # Only emitted when req_fp is enabled (risk_capture reads txn.req_fp.*
        # vars set by the Rust module).
        if req_fp_enabled and _req_fp_module_available():
            from . import risk_scoring
            risk_scoring.emit_risk_scoring(listener, db, lines)

        # Security Rules — run BEFORE rate-limiting and WAF so skip flags take effect.
        # First-match-wins via txn.sec.done; sets txn.sec.skip_ratelimit / skip_waf.
        from . import security_rules
        security_rules.emit_security_rules(listener, db, lines)

        waf_rate_limits = []
        for rl in listener_rate_limits:
            rname = _safe_name(rl.name)
            rl_status = rl.response_code or 429
            rl_window = rl.window_seconds or 60
            rl_duration = rl.duration_seconds or 0
            rl_log = getattr(rl, "log", True)
            rl_no_log = getattr(rl, "no_log", False)
            rl_rk = _safe_token(getattr(rl, "rate_key", "src") or "src")
            # Use resolved track expression — ASN may fall back to src
            rl_is_nonsrc = _rate_key_track_expr(rl_rk, getattr(rl, "rate_header", None)) != "src"
            rl_sc = 1 if rl_is_nonsrc else 0  # non-src keys use sc1 (string table)
            # Per-endpoint scoping (API Armor) — add path/method ACLs to the condition
            rl_path = getattr(rl, "path_pattern", None)
            rl_method = getattr(rl, "method", None)
            rl_scope_cond = ""
            if rl_path:
                rl_scope_cond += f" {{ path_beg {rl_path} }}"
            if rl_method:
                rl_scope_cond += f" {{ method {rl_method.upper()} }}"
            if rl.limit_type == "basic":
                rl_cond = f"{{ sc_http_req_rate({rl_sc}) gt {rl.events} }}{rl_scope_cond}"
                rl_action = _safe_token(getattr(rl, "action", "block") or "block")
                if rl_no_log:
                    lines.append(f"    http-request set-log-level silent if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                if rl_log:
                    lines.append(f"    http-request set-var(txn.ratelimit.action) str(blocked) if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                    lines.append(f"    http-request set-var(txn.ratelimit.name) str({rname}) if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                lines.append(f"    http-request set-var(txn.rate_limit_window) str({rl_window})")
                lines.append(f"    http-request set-var(txn.rate_limit_duration) str({rl_duration})")
                if rl_action == "challenge":
                    from ..services.settings import get_setting as _gs
                    _emit_challenge_redirect(lines, f"{rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}", settings.CAPTCHA_CHALLENGE_URL, rl.id, "rate_limit", rl.name)
                else:
                    lines.append(f"    http-request deny deny_status {rl_status} default-errorfiles if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                if rl_duration > 0:
                    lines.append(f"    http-request sc-inc-gpc0(2) if {rl_cond} {{ sc_get_gpc0(2) eq 0 }} !{{ var(txn.sec.skip_ratelimit) -m found }}")
            elif rl.limit_type == "advanced" and rl.expression:
                lines.append(f"    acl ratelimit_{rname} {_safe_token(rl.expression)}")
                rl_cond = f"ratelimit_{rname} {{ sc_http_req_rate({rl_sc}) gt {rl.events} }}{rl_scope_cond}"
                rl_action = _safe_token(getattr(rl, "action", "block") or "block")
                if rl_no_log:
                    lines.append(f"    http-request set-log-level silent if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                if rl_log:
                    lines.append(f"    http-request set-var(txn.ratelimit.action) str(blocked) if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                    lines.append(f"    http-request set-var(txn.ratelimit.name) str({rname}) if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                lines.append(f"    http-request set-var(txn.rate_limit_window) str({rl_window})")
                lines.append(f"    http-request set-var(txn.rate_limit_duration) str({rl_duration})")
                if rl_action == "challenge":
                    _emit_challenge_redirect(lines, f"{rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}", settings.CAPTCHA_CHALLENGE_URL, rl.id, "rate_limit", rl.name)
                else:
                    lines.append(f"    http-request deny deny_status {rl_status} default-errorfiles if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                if rl_duration > 0:
                    lines.append(f"    http-request sc-inc-gpc0(2) if {rl_cond} {{ sc_get_gpc0(2) eq 0 }} !{{ var(txn.sec.skip_ratelimit) -m found }}")
            elif rl.limit_type == "response_code":
                match_code = rl.match_status_code or 404
                rl_cond = f"{{ sc_gpc0_rate(3) gt {rl.events} }}"
                # Increment gpc0 on sc3 (resp_code_table) for each matching
                # response. Use http-after-response (not http-response) because
                # http-response rules are NOT evaluated for internally generated
                # responses (e.g., 503 when no backend server is available).
                # http-after-response runs on ALL responses including HAProxy-
                # generated errors. The sc3 tracking is already established
                # during the request phase via track-sc3, so sc-inc-gpc0(3)
                # can safely reference the tracked entry here.
                lines.append(f"    http-after-response sc-inc-gpc0(3) if {{ status {match_code} }}")
                if rl_no_log:
                    lines.append(f"    http-request set-log-level silent if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                if rl_log:
                    lines.append(f"    http-request set-var(txn.ratelimit.action) str(blocked) if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                    lines.append(f"    http-request set-var(txn.ratelimit.name) str({rname}) if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                lines.append(f"    http-request set-var(txn.rate_limit_window) str({rl_window})")
                lines.append(f"    http-request set-var(txn.rate_limit_duration) str({rl_duration})")
                lines.append(f"    http-request deny deny_status {rl_status} default-errorfiles if {rl_cond} !{{ var(txn.sec.skip_ratelimit) -m found }}")
                if rl_duration > 0:
                    lines.append(f"    http-request sc-inc-gpc0(2) if {rl_cond} {{ sc_get_gpc0(2) eq 0 }} !{{ var(txn.sec.skip_ratelimit) -m found }}")
            elif rl.limit_type == "waf":
                waf_rate_limits.append(rl)

        # Coraza WAF integration via SPOE (per listener)
        if settings.CORAZA_SPOA_ENABLED and waf_enabled_for_listener:
            spoe_path = os.path.abspath(settings.CORAZA_SPOE_CONFIG_PATH).replace("\\", "/")
            app_name = _safe_token(coraza_config.coraza_app_for_listener(listener.id, db))
            primary = rules[0]
            action = _safe_token(primary.action) or "block"
            status = primary.status_code or 403
            redirect_url = _safe_token(primary.redirect_url or "")

            lines.append(f"    http-request set-var(txn.coraza.app) str({app_name})")
            lines.append(f"    filter spoe engine coraza config {spoe_path}")

            lines.append("    http-request set-var(txn.waf.backend) str(default) if !{ var(txn.waf.backend) -m found }")
            lines.append("    http-request send-spoe-group coraza coraza-req if !{ var(txn.sec.skip_waf) -m found }")

            # Copy the Coraza SPOE verdict into txn.waf.* for log-format inclusion.
            # txn.coraza.action is set by the SPOE filter; txn.waf.action mirrors it
            # so the unified log-format can reference a stable var name.
            lines.append("    http-request set-var(txn.waf.action) var(txn.coraza.action) if !{ var(txn.sec.skip_waf) -m found }")

            if action == "allow":
                lines.append("    http-request allow if { var(txn.coraza.action) -m str allow }")
                lines.append("    http-response allow if { var(txn.coraza.action) -m str allow }")
            else:
                # Increment rate counters on WAF deny/drop BEFORE any blocking action,
                # otherwise a deny/redirect/drop short-circuits and the counter never updates.
                for rl in waf_rate_limits:
                    rl_rk = _safe_token(getattr(rl, "rate_key", "src") or "src")
                    rl_is_nonsrc = _rate_key_track_expr(rl_rk, getattr(rl, "rate_header", None)) != "src"
                    rl_sc = 1 if rl_is_nonsrc else 0
                    lines.append(f"    http-request sc-inc-gpc0({rl_sc}) if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                    lines.append(f"    http-request sc-inc-gpc0({rl_sc}) if {{ var(txn.coraza.action) -m str drop }} !{{ var(txn.sec.skip_waf) -m found }}")
                if waf_rule_rate:
                    rate_key = _safe_token(waf_rule_rate.rate_key)
                    wr_is_nonsrc = _rate_key_track_expr(rate_key, getattr(waf_rule_rate, "rate_header", None)) != "src"
                    sc_id = 1 if wr_is_nonsrc else 0
                    lines.append(f"    http-request sc-inc-gpc1({sc_id}) if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                    lines.append(f"    http-request sc-inc-gpc1({sc_id}) if {{ var(txn.coraza.action) -m str drop }} !{{ var(txn.sec.skip_waf) -m found }}")

                # Rate threshold checks - deny the source immediately if it exceeds a limit.
                for rl in waf_rate_limits:
                    rl_rk = _safe_token(getattr(rl, "rate_key", "src") or "src")
                    rl_is_nonsrc = _rate_key_track_expr(rl_rk, getattr(rl, "rate_header", None)) != "src"
                    rl_sc = 1 if rl_is_nonsrc else 0
                    threshold = rl.waf_event_threshold or 1
                    waf_window = rl.waf_window_seconds or 60
                    waf_dur = rl.waf_block_duration or 0
                    lines.append(f"    http-request set-var(txn.rate_limit_window) str({waf_window})")
                    lines.append(f"    http-request set-var(txn.rate_limit_duration) str({waf_dur})")
                    lines.append(f"    http-request deny deny_status 403 default-errorfiles if {{ sc_gpc0_rate({rl_sc}) gt {threshold} }} !{{ var(txn.sec.skip_waf) -m found }}")
                    # Block increment: mark as blocked on first exceedance (only if not already blocked)
                    if waf_dur > 0:
                        lines.append(f"    http-request sc-inc-gpc0(2) if {{ sc_gpc0_rate({rl_sc}) gt {threshold} }} {{ sc_get_gpc0(2) eq 0 }} !{{ var(txn.sec.skip_waf) -m found }}")
                if waf_rule_rate:
                    threshold = waf_rule_rate.rate_events or 100
                    rate_status = 429 if _safe_token(waf_rule_rate.rate_action) == "block" else 403
                    rule_window = waf_rule_rate.rate_window_seconds or 60
                    rule_dur = waf_rule_rate.rate_duration_seconds or 0
                    lines.append(f"    http-request set-var(txn.rate_limit_window) str({rule_window})")
                    lines.append(f"    http-request set-var(txn.rate_limit_duration) str({rule_dur})")
                    lines.append(f"    http-request deny deny_status {rate_status} default-errorfiles if {{ sc_gpc1_rate({sc_id}) gt {threshold} }} !{{ var(txn.sec.skip_waf) -m found }}")
                    # Block increment: mark as blocked on first exceedance (only if not already blocked)
                    if rule_dur > 0:
                        lines.append(f"    http-request sc-inc-gpc0(2) if {{ sc_gpc1_rate({sc_id}) gt {threshold} }} {{ sc_get_gpc0(2) eq 0 }} !{{ var(txn.sec.skip_waf) -m found }}")

                if action == "log":
                    # http-response capture does not accept 'len'; it requires a
                    # declared response capture slot and an id.
                    lines.append("    declare capture response len 64")
                    lines.append("    http-request capture req.hdr(Host) len 64")
                    lines.append("    http-response capture res.hdr(Server) id 0")
                elif action == "redirect":
                    if redirect_url:
                        # Redirect requests that Coraza decided to deny to a custom URL
                        lines.append(f"    http-request redirect location {redirect_url} code 302 if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                        lines.append(f"    http-response set-var(txn.status_source) str(haproxy) if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                        lines.append(f"    http-response redirect location {redirect_url} code 302 if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                    else:
                        lines.append(f"    http-request deny deny_status {status} default-errorfiles if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                        lines.append(f"    http-response set-var(txn.status_source) str(haproxy) if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                        lines.append(f"    http-response deny deny_status {status} default-errorfiles if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                elif action == "challenge":
                    challenge_url = _safe_token(redirect_url or settings.CAPTCHA_CHALLENGE_URL)
                    waf_cond = "{ var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }"
                    _emit_challenge_redirect(lines, waf_cond, challenge_url, primary.id, "waf", primary.name)
                else:  # block
                    lines.append(f"    http-request deny deny_status {status} default-errorfiles if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                    lines.append(f"    http-response set-var(txn.status_source) str(haproxy) if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")
                    lines.append(f"    http-response deny deny_status {status} default-errorfiles if {{ var(txn.coraza.action) -m str deny }} !{{ var(txn.sec.skip_waf) -m found }}")

                # Coraza "drop" action: use deny (not silent-drop) so the block
                # is logged and visible to the WAF metrics sampler. silent-drop
                # suppresses logging entirely, making WAF drops invisible.
                lines.append(f"    http-request deny deny_status {status} default-errorfiles if {{ var(txn.coraza.action) -m str drop }} !{{ var(txn.sec.skip_waf) -m found }}")
                lines.append(f"    http-response set-var(txn.status_source) str(haproxy) if {{ var(txn.coraza.action) -m str drop }} !{{ var(txn.sec.skip_waf) -m found }}")
                lines.append(f"    http-response deny deny_status {status} default-errorfiles if {{ var(txn.coraza.action) -m str drop }} !{{ var(txn.sec.skip_waf) -m found }}")
                if not primary.fail_open:
                    lines.append("    http-request deny deny_status 500 default-errorfiles if { var(txn.coraza.error) -m int gt 0 } !{ var(txn.sec.skip_waf) -m found }")
                    lines.append("    http-response set-var(txn.status_source) str(haproxy) if { var(txn.coraza.error) -m int gt 0 } !{ var(txn.sec.skip_waf) -m found }")
                    lines.append("    http-response deny deny_status 500 default-errorfiles if { var(txn.coraza.error) -m int gt 0 } !{ var(txn.sec.skip_waf) -m found }")

        # Force HTTP to HTTPS redirect for non-TLS listeners.
        # Placed after Security Rules, Rate Limiting, and WAF so those layers can
        # block/challenge on the HTTP request before the redirect. It skips
        # Varnish fetches (so disk-cache backend fetches stay HTTP) and ACME
        # challenges (so the fallback use_backend to the ACME backend is reached
        # when the webroot token file is not present).
        if listener.force_https and not listener.ssl_enabled:
            lines.append("    http-request redirect scheme https code 301 if !{ ssl_fc } !is_varnish_fetch !is_acme_challenge")

        # Redirects (per listener)
        for redirect in db.query(Redirect).order_by(Redirect.priority).all():
            if not _matches_listener(redirect, listener):
                continue
            source = _safe_token(redirect.source)
            if redirect.error_page_id:
                ep = db.get(CustomErrorPage, redirect.error_page_id)
                if ep:
                    base_dir = os.path.dirname(settings.HAPROXY_CONFIG_PATH)
                    ep_dir = os.path.join(base_dir, "errorfiles", "redirects", _safe_path_name(listener.name))
                    os.makedirs(ep_dir, exist_ok=True)
                    ep_path = os.path.join(ep_dir, f"r{redirect.id}_{ep.code}.http")
                    content_type = _safe_token(ep.content_type) or "text/html"
                    _write_error_file(ep_path, ep.content, content_type)
                    condition = (
                        f"{{ path_reg {source} }} !is_varnish_fetch"
                        if redirect.type == "regex"
                        else f"{{ path_beg {source} }} !is_varnish_fetch"
                    )
                    if redirect.error_page_query:
                        query = _safe_query(redirect.error_page_query)
                        if query:
                            lines.append(f"    http-request set-query {query} if {condition}")
                    lines.append(
                        f'    http-request return status {ep.code} content-type "{content_type}" '
                        f'lf-file {ep_path} if {condition}'
                    )
                continue
            target = _safe_token(redirect.target)
            if redirect.preserve_query:
                target = target + "%[query]"
            if redirect.type == "regex":
                line = f"    http-request redirect location {target} if {{ path_reg {source} }} !is_varnish_fetch"
            else:
                line = f"    http-request redirect location {target} if {{ path_beg {source} }} !is_varnish_fetch"
            if redirect.code in (301, 302, 307, 308):
                line += f" code {redirect.code}"
            lines.append(line)

        # Rewrites (per listener)
        for rewrite in db.query(Rewrite).order_by(Rewrite.priority).all():
            if not _matches_listener(rewrite, listener):
                continue
            target = _safe_token(rewrite.target)
            source_regex = _safe_token(rewrite.source_regex)
            # Use ACL and re substitution to avoid invalid path/query inline regex syntax
            rewrite_name = _safe_name(rewrite.name)
            # Optional host ACL: when host_match is set, the rewrite only applies
            # to requests whose Host header matches (case-insensitive equality).
            # This lets a rewrite live on a shared listener without affecting
            # other virtual hosts served by the same listener.
            host_acl = ""
            host_cond = ""
            if rewrite.host_match:
                host_value = _safe_token(rewrite.host_match)
                host_acl = f"    acl rewrite_host_{rewrite_name} hdr(host) -i {host_value}"
                host_cond = f" rewrite_host_{rewrite_name}"
            if rewrite.type in ("path", "both"):
                lines.append(f"    acl rewrite_path_{rewrite_name} path_reg {source_regex}")
                if host_acl:
                    lines.append(host_acl)
                lines.append(f"    http-request set-path {target} if rewrite_path_{rewrite_name}{host_cond} !is_varnish_fetch")
            if rewrite.type in ("query", "both"):
                # For "both" the path_reg / host ACLs were already emitted by the
                # path block above; for "query"-only we emit them here as the guard.
                if rewrite.type == "query":
                    lines.append(f"    acl rewrite_path_{rewrite_name} path_reg {source_regex}")
                    if host_acl:
                        lines.append(host_acl)
                lines.append(f"    http-request set-query %{{query,regsub({source_regex},{target})}} if rewrite_path_{rewrite_name}{host_cond} !is_varnish_fetch")

    # ACME HTTP-01 challenge fallback — routes to the API container for
    # backward compat with old --standalone renewals. Only fires for exact
    # token paths where the webroot file doesn't exist (the http-request
    # return above is terminal when the file exists).
    # Only on plain HTTP listeners — is_acme_challenge ACL is only defined
    # for non-SSL listeners (see above).
    if effective_mode == "http" and not listener.ssl_enabled:
        lines.append(f"    use_backend {ACME_CHALLENGE_BACKEND_NAME} if is_acme_challenge !{{ var(txn.acme_content) -m found }}")

    # Cap CAPTCHA proxy — exact-match rules for the challenge page and verify
    # endpoint route to the backend API; everything else under /_cap/ (widget
    # API calls like /_cap/{siteKey}/challenge and /_cap/{siteKey}/redeem)
    # routes to the Cap service. The is_cap_proxy ACL was emitted early in
    # the pipeline with an http-request allow that bypasses security controls.
    if _listener_has_challenge_action(db, listener.id):
        cap_path = _safe_token(settings.CAPTCHA_PROXY_PATH)
        lines.append(f"    use_backend {CAP_API_PROXY_BACKEND_NAME} if {{ path -m str {cap_path}/challenge }}")
        lines.append(f"    use_backend {CAP_API_PROXY_BACKEND_NAME} if {{ path -m str {cap_path}/verify }}")
        # Only route to cap_service_proxy when the Cap (Native) provider is
        # active — other providers (reCAPTCHA, Turnstile) talk directly to
        # Google/Cloudflare and don't need the service proxy backend.
        from .settings import get_setting as _gs
        _provider = _gs(db, "captcha_provider", "cap") or "cap"
        if _provider == "cap":
            lines.append(f"    use_backend {CAP_SERVICE_PROXY_BACKEND_NAME} if is_cap_proxy")

    # MCP Gateway — route /mcp and the OAuth protected-resource well-known
    # path to the mcp_gateway backend. Emitted when the MCP feature flag is on
    # and this listener is HTTP mode. A dedicated MCP listener (protocol=mcp)
    # uses default_backend instead of a path-based use_backend rule.
    if effective_mode == "http":
        from .settings import get_setting as _mcp_gs
        mcp_on = _mcp_gs(db, "mcp_gateway_enabled", str(settings.MCP_GATEWAY_ENABLED)).lower() in ("true", "1", "yes")
        if mcp_on:
            if getattr(listener, "protocol", None) == "mcp":
                # Dedicated MCP listener — everything goes to the gateway
                lines.append(f"    default_backend mcp_gateway")
            else:
                lines.append(f"    use_backend mcp_gateway if {{ path_beg /mcp }} || {{ path_beg /.well-known/oauth-protected-resource }}")

    # Content switching rules (per listener) — use_backend lines only.
    # ACL definitions were hoisted earlier (before rate limiting) so the
    # Restore Client IP set-src rules can reference them. Here we just emit
    # the use_backend directives using the pre-computed combined expressions.
    for br, br_backend, combined_expr in rule_combined_acls:
        lines.append(f"    use_backend {_backend_name(br_backend)} if {combined_expr}")

    # Varnish fetch routing on force_https listeners.
    #
    # When a listener has force_https=True and ssl_enabled=False, it exists
    # solely to redirect HTTP traffic to HTTPS. But Varnish fetches (which
    # skip the redirect via !is_varnish_fetch) still need to be routed to
    # the correct backend based on the Host header. This listener has no
    # BackendRules of its own, so we query BackendRules from all other
    # enabled HTTP-mode listeners and emit their ACLs + use_backend rules
    # here, conditioned on is_varnish_fetch so they only fire for Varnish
    # fetches (regular HTTP traffic was already redirected above).
    if (
        effective_mode == "http"
        and listener.force_https
        and not listener.ssl_enabled
        and disk_cache_enabled
        and not rule_combined_acls  # this listener has no BackendRules
    ):
        vfetch_rules = _emit_varnish_fetch_routing(db, listener, backend_names or {})
        lines.extend(vfetch_rules)

    # User-defined listener HAProxy options
    lines.extend(extra_frontend)

    # Use backend
    if backend_default:
        lines.append(f"    default_backend {_backend_name(backend_default)}")

    return "\n".join(lines) + "\n\n"


def generate_fcgi_app(app: FcgiApp) -> str:
    """Emit a HAProxy fcgi-app section."""
    app_name = _safe_name(app.name)
    lines = [f"fcgi-app {app_name}"]
    if app.log_stderr_enabled:
        target = _safe_token(app.log_stderr_target) if app.log_stderr_target else "global"
        lines.append(f"    log-stderr {target}")
    if app.docroot:
        lines.append(f"    docroot {_safe_token(app.docroot)}")
    if app.index:
        lines.append(f"    index {_safe_token(app.index)}")
    if app.path_info:
        lines.append(f"    path-info {_safe_token(app.path_info)}")
    if app.keep_conn:
        lines.append("    option keep-conn")
    if app.mpxs_conns:
        lines.append("    option mpxs-conns")
    if app.mpxs_conns and app.max_reqs and app.max_reqs > 0:
        lines.append(f"    option max-reqs {int(app.max_reqs)}")

    if app.params:
        for p in app.params:
            if not p.get("enabled"):
                continue
            name = _safe_token(p.get("name") or "")
            value = _safe_fcgi_param_value(p.get("value") or "")
            if name:
                lines.append(f"    set-param {name} {value}")

    return "\n".join(lines) + "\n\n"


def _fcgi_app_name_for_backend(db: Session, fcgi_app_id: Optional[int]) -> Optional[str]:
    if not fcgi_app_id:
        return None
    app = db.get(FcgiApp, fcgi_app_id)
    return _safe_name(app.name) if app else None


def generate_backend(
    backend: Backend,
    db: Session,
    backend_names: Optional[Dict[int, str]] = None,
    page_protect_enabled: bool = False,
    compression_enabled: bool = False,
    disk_cache_enabled: bool = False,
    cache_section_names: Optional[Dict[int, str]] = None,
    resp_transform_enabled: bool = False,
    img_2_webp_enabled: bool = False,
    page_protect_beacon: Optional[Dict[str, Any]] = None,
) -> str:
    backend_name = (backend_names or {}).get(backend.id, _safe_name(backend.name))
    effective_mode = "tcp" if backend.protocol == "tcp" else "http"
    lines = [f"backend {backend_name}"]
    lines.append(f"    mode {effective_mode}")

    fcgi_app_name = _fcgi_app_name_for_backend(db, backend.fcgi_app_id)

    # Response transform filter compatibility with FCGI backends:
    #
    # HAProxy 3.4's fcgi_flt_check() (src/fcgi-app.c) rejects ANY non-cache/
    # non-compression filter in the same backend as use-fcgi-app, regardless of
    # whether an explicit `filter fcgi-app` is declared. This is a bug — the
    # cache filter's check (cache_store_check in src/cache.c) properly uses a
    # CACHE_FLT_F_IMPLICIT_DECL flag to only reject implicit declarations, but
    # the fcgi-app check is missing this flag check. The HAProxy documentation
    # says an explicit `filter fcgi-app` should suffice, but the code doesn't
    # match the docs.
    #
    # As a workaround, when a backend uses FCGI and has resp_transform rules,
    # we skip the resp_transform filter and emit a warning comment. The FCGI
    # backend works normally; response transforms are simply not applied.
    from . import resp_transform as _rt_svc
    # Check for user-defined transform rules OR beacon injection rules
    _beacon = page_protect_beacon or {}
    _beacon_enabled = _beacon.get("enabled", False)
    _beacon_backend_ids = _beacon.get("backend_ids") or []
    _backend_has_beacon = _beacon_enabled and (not _beacon_backend_ids or backend.id in _beacon_backend_ids)
    rt_has_rules = (
        effective_mode == "http"
        and (_rt_svc._matches_backend_any(db, backend) or _backend_has_beacon)
    )
    rt_will_emit = rt_has_rules and resp_transform_enabled
    fcgi_blocks_rt = bool(fcgi_app_name) and rt_will_emit

    if fcgi_app_name:
        lines.append(f"    use-fcgi-app {fcgi_app_name}")

    if fcgi_blocks_rt:
        lines.append(
            f"    # WARNING: resp_transform rules exist for this backend but cannot be"
            f" applied because HAProxy 3.4 does not allow Lua filters alongside"
            f" use-fcgi-app (fcgi_flt_check bug — missing implicit/explicit flag)."
        )

    algorithm = _safe_token(backend.algorithm)
    balance_args = _safe_token(backend.balance_args) if backend.balance_args else ""
    lines.append(f"    balance {algorithm}" + (f" {balance_args}" if balance_args else ""))

    if backend.host_header and effective_mode == "http":
        lines.append(f"    http-request set-header Host {_safe_header_value(backend.host_header)}")

    # Request headers (per backend) — applied in the backend section so they
    # reach the upstream server. Only emitted for HTTP mode backends; TCP
    # backends have no request headers to mutate.
    if effective_mode == "http":
        for h in db.query(RequestHeader).all():
            if not _matches_backend(h, backend):
                continue
            header_name = _safe_token(h.header)
            header_value = _safe_header_value(h.value)
            condition = _format_condition(h.condition)
            if h.action in ("set", "override"):
                lines.append(f"    http-request set-header {header_name} {header_value}{condition}")
            elif h.action == "add":
                lines.append(f"    http-request add-header {header_name} {header_value}{condition}")
            elif h.action == "del":
                lines.append(f"    http-request del-header {header_name}{condition}")

    # Page Protect — CSP response headers (per backend).
    # Each enabled PageProtectPolicy matching this backend emits a CSP header.
    # Monitor mode → Content-Security-Policy-Report-Only (log only, no blocking).
    # Enforce mode → Content-Security-Policy (blocks disallowed resources).
    # Sampling: when sample_rate_percent < 100, only apply to a percentage of
    # responses using HAProxy's rand() sample fetch.
    # Guarded with !{ var(txn.is_varnish_fetch) -m found } so the CSP header
    # is not baked into Varnish cache objects on the origin→Varnish fetch
    # (would be duplicated on cache-hit delivery). The txn var is set during
    # the request phase in generate_frontend (where the is_varnish_fetch ACL
    # is declared). Using the txn var instead of an inline req.hdr_cnt check
    # because req.hdr_cnt is incompatible with http-response rules in
    # HAProxy 3.4+ (request headers aren't available during response
    # processing). The var persists across the request→response phases and
    # is available in both frontend and backend http-response rules.
    if effective_mode == "http" and page_protect_enabled:
        from .page_protect import build_csp_header
        beacon = page_protect_beacon or {}
        beacon_enabled = beacon.get("enabled", False)
        beacon_backend_ids = beacon.get("backend_ids") or []
        beacon_script_path = beacon.get("beacon_script_path") or "/_asset-beacon.js"
        # Check if beacon injection applies to this backend
        backend_has_beacon = beacon_enabled and (not beacon_backend_ids or backend.id in beacon_backend_ids)
        for policy in db.query(PageProtectPolicy).filter(PageProtectPolicy.enabled == True).all():  # noqa: E712
            if not _matches_backend(policy, backend):
                continue
            report_uri = _safe_token(policy.report_path or "/_csp-report") or "/_csp-report"
            directives = dict(policy.directives or {})
            # When beacon injection is enabled for this backend, add the beacon
            # script path to script-src so CSP doesn't block it in enforce mode.
            if backend_has_beacon:
                script_src = directives.get("script-src")
                if script_src is None:
                    # If no script-src, add to default-src if it exists
                    default_src = directives.get("default-src")
                    if default_src and "'self'" not in default_src:
                        directives["default-src"] = list(default_src) + ["'self'"]
                else:
                    if "'self'" not in script_src and beacon_script_path not in script_src:
                        directives["script-src"] = list(script_src) + ["'self'"]
            csp_value = build_csp_header(directives, report_uri=report_uri)
            if not csp_value:
                continue
            if policy.mode == "monitor":
                header_name = "Content-Security-Policy-Report-Only"
            else:
                header_name = "Content-Security-Policy"
            sample_rate = max(1, min(100, int(policy.sample_rate_percent or 100)))
            if sample_rate < 100:
                condition = f" if {{ rand(100) lt {sample_rate} }} !{{ var(txn.is_varnish_fetch) -m found }}"
            else:
                condition = " if !{ var(txn.is_varnish_fetch) -m found }"
            lines.append(f'    http-response set-header {header_name} {_safe_header_value(csp_value)}{condition}')

    # Cache directives (per backend) — memory cache (HAProxy native) and disk
    # cache routing header. Server-line replacement for disk cache happens below.
    cache_config = db.query(CacheConfig).filter(CacheConfig.backend_id == backend.id).first() if effective_mode == "http" else None
    disk_cache_active = bool(cache_config and cache_config.disk_cache_enabled and disk_cache_enabled and effective_mode == "http")
    if effective_mode == "http":
        cache_lines = _emit_cache_directives(backend, cache_config, backend_name, cache_section_names or {}, disk_cache_enabled)
        lines.extend(cache_lines)
        if cache_config and cache_config.disk_cache_enabled and not disk_cache_enabled:
            lines.append("    # disk cache requested but not enabled in Global Options")

    # Response compression filter (per backend).
    # gzip uses HAProxy's native `filter compression`; brotli/zstd use the
    # `lua.compress` filter registered by the haproxy-compression Rust module
    # (loaded globally when either encoder is enabled in Global Options).
    # Declared in the backend section so different backends can use different
    # algorithms. Only emitted for HTTP-mode backends (TCP has no HTTP filters).
    #
    # IMPORTANT: the cache filter must be declared before any compression filter
    # so HAProxy stores the raw response and compresses on delivery, rather than
    # compressing before the cache filter sees it. This ordering also matches
    # HAProxy's own cache_store_check() constraint for the native compression
    # filter.
    #
    # Response transform filter (per backend) is emitted BEFORE compression so
    # compression compresses the transformed output. Filter ordering:
    # cache → resp_transform → compression.
    #
    # NOTE: resp_transform is skipped for FCGI backends due to HAProxy 3.4's
    # fcgi_flt_check bug (see comment above). brotli/zstd compression (lua.compress)
    # is also a Lua filter and has the same limitation with FCGI backends.
    if effective_mode == "http":
        # Response transform filter — replace/inject/mask response body content.
        # Uses the haproxy-resp-transform Rust Lua module (loaded globally when
        # resp_transform_enabled is true). Reads per-backend JSON config from
        # data/resp-transform/{backend_name}.json (written by write_resp_transform_files).
        # Skipped for FCGI backends (fcgi_blocks_rt).
        if rt_has_rules:
            if rt_will_emit and not fcgi_blocks_rt:
                rt_config_path = os.path.join(settings.RESP_TRANSFORM_DIR, f"{_safe_path_name(backend.name)}.json")
                lines.append(f"    filter lua.resp_transform file:{rt_config_path}")
                # Strip Accept-Encoding so the origin sends uncompressed content.
                # The resp_transform filter needs raw (uncompressed) HTML to find
                # anchors like </head>. The lua.compress filter re-compresses the
                # transformed response before sending to the client.
                #
                # When disk cache is active, guard with is_varnish_fetch so the
                # header is only stripped on the Varnish→origin fetch path (where
                # resp_transform needs uncompressed content). Client→Varnish
                # requests keep Accept-Encoding so Varnish can vary on encoding
                # and HAProxy's compression filter can negotiate on delivery.
                if disk_cache_active:
                    lines.append("    http-request del-header Accept-Encoding if is_varnish_fetch")
                else:
                    lines.append("    http-request del-header Accept-Encoding")
                # Query-string detokenization: if any mask rule with
                # detokenize_query=True applies to this backend, emit the Lua
                # action + set-query to resolve tokens in URL query strings on
                # incoming requests (e.g. tokens in href links). The ACL guard
                # ensures the action only runs when the query contains a known
                # token prefix, so normal traffic has zero overhead.
                detok_prefixes = _rt_svc._mask_detokenize_prefixes_for_backend(db, backend)
                if detok_prefixes:
                    prefix_re = "|".join(re.escape(p) for p in detok_prefixes)
                    lines.append(f'    http-request lua.detokenize_query if {{ query -m reg "{prefix_re}" }}')
                    lines.append("    http-request set-query %[var(txn.detok_query)] if { var(txn.detok_query) -m found }")
            elif not resp_transform_enabled:
                lines.append("    # resp_transform: rules exist but module not enabled in Global Options")
            # When fcgi_blocks_rt is True, the warning comment was already emitted above
        comp_lines = _emit_compression_filter(backend, compression_enabled, has_fcgi=bool(fcgi_app_name))
        lines.extend(comp_lines)
        # Image conversion filter (on-the-fly JPEG/PNG/GIF to WebP). Emitted
        # after compression so WebP output (already compressed) is not
        # re-compressed. The compression filter's content-type check excludes
        # image/webp by default (image/ is not in the default content_types).
        ic_lines = _emit_img_2_webp_filter(backend, img_2_webp_enabled, has_fcgi=bool(fcgi_app_name))
        lines.extend(ic_lines)

    _, extra_backend = _render_haproxy_options(backend.haproxy_options, "backend")
    lines.extend(extra_backend)

    # Backend-level tuning
    lines.append(f"    retries {max(0, int(backend.retries or 3))}")
    # When disk cache is active, enable redispatch + retry-on so that if the
    # Varnish server returns an error (503/502/504) or fails a connection,
    # HAProxy retries to the origin servers instead of returning 503 to the client.
    if disk_cache_active:
        lines.append("    option redispatch")
        lines.append("    retry-on 503 502 504")
    elif backend.redispatch:
        lines.append("    option redispatch")
    if backend.timeout_queue:
        lines.append(f"    timeout queue {backend.timeout_queue}ms")
    if backend.timeout_check:
        lines.append(f"    timeout check {backend.timeout_check}ms")
    if backend.timeout_tunnel:
        lines.append(f"    timeout tunnel {backend.timeout_tunnel}ms")
    if backend.http_reuse:
        lines.append(f"    http-reuse {_safe_token(backend.http_reuse)}")
    if backend.fullconn:
        lines.append(f"    fullconn {backend.fullconn}")

    # Session persistence
    if backend.sticky_sessions and backend.cookie_name and effective_mode == "http":
        lines.append(f"    cookie {_safe_token(backend.cookie_name)} insert indirect nocache")

    if backend.stick_table:
        st_type = _safe_token(backend.stick_table_type)
        st_size = _safe_token(backend.stick_table_size)
        st_expire = _safe_token(backend.stick_table_expire)
        lines.append(f"    stick-table type {st_type} size {st_size} expire {st_expire}")
        if st_type == "ip":
            lines.append("    stick on src")
        elif st_type == "cookie" and backend.cookie_name:
            lines.append(f"    stick on req.cook({_safe_token(backend.cookie_name)})")

    # Health checks
    if backend.health_check_enabled:
        if backend.protocol == "tcp":
            lines.append("    option tcp-check")
        else:
            method = _safe_token(backend.health_check_method) or "GET"
            uri = _safe_token(backend.health_check_uri) or "/"
            lines.append(f"    option httpchk {method} {uri}")
            if fcgi_app_name:
                lines.append("    http-check connect proto fcgi")
            if backend.health_check_expect_status or backend.health_check_expect_body:
                lines.append(f"    http-check send meth {method} uri {uri}")
                if backend.health_check_expect_status:
                    lines.append(f"    http-check expect status {backend.health_check_expect_status}")
                elif backend.health_check_expect_body:
                    lines.append(f"    http-check expect string {_safe_token(backend.health_check_expect_body)}")

        default_server = f"    default-server inter {backend.health_check_interval}ms"
        if backend.protocol == "tcp":
            default_server += " fall 3 rise 2"
        else:
            default_server += " fall 3 rise 2"
        lines.append(default_server)

    servers: List[Server] = (
        db.query(Server)
        .filter(Server.backend_id == backend.id)
        .options(joinedload(Server.ca_certificate), joinedload(Server.client_certificate))
        .all()
    )

    # Disk cache routing: when disk cache is enabled and the global toggle is on,
    # emit the Varnish container as a backup server. It is only selected by the
    # explicit use-server directives emitted in _emit_cache_directives. Normal
    # load balancing (and Varnish fetch requests) will use the active origin
    # servers, so a Varnish cache miss is never routed back to Varnish. If
    # Varnish is down or errors, redispatch+retry-on ensures cache-eligible
    # requests fail over to origins.

    if disk_cache_active:
        varnish_host = _safe_token(settings.VARNISH_CONTAINER_NAME)
        varnish_port = int(settings.VARNISH_PORT)
        lines.append(f"    server disk_cache {varnish_host}:{varnish_port} check resolvers docker init-addr none backup")

    for s in servers:
        server_name = _safe_name(s.name)
        server_port = max(1, min(65535, int(s.port))) if s.port else 80
        cookie_arg = f" cookie {server_name}" if backend.sticky_sessions and backend.cookie_name and effective_mode == "http" else ""
        parts = [
            f"server {server_name} {_safe_token(s.address)}:{server_port}",
            f"weight {s.weight}",
            f"maxconn {s.maxconn}",
        ]
        if s.check:
            parts.append("check")
        # Only mark as backup if explicitly configured on the Server model
        if s.backup:
            parts.append("backup")
        if s.inter:
            parts.append(f"inter {s.inter}ms")
        if s.rise:
            parts.append(f"rise {s.rise}")
        if s.fall:
            parts.append(f"fall {s.fall}")
        if s.slowstart:
            parts.append(f"slowstart {s.slowstart}s")
        if s.maxqueue:
            parts.append(f"maxqueue {s.maxqueue}")
        if s.check_ssl:
            parts.append("check-ssl")
            if s.check_sni:
                parts.append(f"sni {_safe_token(s.check_sni)}")
        if s.check_sni and not s.check_ssl:
            parts.append(f"check-sni {_safe_token(s.check_sni)}")
        if s.check_port:
            parts.append(f"port {s.check_port}")
        if s.send_proxy:
            parts.append("send-proxy")
        if s.send_proxy_v2:
            parts.append("send-proxy-v2")
        if s.resolve and s.resolvers:
            parts.append(f"resolvers {_safe_token(s.resolvers)}")
            if s.init_addr:
                parts.append(f"init-addr {_safe_token(s.init_addr)}")
        if s.agent_check:
            parts.append("agent-check")
            if s.agent_port:
                parts.append(f"agent-port {s.agent_port}")
        if s.track:
            parts.append(f"track {s.track}")
        if s.ssl:
            parts.append("ssl")
            if s.verify:
                parts.append(f"verify {_safe_token(s.verify)}")
            if s.verifyhost:
                parts.append(f"verifyhost {_safe_token(s.verifyhost)}")
            if s.ca_certificate and s.ca_certificate.cert_path:
                parts.append(f"ca-file {_safe_token(s.ca_certificate.cert_path)}")
            if s.client_certificate and s.client_certificate.cert_path:
                parts.append(f"crt {_safe_token(s.client_certificate.cert_path)}")
            if s.ciphers:
                parts.append(f"ciphers {_safe_token(s.ciphers)}")
            if s.alpn:
                parts.append(f"alpn {_safe_token(s.alpn)}")
            if s.sni:
                parts.append(f"sni {_safe_token(s.sni)}")
        if backend.fcgi_app_id or s.protocol == "fastcgi":
            parts.append("proto fcgi")
        elif s.protocol == "grpc":
            parts.append("proto h2")

        lines.append("    " + " ".join(parts) + cookie_arg)

    return "\n".join(lines) + "\n\n"


def _waf_enabled(db: Session) -> bool:
    if not settings.CORAZA_SPOA_ENABLED:
        return False
    for listener in db.query(Listener).all():
        if listener.enabled and coraza_config.has_waf_for_listener(db, listener.id):
            return True
    return False


def _is_ip_address(host: str) -> bool:
    """Return True if host is a literal IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


def _coraza_spoa_servers() -> List[str]:
    """Return HAProxy server lines for the Coraza SPOA backend."""
    targets = _safe_token(settings.CORAZA_SPOA_TARGETS or "").split(",")
    if not targets or not targets[0]:
        targets = [f"{settings.CORAZA_SPOA_HOST}:{settings.CORAZA_SPOA_PORT}"]
    lines = []
    resolver_options = ""
    if settings.CORAZA_SPOA_ENABLED:
        resolver_options = " resolvers docker"
    for i, t in enumerate(targets, start=1):
        t = t.strip()
        if not t:
            continue
        if ":" in t:
            host, port = t.rsplit(":", 1)
        else:
            host, port = t, str(settings.CORAZA_SPOA_PORT)
        host = host.strip()
        init_addr = ""
        if not _is_ip_address(host):
            # Avoid a load-time libc DNS failure on the SPOA hostname.
            # The docker resolver will resolve it at runtime.
            init_addr = " init-addr none"
        lines.append(f"    server s{i} {_safe_token(host)}:{int(port)} check{init_addr}{resolver_options}")
    return lines


def generate_coraza_spoe_config(db: Session = None, coraza_backend_name: str = "coraza-spoa") -> str:
    spoe_path = os.path.abspath(settings.CORAZA_SPOE_CONFIG_PATH).replace("\\", "/")
    # Rule ID export is always enabled — the SPOA sends back rule_ids, anomaly_score,
    # rules_hit, and status for logging and the expanded log view.
    export_ids = "true"
    return f"""# Coraza SPOE configuration
# Generated by coreX Manager - do not edit manually
[coraza]
spoe-agent coraza-agent
    groups      coraza-req
    option      var-prefix      coraza
    option      set-on-error    error
    option      continue-on-error
    timeout     hello           2s
    timeout     idle            2m
    timeout     processing      500ms
    use-backend {coraza_backend_name}

spoe-message coraza-req
    args app=var(txn.coraza.app) id=unique-id src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body exportRuleIDs=bool({export_ids})

spoe-group coraza-req
    messages coraza-req
"""


def _coraza_backend_name() -> str:
    return "coraza-spoa"


def generate_coraza_backend(name: str = "coraza-spoa") -> str:
    servers = "\n".join(_coraza_spoa_servers())
    return f"""backend {name}
    mode tcp
{servers}

"""


def generate_acme_challenge_backend() -> str:
    """Emit the ACME HTTP-01 challenge fallback backend.

    Points to the api container for backward compat with old --standalone
    renewals. Only reachable for exact challenge token paths where the
    webroot file doesn't exist. When no challenge is in progress the server
    has no listener and HAProxy returns 503.
    """
    host = _safe_token(settings.ACME_CHALLENGE_BACKEND_HOST)
    port = int(settings.ACME_CHALLENGE_BACKEND_PORT)
    return f"""backend {ACME_CHALLENGE_BACKEND_NAME}
    mode http
    # Defense in depth: reject any request that doesn't match a valid
    # challenge token path (the frontend ACL already enforces this, but
    # this prevents direct backend access if the backend is ever reachable).
    http-request deny status 403 unless {{ path -m reg '^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$' }}
    server api {host}:{port}

"""


def _emit_challenge_redirect(
    lines: List[str],
    condition: str,
    challenge_url: str,
    rule_id: Optional[int],
    rule_type: str,
    rule_name: str,
) -> None:
    """Emit cv cookie check + challenge redirect for any rule type.

    Shared by WAF rules, security rules, and rate limits when their action is
    "challenge". The cookie check is emitted first so already-challenged users
    bypass the rule for the TTL duration. The redirect sends the user to the
    challenge page with rule context (rule_id, rule_type, rule_name) so the
    challenge page and verify endpoint can log per-rule solve statistics.

    The cookie validation (Valkey lookup via Lua action) is emitted once per
    listener in generate_frontend, not here. This function only checks the
    result: ``txn.captcha_cookie_valid`` is set by the Lua action when the
    cookie's opaque token exists in Valkey (i.e. the user previously solved
    a challenge and the TTL has not expired).
    """
    # If the user already solved a challenge in this TTL window, allow the request
    lines.append(f"    http-request allow if {{ var(txn.captcha_cookie_valid) -m found }} {condition}")
    # Capture HAProxy's unique-id so challenge events can be correlated with logs
    lines.append("    http-request set-var(txn.captcha_request_id) unique-id")
    # Build the full original URL so the challenge page can send the user back
    # after solving. Store it server-side in Valkey to prevent open redirect
    # attacks (user cannot manipulate the redirect destination).
    lines.append("    http-request set-var(txn.captcha_scheme) str(https) if { ssl_fc }")
    lines.append("    http-request set-var(txn.captcha_scheme) str(http) unless { ssl_fc }")
    lines.append("    http-request set-var-fmt(txn.captcha_redirect) %[var(txn.captcha_scheme)]://%[req.hdr(host)]%[pathq]")
    safe_name = _safe_token(rule_name).replace(" ", "_") if rule_name else "-"
    rid = rule_id if rule_id is not None else 0
    # Store the rule context (rule_id, rule_type, rule_name, request_id, redirect_url)
    # in Valkey server-side via the captcha_ctx Lua action. The action generates
    # a random token, stores the context as JSON with a 120-second TTL, and sets
    # txn.captcha_cid_token. The challenge URL contains only the opaque token —
    # no internal rule details or redirect destination are exposed to the user.
    # This prevents open redirect attacks since the redirect is server-controlled.
    # Note: safe_name uses "-" placeholder when empty because HAProxy's Lua
    # action parser requires exactly 3 arguments; an empty string would be
    # skipped, causing a config validation error. Whitespace is replaced with
    # "_" because the parser treats each space-separated word as a separate
    # argument — a multi-word rule name like "low header count" would produce
    # 5 arguments instead of 3, and HAProxy would reject the config.
    lines.append(
        f'    http-request lua.captcha_store_ctx {rid} {rule_type} {safe_name} if {condition}'
    )
    redirect_url = f"{challenge_url}?cid=%[var(txn.captcha_cid_token)]"
    lines.append(f"    http-request redirect location {redirect_url} code 302 if {condition}")


def _listener_has_challenge_action(db: Session, listener_id: int) -> bool:
    """Return True if any enabled rule on this listener uses action=challenge.

    Checks WAF rules, security rules, and rate limits.
    """
    from . import coraza_config, security_rules
    listener = db.query(Listener).filter(Listener.id == listener_id).first()
    # WAF rules
    for rule in coraza_config.rules_for_listener(db, listener_id):
        if rule.enabled and _safe_token(getattr(rule, "action", "")) == "challenge":
            return True
        # WAF rate_action are checked in the generator's WAF rate section
        if rule.enabled and getattr(rule, "rate_enabled", False) and _safe_token(getattr(rule, "rate_action", "")) == "challenge":
            return True
    # Security rules
    for rule in security_rules.rules_for_listener(db, listener_id):
        if rule.enabled and _safe_token(getattr(rule, "action", "")) == "challenge":
            return True
    # Rate limits
    for rl in db.query(RateLimit).all():
        if not rl.enabled:
            continue
        if listener and not _matches_listener(rl, listener):
            continue
        if _safe_token(getattr(rl, "action", "")) == "challenge":
            return True
    return False


def _any_listener_has_challenge(db: Session) -> bool:
    """Return True if any enabled listener has a challenge-action rule."""
    for listener in db.query(Listener).all():
        if listener.enabled and _listener_has_challenge_action(db, listener.id):
            return True
    return False


def generate_cap_proxy_backends(db: Session = None) -> str:
    """Emit the CAPTCHA proxy backends.

    cap_api_proxy routes /_cap/challenge and /_cap/verify to the backend API
    (which serves the challenge HTML page and processes verification). This is
    always emitted when any challenge-action rule exists — it's provider-agnostic.

    cap_service_proxy strips the /_cap prefix and forwards everything else
    (widget API calls like /{siteKey}/challenge and /{siteKey}/redeem) to the
    Cap service. This is only emitted when the active provider is Cap (Native),
    since reCAPTCHA and Turnstile widgets talk directly to Google/Cloudflare.
    """
    cap_path = _safe_token(settings.CAPTCHA_PROXY_PATH)
    api_host = _safe_token(settings.CAPTCHA_API_BACKEND_HOST)
    api_port = int(settings.CAPTCHA_API_BACKEND_PORT)

    # Determine if the service proxy is needed (only for Cap/Native provider)
    needs_service_proxy = True
    if db is not None:
        from .settings import get_setting as _gs
        provider_name = _gs(db, "captcha_provider", "cap") or "cap"
        if provider_name != "cap":
            needs_service_proxy = False

    parts = [f"""backend {CAP_API_PROXY_BACKEND_NAME}
    mode http
    http-request set-path /api/v1/waf/captcha if {{ path -m str {cap_path}/challenge }}
    http-request set-path /api/v1/waf/verify-captcha if {{ path -m str {cap_path}/verify }}
    server api {api_host}:{api_port} ssl verify none sni str({api_host})
"""]

    if needs_service_proxy:
        # Parse host:port from CAPTCHA_SERVICE_URL
        service_url = settings.CAPTCHA_SERVICE_URL
        if "://" in service_url:
            service_url = service_url.split("://", 1)[1]
        if "/" in service_url:
            service_url = service_url.split("/", 1)[0]
        cap_host, cap_port = service_url.split(":", 1) if ":" in service_url else (service_url, "3000")
        cap_host = _safe_token(cap_host)
        cap_port = _safe_token(cap_port)
        parts.append(f"""backend {CAP_SERVICE_PROXY_BACKEND_NAME}
    mode http
    http-request set-path %[path,regsub(^{cap_path},)]
    server cap {cap_host}:{cap_port}
""")

    return "\n".join(parts) + "\n"


def write_coraza_spoe_config(db: Session = None, coraza_backend_name: str = "coraza-spoa") -> str:
    path = settings.CORAZA_SPOE_CONFIG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    config = generate_coraza_spoe_config(db, coraza_backend_name=coraza_backend_name)
    with open(path, "w") as f:
        f.write(config)
    return config


def generate_config(
    db: Session,
    frontend_names: Optional[Dict[int, str]] = None,
    backend_names: Optional[Dict[int, str]] = None,
    stats_name: Optional[str] = None,
    coraza_name: Optional[str] = None,
    compression_enabled_override: Optional[bool] = None,
    resp_transform_enabled_override: Optional[bool] = None,
    img_2_webp_enabled_override: Optional[bool] = None,
) -> str:
    from ..services.settings import get_setting
    import json

    ciphers = db.query(CipherSuite).all()
    listeners = db.query(Listener).all()
    backends = db.query(Backend).all()
    logs = db.query(LogDestination).all()
    logged_fields = db.query(LoggedField).all()
    headers = db.query(ResponseHeader).all()
    error_pages = db.query(CustomErrorPage).all()
    fcgi_apps = db.query(FcgiApp).all()

    global_options_raw = get_setting(db, "haproxy_global_options", "[]")
    try:
        global_options = json.loads(global_options_raw or "[]") if isinstance(global_options_raw, str) else (global_options_raw or [])
    except json.JSONDecodeError:
        global_options = []

    # Lua fingerprint toggles (DB setting with env fallback)
    ja4_enabled = get_setting(db, "ja4_enabled", str(settings.JA4_ENABLED)).lower() in ("true", "1", "yes")
    req_fp_enabled = get_setting(db, "req_fp_enabled", str(settings.REQ_FP_ENABLED)).lower() in ("true", "1", "yes")
    req_fp_parse_body = get_setting(db, "req_fp_parse_body", str(settings.REQ_FP_PARSE_BODY)).lower() in ("true", "1", "yes")
    req_fp_max_body_bytes = int(get_setting(db, "req_fp_max_body_bytes", str(settings.REQ_FP_MAX_BODY_BYTES)))
    req_fp_enforce_max_body = get_setting(db, "req_fp_enforce_max_body", str(settings.REQ_FP_ENFORCE_MAX_BODY)).lower() in ("true", "1", "yes")

    # API Armor toggle (DB setting with env fallback) — loads the Rust Lua
    # module globally and gates conditional body buffering + API/GraphQL/auth
    # inspection per-listener. Also reads the max body size setting.
    api_armor_enabled = get_setting(db, "api_armor_enabled", str(settings.API_ARMOR_ENABLED)).lower() in ("true", "1", "yes")
    api_armor_max_body_bytes = int(get_setting(db, "api_armor_max_body_bytes", str(settings.API_ARMOR_MAX_BODY_BYTES)))

    # Defensive guard: API Armor depends on req_fp subfields at runtime
    # (req_fp_ctype, req_fp_method, req_fp_path, etc. are read by the body
    # parser). If api_armor is on but req_fp is off (e.g. DB manipulated
    # directly via system/restore bypassing the API validation gates), force
    # req_fp on so the generated config is consistent and api-armor has the
    # subfields it needs.
    if api_armor_enabled and not req_fp_enabled:
        logging.warning(
            "API Armor is enabled but request fingerprinting is disabled. "
            "Forcing req_fp_enabled=true for config generation because API "
            "Armor depends on req_fp subfields. Enable req_fp in Global "
            "Options to resolve this warning."
        )
        req_fp_enabled = True

    # Compression toggle (DB setting with env fallback) — loads the Rust Lua
    # module globally and gates brotli/zstd algorithm selection per-backend.
    # Callers may pass an override for testing without touching the DB.
    if compression_enabled_override is not None:
        compression_enabled = compression_enabled_override
    else:
        compression_enabled = get_setting(db, "compression_enabled", str(settings.COMPRESSION_ENABLED)).lower() in ("true", "1", "yes")

    # Disk cache toggle (DB setting with env fallback) — gates the disk cache
    # (file-backed) option per-backend. Memory cache (HAProxy native) is always
    # available and does not require this toggle.
    disk_cache_enabled = get_setting(db, "disk_cache_enabled", str(settings.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")

    # Response transform toggle (DB setting with env fallback) — loads the
    # haproxy-resp-transform Rust Lua module globally and gates replace/inject/mask
    # rules per-backend. Callers may pass an override for testing.
    if resp_transform_enabled_override is not None:
        resp_transform_enabled = resp_transform_enabled_override
    else:
        resp_transform_enabled = get_setting(db, "resp_transform_enabled", str(settings.RESP_TRANSFORM_ENABLED)).lower() in ("true", "1", "yes")

    # Image conversion toggle (DB setting with env fallback) — loads the
    # haproxy-img-2-webp Rust Lua module globally and gates per-backend
    # on-the-fly JPEG/PNG/GIF to WebP conversion. Default off.
    # Callers may pass an override for testing without touching the DB.
    if img_2_webp_enabled_override is not None:
        img_2_webp_enabled = img_2_webp_enabled_override
    else:
        img_2_webp_enabled = get_setting(db, "img_2_webp_enabled", str(settings.IMG_2_WEBP_ENABLED)).lower() in ("true", "1", "yes")

    # Page Protect toggle + report path (DB setting with env fallback)
    from .page_protect import is_page_protect_enabled, get_report_path, get_beacon_settings
    page_protect_enabled = is_page_protect_enabled(db)
    page_protect_report_path = get_report_path(db)
    page_protect_beacon = get_beacon_settings(db) if page_protect_enabled else None

    # When Page Protect beacon injection is enabled, force resp_transform on
    # so the Rust Lua module is loaded (the beacon rule is injected via the
    # resp_transform filter). This overrides the global resp_transform setting.
    if page_protect_beacon and page_protect_beacon.get("enabled"):
        resp_transform_enabled = True

    if frontend_names is None or backend_names is None or stats_name is None or coraza_name is None:
        frontend_names, backend_names, stats_name, coraza_name = _get_section_names(db)

    config = "# Generated by coreX Manager\n# Do not edit manually\n\n"
    config += generate_global_section(ciphers, logs, logged_fields, global_options, ja4_enabled=ja4_enabled, compression_enabled=compression_enabled, disk_cache_enabled=disk_cache_enabled, resp_transform_enabled=resp_transform_enabled, img_2_webp_enabled=img_2_webp_enabled, captcha_challenge_enabled=_any_listener_has_challenge(db), api_armor_enabled=api_armor_enabled, req_fp_enabled=req_fp_enabled)
    config += generate_defaults_section(headers, error_pages)
    config += generate_dataplane_section()
    config += generate_stats_frontend(stats_name)

    # Cache sections (HAProxy native memory cache) — emitted before frontends
    # so they're available for `cache-use`/`cache-store` references in backends.
    config += generate_cache_sections(db, img_2_webp_enabled=img_2_webp_enabled)

    # Build a map of backend_id → cache section name for use in generate_backend.
    cache_section_names: Dict[int, str] = {}
    used: set = set(backend_names.values()) if backend_names else set()
    for cc in db.query(CacheConfig).filter(CacheConfig.haproxy_enabled == True).all():  # noqa: E712
        backend = db.get(Backend, cc.backend_id)
        if not backend or backend.protocol == "tcp":
            continue
        cache_section_names[cc.backend_id] = _unique_section_name(f"cache_{_safe_name(backend.name)}", used)

    for listener in listeners:
        if listener.enabled:
            config += generate_frontend(listener, db, frontend_names=frontend_names, backend_names=backend_names, req_fp_enabled=req_fp_enabled, req_fp_parse_body=req_fp_parse_body, req_fp_max_body_bytes=req_fp_max_body_bytes, req_fp_enforce_max_body=req_fp_enforce_max_body, page_protect_enabled=page_protect_enabled, page_protect_report_path=page_protect_report_path, page_protect_beacon=page_protect_beacon, api_armor_enabled=api_armor_enabled, api_armor_max_body_bytes=api_armor_max_body_bytes, ja4_enabled=ja4_enabled, disk_cache_enabled=disk_cache_enabled, logged_fields=logged_fields)

    for app in fcgi_apps:
        config += generate_fcgi_app(app)

    for backend in backends:
        config += generate_backend(backend, db, backend_names=backend_names, page_protect_enabled=page_protect_enabled, compression_enabled=compression_enabled, disk_cache_enabled=disk_cache_enabled, cache_section_names=cache_section_names, resp_transform_enabled=resp_transform_enabled, img_2_webp_enabled=img_2_webp_enabled, page_protect_beacon=page_protect_beacon)

    # WAF rate-limit stick-table backends for non-src rate keys
    if settings.CORAZA_SPOA_ENABLED:
        config += _generate_waf_rate_backends(db)

    # RateLimit-page string stick-table backends for non-src rate keys
    config += _generate_rl_rate_backends(db)

    # Block duration (tarpit) stick-table backends
    config += _generate_block_tables(db)

    # Response-code rate-limit stick-table backends (sc3 tracking)
    config += _generate_resp_code_tables(db)

    if _waf_enabled(db):
        config += generate_coraza_backend(coraza_name)

    # ACME HTTP-01 challenge backend (always emitted; only reachable via
    # /.well-known/acme-challenge/ ACL on HTTP-mode listeners)
    config += generate_acme_challenge_backend()

    # Cap CAPTCHA proxy backends — only emitted when at least one enabled
    # listener has a challenge-action rule (WAF, security, or rate limit).
    if _any_listener_has_challenge(db):
        config += generate_cap_proxy_backends(db)

    # MCP Gateway — backend + internal upstreams (only when feature is enabled)
    mcp_enabled = get_setting(db, "mcp_gateway_enabled", str(settings.MCP_GATEWAY_ENABLED)).lower() in ("true", "1", "yes")
    if mcp_enabled:
        config += generate_mcp_gateway_backend(db)
        config += generate_mcp_upstreams(db)

    return config


def generate_mcp_gateway_backend(db: Session) -> str:
    """Emit the backend that fronts the mcp-gateway service.

    Includes a stick-table on Mcp-Session-Id for SSE affinity so a session's
    POST and GET SSE land on the same gateway replica.
    """
    host = settings.MCP_GATEWAY_INTERNAL_HOST
    port = settings.MCP_GATEWAY_INTERNAL_PORT
    return f"""backend mcp_gateway
    mode http
    option http-keep-alive
    timeout server 300s
    timeout tunnel 300s
    http-request set-header Cache-Control no-store
    stick-table type string len 128 size 10k expire 1h
    stick on req.hdr(Mcp-Session-Id)
    server mcp-gateway {host}:{port} check

"""


def generate_mcp_upstreams(db: Session) -> str:
    """Emit internal upstream frontend + backends for multi-replica MCP servers.

    Only emitted when at least one enabled McpServer has enabled replicas.
    Single-replica servers use McpServer.url directly (no internal config).
    """
    from .mcp_config import get_multi_replica_servers
    from ..models.models import McpServerReplica

    multi_servers = get_multi_replica_servers(db)
    if not multi_servers:
        return ""

    upstream_port = settings.MCP_UPSTREAM_PORT
    sections = []

    # Shared internal frontend (haproxy-net only, not publicly exposed)
    fe_lines = [
        f"\nfrontend mcp_upstreams",
        f"    bind :{upstream_port}",
        f"    mode http",
        f"    option http-keep-alive",
        f"    timeout tunnel 300s",
    ]

    for server in multi_servers:
        ns = _safe_name(server.namespace)
        path_prefix = f"/mcp-up/{server.namespace}/"
        fe_lines.append(f"    use_backend mcp_up_{ns} if {{ path_beg {path_prefix} }}")

    sections.append("\n".join(fe_lines) + "\n")

    # One backend per multi-replica server
    for server in multi_servers:
        ns = _safe_name(server.namespace)
        replicas = db.query(McpServerReplica).filter(
            McpServerReplica.server_id == server.id,
            McpServerReplica.enabled == True,  # noqa: E712
        ).all()

        be_lines = [
            f"\nbackend mcp_up_{ns}",
            f"    mode http",
            f"    balance roundrobin",
            f"    stick-table type string len 128 size 10k expire 1h",
            f"    stick on req.hdr(Mcp-Session-Id)",
            f"    http-request set-path %[path,regsub(^/mcp-up/{re.escape(server.namespace)},)]",
        ]

        # Primary server line
        from urllib.parse import urlparse
        parsed = urlparse(server.url)
        scheme = "https" if parsed.scheme == "https" else "http"
        verify_str = "ssl verify" if server.verify_tls and scheme == "https" else ""
        if scheme == "https" and not server.verify_tls:
            verify_str = "ssl verify none"
        host_port = parsed.hostname
        if parsed.port:
            host_port = f"{parsed.hostname}:{parsed.port}"
        elif scheme == "https":
            host_port = f"{parsed.hostname}:443"
        else:
            host_port = f"{parsed.hostname}:80"
        be_lines.append(f"    server primary {scheme}://{host_port} check {verify_str}".rstrip())

        # Replica server lines
        for i, replica in enumerate(replicas):
            r_parsed = urlparse(replica.url)
            r_scheme = "https" if r_parsed.scheme == "https" else "http"
            r_verify = "ssl verify" if replica.verify_tls and r_scheme == "https" else ""
            if r_scheme == "https" and not replica.verify_tls:
                r_verify = "ssl verify none"
            r_host_port = r_parsed.hostname
            if r_parsed.port:
                r_host_port = f"{r_parsed.hostname}:{r_parsed.port}"
            elif r_scheme == "https":
                r_host_port = f"{r_parsed.hostname}:443"
            else:
                r_host_port = f"{r_parsed.hostname}:80"
            be_lines.append(f"    server replica_{i+1} {r_scheme}://{r_host_port} check {r_verify}".rstrip())

        sections.append("\n".join(be_lines) + "\n")

    return "".join(sections)


def _generate_waf_rate_backends(db: Session) -> str:
    """Emit string-type stick-table backends for WAF rules with non-src rate keys."""
    from . import coraza_config
    sections = []
    seen_names = set()
    for listener in db.query(Listener).all():
        if not listener.enabled:
            continue
        rules = coraza_config.rules_for_listener(db, listener.id)
        if not rules:
            continue
        primary = rules[0]
        if not getattr(primary, "rate_enabled", False):
            continue
        # Check the resolved track expression — ASN may fall back to src
        # when no MaxMind DB/map is available, in which case no string
        # table backend is needed.
        track_expr = _rate_key_track_expr(primary.rate_key, getattr(primary, "rate_header", None))
        if track_expr == "src":
            continue
        lname = _safe_name(listener.name)
        backend_name = f"waf_rate_{lname}"
        if backend_name in seen_names:
            continue
        seen_names.add(backend_name)
        window = primary.rate_window_seconds or 60
        expire = window * 2
        sections.append(
            f"\nbackend {backend_name}\n"
            f"    stick-table type string len 256 size 1m expire {expire}s store gpc1_rate({window}s)\n"
        )
    return "".join(sections)


def _generate_rl_rate_backends(db: Session) -> str:
    """Emit string-type stick-table backends for RateLimit-page rate limits with non-src keys.

    Basic/advanced types need ``http_req_rate``; waf type needs ``gpc0_rate``.
    Both stores are added when a listener has mixed types so a single string
    table per listener serves all non-src RateLimit checks on sc1.
    """
    sections = []
    seen_names = set()
    for listener in db.query(Listener).all():
        if not listener.enabled:
            continue
        listener_rls = [
            rl for rl in db.query(RateLimit).all()
            if _matches_listener(rl, listener) and rl.enabled
        ]
        # Use the resolved track expression — ASN may fall back to src
        def _rl_is_src(rl):
            return _rate_key_track_expr(getattr(rl, "rate_key", "src"), getattr(rl, "rate_header", None)) == "src"
        needs_http_req = any(
            rl.limit_type in ("basic", "advanced") and not _rl_is_src(rl)
            for rl in listener_rls
        )
        needs_gpc0 = any(
            rl.limit_type == "waf" and not _rl_is_src(rl)
            for rl in listener_rls
        )
        if not (needs_http_req or needs_gpc0):
            continue
        lname = _safe_name(listener.name)
        backend_name = f"rl_rate_{lname}"
        if backend_name in seen_names:
            continue
        seen_names.add(backend_name)
        stores = []
        max_window = 60
        if needs_http_req:
            windows = [rl.window_seconds for rl in listener_rls
                       if rl.limit_type in ("basic", "advanced")
                       and _safe_token(getattr(rl, "rate_key", "src") or "src") != "src"]
            max_window = max(windows) if windows else 60
            stores.append(f"http_req_rate({max_window}s)")
        if needs_gpc0:
            waf_windows = [rl.window_seconds for rl in listener_rls
                           if rl.limit_type == "waf"
                           and _safe_token(getattr(rl, "rate_key", "src") or "src") != "src"]
            waf_max = max(waf_windows) if waf_windows else 60
            max_window = max(max_window, waf_max)
            stores.append(f"gpc0_rate({waf_max}s)")
        expire = max_window * 2
        sections.append(
            f"\nbackend {backend_name}\n"
            f"    stick-table type string len 256 size 1m expire {expire}s store {','.join(stores)}\n"
        )
    return "".join(sections)


def _generate_block_tables(db: Session) -> str:
    """Emit block stick-table backends for listeners with block duration > 0.

    Block duration (tarpit) keeps a client blocked for N seconds after their
    first rate limit exceedance, regardless of their current rate. The block
    entry auto-expires after the max duration across all rate limits on the
    listener.
    """
    from . import coraza_config
    sections = []
    seen_names = set()
    for listener in db.query(Listener).all():
        if not listener.enabled:
            continue
        max_duration = 0
        has_block = False
        needs_str_table = False

        # Listener rate limits
        for rl in db.query(RateLimit).all():
            if not _matches_listener(rl, listener) or not rl.enabled:
                continue
            dur = rl.duration_seconds or 0
            if dur > 0:
                has_block = True
                max_duration = max(max_duration, dur)
            if rl.limit_type == "waf":
                waf_dur = rl.waf_block_duration or 0
                if waf_dur > 0:
                    has_block = True
                    max_duration = max(max_duration, waf_dur)
            # Non-src rate keys need the string block table for sc2 tracking
            rl_track = _rate_key_track_expr(getattr(rl, "rate_key", "src"), getattr(rl, "rate_header", None))
            if rl_track != "src" and rl.limit_type in ("basic", "advanced", "waf"):
                if dur > 0 or (rl.limit_type == "waf" and (rl.waf_block_duration or 0) > 0):
                    needs_str_table = True

        # WafRule rate limits
        rules = coraza_config.rules_for_listener(db, listener.id)
        for rule in rules:
            if getattr(rule, "rate_enabled", False) and (rule.rate_duration_seconds or 0) > 0:
                has_block = True
                max_duration = max(max_duration, rule.rate_duration_seconds)
                rate_key = _safe_token(rule.rate_key)
                if rate_key != "src":
                    needs_str_table = True

        if not has_block:
            continue

        lname = _safe_name(listener.name)
        ip_table = f"block_table_{lname}"
        if ip_table not in seen_names:
            seen_names.add(ip_table)
            sections.append(
                f"\nbackend {ip_table}\n"
                f"    stick-table type ip size 1m expire {max_duration}s store gpc0\n"
            )
        if needs_str_table:
            str_table = f"block_table_str_{lname}"
            if str_table not in seen_names:
                seen_names.add(str_table)
                sections.append(
                    f"\nbackend {str_table}\n"
                    f"    stick-table type string len 256 size 1m expire {max_duration}s store gpc0\n"
                )
    return "".join(sections)


def _generate_resp_code_tables(db: Session) -> str:
    """Emit stick-table backends for response_code rate limits.

    Response-code rate limiting counts backend responses with a specific
    status code (e.g. 503) per client IP and blocks clients who exceed a
    threshold. HAProxy only supports gpc0_rate/gpc1_rate as stick-table
    rate stores, so this uses a dedicated backend with gpc0_rate tracked
    on sc3 (separate from sc0 which may already use gpc0_rate for WAF).
    """
    sections = []
    seen_names = set()
    for listener in db.query(Listener).all():
        if not listener.enabled:
            continue
        has_resp_code = False
        max_window = 0
        for rl in db.query(RateLimit).all():
            if not _matches_listener(rl, listener) or not rl.enabled:
                continue
            if rl.limit_type == "response_code":
                has_resp_code = True
                max_window = max(max_window, rl.window_seconds or 60)
        if not has_resp_code:
            continue
        lname = _safe_name(listener.name)
        table_name = f"resp_code_table_{lname}"
        if table_name in seen_names:
            continue
        seen_names.add(table_name)
        expire = max_window * 2
        sections.append(
            f"\nbackend {table_name}\n"
            f"    stick-table type ip size 1m expire {expire}s store gpc0_rate({max_window}s)\n"
        )
    return "".join(sections)


def write_config(
    db: Session,
    created_by: Optional[str] = None,
    previous_config: Optional[str] = None,
    comment: Optional[str] = None,
) -> str:
    print("[WRITE_CONFIG] step 1 — generate_config", flush=True)
    logger.info("write_config: step 1 — generate_config")
    frontend_names, backend_names, stats_name, coraza_name = _get_section_names(db)
    config = generate_config(db, frontend_names=frontend_names, backend_names=backend_names, stats_name=stats_name, coraza_name=coraza_name)

    logger.info("write_config: step 2 — write_security_list_files")
    from .security_lists import write_security_list_files
    write_security_list_files(db)

    logger.info("write_config: step 2b — write_risk_rules_data_file")
    try:
        from .risk_scoring import write_risk_rules_data_file
        write_risk_rules_data_file(db)
    except Exception as e:
        logger.warning("Failed to write risk rules data file: %s", e)

    logger.info("write_config: step 3 — MCP config bundle")
    try:
        from .mcp_config import write_config_bundle, write_applied_mcp_bundle
        from .settings import get_setting as _mcp_get_setting
        mcp_on = _mcp_get_setting(db, "mcp_gateway_enabled", str(settings.MCP_GATEWAY_ENABLED)).lower() in ("true", "1", "yes")
        if mcp_on:
            write_config_bundle(db)
            write_applied_mcp_bundle(db)
    except Exception as e:
        logger.warning("Failed to write MCP config bundle: %s", e)

    logger.info("write_config: step 4 — resp_transform_files")
    from .resp_transform import write_resp_transform_files
    write_resp_transform_files(db)

    # Write the Page Protect beacon JS to the data directory so HAProxy can
    # serve it via http-request return lf-file. The JS is embedded as a string
    # constant (not copied from the repo) because the haproxy/ source directory
    # is only present in the HAProxy build context, not the backend container.
    try:
        from .page_protect_beacon_js import BEACON_JS
        beacon_dest = settings.PAGE_PROTECT_BEACON_JS_PATH
        os.makedirs(os.path.dirname(beacon_dest) or ".", exist_ok=True)
        with open(beacon_dest, "w") as f:
            f.write(BEACON_JS)
    except Exception as e:
        logger.warning("Failed to write beacon JS file: %s", e)

    logger.info("write_config: step 5 — coraza config")
    waf_configs: Optional[Dict[str, str]] = None
    previous_waf_configs: Optional[Dict[str, str]] = None
    if settings.CORAZA_SPOA_ENABLED:
        previous_waf_configs = {}
        waf_configs = {}
        for label, path in (
            ("coraza.cfg", settings.CORAZA_SPOE_CONFIG_PATH),
            ("coraza-spoa.yaml", settings.CORAZA_SPOA_CONFIG_PATH),
        ):
            previous_waf_configs[label] = _read_file(path)
        waf_configs["coraza.cfg"] = write_coraza_spoe_config(db, coraza_backend_name=coraza_name)
        waf_configs["coraza-spoa.yaml"] = coraza_config.write_coraza_spoa_config(db)

    print("[WRITE_CONFIG] step 6 — validate_config_text (haproxy -c)", flush=True)
    logger.info("write_config: step 6 — validate_config_text (haproxy -c)")
    is_valid, validation_output = validate_config_text(config)
    if not is_valid:
        raise ValueError(f"Generated HAProxy configuration failed validation:\n{validation_output}")

    logger.info("write_config: step 7 — write config files to disk")
    print("[WRITE_CONFIG] step 7 — write config files to disk", flush=True)
    logger.info("write_config: step 7 — write config files to disk")
    path = settings.HAPROXY_CONFIG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    applied_path = f"{path}.applied"
    old_config = ""
    if previous_config is not None:
        old_config = previous_config
    elif os.path.exists(applied_path):
        with open(applied_path, "r") as f:
            old_config = f.read()
    with open(path, "w") as f:
        f.write(config)
    with open(applied_path, "w") as f:
        f.write(config)

    if settings.CORAZA_SPOA_ENABLED and waf_configs:
        for label, path in (
            ("coraza.cfg", settings.CORAZA_SPOE_CONFIG_PATH),
            ("coraza-spoa.yaml", settings.CORAZA_SPOA_CONFIG_PATH),
        ):
            with open(f"{path}.applied", "w") as f:
                f.write(waf_configs[label])

    print("[WRITE_CONFIG] step 8 — varnish VCL", flush=True)
    logger.info("write_config: step 8 — varnish VCL")
    from .settings import get_setting as _get_setting
    disk_cache_on = _get_setting(db, "disk_cache_enabled", str(settings.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")
    varnish_config: Optional[str] = None
    previous_varnish_config: Optional[str] = None
    if disk_cache_on:
        any_disk = db.query(CacheConfig).filter(CacheConfig.disk_cache_enabled == True).first()  # noqa: E712
        if any_disk:
            try:
                from . import varnish
                previous_varnish_config = _read_file(settings.VARNISH_VCL_PATH)
                varnish_config = varnish.write_vcl(db)
            except Exception as exc:
                logger.warning("Varnish VCL write/reload failed: %s", exc)

    print("[WRITE_CONFIG] step 9 — save_config_snapshot", flush=True)
    logger.info("write_config: step 9 — save_config_snapshot")
    save_config_snapshot(
        db,
        config,
        previous_config=old_config,
        waf_configs=waf_configs,
        previous_waf_configs=previous_waf_configs,
        varnish_config=varnish_config,
        previous_varnish_config=previous_varnish_config,
        created_by=created_by,
        comment=comment,
    )

    print("[WRITE_CONFIG] step 10 — dataplane.push_config", flush=True)
    logger.info("write_config: step 10 — dataplane.push_config")
    if settings.DATAPLANE_API_ENABLED:
        dataplane.push_config(config)
    print("[WRITE_CONFIG] done", flush=True)
    logger.info("write_config: done")
    return config


def _haproxy_check_docker(config_path: str) -> Tuple[bool, str]:
    """Run haproxy -c inside the running haproxy container via the Docker SDK.

    Wraps ``container.exec_run`` in a thread with a 30-second timeout because
    the Docker SDK's exec_run has no native timeout parameter and can hang
    indefinitely if the container or haproxy process is unresponsive.

    Note: we deliberately avoid the ``with ThreadPoolExecutor`` context manager
    because its ``__exit__`` calls ``shutdown(wait=True)``, which blocks until
    the worker thread finishes — defeating the timeout. Instead we use
    ``shutdown(wait=False)`` on timeout so the main thread can continue while
    the orphaned daemon thread cleans up on process exit.
    """
    if docker is None:
        return False, "haproxy container check failed: docker SDK not installed"
    container_name = os.environ.get("HAPROXY_CONTAINER_NAME", "haproxy")

    def _run() -> Tuple[int, str]:
        print(f"[DOCKER_CHECK] creating docker client", flush=True)
        client = docker.from_env()
        print(f"[DOCKER_CHECK] getting container: {container_name}", flush=True)
        container = client.containers.get(container_name)
        print(f"[DOCKER_CHECK] calling exec_run: haproxy -c -f {config_path}", flush=True)
        ec, output = container.exec_run(f"haproxy -c -f {config_path}")
        print(f"[DOCKER_CHECK] exec_run returned: ec={ec}", flush=True)
        return ec, (output or b"").decode().strip()

    import concurrent.futures
    print("[DOCKER_CHECK] starting thread pool", flush=True)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_run)
    try:
        print("[DOCKER_CHECK] waiting for result (30s timeout)", flush=True)
        ec, output = future.result(timeout=30)
        executor.shutdown(wait=True)
        print(f"[DOCKER_CHECK] result: ec={ec}", flush=True)
        return ec == 0, output
    except concurrent.futures.TimeoutExpired:
        executor.shutdown(wait=False)
        print("[DOCKER_CHECK] TIMED OUT after 30s", flush=True)
        return False, "haproxy -c timed out after 30s in container"
    except Exception as e:
        executor.shutdown(wait=False)
        print(f"[DOCKER_CHECK] exception: {e}", flush=True)
        return False, f"haproxy container check failed: {e}"


def _haproxy_check_local(config_path: str) -> Tuple[bool, str]:
    """Fallback: validate against a locally installed haproxy binary."""
    haproxy_bin = shutil.which("haproxy")
    if not haproxy_bin:
        return True, "haproxy binary not found, skipping validation"
    try:
        result = subprocess.run(
            [haproxy_bin, "-c", "-f", config_path],
            capture_output=True, text=True, timeout=30,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "haproxy -c timed out after 30s"
    except Exception as e:
        return False, f"haproxy local check failed: {e}"


def validate_config_text(config_text: str) -> Tuple[bool, str]:
    """Validate a HAProxy config string using the haproxy container if available.

    Returns a tuple of (is_valid, details) where details is any stdout/stderr
    from the HAProxy check, in particular the error messages on failure.
    """
    import tempfile
    data_dir = os.path.dirname(settings.HAPROXY_CONFIG_PATH)
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False, dir=data_dir) as f:
        f.write(config_text)
        tmp_path = f.name
    try:
        ok, details = _haproxy_check_docker(tmp_path)
        if ok:
            return True, details
        if details.startswith("haproxy container check failed"):
            return _haproxy_check_local(tmp_path)
        return False, details
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def validate_config() -> Tuple[bool, str]:
    """Validate the current HAProxy config file.

    Returns (is_valid, details) where details is the HAProxy output on failure
    or an empty string on success.
    """
    if not os.path.exists(settings.HAPROXY_CONFIG_PATH):
        return True, ""
    ok, details = _haproxy_check_docker(settings.HAPROXY_CONFIG_PATH)
    if ok:
        return True, ""
    if details.startswith("haproxy container check failed"):
        local_ok, local_details = _haproxy_check_local(settings.HAPROXY_CONFIG_PATH)
        return local_ok, local_details
    return False, details


def _send_master_command(cmd: str) -> str:
    """Send a command to the HAProxy master CLI socket."""
    path = settings.HAPROXY_MASTER_SOCKET_PATH
    if not os.path.exists(path):
        return f"error: HAProxy master socket not found at {path}"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            # The master CLI reload command is synchronous and may block until
            # the reload is complete (including reload-delay), so allow a long
            # timeout rather than the previous 5s default.
            s.settimeout(90)
            s.connect(path)
            s.sendall(f"{cmd}\n".encode())
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode() or f"error: no response from master socket for {cmd}"
    except Exception as e:
        return f"error: {e}"


def _socket_reload(max_retries: int = 3, delay: float = 2.0) -> dict:
    """Reload HAProxy through the master CLI socket (-S)."""
    last_out = ""
    for attempt in range(1, max_retries + 1):
        out = _send_master_command("reload")
        last_out = out
        if out.startswith("error:"):
            return {"status": "error", "message": out}
        if "unknown command" in out.lower():
            return {"status": "error", "message": "HAProxy master socket does not support the reload command"}
        if "Success=1" in out:
            return {"status": "ok", "message": "HAProxy reloaded", "output": out}
        if "Another reload is still in progress" in out or "reload is still in progress" in out.lower():
            if attempt < max_retries:
                time.sleep(delay)
                continue
        if "Success=0" in out:
            return {"status": "error", "message": f"HAProxy master socket reload failed: {out}"}
        # Treat any non-error, non-Success=0 output as success
        return {"status": "ok", "message": "HAProxy reloaded", "output": out}
    return {"status": "error", "message": f"HAProxy master socket reload failed: {last_out}"}


def reload_haproxy() -> dict:
    print("[RELOAD] step 1 — validate_config (haproxy -c on disk)", flush=True)
    logger.info("reload_haproxy: step 1 — validate_config (haproxy -c on disk)")
    ok, details = validate_config()
    if not ok:
        logger.error("reload_haproxy: validation failed: %s", details)
        return {"status": "error", "message": f"HAProxy configuration validation failed: {details}"}

    if settings.DATAPLANE_API_ENABLED:
        print("[RELOAD] step 2 — dataplane.reload_haproxy", flush=True)
        logger.info("reload_haproxy: step 2 — dataplane.reload_haproxy")
        dp_result = dataplane.reload_haproxy()
        if dp_result.get("status") == "ok":
            logger.info("reload_haproxy: dataplane reload ok")
            return dp_result
        logger.warning("reload_haproxy: dataplane reload failed (%s), falling back to socket", dp_result.get("message"))
        logger.info("reload_haproxy: step 3 — _socket_reload (fallback)")
        socket_result = _socket_reload()
        if socket_result.get("status") == "ok":
            logger.info("reload_haproxy: socket reload ok")
            return {**socket_result, "message": f"{socket_result['message']} (Data Plane API fallback: {dp_result.get('message')})"}
        logger.error("reload_haproxy: both dataplane and socket reload failed")
        return {"status": "error", "message": f"{dp_result.get('message')}; socket fallback: {socket_result.get('message')}"}

    print("[RELOAD] step 2 — _socket_reload", flush=True)
    logger.info("reload_haproxy: step 2 — _socket_reload")
    result = _socket_reload()
    logger.info("reload_haproxy: socket reload result: %s", result.get("status"))
    return result


# Tables that contain runtime data, logs, users, or version history and should
# not be reverted with the HAProxy configuration.
_SNAPSHOT_EXCLUDED = {
    "users",
    "audit_events",
    "tasks",
    "metric_snapshots",
    "waf_metrics",
    "waf_rule_versions",
    "csp_reports",
    "page_protect_scripts",
    "cache_metric_snapshots",
    "challenge_events",
    # API Armor observational data (not configuration)
    "api_profiles",
    "api_anomalies",
    # MCP Gateway observational data (not configuration)
    "mcp_events",
}


def _snapshot_path() -> str:
    return os.path.join(os.path.dirname(settings.HAPROXY_CONFIG_PATH), "haproxy_config_snapshot.json")


def _snapshots_dir() -> str:
    return os.path.join(os.path.dirname(settings.HAPROXY_CONFIG_PATH), "snapshots")


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _serialize_row(row: Any, table: Table) -> Dict[str, Any]:
    return {col.name: _jsonable(row[col.name]) for col in table.columns}


def _build_db_snapshot(db: Session) -> Dict[str, List[Dict[str, Any]]]:
    snapshot: Dict[str, List[Dict[str, Any]]] = {}
    for table in Base.metadata.tables.values():
        if table.name in _SNAPSHOT_EXCLUDED:
            continue
        print(f"[SNAPSHOT] querying table: {table.name}", flush=True)
        rows = []
        for row in db.execute(table.select()).mappings():
            rows.append(_serialize_row(row, table))
        snapshot[table.name] = rows
        print(f"[SNAPSHOT] table {table.name}: {len(rows)} rows", flush=True)
    return snapshot


def _write_db_snapshot(snapshot: Dict[str, List[Dict[str, Any]]], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)


def _max_snapshots(db: Session) -> int:
    from ..services.settings import get_setting
    try:
        return int(get_setting(db, "max_snapshots", "10") or 10)
    except (TypeError, ValueError):
        return 10


def _prune_snapshots(db: Session) -> None:
    from ..models.models import ConfigSnapshot
    max_keep = _max_snapshots(db)
    total = db.query(ConfigSnapshot).count()
    if total <= max_keep:
        return
    to_remove = (
        db.query(ConfigSnapshot)
        .order_by(ConfigSnapshot.created_at.desc())
        .offset(max_keep)
        .all()
    )
    for snap in to_remove:
        # Delete the dated snapshot file on disk to save space, but KEEP the
        # ConfigSnapshot DB record. Audit events reference it via snapshot_id
        # FK, and nulling that FK would make them reappear as "pending changes"
        # in the audit log. The DB record is also needed for rollback.
        if snap.snapshot_path and os.path.exists(snap.snapshot_path):
            try:
                os.remove(snap.snapshot_path)
            except OSError:
                pass
        # Mark the snapshot as pruned so the UI/rollback can show it's no
        # longer available on disk, but keep the row for FK integrity.
        snap.snapshot_path = ""
        db.commit()


def _build_snapshot_diff(configs: Dict[str, str], previous: Dict[str, str]) -> str:
    """Build a combined unified diff for all generated files (HAProxy + WAF)."""
    parts: List[str] = []
    for label, current in configs.items():
        old = previous.get(label) or ""
        diff = "\n".join(
            difflib.unified_diff(
                old.splitlines(),
                current.splitlines(),
                fromfile=f"{label}.applied",
                tofile=label,
                lineterm="",
            )
        )
        if diff:
            parts.append(f"--- {label} ---\n{diff}")
    return "\n\n".join(parts)


def save_config_snapshot(
    db: Session,
    config_text: str,
    previous_config: Optional[str] = None,
    waf_configs: Optional[Dict[str, str]] = None,
    previous_waf_configs: Optional[Dict[str, str]] = None,
    varnish_config: Optional[str] = None,
    previous_varnish_config: Optional[str] = None,
    created_by: Optional[str] = None,
    comment: Optional[str] = None,
) -> ConfigSnapshot:
    """Persist a JSON snapshot of all configuration tables.

    The snapshot lives next to the applied HAProxy config so it can be restored
    later to discard unapplied changes.  A dated copy is also kept in the
    snapshots directory so users can roll back to any previous apply.
    """
    from ..models.models import ConfigSnapshot

    print("[SNAPSHOT] building db snapshot", flush=True)
    snapshot = _build_db_snapshot(db)
    print(f"[SNAPSHOT] db snapshot done: {len(snapshot)} tables", flush=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S_%f")
    snapshot_dir = _snapshots_dir()
    dated_path = os.path.join(snapshot_dir, f"snapshot_{timestamp}.json")

    print("[SNAPSHOT] writing snapshot files", flush=True)
    _write_db_snapshot(snapshot, _snapshot_path())
    _write_db_snapshot(snapshot, dated_path)
    print("[SNAPSHOT] snapshot files written", flush=True)

    configs: Dict[str, str] = {"haproxy.cfg": config_text}
    previous: Dict[str, str] = {"haproxy.cfg": previous_config or ""}
    if waf_configs:
        configs.update(waf_configs)
        previous.update(previous_waf_configs or {})
    if varnish_config is not None:
        configs["varnish.vcl"] = varnish_config
        previous["varnish.vcl"] = previous_varnish_config or ""

    print("[SNAPSHOT] building diff", flush=True)
    diff = _build_snapshot_diff(configs, previous)
    print("[SNAPSHOT] creating ConfigSnapshot record", flush=True)
    record = ConfigSnapshot(
        created_by=created_by,
        comment=comment,
        diff=diff,
        snapshot_path=dated_path,
    )
    db.add(record)
    print("[SNAPSHOT] committing", flush=True)
    db.commit()
    db.refresh(record)
    print(f"[SNAPSHOT] committed, record id={record.id}", flush=True)

    # Record the timestamp of this apply as the "last applied" marker.
    # The audit log uses this (not snapshot_id FKs) to determine which
    # events are pending vs applied — see audit_events.py.
    from .settings import set_setting as _set_setting
    _set_setting(db, "last_applied_at", (record.created_at or datetime.now(timezone.utc)).isoformat())
    print("[SNAPSHOT] last_applied_at set", flush=True)

    print("[SNAPSHOT] pruning old snapshots", flush=True)
    try:
        _prune_snapshots(db)
    except Exception as e:
        print(f"[SNAPSHOT] prune failed (non-fatal): {e}", flush=True)
        logger.warning("Snapshot pruning failed (non-fatal): %s", e)
        db.rollback()
    print("[SNAPSHOT] done", flush=True)
    return record


def _parse_value(value: Any, col: Any) -> Any:
    if value is None:
        return None
    if isinstance(col.type, DateTime) and isinstance(value, str):
        return datetime.fromisoformat(value)
    return value


def _reset_sequences(db: Session, snapshot: Dict[str, List[Dict[str, Any]]]) -> None:
    """Reset auto-increment sequences after a snapshot restore.

    On SQLite, updates the sqlite_sequence table so the next insert doesn't
    reuse an ID from the restored rows. On PostgreSQL, uses setval() to
    advance sequences past the highest restored ID.
    """
    if settings.DATABASE_URL.startswith("sqlite"):
        res = db.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"))
        if not res.fetchone():
            return
        for table in Base.metadata.sorted_tables:
            if table.name in _SNAPSHOT_EXCLUDED or table.name not in snapshot:
                continue
            rows = snapshot[table.name]
            ids = [r.get("id") for r in rows if r.get("id") is not None]
            if not ids:
                continue
            db.execute(
                text("INSERT OR REPLACE INTO sqlite_sequence(name, seq) VALUES (:name, :seq)"),
                {"name": table.name, "seq": max(ids)},
            )
        db.commit()
    else:
        for table in Base.metadata.sorted_tables:
            if table.name in _SNAPSHOT_EXCLUDED or table.name not in snapshot:
                continue
            rows = snapshot[table.name]
            ids = [r.get("id") for r in rows if r.get("id") is not None]
            if not ids:
                continue
            # Find the sequence backing the 'id' column (if any) and reset it.
            pk_col = next((c for c in table.columns if c.name == "id"), None)
            if pk_col is None:
                continue
            seq_result = db.execute(text(
                f"SELECT pg_get_serial_sequence('{table.name}', 'id')"
            )).scalar()
            if seq_result:
                db.execute(text(
                    f"SELECT setval('{seq_result}', {max(ids)}, true)"
                ))
        db.commit()


def _clear_excluded_table_fks(db: Session) -> None:
    """Clear FK references from excluded (runtime) tables to included (config) tables.

    Excluded tables contain runtime/observational data that shouldn't be reverted.
    But some have FK constraints to config tables that ARE being deleted+restored.
    On PostgreSQL, deleting a config row that's still referenced by an excluded
    table raises a ForeignKeyViolation and aborts the transaction. On SQLite, FK
    enforcement is off by default so this silently succeeds.

    For nullable FKs: SET NULL (preserves observational data, detaches from config).
    For non-nullable FKs: DELETE the rows (can't preserve them without the parent).
    """
    included_table_names = {
        t.name for t in Base.metadata.sorted_tables if t.name not in _SNAPSHOT_EXCLUDED
    }
    for table in Base.metadata.sorted_tables:
        if table.name not in _SNAPSHOT_EXCLUDED:
            continue
        for fk in table.foreign_keys:
            ref_table_name = fk.column.table.name
            if ref_table_name not in included_table_names:
                continue
            col = fk.parent
            if col.nullable:
                db.execute(table.update().values({col.name: None}))
            else:
                db.execute(table.delete())


def load_config_snapshot(db: Session, path: Optional[str] = None) -> None:
    """Restore configuration tables from a saved JSON snapshot."""
    path = path or _snapshot_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"No configuration snapshot exists at {path}")

    with open(path, "r") as f:
        snapshot = json.load(f)

    sorted_tables = list(Base.metadata.sorted_tables)
    # Clear FK references from excluded (runtime) tables to config tables that
    # are about to be deleted. Without this, PostgreSQL raises a FK violation
    # (e.g. waf_rule_versions → waf_rules) and aborts the entire transaction.
    _clear_excluded_table_fks(db)
    # Delete in reverse dependency order to avoid FK errors.
    for table in reversed(sorted_tables):
        if table.name in _SNAPSHOT_EXCLUDED:
            continue
        db.execute(table.delete())

    # Insert in dependency order.
    for table in sorted_tables:
        if table.name in _SNAPSHOT_EXCLUDED or table.name not in snapshot:
            continue
        rows = snapshot[table.name]
        if not rows:
            continue
        cleaned_rows = []
        for row in rows:
            cleaned = {col.name: _parse_value(row.get(col.name), col) for col in table.columns if col.name in row}
            cleaned_rows.append(cleaned)
        if cleaned_rows:
            db.execute(table.insert(), cleaned_rows)

    db.commit()
    _reset_sequences(db, snapshot)


def revert_to_applied_config(db: Session, created_by: Optional[str] = None) -> Dict[str, Any]:
    """Restore the database to the last applied configuration and reload HAProxy."""
    load_config_snapshot(db)
    write_config(db, created_by=created_by)
    return reload_haproxy()


def rollback_to_snapshot(db: Session, snapshot_id: int, created_by: Optional[str] = None) -> Dict[str, Any]:
    """Restore the database to a named ConfigSnapshot and reload HAProxy."""
    from ..models.models import ConfigSnapshot
    snap = db.get(ConfigSnapshot, snapshot_id)
    if not snap:
        raise ValueError(f"Snapshot {snapshot_id} not found")
    load_config_snapshot(db, snap.snapshot_path)
    write_config(db, created_by=created_by, comment=f"Rollback to snapshot {snapshot_id}")
    return reload_haproxy()
