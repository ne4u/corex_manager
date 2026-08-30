"""Streamable HTTP protocol handler for MCP Gateway.

Implements MCP spec 2025-11-25:
- POST /mcp: JSON-RPC request/notification/response
- GET /mcp: SSE listen (405 in v1 — no unsolicited server messages)
- Session management via Mcp-Session-Id header
- Origin validation
- Virtual registry: merged tools/resources/prompts with namespace prefixing
- Catalog-based list responses (Phase 2)
- Resource URI wrapping: mcp://{namespace}/{original_uri}
- Partial failure handling with _meta.warnings
- notifications/cancelled support
"""
import json
import logging
import time
from typing import Any, Optional
from urllib.parse import quote, unquote

from fastapi import Request
from fastapi.responses import JSONResponse, Response

try:
    from .auth import authenticate, AuthError, AuthContext
    from .config_loader import get_config, is_configured, check_origin, get_enabled_servers, get_server_by_namespace
    from .sessions import (
        create_session, get_session, refresh_session, delete_session,
        set_upstream_session, get_upstream_session, validate_session,
    )
    from .revocation import is_token_valid
    from .upstream import (
        initialize_upstream, send_request, send_notification,
        send_request_tracked, cancel_inflight, is_circuit_open,
    )
    from .catalog import get_catalog, get_all_catalogs, pop_changed_servers, store_catalog
    from .policy import (
        load_policies, evaluate_policy, check_tool_access,
        check_resource_access, check_prompt_access,
        filter_tool_list, filter_resource_list, filter_prompt_list,
        MCP_POLICY_DENIED,
    )
    from .expression import build_mcp_context
    from .ratelimit import check_rate_limit, check_ip_rate_limit, acquire_concurrent_slot, release_concurrent_slot, get_team_rpm, MCP_RATE_LIMITED
    from .events import log_event, generate_request_id
    from .alerting import record_event as record_alert
    from .dlp import (
        load_dlp_rules, has_dlp_rules, get_dlp_rules,
        scan_request as dlp_scan_request, scan_response as dlp_scan_response,
        MCP_DLP_BLOCKED,
    )
    from .guardrails import (
        load_guardrails, has_guardrails, get_guardrails,
        scan_request as gr_scan_request, scan_response as gr_scan_response,
        MCP_GUARDRAIL_BLOCKED,
    )
    from .skills import (
        load_skills, has_skills, get_enabled_skills,
        get_skill_by_name, render_skill_prompt, build_prompt_entry,
    )
except ImportError:
    from auth import authenticate, AuthError, AuthContext
    from config_loader import get_config, is_configured, check_origin, get_enabled_servers, get_server_by_namespace
    from sessions import (
        create_session, get_session, refresh_session, delete_session,
        set_upstream_session, get_upstream_session, validate_session,
    )
    from revocation import is_token_valid
    from upstream import (
        initialize_upstream, send_request, send_notification,
        send_request_tracked, cancel_inflight, is_circuit_open,
    )
    from catalog import get_catalog, get_all_catalogs, pop_changed_servers, store_catalog
    from policy import (
        load_policies, evaluate_policy, check_tool_access,
        check_resource_access, check_prompt_access,
        filter_tool_list, filter_resource_list, filter_prompt_list,
        MCP_POLICY_DENIED,
    )
    from expression import build_mcp_context
    from ratelimit import check_rate_limit, check_ip_rate_limit, acquire_concurrent_slot, release_concurrent_slot, get_team_rpm, MCP_RATE_LIMITED
    from events import log_event, generate_request_id
    from alerting import record_event as record_alert
    from dlp import (
        load_dlp_rules, has_dlp_rules, get_dlp_rules,
        scan_request as dlp_scan_request, scan_response as dlp_scan_response,
        MCP_DLP_BLOCKED,
    )
    from guardrails import (
        load_guardrails, has_guardrails, get_guardrails,
        scan_request as gr_scan_request, scan_response as gr_scan_response,
        MCP_GUARDRAIL_BLOCKED,
    )
    from skills import (
        load_skills, has_skills, get_enabled_skills,
        get_skill_by_name, render_skill_prompt, build_prompt_entry,
    )

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2024-11-05"]

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INTERNAL_ERROR = -32603
MCP_GATEWAY_ERROR = -32000
MCP_RESOURCE_NOT_SUPPORTED = -32001


def _get_default_rpm() -> int:
    """Get default RPM from config bundle."""
    config = get_config()
    if config:
        return int(config.get("default_rpm", 60))
    return 60


def _get_max_body_bytes(config: dict) -> int:
    """Get max body bytes from config, default 1MB."""
    return int(config.get("max_body_bytes", 1048576))


def _ensure_policies_loaded():
    """Load policies from the current config bundle if not already loaded."""
    config = get_config()
    if config and "policies" in config:
        load_policies(config)


def _ensure_dlp_loaded():
    """Load DLP rules from the current config bundle if not already loaded."""
    config = get_config()
    if config and "dlp_rules" in config:
        load_dlp_rules(config)


def _ensure_guardrails_loaded():
    """Load guardrail rules from the current config bundle if not already loaded."""
    config = get_config()
    if config and "guardrails" in config:
        load_guardrails(config)


def _ensure_skills_loaded():
    """Load skills from the current config bundle if not already loaded."""
    config = get_config()
    if config and "skills" in config:
        load_skills(config)


def _error_response(id: Any, code: int, message: str, status: int = 200) -> JSONResponse:
    """Build a JSON-RPC error response."""
    return JSONResponse(
        status_code=status,
        content={
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message},
        },
    )


def _unauthorized_response(resource_metadata_url: str) -> JSONResponse:
    """401 with WWW-Authenticate per RFC 9728."""
    return JSONResponse(
        status_code=401,
        content={
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32000, "message": "Unauthorized"},
        },
        headers={
            "WWW-Authenticate": f'Bearer realm="mcp", resource_metadata="{resource_metadata_url}"',
        },
    )


def _get_resource_metadata_url(request: Request) -> str:
    host = request.headers.get("host", "")
    scheme = request.headers.get("x-forwarded-proto", "https")
    return f"{scheme}://{host}/.well-known/oauth-protected-resource"


def _is_notification(message: dict) -> bool:
    """A JSON-RPC notification has no 'id' field."""
    return "id" not in message


def _is_response(message: dict) -> bool:
    """A JSON-RPC response has 'result' or 'error' but no 'method'."""
    return "method" not in message and ("result" in message or "error" in message)


def _prefix_tool_name(namespace: str, name: str) -> str:
    """Prefix a tool name: {namespace}__{name}."""
    return f"{namespace}__{name}"


def _wrap_resource_uri(namespace: str, original_uri: str) -> str:
    """Wrap an upstream resource URI: mcp://{namespace}/{urlquoted original}."""
    return f"mcp://{namespace}/{quote(original_uri, safe='')}"


def _unwrap_resource_uri(wrapped_uri: str) -> tuple[Optional[str], str]:
    """Invert a wrapped resource URI -> (namespace, original_uri).

    Returns (None, original) if the URI is not wrapped.
    """
    if not wrapped_uri.startswith("mcp://"):
        return None, wrapped_uri
    rest = wrapped_uri[6:]  # strip "mcp://"
    slash_idx = rest.find("/")
    if slash_idx == -1:
        return None, wrapped_uri
    namespace = rest[:slash_idx]
    original = unquote(rest[slash_idx + 1:])
    return namespace, original


def _prefix_list_items(items: list[dict], namespace: str, name_field: str = "name") -> list[dict]:
    """Prefix names in a list of items (tools, prompts, resources)."""
    result = []
    for item in items:
        prefixed = dict(item)
        original_name = prefixed.get(name_field, "")
        prefixed[name_field] = _prefix_tool_name(namespace, original_name)
        prefixed["_meta"] = prefixed.get("_meta", {})
        prefixed["_meta"]["mcp_server"] = namespace
        prefixed["_meta"]["mcp_original_name"] = original_name
        result.append(prefixed)
    return result


async def handle_mcp_post(request: Request) -> Response:
    """Handle POST /mcp — the main JSON-RPC endpoint."""
    # Check gateway is configured
    if not is_configured():
        return _error_response(None, MCP_GATEWAY_ERROR, "MCP gateway disabled or not configured", 503)

    # Validate Origin
    origin = request.headers.get("origin", "")
    if not check_origin(origin):
        return JSONResponse(
            status_code=403,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": MCP_GATEWAY_ERROR, "message": "Invalid Origin"}},
        )

    # Extract client IP for rate limiting and brute-force protection
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host if request.client else ""

    # Per-IP rate limiting (before auth to block credential stuffing)
    ip_allowed, _ = check_ip_rate_limit(client_ip)
    if not ip_allowed:
        return _error_response(None, MCP_RATE_LIMITED, "IP rate limit exceeded")

    # Authenticate
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return _unauthorized_response(_get_resource_metadata_url(request))
    token = auth_header[7:]
    config = get_config()
    try:
        auth_ctx = await authenticate(token, config, client_ip)
    except AuthError:
        record_alert("auth_failed")
        return _unauthorized_response(_get_resource_metadata_url(request))

    # Parse body with size enforcement
    content_length = int(request.headers.get("content-length", "0"))
    max_body = _get_max_body_bytes(config)
    if max_body > 0 and content_length > max_body:
        return _error_response(None, JSONRPC_PARSE_ERROR, f"Request body too large ({content_length} > {max_body} bytes)", 413)

    try:
        raw_body = await request.body()
    except Exception:
        return _error_response(None, JSONRPC_PARSE_ERROR, "Failed to read request body", 400)

    if max_body > 0 and len(raw_body) > max_body:
        return _error_response(None, JSONRPC_PARSE_ERROR, f"Request body too large ({len(raw_body)} > {max_body} bytes)", 413)

    try:
        body = json.loads(raw_body)
    except Exception:
        return _error_response(None, JSONRPC_PARSE_ERROR, "Parse error", 400)

    if not isinstance(body, dict):
        return _error_response(None, JSONRPC_INVALID_REQUEST, "Invalid Request", 400)

    msg_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    # Notifications/responses → 202 Accepted (no body)
    if _is_notification(body) or _is_response(body):
        session_id = request.headers.get("mcp-session-id")
        if session_id and method:
            await _handle_notification(session_id, method, params, auth_ctx)
        return Response(status_code=202)

    # It's a request — must have method
    if not method:
        return _error_response(msg_id, JSONRPC_INVALID_REQUEST, "Invalid Request", 400)

    # Session handling
    session_id = request.headers.get("mcp-session-id")

    # initialize creates the session
    if method == "initialize":
        return await _handle_initialize(body, msg_id, params, auth_ctx, request)

    # All other requests require a valid session
    if not session_id or not validate_session(session_id):
        return _error_response(msg_id, MCP_GATEWAY_ERROR, "Invalid or missing session. Call initialize first.", 400)

    # Session re-validation: check identity is still enabled
    session_data = get_session(session_id)
    if session_data and session_data.get("identity_id") != auth_ctx.identity_id:
        return _error_response(msg_id, MCP_GATEWAY_ERROR, "Session identity mismatch", 403)
    if session_data and not is_token_valid(auth_ctx.identity_id):
        return _error_response(msg_id, MCP_GATEWAY_ERROR, "Identity has been revoked", 403)

    refresh_session(session_id)

    # Route to handler
    if method == "ping":
        return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": {}})

    if method == "logging/setLevel":
        return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": {}})

    # Catalog-based list methods (no live upstream call)
    if method == "tools/list":
        return _handle_tools_list(auth_ctx, params, msg_id)
    if method == "resources/list":
        return _handle_resources_list(auth_ctx, params, msg_id)
    if method == "resources/templates/list":
        return _handle_resources_templates_list(auth_ctx, params, msg_id)
    if method == "prompts/list":
        return _handle_prompts_list(auth_ctx, params, msg_id)

    # Not supported in v1
    if method == "resources/subscribe":
        return _error_response(msg_id, MCP_RESOURCE_NOT_SUPPORTED, "resources/subscribe is not supported in v1")

    # Call methods — route by namespace prefix
    if method == "tools/call":
        return await _route_call(session_id, auth_ctx, method, params, msg_id, body, "tool")
    if method == "resources/read":
        return await _route_call(session_id, auth_ctx, method, params, msg_id, body, "resource")
    if method == "prompts/get":
        return await _route_call(session_id, auth_ctx, method, params, msg_id, body, "prompt")

    # Unknown method
    return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, f"Method not found: {method}")


async def handle_mcp_get(request: Request) -> Response:
    """Handle GET /mcp — SSE listen stream.

    v1: return 405 Method Not Allowed (we don't offer unsolicited server messages).
    """
    return JSONResponse(
        status_code=405,
        content={"jsonrpc": "2.0", "id": None, "error": {"code": MCP_GATEWAY_ERROR, "message": "SSE not supported in v1"}},
        headers={"Allow": "POST"},
    )


async def _handle_initialize(
    body: dict,
    msg_id: Any,
    params: dict,
    auth_ctx: AuthContext,
    request: Request,
) -> JSONResponse:
    """Handle initialize — create session, init upstreams, merge capabilities."""
    client_protocol = params.get("protocolVersion", PROTOCOL_VERSION)
    if client_protocol not in SUPPORTED_PROTOCOL_VERSIONS:
        logger.info("Client requested protocol %s, advertising %s", client_protocol, PROTOCOL_VERSION)

    # Create session
    session_id = create_session(auth_ctx.identity_id, auth_ctx.team_id)

    # Get servers for this team
    servers = _get_team_servers(auth_ctx.team_id)

    # Initialize upstream sessions and merge capabilities from catalogs
    has_tools = False
    has_resources = False
    has_prompts = False

    for server in servers:
        upstream_sid = await initialize_upstream(server)
        if upstream_sid:
            set_upstream_session(session_id, server["id"], upstream_sid)
        # Check catalog for capabilities
        catalog = get_catalog(server["id"])
        if catalog:
            if catalog.get("tools"):
                has_tools = True
            if catalog.get("resources"):
                has_resources = True
            if catalog.get("prompts"):
                has_prompts = True

    capabilities: dict = {}
    if has_tools:
        capabilities["tools"] = {"listChanged": True}
    if has_resources:
        capabilities["resources"] = {"listChanged": True, "subscribe": False}
    if has_prompts:
        capabilities["prompts"] = {"listChanged": True}
    capabilities["logging"] = {}

    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": capabilities,
            "serverInfo": {
                "name": "mcp-gateway",
                "version": "0.2.0",
            },
        },
    }
    resp = JSONResponse(content=response)
    resp.headers["Mcp-Session-Id"] = session_id
    return resp


def _get_team_servers(team_id: int) -> list[dict]:
    """Return enabled servers for a team."""
    return [s for s in get_enabled_servers() if s.get("team_id") == team_id]


def _handle_tools_list(
    auth_ctx: AuthContext,
    params: dict,
    msg_id: Any,
) -> Response:
    """Merge tools from all team server catalogs with namespace prefixing.

    Policy-filtered at list time: clients must not see tools they cannot invoke.
    """
    _ensure_policies_loaded()
    servers = _get_team_servers(auth_ctx.team_id)
    merged_tools: list[dict] = []
    warnings: list[dict] = []

    for server in servers:
        catalog = get_catalog(server["id"])
        if catalog is None:
            warnings.append({"server": server.get("namespace"), "error": "catalog not available"})
            continue
        namespace = server.get("namespace", server["name"])
        tools = catalog.get("tools", [])
        prefixed = _prefix_list_items(tools, namespace, "name")
        # Policy filter at list time
        filtered = filter_tool_list(prefixed, namespace, auth_ctx)
        merged_tools.extend(filtered)

    result: dict = {"tools": merged_tools}
    if warnings:
        result["_meta"] = {"warnings": warnings}
    return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": result})


def _handle_resources_list(
    auth_ctx: AuthContext,
    params: dict,
    msg_id: Any,
) -> Response:
    """Merge resources from all team server catalogs with URI wrapping.

    Policy-filtered at list time.
    """
    _ensure_policies_loaded()
    servers = _get_team_servers(auth_ctx.team_id)
    merged_resources: list[dict] = []
    warnings: list[dict] = []

    for server in servers:
        catalog = get_catalog(server["id"])
        if catalog is None:
            warnings.append({"server": server.get("namespace"), "error": "catalog not available"})
            continue
        namespace = server.get("namespace", server["name"])
        resources = catalog.get("resources", [])
        wrapped = []
        for res in resources:
            prefixed = dict(res)
            original_uri = prefixed.get("uri", "")
            prefixed["uri"] = _wrap_resource_uri(namespace, original_uri)
            prefixed["_meta"] = prefixed.get("_meta", {})
            prefixed["_meta"]["mcp_server"] = namespace
            prefixed["_meta"]["mcp_original_uri"] = original_uri
            wrapped.append(prefixed)
        # Policy filter at list time
        filtered = filter_resource_list(wrapped, namespace, auth_ctx)
        merged_resources.extend(filtered)

    result: dict = {"resources": merged_resources}
    if warnings:
        result["_meta"] = {"warnings": warnings}
    return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": result})


def _handle_resources_templates_list(
    auth_ctx: AuthContext,
    params: dict,
    msg_id: Any,
) -> Response:
    """Merge resource templates from all team server catalogs with URI template wrapping."""
    servers = _get_team_servers(auth_ctx.team_id)
    merged_templates: list[dict] = []
    warnings: list[dict] = []

    for server in servers:
        catalog = get_catalog(server["id"])
        if catalog is None:
            warnings.append({"server": server.get("namespace"), "error": "catalog not available"})
            continue
        namespace = server.get("namespace", server["name"])
        resources = catalog.get("resources", [])
        for res in resources:
            if "uriTemplate" in res:
                prefixed = dict(res)
                original_template = prefixed["uriTemplate"]
                prefixed["uriTemplate"] = _wrap_resource_uri(namespace, original_template)
                prefixed["_meta"] = prefixed.get("_meta", {})
                prefixed["_meta"]["mcp_server"] = namespace
                merged_templates.append(prefixed)

    result: dict = {"resourceTemplates": merged_templates}
    if warnings:
        result["_meta"] = {"warnings": warnings}
    return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": result})


def _handle_prompts_list(
    auth_ctx: AuthContext,
    params: dict,
    msg_id: Any,
) -> Response:
    """Merge prompts from all team server catalogs with namespace prefixing.

    Policy-filtered at list time. Skills are injected as virtual prompts.
    """
    _ensure_policies_loaded()
    _ensure_skills_loaded()
    servers = _get_team_servers(auth_ctx.team_id)
    merged_prompts: list[dict] = []
    warnings: list[dict] = []

    for server in servers:
        catalog = get_catalog(server["id"])
        if catalog is None:
            warnings.append({"server": server.get("namespace"), "error": "catalog not available"})
            continue
        namespace = server.get("namespace", server["name"])
        prompts = catalog.get("prompts", [])
        prefixed = _prefix_list_items(prompts, namespace, "name")
        # Policy filter at list time
        filtered = filter_prompt_list(prefixed, namespace, auth_ctx)
        merged_prompts.extend(filtered)

    # Inject enabled skills as virtual prompts
    if has_skills():
        enabled_skills = get_enabled_skills(auth_ctx)
        for skill in enabled_skills:
            merged_prompts.append(build_prompt_entry(skill))

    result: dict = {"prompts": merged_prompts}
    if warnings:
        result["_meta"] = {"warnings": warnings}
    return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": result})


async def _route_call(
    session_id: str,
    auth_ctx: AuthContext,
    method: str,
    params: dict,
    msg_id: Any,
    original_body: dict,
    kind: str,
) -> Response:
    """Route a call (tools/call, resources/read, prompts/get) by namespace prefix.

    For tools/call and prompts/get: split name on first '__'.
    For resources/read: invert wrapped URI mcp://{namespace}/{original}.
    """
    name = params.get("name") or params.get("uri") or ""

    # Determine namespace and original name
    if kind == "resource":
        namespace, original_name = _unwrap_resource_uri(name)
        if namespace is None:
            # Fall back to '__' split for backward compat
            if "__" not in name:
                return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, "Missing namespace in resource URI")
            parts = name.split("__", 1)
            namespace, original_name = parts[0], parts[1]
    else:
        if "__" not in name:
            return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, f"Missing namespace prefix in {kind} name")
        parts = name.split("__", 1)
        namespace, original_name = parts[0], parts[1]

    server = get_server_by_namespace(namespace)

    # Handle skill namespace — render locally, don't forward upstream
    if namespace == "skill" and kind == "prompt":
        _ensure_skills_loaded()
        skill = get_skill_by_name(original_name)
        if not skill:
            return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, f"Unknown skill: {original_name}")
        if not skill.get("published_version_id"):
            return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, f"Skill not published: {original_name}")
        rendered = render_skill_prompt(skill)
        rendered["id"] = msg_id
        req_id = generate_request_id()
        log_event(
            request_id=req_id, session_id=session_id,
            identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
            server_id=None, jsonrpc_method=method,
            prompt=name,
            action="allow", status="ok",
            latency_ms=0,
        )
        return JSONResponse(content=rendered)

    if not server:
        return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, f"Unknown namespace: {namespace}")

    # Verify server belongs to caller's team
    if server.get("team_id") != auth_ctx.team_id:
        return _error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, f"Unknown namespace: {namespace}")

    # Call-time policy evaluation
    _ensure_policies_loaded()
    call_args = params.get("arguments") if kind == "tool" else None
    if kind == "tool":
        pr = check_tool_access(method, name, namespace, auth_ctx, args=call_args)
    elif kind == "resource":
        pr = check_resource_access(method, name, namespace, auth_ctx)
    else:
        pr = check_prompt_access(method, name, namespace, auth_ctx)

    req_id = generate_request_id()

    if pr.denied:
        record_alert("policy_denied")
        log_event(
            request_id=req_id, session_id=session_id,
            identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
            server_id=server["id"], jsonrpc_method=method,
            tool=name if kind == "tool" else None,
            resource_uri=name if kind == "resource" else None,
            prompt=name if kind == "prompt" else None,
            action="deny", status="policy_denied",
            error=f"Policy denied: {pr.rule_name}",
        )
        return _error_response(msg_id, MCP_POLICY_DENIED, f"Policy denied: {pr.rule_name}")

    # Rate limiting (skip if policy says skip_ratelimit)
    if not pr.skip_ratelimit:
        config = get_config()
        max_rpm = get_team_rpm(config, auth_ctx.team_id, _get_default_rpm())
        allowed, remaining = check_rate_limit(auth_ctx.identity_id, name, max_rpm)
        if not allowed:
            record_alert("rate_limited")
            log_event(
                request_id=req_id, session_id=session_id,
                identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
                server_id=server["id"], jsonrpc_method=method,
                tool=name if kind == "tool" else None,
                resource_uri=name if kind == "resource" else None,
                prompt=name if kind == "prompt" else None,
                action="rate_limited", status="rate_limited",
                error=f"Rate limit exceeded for {name}",
            )
            return _error_response(msg_id, MCP_RATE_LIMITED, f"Rate limit exceeded for {name}")

    # DLP request scanning (skip if policy says skip_dlp)
    dlp_hits: list = []
    if not pr.skip_dlp:
        _ensure_dlp_loaded()
        if has_dlp_rules():
            dlp_rules = get_dlp_rules()
            req_scan = dlp_scan_request(method, params, dlp_rules)
            if req_scan.blocked:
                dlp_hits = req_scan.to_hit_list()
                record_alert("dlp_blocked")
                log_event(
                    request_id=req_id, session_id=session_id,
                    identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
                    server_id=server["id"], jsonrpc_method=method,
                    tool=name if kind == "tool" else None,
                    resource_uri=name if kind == "resource" else None,
                    prompt=name if kind == "prompt" else None,
                    action="dlp_blocked", status="dlp_blocked",
                    error=f"DLP blocked: {req_scan.hits[0].rule_name}",
                    dlp_hits=dlp_hits,
                )
                return _error_response(msg_id, MCP_DLP_BLOCKED, f"DLP blocked: {req_scan.hits[0].rule_name}")
            if req_scan.modified:
                params = req_scan.modified_data
                dlp_hits = req_scan.to_hit_list()

    # Guardrail request scanning
    guardrail_hits: list = []
    _ensure_guardrails_loaded()
    if has_guardrails():
        gr_rules = get_guardrails()
        gr_req_scan = gr_scan_request(method, params, gr_rules)
        if gr_req_scan.blocked:
            guardrail_hits = gr_req_scan.to_hit_list()
            record_alert("guardrail_blocked")
            log_event(
                request_id=req_id, session_id=session_id,
                identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
                server_id=server["id"], jsonrpc_method=method,
                tool=name if kind == "tool" else None,
                resource_uri=name if kind == "resource" else None,
                prompt=name if kind == "prompt" else None,
                action="guardrail_blocked", status="guardrail_blocked",
                error=f"Guardrail blocked: {gr_req_scan.hits[0].rule_name}",
                guardrail_hits=guardrail_hits,
            )
            return _error_response(msg_id, MCP_GUARDRAIL_BLOCKED, f"Guardrail blocked: {gr_req_scan.hits[0].rule_name}")
        if gr_req_scan.modified:
            params = gr_req_scan.modified_data
            guardrail_hits = gr_req_scan.to_hit_list()

    upstream_sid = get_upstream_session(session_id, server["id"])

    # Concurrent request limiting
    if not acquire_concurrent_slot(auth_ctx.identity_id):
        log_event(
            request_id=req_id, session_id=session_id,
            identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
            server_id=server["id"], jsonrpc_method=method,
            tool=name if kind == "tool" else None,
            resource_uri=name if kind == "resource" else None,
            prompt=name if kind == "prompt" else None,
            action="rate_limited", status="concurrent_limit",
            error=f"Concurrent request limit exceeded for identity {auth_ctx.identity_id}",
        )
        return _error_response(msg_id, MCP_RATE_LIMITED, "Concurrent request limit exceeded")

    # Strip prefix from params
    forward_params = dict(params)
    if "name" in forward_params:
        forward_params["name"] = original_name
    if "uri" in forward_params:
        forward_params["uri"] = original_name

    upstream_body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": forward_params,
    }

    t0 = time.time()
    try:
        status, body, _ = await send_request_tracked(
            session_id, msg_id, server, upstream_body, upstream_sid,
        )
    finally:
        release_concurrent_slot(auth_ctx.identity_id)
    latency_ms = int((time.time() - t0) * 1000)

    # Upstream response validation (#10): check size and structure
    max_resp_bytes = _get_max_body_bytes(get_config())
    if isinstance(body, str) and max_resp_bytes > 0 and len(body) > max_resp_bytes:
        log_event(
            request_id=req_id, session_id=session_id,
            identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
            server_id=server["id"], jsonrpc_method=method,
            tool=name if kind == "tool" else None,
            resource_uri=name if kind == "resource" else None,
            prompt=name if kind == "prompt" else None,
            action="block", status="response_too_large",
            error=f"Upstream response too large ({len(body)} > {max_resp_bytes} bytes)",
            latency_ms=latency_ms,
        )
        return _error_response(msg_id, MCP_GATEWAY_ERROR, "Upstream response too large")
    if isinstance(body, bytes) and max_resp_bytes > 0 and len(body) > max_resp_bytes:
        log_event(
            request_id=req_id, session_id=session_id,
            identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
            server_id=server["id"], jsonrpc_method=method,
            tool=name if kind == "tool" else None,
            resource_uri=name if kind == "resource" else None,
            prompt=name if kind == "prompt" else None,
            action="block", status="response_too_large",
            error=f"Upstream response too large ({len(body)} > {max_resp_bytes} bytes)",
            latency_ms=latency_ms,
        )
        return _error_response(msg_id, MCP_GATEWAY_ERROR, "Upstream response too large")

    # DLP response scanning
    if not pr.skip_dlp and has_dlp_rules():
        dlp_rules = get_dlp_rules()
        if isinstance(body, dict):
            resp_scan = dlp_scan_response(body, dlp_rules)
            if resp_scan.blocked:
                dlp_hits.extend(resp_scan.to_hit_list())
                record_alert("dlp_blocked")
                log_event(
                    request_id=req_id, session_id=session_id,
                    identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
                    server_id=server["id"], jsonrpc_method=method,
                    tool=name if kind == "tool" else None,
                    resource_uri=name if kind == "resource" else None,
                    prompt=name if kind == "prompt" else None,
                    action="dlp_blocked", status="dlp_blocked_response",
                    error=f"DLP blocked in response: {resp_scan.hits[0].rule_name}",
                    latency_ms=latency_ms,
                    dlp_hits=dlp_hits,
                )
                return _error_response(msg_id, MCP_DLP_BLOCKED, f"DLP blocked in response: {resp_scan.hits[0].rule_name}")
            if resp_scan.modified:
                body = resp_scan.modified_data
                dlp_hits.extend(resp_scan.to_hit_list())

    # Guardrail response scanning
    if has_guardrails():
        gr_rules = get_guardrails()
        if isinstance(body, dict):
            gr_resp_scan = gr_scan_response(body, gr_rules)
            if gr_resp_scan.blocked:
                guardrail_hits.extend(gr_resp_scan.to_hit_list())
                record_alert("guardrail_blocked")
                log_event(
                    request_id=req_id, session_id=session_id,
                    identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
                    server_id=server["id"], jsonrpc_method=method,
                    tool=name if kind == "tool" else None,
                    resource_uri=name if kind == "resource" else None,
                    prompt=name if kind == "prompt" else None,
                    action="guardrail_blocked", status="guardrail_blocked_response",
                    error=f"Guardrail blocked in response: {gr_resp_scan.hits[0].rule_name}",
                    latency_ms=latency_ms,
                    guardrail_hits=guardrail_hits,
                )
                return _error_response(msg_id, MCP_GUARDRAIL_BLOCKED, f"Guardrail blocked in response: {gr_resp_scan.hits[0].rule_name}")
            if gr_resp_scan.modified:
                body = gr_resp_scan.modified_data
                guardrail_hits.extend(gr_resp_scan.to_hit_list())

    # Log the event
    log_event(
        request_id=req_id, session_id=session_id,
        identity_id=auth_ctx.identity_id, team_id=auth_ctx.team_id,
        server_id=server["id"], jsonrpc_method=method,
        tool=name if kind == "tool" else None,
        resource_uri=name if kind == "resource" else None,
        prompt=name if kind == "prompt" else None,
        action="allow", status="ok" if status == 200 else "upstream_error",
        latency_ms=latency_ms,
        bytes_out=len(body) if isinstance(body, (str, bytes)) else None,
        dlp_hits=dlp_hits if dlp_hits else None,
        guardrail_hits=guardrail_hits if guardrail_hits else None,
    )

    if isinstance(body, dict):
        body["id"] = msg_id
        return JSONResponse(status_code=status, content=body)
    return Response(status_code=status, content=body, media_type="text/plain")


async def _handle_notification(
    session_id: str,
    method: str,
    params: dict,
    auth_ctx: AuthContext,
) -> None:
    """Handle a client notification (no response expected)."""
    if method == "notifications/cancelled":
        # Cancel an in-flight upstream request
        cancelled_id = params.get("requestId")
        if cancelled_id is not None:
            cancel_inflight(session_id, cancelled_id)
        return

    if method == "notifications/initialized":
        # Fan-out to all upstream servers for this session
        servers = _get_team_servers(auth_ctx.team_id)
        for server in servers:
            upstream_sid = get_upstream_session(session_id, server["id"])
            notification = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }
            await send_notification(server, notification, upstream_sid)
        return

    # Forward other notifications to all upstream servers
    servers = _get_team_servers(auth_ctx.team_id)
    for server in servers:
        upstream_sid = get_upstream_session(session_id, server["id"])
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        await send_notification(server, notification, upstream_sid)
