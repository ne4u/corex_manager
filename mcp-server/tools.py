"""Tool discovery and execution — proxies MCP tools to the backend API over HTTP.

Tools are generated from the backend's OpenAPI spec (GET {backend}/openapi.json)
and executed by forwarding requests to the api service over its internal HTTPS
endpoint with a service admin JWT. All route logic, validation, and middleware
run in the api container exactly as they would for a normal HTTP request.
"""
import json
import logging
import os
import re
import time
from typing import Any, Optional

import httpx
import jwt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend connection
# ---------------------------------------------------------------------------

# The api service serves HTTPS internally with a self-signed cert
# (SANs: api, localhost, 127.0.0.1 — see backend/entrypoint.sh). The cert is
# written to the shared certs volume, so it doubles as its own CA bundle.
_BACKEND_URL = os.environ.get("MCP_BACKEND_URL", "https://api:8000").rstrip("/")
_BACKEND_CA = os.environ.get("MCP_BACKEND_CA", "/app/certs/internal/api.crt")
_SECRET_KEY = os.environ.get("SECRET_KEY", "")

# ---------------------------------------------------------------------------
# Service JWT management
# ---------------------------------------------------------------------------

_service_jwt: Optional[str] = None
_service_jwt_at: float = 0.0
_JWT_TTL = 20 * 3600  # 20 hours — refresh before the 24h expiry


def _get_service_jwt() -> str:
    """Mint (or return cached) a service admin JWT.

    Matches backend core.security.create_access_token: HS256 signed with
    SECRET_KEY, {"sub": "admin", "exp": ...}.
    """
    global _service_jwt, _service_jwt_at
    now = time.time()
    if _service_jwt and (now - _service_jwt_at) < _JWT_TTL:
        return _service_jwt
    _service_jwt = jwt.encode(
        {"sub": "admin", "exp": int(now) + 24 * 3600},
        _SECRET_KEY,
        algorithm="HS256",
    )
    _service_jwt_at = now
    return _service_jwt


def _get_service_token() -> Optional[str]:
    """Return the MCP_SERVICE_TOKEN for rate-limit bypass, if configured."""
    return os.environ.get("MCP_SERVICE_TOKEN")


# ---------------------------------------------------------------------------
# HTTP client (to the api service)
# ---------------------------------------------------------------------------

_client: Optional[httpx.AsyncClient] = None


def _tls_verify():
    """Resolve TLS verification for the backend client.

    Uses the internal self-signed cert as CA when present; explicit
    off/false/none disables verification. A missing CA file falls back to
    disabled with a warning (dev setups where MCP_BACKEND_URL is plain http
    or the api cert isn't shared).
    """
    ca = _BACKEND_CA.strip()
    if ca.lower() in ("", "off", "false", "none", "disabled"):
        return False
    if os.path.isfile(ca):
        return ca
    logger.warning("MCP_BACKEND_CA %s not found — TLS verification disabled", ca)
    return False


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=_BACKEND_URL,
            verify=_tls_verify(),
            timeout=60.0,
        )
    return _client


async def _fetch_openapi() -> dict:
    """Fetch the backend's OpenAPI spec (public endpoint)."""
    resp = await _get_client().get("/openapi.json")
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# OpenAPI → MCP tool transform
# ---------------------------------------------------------------------------

# Paths to exclude from tool generation
_EXCLUDE_PATHS = {
    "/openapi.json",
    "/docs",
    "/redoc",
    "/healthz",
}

_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")


def _clean_tool_name(endpoint_name: str) -> str:
    """Derive a clean MCP tool name from an endpoint function name."""
    name = endpoint_name
    for suffix in ("_endpoint", "_route"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def _tool_name(operation_id: str, path: str, method: str) -> str:
    """Recover the endpoint function name from a FastAPI operationId.

    FastAPI builds operationId as re.sub(r"\\W", "_", f"{name}{path}") plus
    "_{method}", so stripping the path+method suffix recovers the name.
    Falls back to the full operationId if the pattern doesn't match.
    """
    if operation_id:
        suffix = re.sub(r"\W", "_", path) + "_" + method.lower()
        if operation_id.endswith(suffix):
            name = operation_id[: -len(suffix)]
            if name:
                return name
        return operation_id
    # No operationId — derive from method + path
    return re.sub(r"_+", "_", re.sub(r"\W", "_", f"{method.lower()}_{path}")).strip("_")


def _rewrite_component_refs(node: Any) -> Any:
    """Copy the schema, rewriting #/components/schemas/X refs to #/$defs/X."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str) and v.startswith("#/components/schemas/"):
                out[k] = "#/$defs/" + v.rsplit("/", 1)[-1]
            else:
                out[k] = _rewrite_component_refs(v)
        return out
    if isinstance(node, list):
        return [_rewrite_component_refs(v) for v in node]
    return node


def _collect_component_refs(node: Any, out: set) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            out.add(ref.rsplit("/", 1)[-1])
        for v in node.values():
            _collect_component_refs(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_component_refs(v, out)


def _standalone_schema(schema: dict, components: dict) -> dict:
    """Return a self-contained copy of an OpenAPI schema.

    Referenced #/components/schemas entries (transitively) are attached under
    $defs so the result is usable as a JSON Schema without the full spec —
    matching the shape of Pydantic's model_json_schema output.
    """
    needed: set = set()
    _collect_component_refs(schema, needed)
    resolved: set = set()
    queue = list(needed)
    while queue:
        name = queue.pop()
        if name in resolved:
            continue
        resolved.add(name)
        comp = components.get(name)
        if isinstance(comp, dict):
            nested: set = set()
            _collect_component_refs(comp, nested)
            queue.extend(nested - resolved)

    out = _rewrite_component_refs(schema)
    if resolved:
        defs = {n: _rewrite_component_refs(components[n]) for n in resolved if n in components}
        if defs:
            out["$defs"] = defs
    return out


def _has_file_field(schema: dict, components: dict, _depth: int = 0) -> bool:
    """True if a form schema (or its $ref'd components) contains a binary field."""
    if _depth > 10 or not isinstance(schema, dict):
        return False
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        comp = components.get(ref.rsplit("/", 1)[-1])
        return _has_file_field(comp, components, _depth + 1) if isinstance(comp, dict) else False
    if schema.get("format") == "binary" or schema.get("contentMediaType"):
        return True
    for v in schema.values():
        if _has_file_field(v, components, _depth + 1):
            return True
    return False


async def discover_tools(spec: Optional[dict] = None) -> list[dict]:
    """Build MCP tool definitions from the backend OpenAPI spec.

    Each tool dict has: name, description, inputSchema, and private fields
    (_method, _path, _body_kind, _path_params, _query_params) used by call_tool.
    Pass `spec` to inject a spec document (tests); otherwise it is fetched
    from the backend.
    """
    if spec is None:
        spec = await _fetch_openapi()

    components = spec.get("components", {}).get("schemas", {})
    tools: list[dict] = []
    seen_names: dict[str, int] = {}

    for path, path_item in (spec.get("paths") or {}).items():
        if path in _EXCLUDE_PATHS or not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method = method.upper()
            if method not in _HTTP_METHODS or not isinstance(operation, dict):
                continue

            name = _clean_tool_name(_tool_name(operation.get("operationId", ""), path, method))
            # Dedup: if the same name appears for different routes, suffix with method
            if name in seen_names:
                seen_names[name] += 1
                name = f"{name}_{method.lower()}"
            else:
                seen_names[name] = 1

            summary = operation.get("summary") or ""
            op_desc = operation.get("description") or ""
            if summary and op_desc:
                description = f"{summary}: {op_desc[:200]}"
            else:
                description = summary or op_desc or f"{method} {path}"

            # Parameters (path + query)
            properties: dict[str, Any] = {}
            required: list[str] = []
            path_params: list[str] = []
            query_params: list[str] = []

            for p in operation.get("parameters", []) or []:
                if not isinstance(p, dict):
                    continue
                loc = p.get("in")
                pname = p.get("name")
                if not pname or loc not in ("path", "query"):
                    continue
                pschema = p.get("schema") or {}
                prop: dict[str, Any] = {
                    "description": p.get("description") or f"{'Path' if loc == 'path' else 'Query'} parameter: {pname}"
                }
                for key in ("type", "default", "enum", "format", "items"):
                    if key in pschema:
                        prop[key] = pschema[key]
                if "type" not in prop:
                    prop["type"] = "string"
                properties[pname] = prop
                if loc == "path":
                    path_params.append(pname)
                    required.append(pname)
                else:
                    query_params.append(pname)
                    if p.get("required"):
                        required.append(pname)

            # Request body
            body_kind: Optional[str] = None
            request_body = operation.get("requestBody") or {}
            content = request_body.get("content") or {}
            if "application/json" in content:
                body_schema = _standalone_schema(content["application/json"].get("schema") or {}, components)
                body_schema.setdefault("description", "Request body")
                properties["body"] = body_schema
                body_kind = "json"
            else:
                form_ct = next(
                    (ct for ct in ("application/x-www-form-urlencoded", "multipart/form-data") if ct in content),
                    None,
                )
                if form_ct:
                    form_schema = content[form_ct].get("schema") or {}
                    if _has_file_field(form_schema, components):
                        continue  # File uploads can't be represented as JSON tool args
                    body_schema = _standalone_schema(form_schema, components)
                    body_schema.setdefault("type", "object")
                    body_schema.setdefault("description", "Form fields")
                    properties["body"] = body_schema
                    body_kind = "form"

            if body_kind and request_body.get("required", False):
                required.append("body")

            tools.append({
                "name": name,
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
                "_method": method,
                "_path": path,
                "_body_kind": body_kind,
                "_path_params": path_params,
                "_query_params": query_params,
            })

    return tools


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

async def call_tool(tool: dict, args: dict) -> tuple[str, bool]:
    """Execute a tool by forwarding the request to the backend API.

    Returns (text, is_error). text is the response body as a JSON string
    (or plain text). is_error is True when the backend returned >= 400.
    """
    client = _get_client()
    method = tool["_method"]
    path = tool["_path"]
    path_params = tool.get("_path_params", [])
    query_params = tool.get("_query_params", [])
    body_kind = tool.get("_body_kind")

    # Substitute path params
    url_path = path
    for pp in path_params:
        val = args.get(pp)
        if val is not None:
            url_path = url_path.replace(f"{{{pp}}}", str(val))

    # Collect query params (exclude path params and body)
    params = {}
    for qp in query_params:
        val = args.get(qp)
        if val is not None:
            params[qp] = val

    # Body
    json_body = None
    form_body = None
    if body_kind and "body" in args:
        if body_kind == "form":
            form_body = args["body"]
        else:
            json_body = args["body"]

    # Headers
    headers = {
        "Authorization": f"Bearer {_get_service_jwt()}",
    }
    service_token = _get_service_token()
    if service_token:
        headers["X-MCP-Service-Token"] = service_token

    try:
        resp = await client.request(
            method,
            url_path,
            params=params or None,
            json=json_body,
            data=form_body,
            headers=headers,
        )
    except Exception as e:
        logger.exception("Tool call failed: %s %s", method, url_path)
        return json.dumps({"error": str(e)}), True

    # Parse response
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            text = json.dumps(resp.json(), indent=2, default=str)
        except Exception:
            text = resp.text
    else:
        text = resp.text

    is_error = resp.status_code >= 400
    if is_error:
        # Prefix with status code for clarity
        text = f"HTTP {resp.status_code}: {text}"

    return text, is_error


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
