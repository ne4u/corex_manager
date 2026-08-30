"""Tool discovery and execution — auto-generates MCP tools from the backend v1 router.

Introspects the backend FastAPI app's routes and builds one MCP tool per
APIRoute+method. Tools are executed in-process via an httpx ASGI transport
with a service admin JWT, so all route logic, validation, and audit
middleware run exactly as they would for a normal HTTP request.
"""
import json
import logging
import os
import time
import typing
from typing import Any, Optional

from fastapi.datastructures import UploadFile

import httpx
from fastapi.routing import APIRoute

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Service JWT management
# ---------------------------------------------------------------------------

_service_jwt: Optional[str] = None
_service_jwt_at: float = 0.0
_JWT_TTL = 20 * 3600  # 20 hours — refresh before the 24h expiry


def _get_service_jwt() -> str:
    """Mint (or return cached) a service admin JWT for in-process calls."""
    global _service_jwt, _service_jwt_at
    now = time.time()
    if _service_jwt and (now - _service_jwt_at) < _JWT_TTL:
        return _service_jwt
    from app.core.security import create_access_token
    from datetime import timedelta
    _service_jwt = create_access_token(
        {"sub": "admin"},
        expires_delta=timedelta(hours=24),
    )
    _service_jwt_at = now
    return _service_jwt


def _get_service_token() -> Optional[str]:
    """Return the MCP_SERVICE_TOKEN for rate-limit bypass, if configured."""
    return os.environ.get("MCP_SERVICE_TOKEN")


# ---------------------------------------------------------------------------
# Route introspection
# ---------------------------------------------------------------------------

def _walk_routes(routes, prefix=""):
    """Recursively walk app routes, yielding (full_path, APIRoute) pairs.

    Handles FastAPI 0.141+ _IncludedRouter wrappers which nest sub-routers.
    """
    out = []
    for x in routes:
        t = type(x).__name__
        if isinstance(x, APIRoute):
            out.append((prefix + x.path, x))
        elif t == "_IncludedRouter":
            p = getattr(x.include_context, "prefix", "") or ""
            out += _walk_routes(x.original_router.routes, prefix + p)
        elif hasattr(x, "routes"):
            out += _walk_routes(x.routes, prefix)
    return out


# Paths to exclude from tool generation
_EXCLUDE_PATHS = {
    "/openapi.json",
    "/docs",
    "/redoc",
    "/healthz",
}


def _clean_tool_name(endpoint_name: str) -> str:
    """Derive a clean MCP tool name from an endpoint function name."""
    name = endpoint_name
    for suffix in ("_endpoint", "_route"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def _build_body_schema(annotation) -> dict | None:
    """Build a JSON Schema for a body parameter annotation.

    Handles Pydantic models, lists of models, primitives, and dicts.
    Returns None if the body can't be represented as JSON (e.g. UploadFile).
    """
    # Pydantic model
    if hasattr(annotation, "model_json_schema"):
        try:
            schema = annotation.model_json_schema()
            # Sanitize: model_json_schema() can contain non-JSON-serializable
            # objects (e.g. ModelField instances in $defs for some models).
            # Round-trip through JSON with default=str to coerce any stragglers.
            schema = json.loads(json.dumps(schema, default=str))
            schema["description"] = f"Request body ({annotation.__name__})"
            return schema
        except Exception as e:
            logger.warning("Failed to get schema for %s: %s", annotation, e)
            return {"type": "object", "description": f"Request body ({annotation.__name__})"}

    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)

    # List of Pydantic models
    if origin is list and args and hasattr(args[0], "model_json_schema"):
        try:
            item_schema = args[0].model_json_schema()
            item_schema = json.loads(json.dumps(item_schema, default=str))
            return {
                "type": "array",
                "items": item_schema,
                "description": f"Request body (list of {args[0].__name__})",
            }
        except Exception:
            return {"type": "array", "description": "Request body (list)"}

    # Optional[X] — unwrap to inner type
    if origin is typing.Union:
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return _build_body_schema(non_none[0])

    # Primitives
    if annotation is str:
        return {"type": "string", "description": "Request body (string)"}
    if annotation is int:
        return {"type": "integer", "description": "Request body (integer)"}
    if annotation is float:
        return {"type": "number", "description": "Request body (number)"}
    if annotation is bool:
        return {"type": "boolean", "description": "Request body (boolean)"}
    if annotation is dict:
        return {"type": "object", "description": "Request body (object)"}

    # Fallback
    return {"type": "object", "description": f"Request body ({annotation})"}


def discover_tools() -> list[dict]:
    """Introspect the backend app and return a list of MCP tool definitions.

    Each tool dict has: name, description, inputSchema, and private fields
    (_method, _path, _has_body) used by call_tool.
    """
    from app.main import app

    all_routes = _walk_routes(app.routes)
    tools: list[dict] = []
    seen_names: dict[str, int] = {}

    for full_path, route in all_routes:
        # Skip excluded paths
        if full_path in _EXCLUDE_PATHS:
            continue
        # Skip non-API routes (static mounts have no methods)
        if not route.methods:
            continue

        for method in sorted(route.methods):
            if method in ("HEAD", "OPTIONS"):
                continue

            name = _clean_tool_name(route.endpoint.__name__)
            # Dedup: if the same name appears for different routes, suffix with method
            if name in seen_names:
                seen_names[name] += 1
                name = f"{name}_{method.lower()}"
            else:
                seen_names[name] = 1

            d = route.dependant
            description = (
                route.summary
                or route.description
                or f"{method} {full_path}"
            )
            if route.description and route.summary:
                description = f"{route.summary}: {route.description[:200]}"

            # Build input schema
            properties: dict[str, Any] = {}
            required: list[str] = []

            # Path params
            for p in d.path_params:
                prop = {"type": "string", "description": f"Path parameter: {p.name}"}
                properties[p.name] = prop
                required.append(p.name)

            # Query params
            for q in d.query_params:
                prop: dict[str, Any] = {"description": f"Query parameter: {q.name}"}
                # Infer type from default. Pydantic uses a sentinel (PydanticUndefined)
                # for "no default" — treat it like None.
                default = q.default
                _is_undefined = default is None or callable(default) or \
                    type(default).__name__ == "PydanticUndefinedType"
                if not _is_undefined:
                    if isinstance(default, bool):
                        prop["type"] = "boolean"
                    elif isinstance(default, int):
                        prop["type"] = "integer"
                    elif isinstance(default, float):
                        prop["type"] = "number"
                    else:
                        prop["type"] = "string"
                    prop["default"] = default
                else:
                    prop["type"] = "string"
                if q.field_info.is_required():
                    required.append(q.name)
                properties[q.name] = prop

            # Body param (first body model)
            has_body = bool(d.body_params)
            if has_body:
                bp = d.body_params[0]
                model_cls = bp.field_info.annotation

                # Skip file-upload tools (can't be sent as JSON)
                if model_cls is UploadFile or (
                    typing.get_origin(model_cls) is list
                    and UploadFile in (typing.get_args(model_cls) or ())
                ):
                    continue  # Skip this method — can't represent file upload as JSON

                body_schema = _build_body_schema(model_cls)
                if body_schema is not None:
                    properties["body"] = body_schema
                    if bp.field_info.is_required():
                        required.append("body")
                    has_body = True
                else:
                    has_body = False

            input_schema = {
                "type": "object",
                "properties": properties,
                "required": required,
            }

            tools.append({
                "name": name,
                "description": description,
                "inputSchema": input_schema,
                "_method": method,
                "_path": full_path,
                "_has_body": has_body,
                "_path_params": [p.name for p in d.path_params],
                "_query_params": [q.name for q in d.query_params],
            })

    return tools


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

# Lazily-created ASGI client (in-process)
_asgi_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    global _asgi_client
    if _asgi_client is None:
        from app.main import app
        _asgi_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://in-process",
            timeout=60.0,
        )
    return _asgi_client


async def call_tool(tool: dict, args: dict) -> tuple[str, bool]:
    """Execute a tool against the backend in-process.

    Returns (text, is_error). text is the response body as a JSON string
    (or plain text). is_error is True when the backend returned >= 400.
    """
    client = _get_client()
    method = tool["_method"]
    path = tool["_path"]
    path_params = tool.get("_path_params", [])
    query_params = tool.get("_query_params", [])
    has_body = tool.get("_has_body", False)

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
    if has_body and "body" in args:
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
    global _asgi_client
    if _asgi_client is not None:
        await _asgi_client.aclose()
        _asgi_client = None
