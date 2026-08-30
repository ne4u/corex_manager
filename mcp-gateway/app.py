"""MCP Gateway — main FastAPI application (Phase 1).

Implements:
- GET /healthz
- POST /mcp — Streamable HTTP JSON-RPC endpoint
- GET /mcp — SSE listen (405 in v1)
- GET /.well-known/oauth-protected-resource (RFC 9728)
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

try:
    from .config_loader import is_configured, get_config, get_allowed_origins
    from .protocol import handle_mcp_post, handle_mcp_get
    from .upstream import close_all_clients
    from .catalog import get_worker, clear_all_catalogs
    from .policy import load_policies
    from .dlp import load_dlp_rules
    from .guardrails import load_guardrails
    from .skills import load_skills
    from .health import get_health_checker
except ImportError:
    from config_loader import is_configured, get_config, get_allowed_origins
    from protocol import handle_mcp_post, handle_mcp_get
    from upstream import close_all_clients
    from catalog import get_worker, clear_all_catalogs
    from policy import load_policies
    from dlp import load_dlp_rules
    from guardrails import load_guardrails
    from skills import load_skills
    from health import get_health_checker

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("MCP Gateway starting")
    # Load policies, DLP rules, guardrails, and skills from config bundle
    config = get_config()
    if config and "policies" in config:
        load_policies(config)
    if config and "dlp_rules" in config:
        load_dlp_rules(config)
    if config and "guardrails" in config:
        load_guardrails(config)
    if config and "skills" in config:
        load_skills(config)
    # Start catalog worker for periodic upstream catalog refresh
    worker = get_worker()
    worker.start()
    # Start health checker
    health_checker = get_health_checker()
    await health_checker.start()
    yield
    logger.info("MCP Gateway shutting down")
    await health_checker.stop()
    await worker.stop()
    await close_all_clients()
    clear_all_catalogs()


app = FastAPI(
    title="MCP Gateway",
    description="Streamable HTTP MCP gateway with federation, policy, DLP, and guardrails.",
    version="0.7.0",
    lifespan=lifespan,
)

# --- Security headers middleware ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# --- CORS preflight handling ---
@app.api_route("/mcp", methods=["OPTIONS"])
async def mcp_options(request: Request):
    origin = request.headers.get("origin", "")
    allowed = get_allowed_origins()
    if origin and origin in allowed:
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Session-Id",
                "Access-Control-Max-Age": "3600",
            },
        )
    return Response(status_code=403)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "configured": is_configured()}


@app.api_route("/mcp", methods=["POST"])
async def mcp_post(request: Request):
    return await handle_mcp_post(request)


@app.api_route("/mcp", methods=["GET"])
async def mcp_get(request: Request):
    return await handle_mcp_get(request)


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    """RFC 9728 Protected Resource Metadata."""
    host = request.headers.get("host", "")
    scheme = request.headers.get("x-forwarded-proto", "https")
    base_url = f"{scheme}://{host}"
    return {
        "resource": f"{base_url}/mcp",
        "authorization_servers": [],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }
