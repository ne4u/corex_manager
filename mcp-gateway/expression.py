"""Expression engine for MCP Gateway — evaluator and MCP context builder.

The tokenizer, parser, AST, and DNF normalizer live in ``shared.expression_core``
and are imported here. This module provides the MCP-specific field resolver,
evaluator context builder, and re-exports the parse/evaluate functions.

MCP field map (gateway evaluator only):
    mcp.method            string   # tools/call, resources/read, ...
    mcp.server            string   # namespace
    mcp.tool              string   # virtual (namespaced) tool name
    mcp.resource          string   # virtual (wrapped) resource URI
    mcp.prompt            string   # virtual (namespaced) prompt name
    mcp.identity          string   # identity.name or JWT sub
    mcp.identity.kind     string   # pat | jwt
    mcp.team              string   # team.slug
    mcp.arg["path"]       string   # JSONPath-lite on tools/call arguments (stringified)
    auth.claim["key"]     string   # JWT claims
    auth.claim.sub        string
    auth.claim.iss        string
    auth.claim.aud        string
    ip.src                string   # from X-Forwarded-For
"""
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Import shared expression engine
# In Docker, PYTHONPATH=/app makes 'shared' importable.
# For local dev, add the project root to sys.path.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from shared.expression_core import (
    parse_expression,
    validate_expression,
    evaluate,
    evaluate_leaf,
    resolve_field_value,
)


# Re-export for backward compatibility
_resolve_field_value = resolve_field_value
_evaluate_leaf = evaluate_leaf


# ---------------------------------------------------------------------------
# MCP context builder
# ---------------------------------------------------------------------------

def build_mcp_context(
    method: str = "",
    server: str = "",
    tool: str = "",
    resource: str = "",
    prompt: str = "",
    identity_name: str = "",
    identity_kind: str = "",
    team_slug: str = "",
    args: Optional[dict] = None,
    claims: Optional[dict] = None,
    ip_src: str = "",
    list_resolver=None,
) -> Dict[str, Any]:
    """Build an MCP evaluation context dict from request parameters."""
    ctx: Dict[str, Any] = {
        "mcp.method": method,
        "mcp.server": server,
        "mcp.tool": tool,
        "mcp.resource": resource,
        "mcp.prompt": prompt,
        "mcp.identity": identity_name,
        "mcp.identity.kind": identity_kind,
        "mcp.team": team_slug,
        "mcp.arg": args or {},
        "auth.claim": claims or {},
        "ip.src": ip_src,
    }
    # Flatten common claim fields for dot-path access
    if claims:
        ctx["auth.claim.sub"] = str(claims.get("sub", ""))
        ctx["auth.claim.iss"] = str(claims.get("iss", ""))
        ctx["auth.claim.aud"] = str(claims.get("aud", ""))

    if list_resolver:
        ctx["_list_resolver"] = list_resolver

    return ctx
