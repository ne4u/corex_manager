"""Policy engine for MCP Gateway — first-match-wins Security Rules evaluation.

Loads policies from the config bundle, compiles expressions to ASTs, and
evaluates them against an MCP context. Actions: allow, deny, skip_dlp,
skip_ratelimit. Default if no match: deny (fail closed).

JSON-RPC error for deny: -32010 "policy denied" (HTTP 200 with RPC error).
"""
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

MCP_POLICY_DENIED = -32010

# Import expression module (try relative, fall back to absolute for standalone)
try:
    from .expression import parse_expression, evaluate as eval_ast, build_mcp_context
except ImportError:
    from expression import parse_expression, evaluate as eval_ast, build_mcp_context


class PolicyResult:
    """Result of policy evaluation."""
    def __init__(self, action: str, rule_name: str = "", skip_dlp: bool = False, skip_ratelimit: bool = False):
        self.action = action  # allow | deny | skip_dlp | skip_ratelimit
        self.rule_name = rule_name
        self.skip_dlp = skip_dlp
        self.skip_ratelimit = skip_ratelimit

    @property
    def denied(self) -> bool:
        return self.action == "deny"

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "rule": self.rule_name,
            "skip_dlp": self.skip_dlp,
            "skip_ratelimit": self.skip_ratelimit,
        }


# Compiled policy: {name, priority, ast, action, log, no_log}
_compiled_policies: list[dict] = []
_has_policies_configured = False  # True if config bundle had any policies (even disabled)


def load_policies(config: dict) -> None:
    """Load and compile policies from the config bundle.

    Policies are sorted by priority (ascending). Each policy's expression
    is parsed into an AST for fast evaluation.
    """
    global _compiled_policies, _has_policies_configured

    raw_policies = config.get("policies", [])
    _has_policies_configured = len(raw_policies) > 0
    compiled = []

    for p in raw_policies:
        if not p.get("enabled", True):
            continue

        # Use pre-compiled AST if available, else parse
        ast = p.get("expression_ast")
        if ast is None:
            try:
                ast = parse_expression(p["expression"])
            except ValueError as e:
                logger.error("Failed to parse policy %s: %s", p.get("name"), e)
                continue

        compiled.append({
            "name": p["name"],
            "priority": p.get("priority", 0),
            "ast": ast,
            "action": p.get("action", "allow"),
            "log": p.get("log", True),
            "no_log": p.get("no_log", False),
        })

    # Sort by priority (ascending = first match wins)
    compiled.sort(key=lambda x: x["priority"])
    _compiled_policies = compiled
    logger.info("Loaded %d MCP policies (has_config: %s)", len(compiled), _has_policies_configured)


def get_policies() -> list[dict]:
    """Return the currently compiled policies."""
    return list(_compiled_policies)


def evaluate_policy(ctx: dict) -> PolicyResult:
    """Evaluate policies against the MCP context. First match wins.

    If no policies are configured at all, default to allow (open gateway).
    If policies exist but none match, deny (fail closed).
    """
    # No policies configured at all → open gateway (backward compat)
    if not _has_policies_configured:
        return PolicyResult(action="allow", rule_name="<default: no policies>")

    for policy in _compiled_policies:
        try:
            if eval_ast(policy["ast"], ctx):
                action = policy["action"]
                result = PolicyResult(
                    action=action,
                    rule_name=policy["name"],
                    skip_dlp=action == "skip_dlp",
                    skip_ratelimit=action == "skip_ratelimit",
                )
                if policy.get("log", True) and not policy.get("no_log", False):
                    logger.info("Policy %s %s on tool=%s server=%s identity=%s",
                                policy["name"], action,
                                ctx.get("mcp.tool", ""),
                                ctx.get("mcp.server", ""),
                                ctx.get("mcp.identity", ""))
                return result
        except Exception as e:
            logger.error("Error evaluating policy %s: %s", policy["name"], e)
            continue

    # Policies exist but no match → deny (fail closed)
    return PolicyResult(action="deny", rule_name="<default: no match>")


def check_tool_access(
    method: str,
    tool_name: str,
    server_namespace: str,
    auth_ctx,
    args: Optional[dict] = None,
    ip_src: str = "",
) -> PolicyResult:
    """Convenience wrapper: build context and evaluate for a tools/call."""
    ctx = build_mcp_context(
        method=method,
        tool=tool_name,
        server=server_namespace,
        identity_name=auth_ctx.name,
        identity_kind=auth_ctx.kind,
        team_slug=str(auth_ctx.team_id),
        args=args,
        claims=auth_ctx.claims,
        ip_src=ip_src,
    )
    return evaluate_policy(ctx)


def check_resource_access(
    method: str,
    resource_uri: str,
    server_namespace: str,
    auth_ctx,
    ip_src: str = "",
) -> PolicyResult:
    """Convenience wrapper for resources/read."""
    ctx = build_mcp_context(
        method=method,
        resource=resource_uri,
        server=server_namespace,
        identity_name=auth_ctx.name,
        identity_kind=auth_ctx.kind,
        team_slug=str(auth_ctx.team_id),
        claims=auth_ctx.claims,
        ip_src=ip_src,
    )
    return evaluate_policy(ctx)


def check_prompt_access(
    method: str,
    prompt_name: str,
    server_namespace: str,
    auth_ctx,
    ip_src: str = "",
) -> PolicyResult:
    """Convenience wrapper for prompts/get."""
    ctx = build_mcp_context(
        method=method,
        prompt=prompt_name,
        server=server_namespace,
        identity_name=auth_ctx.name,
        identity_kind=auth_ctx.kind,
        team_slug=str(auth_ctx.team_id),
        claims=auth_ctx.claims,
        ip_src=ip_src,
    )
    return evaluate_policy(ctx)


def filter_tool_list(
    tools: list[dict],
    namespace: str,
    auth_ctx,
    ip_src: str = "",
) -> list[dict]:
    """Filter a tool list using policy evaluation at list time.

    Clients must not see tools they cannot invoke.
    """
    result = []
    for tool in tools:
        tool_name = tool.get("name", "")
        ctx = build_mcp_context(
            method="tools/call",
            tool=tool_name,
            server=namespace,
            identity_name=auth_ctx.name,
            identity_kind=auth_ctx.kind,
            team_slug=str(auth_ctx.team_id),
            claims=auth_ctx.claims,
            ip_src=ip_src,
        )
        pr = evaluate_policy(ctx)
        if pr.allowed or pr.action in ("skip_dlp", "skip_ratelimit"):
            result.append(tool)
    return result


def filter_resource_list(
    resources: list[dict],
    namespace: str,
    auth_ctx,
    ip_src: str = "",
) -> list[dict]:
    """Filter a resource list using policy evaluation at list time."""
    result = []
    for res in resources:
        uri = res.get("uri", "")
        ctx = build_mcp_context(
            method="resources/read",
            resource=uri,
            server=namespace,
            identity_name=auth_ctx.name,
            identity_kind=auth_ctx.kind,
            team_slug=str(auth_ctx.team_id),
            claims=auth_ctx.claims,
            ip_src=ip_src,
        )
        pr = evaluate_policy(ctx)
        if pr.allowed or pr.action in ("skip_dlp", "skip_ratelimit"):
            result.append(res)
    return result


def filter_prompt_list(
    prompts: list[dict],
    namespace: str,
    auth_ctx,
    ip_src: str = "",
) -> list[dict]:
    """Filter a prompt list using policy evaluation at list time."""
    result = []
    for prompt in prompts:
        name = prompt.get("name", "")
        ctx = build_mcp_context(
            method="prompts/get",
            prompt=name,
            server=namespace,
            identity_name=auth_ctx.name,
            identity_kind=auth_ctx.kind,
            team_slug=str(auth_ctx.team_id),
            claims=auth_ctx.claims,
            ip_src=ip_src,
        )
        pr = evaluate_policy(ctx)
        if pr.allowed or pr.action in ("skip_dlp", "skip_ratelimit"):
            result.append(prompt)
    return result
