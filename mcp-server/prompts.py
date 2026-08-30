"""MCP prompt templates — workflow guidance and the portable skill prompt.

The `corex-manager-guide` prompt is the primary skill-delivery mechanism:
any MCP-compatible client (Devin, Claude Code, Cursor, Windsurf, etc.) can
fetch it via prompts/get and inject the operating instructions into its
conversation, making the skill fully agent-agnostic.
"""
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The portable skill prompt — returned by prompts/get("corex-manager-guide")
# ---------------------------------------------------------------------------

_SKILL_GUIDE = """\
# coreX Manager — Operating Guide

You are managing **coreX Manager** (an HAProxy + WAF control plane) via MCP tools.
The MCP server exposes the full backend REST API as MCP tools, plus read-only
resources and workflow prompts.

## Tool Naming

- **Direct connection** (to the MCP server): tool names are bare, e.g. `list_backends`,
  `create_backend`, `apply_config`.
- **Via the mcp-gateway**: tool names are prefixed with the namespace, e.g.
  `corex-manager__list_backends`, `corex-manager__apply_config`.

Always call `tools/list` first to discover the exact tool names and their input schemas.

## Key Workflows

### Inspect current state
1. `list_listeners` — see all listeners (frontend bind points).
2. `list_backends` — see all backend pools and their servers.
3. Read `corex://config/status` — check if there are unapplied changes.
4. Read `corex://system/stats` — HAProxy process info and connection counts.

### Make a change (e.g. add a backend server)
1. `create_backend` (if needed) → `add_server` to add a server to a backend.
2. Create a backend rule to route a listener to the backend (`create_backend_rule`).
3. **Always confirm with the user** before applying.
4. `apply_config` — generate and apply the HAProxy config.
5. Verify: read `corex://config/status` (should show "applied"), check `corex://system/stats`.

### WAF / Security
- `list_waf_rules` / `create_waf_rule` — manage Coraza WAF rules.
- Security Lists: `list_network_lists` / `create_network_list` / add entries —
  IP/CIDR, ASN, GeoIP, JA4 fingerprint lists.
- Security Rules: `list_security_rules` / `create_security_rule` — reference
  security lists in request-matching rules.
- Read `corex://audit-events` to see recent config mutations.

### Rollback
- `list_config_snapshots` — see applied config history.
- `rollback_config_snapshot` — roll back to a previous snapshot.
- `revert_config` — revert to the last applied config (discards pending changes).
- **Always confirm with the user** before rollback/revert — these are destructive.

## Safety Rules

1. **Confirm before destructive operations**: `delete_*`, `revert_config`,
   `rollback_config_snapshot`, `apply_config`. Describe what will happen and ask.
2. **Never delete a resource the user didn't explicitly ask to delete.**
3. **Always apply config after making changes** — changes are pending until
   `apply_config` is called. Use `corex://config/status` to verify.
4. **Check dependencies before deleting** — e.g. a backend referenced by a
   listener's backend rule will cause config generation errors.

## Resources (read-only)

- `corex://config/preview` — preview the generated HAProxy config.
- `corex://config/status` — applied vs pending state.
- `corex://config/snapshots` — config history.
- `corex://system/stats` — HAProxy process stats.
- `corex://system/haproxy-stats` — frontend/backend/server metrics.
- `corex://audit-events` — recent audit log.
- `corex://health` — backend health.

## Other Prompts

- `diagnose-traffic` — diagnose traffic/routing issues.
- `security-review` — review the security configuration.
- `add-backend` — guided backend creation workflow.
- `waf-investigation` — investigate WAF events and tune rules.
- `apply-and-verify` — apply pending config and verify the result.
"""


# ---------------------------------------------------------------------------
# Workflow prompts
# ---------------------------------------------------------------------------

_PROMPTS = [
    {
        "name": "corex-manager-guide",
        "description": "Full operating guide for coreX Manager via MCP tools. "
                       "Fetch this to learn how to use the platform's tools, "
                       "resources, and safety rules.",
        "arguments": [],
        "_render": lambda args: _SKILL_GUIDE,
    },
    {
        "name": "diagnose-traffic",
        "description": "Diagnose traffic or routing issues by inspecting listeners, "
                       "backends, and HAProxy stats.",
        "arguments": [
            {
                "name": "symptom",
                "description": "What the user is observing (e.g. '503 errors on /api')",
                "required": True,
            },
        ],
        "_render": lambda args: (
            f"Diagnose this traffic issue: {args.get('symptom', 'unspecified')}\n\n"
            "Steps:\n"
            "1. Call `list_listeners` to see all frontend bind points.\n"
            "2. Call `list_backends` to see backend pools and server status.\n"
            "3. Call `list_backend_rules` to check listener→backend routing.\n"
            "4. Read `corex://system/haproxy-stats` for frontend/backend metrics.\n"
            "5. Read `corex://system/stats` for HAProxy process health.\n"
            "6. Check for any down servers (status != UP) or zero-active-backend listeners.\n"
            "7. If WAF is involved, call `list_waf_rules` and check recent WAF metrics.\n"
            "8. Report findings with specific listener/backend/server names.\n"
        ),
    },
    {
        "name": "security-review",
        "description": "Review the current security configuration (WAF rules, "
                       "security lists, security rules, rate limits).",
        "arguments": [],
        "_render": lambda args: (
            "Perform a security configuration review:\n\n"
            "1. Call `list_waf_rules` — review enabled WAF rules and their actions.\n"
            "2. Call `list_security_rules` — review request-matching security rules.\n"
            "3. Call `list_network_lists`, `list_asn_lists`, `list_geo_lists`, "
            "`list_ja4_lists` — review security lists and their entry counts.\n"
            "4. Call `list_rate_limits` — review rate limiting configuration.\n"
            "5. Call `list_headers` — review security headers (HSTS, CSP, etc.).\n"
            "6. Read `corex://audit-events` — check for recent security-relevant changes.\n"
            "7. Report: what's protected, what's missing, and recommendations.\n"
        ),
    },
    {
        "name": "add-backend",
        "description": "Guided workflow to add a new backend pool with servers and "
                       "wire it to a listener.",
        "arguments": [
            {
                "name": "name",
                "description": "Backend name (e.g. 'my-app')",
                "required": True,
            },
            {
                "name": "servers",
                "description": "Comma-separated server addresses (e.g. '10.0.0.1:8080,10.0.0.2:8080')",
                "required": True,
            },
        ],
        "_render": lambda args: (
            f"Add a new backend pool and wire it to a listener:\n\n"
            f"Backend name: {args.get('name', '?')}\n"
            f"Servers: {args.get('servers', '?')}\n\n"
            "Steps:\n"
            "1. Call `create_backend` with the name.\n"
            "2. For each server address, call `add_server` with the backend ID "
            "and host:port.\n"
            "3. Call `list_listeners` to find the listener to route through.\n"
            "4. Call `create_backend_rule` to route the listener to the new backend.\n"
            "5. **Confirm with the user** before applying.\n"
            "6. Call `apply_config` to generate and apply the HAProxy config.\n"
            "7. Read `corex://config/status` to verify it was applied.\n"
        ),
    },
    {
        "name": "waf-investigation",
        "description": "Investigate WAF events and tune rules — check recent WAF "
                       "metrics, identify false positives, adjust rules.",
        "arguments": [
            {
                "name": "concern",
                "description": "What the user is concerned about (e.g. 'legitimate traffic being blocked')",
                "required": False,
            },
        ],
        "_render": lambda args: (
            f"Investigate WAF events and tune rules.\n"
            f"Concern: {args.get('concern', 'general review')}\n\n"
            "Steps:\n"
            "1. Call `list_waf_rules` — see all WAF rules and their actions.\n"
            "2. Read `corex://system/haproxy-stats` — check WAF-related metrics.\n"
            "3. If investigating false positives, look for rules with action 'deny' "
            "that may be too broad.\n"
            "4. To tune a rule, call `update_waf_rule` with adjusted conditions "
            "(e.g. narrow the pattern, change action to 'log' first).\n"
            "5. **Confirm with the user** before applying.\n"
            "6. Call `apply_config` to apply the changes.\n"
            "7. Monitor: read `corex://audit-events` for the change record.\n"
        ),
    },
    {
        "name": "apply-and-verify",
        "description": "Apply pending config changes and verify the result — "
                       "check apply status, HAProxy stats, and health.",
        "arguments": [
            {
                "name": "comment",
                "description": "Optional comment for the config snapshot",
                "required": False,
            },
        ],
        "_render": lambda args: (
            f"Apply pending config and verify:\n\n"
            "1. Read `corex://config/status` — confirm there are pending changes.\n"
            "2. **Confirm with the user** that they want to apply.\n"
            f"3. Call `apply_config`"
            + (f" with comment: {args.get('comment')}" if args.get("comment") else "")
            + ".\n"
            "4. Read `corex://config/status` — should now show 'applied'.\n"
            "5. Read `corex://system/stats` — verify HAProxy is healthy.\n"
            "6. Read `corex://health` — verify backend health.\n"
            "7. If anything looks wrong, call `list_config_snapshots` and "
            "`rollback_config_snapshot` to the previous good config (after confirming).\n"
        ),
    },
]


def list_prompts() -> list[dict]:
    """Return MCP prompt descriptors for prompts/list."""
    return [
        {
            "name": p["name"],
            "description": p["description"],
            "arguments": p["arguments"],
        }
        for p in _PROMPTS
    ]


def get_prompt(name: str, args: dict[str, Any] | None = None) -> dict | None:
    """Render a prompt by name. Returns the MCP prompts/get response or None."""
    p = next((x for x in _PROMPTS if x["name"] == name), None)
    if not p:
        return None
    text = p["_render"](args or {})
    return {
        "description": p["description"],
        "messages": [
            {
                "role": "user",
                "content": {"type": "text", "text": text},
            }
        ],
    }
