---
name: corex-manager
description: Manage coreX Manager (HAProxy + WAF control plane) via MCP tools
argument-hint: "[task]"
---

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

## Note

The same guidance is available as the `corex-manager-guide` MCP prompt —
agents that support MCP prompts can fetch it via `prompts/get` instead of
loading this file.
