"""MCP self-registration — idempotently registers the coreX Manager MCP server
and skill into the mcp-gateway's database tables.

Called from main.py lifespan when MCP_GATEWAY_ENABLED is True. Ensures:
1. A "platform" team exists.
2. An McpServer row (namespace "corex-manager") points at the mcp-server container.
3. An McpSkill ("corex-manager") with a published version containing the skill guide.
4. The config bundle is regenerated so the gateway picks up the changes.
"""
import hashlib
import logging
import os
import secrets as _secrets

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.mcp import Team, McpServer, McpSkill, McpSkillVersion
from .mcp_secrets import encrypt_secret, has_secrets_key

logger = logging.getLogger(__name__)
settings = get_settings()

NAMESPACE = "corex-manager"
SERVER_NAME = "corex-manager"
DISPLAY_NAME = "coreX Manager"
SKILL_NAME = "corex-manager"
TEAM_NAME = "platform"
TEAM_SLUG = "platform"


# ---------------------------------------------------------------------------
# Skill content — mirrors .devin/skills/corex-manager/SKILL.md
# ---------------------------------------------------------------------------

SKILL_FRONTMATTER = {
    "name": SKILL_NAME,
    "description": "Manage coreX Manager (HAProxy + WAF control plane) via MCP tools",
    "argument-hint": "[task]",
}

SKILL_BODY = """\
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


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ensure_self_registration(db: Session) -> None:
    """Idempotently register the coreX Manager MCP server and skill.

    Guarded by MCP_GATEWAY_ENABLED and MCP_SELF_REGISTER settings.
    Requires MCP_SECRETS_KEY to be set (for encrypting the auth secret).
    """
    if not settings.MCP_GATEWAY_ENABLED:
        logger.debug("MCP gateway not enabled — skipping self-registration")
        return
    if not getattr(settings, "MCP_SELF_REGISTER", True):
        logger.debug("MCP_SELF_REGISTER is False — skipping self-registration")
        return
    if not has_secrets_key():
        logger.warning(
            "MCP_SECRETS_KEY not configured — cannot self-register coreX Manager "
            "MCP server (the gateway needs it to encrypt the auth secret). "
            "Set MCP_SECRETS_KEY to enable self-registration."
        )
        return

    # 1. Ensure platform team
    team = db.query(Team).filter(Team.slug == TEAM_SLUG).first()
    if not team:
        team = Team(name=TEAM_NAME, slug=TEAM_SLUG, description="Platform-managed MCP resources")
        db.add(team)
        db.commit()
        db.refresh(team)
        logger.info("Created platform team (id=%d)", team.id)

    # 2. Ensure McpServer row
    mcp_token = os.environ.get("COREX_MCP_TOKEN") or _secrets.token_urlsafe(32)
    server_url = f"http://{settings.MCP_SERVER_INTERNAL_HOST}:{settings.MCP_SERVER_INTERNAL_PORT}/mcp"

    server = db.query(McpServer).filter(McpServer.namespace == NAMESPACE).first()
    if not server:
        server = McpServer(
            team_id=team.id,
            name=SERVER_NAME,
            display_name=DISPLAY_NAME,
            description="coreX Manager control plane — full HAProxy + WAF management via MCP tools.",
            url=server_url,
            enabled=True,
            verify_tls=True,
            auth_type="bearer",
            auth_header="Authorization",
            auth_secret_enc=encrypt_secret(mcp_token),
            timeout_ms=60000,
            max_body_bytes=10485760,
            namespace=NAMESPACE,
            transport_type="streamable_http",
        )
        db.add(server)
        db.commit()
        db.refresh(server)
        logger.info("Registered coreX Manager MCP server (id=%d, namespace=%s)", server.id, NAMESPACE)
    else:
        changed = False
        if server.url != server_url:
            server.url = server_url
            changed = True
        if not server.enabled:
            server.enabled = True
            changed = True
        # Update auth secret if COREX_MCP_TOKEN is set and differs
        if os.environ.get("COREX_MCP_TOKEN"):
            try:
                from .mcp_secrets import decrypt_secret
                existing = decrypt_secret(server.auth_secret_enc) if server.auth_secret_enc else ""
                if existing != mcp_token:
                    server.auth_secret_enc = encrypt_secret(mcp_token)
                    changed = True
            except Exception:
                server.auth_secret_enc = encrypt_secret(mcp_token)
                changed = True
        if changed:
            db.commit()
            logger.info("Updated coreX Manager MCP server registration")

    # 3. Ensure McpSkill + published version
    skill = db.query(McpSkill).filter(McpSkill.name == SKILL_NAME).first()
    if not skill:
        skill = McpSkill(
            team_id=team.id,
            name=SKILL_NAME,
            description="Operating guide for coreX Manager via MCP tools.",
            enabled=True,
            tags=["haproxy", "waf", "load-balancer", "corex"],
        )
        db.add(skill)
        db.commit()
        db.refresh(skill)
        logger.info("Created coreX Manager skill (id=%d)", skill.id)

    # Check if we need a new version (content changed)
    content_hash = _content_hash(SKILL_BODY)
    latest = (
        db.query(McpSkillVersion)
        .filter(McpSkillVersion.skill_id == skill.id)
        .order_by(McpSkillVersion.version.desc())
        .first()
    )

    needs_new_version = (
        not latest
        or latest.body != SKILL_BODY
        or (latest.frontmatter or {}) != SKILL_FRONTMATTER
    )

    if needs_new_version:
        version_num = (latest.version + 1) if latest else 1
        version = McpSkillVersion(
            skill_id=skill.id,
            version=version_num,
            frontmatter=SKILL_FRONTMATTER,
            body=SKILL_BODY,
            created_by="system",
        )
        db.add(version)
        db.commit()
        db.refresh(version)
        skill.published_version_id = version.id
        db.commit()
        db.refresh(skill)
        logger.info("Published coreX Manager skill version %d", version_num)

    # 4. Regenerate config bundle
    try:
        from .mcp_config import write_config_bundle
        write_config_bundle(db)
        logger.info("MCP config bundle regenerated after self-registration")
    except Exception as e:
        logger.warning("Failed to regenerate MCP config bundle: %s", e)
