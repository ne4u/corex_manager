"""Skills engine for MCP Gateway — serves published SKILL.md as virtual prompts.

Loads skills from the config bundle, evaluates enable_when expressions
against the MCP context, and injects enabled skills as virtual prompt
entries in prompts/list responses. Skills are rendered as markdown
messages in prompts/get responses.

Skills are namespaced as `skill__{name}` to distinguish them from
upstream prompts.
"""
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    from .expression import parse_expression, evaluate as eval_ast, build_mcp_context
except ImportError:
    from expression import parse_expression, evaluate as eval_ast, build_mcp_context

SKILL_NAMESPACE = "skill"

# ---------------------------------------------------------------------------
# Skill loading
# ---------------------------------------------------------------------------

_compiled_skills: list[dict] = []
_has_skills_configured = False


def load_skills(config: dict) -> None:
    """Load and compile skills from the config bundle."""
    global _compiled_skills, _has_skills_configured

    raw_skills = config.get("skills", [])
    _has_skills_configured = len(raw_skills) > 0
    compiled = []

    for s in raw_skills:
        if not s.get("enabled", True):
            continue

        # Compile enable_when expression if present
        enable_when_ast = s.get("enable_when_ast")
        enable_when = s.get("enable_when")
        if enable_when and not enable_when_ast:
            try:
                enable_when_ast = parse_expression(enable_when)
            except ValueError as e:
                logger.error("Skill %s: failed to parse enable_when: %s", s.get("name"), e)
                enable_when_ast = None

        compiled.append({
            "id": s.get("id"),
            "team_id": s.get("team_id"),
            "name": s["name"],
            "description": s.get("description"),
            "enabled": s.get("enabled", True),
            "enable_when": enable_when,
            "enable_when_ast": enable_when_ast,
            "tags": s.get("tags", []),
            "published_version_id": s.get("published_version_id"),
            "published_body": s.get("published_body"),
            "published_frontmatter": s.get("published_frontmatter"),
            "published_files": s.get("published_files"),
        })

    _compiled_skills = compiled
    logger.info("Loaded %d skills (has_config: %s)", len(compiled), _has_skills_configured)


def has_skills() -> bool:
    """Return True if any skills are configured."""
    return _has_skills_configured and len(_compiled_skills) > 0


def get_all_skills() -> list[dict]:
    """Return all loaded skills."""
    return list(_compiled_skills)


def get_enabled_skills(auth_ctx) -> list[dict]:
    """Return skills that are enabled and whose enable_when passes for this identity."""
    result = []
    for skill in _compiled_skills:
        if not skill["enabled"]:
            continue
        # Only include skills with a published version
        if not skill.get("published_version_id"):
            continue

        # Evaluate enable_when if present
        if skill["enable_when_ast"]:
            ctx = build_mcp_context(
                method="prompts/list",
                tool="",
                server=SKILL_NAMESPACE,
                identity_name=auth_ctx.name,
                identity_kind=auth_ctx.kind,
                team_slug=str(auth_ctx.team_id),
                claims=auth_ctx.claims,
            )
            try:
                if not eval_ast(skill["enable_when_ast"], ctx):
                    continue
            except Exception as e:
                logger.error("Skill %s: enable_when eval error: %s", skill["name"], e)
                continue

        result.append(skill)
    return result


def get_skill_by_name(name: str) -> Optional[dict]:
    """Find a skill by its name."""
    for skill in _compiled_skills:
        if skill["name"] == name:
            return skill
    return None


# ---------------------------------------------------------------------------
# Prompt rendering
# ---------------------------------------------------------------------------

def skill_prompt_name(skill_name: str) -> str:
    """Return the namespaced prompt name for a skill."""
    return f"{SKILL_NAMESPACE}__{skill_name}"


def build_prompt_entry(skill: dict) -> dict:
    """Build a prompts/list entry for a skill."""
    return {
        "name": skill_prompt_name(skill["name"]),
        "description": skill.get("description") or f"Skill: {skill['name']}",
        "arguments": [],
        "_meta": {
            "mcp_server": SKILL_NAMESPACE,
            "mcp_original_name": skill["name"],
            "mcp_skill": True,
            "tags": skill.get("tags", []),
        },
    }


def render_skill_prompt(skill: dict) -> dict:
    """Render a skill as a prompts/get response.

    Returns the MCP prompt response with the published body as a markdown
    user message, plus any attached files as embedded resources.
    """
    messages = []

    body = skill.get("published_body") or ""
    frontmatter = skill.get("published_frontmatter") or {}
    files = skill.get("published_files") or []

    # Build the main message with the skill body
    message = {
        "role": "user",
        "content": {
            "type": "text",
            "text": body,
        },
    }

    # Add frontmatter as metadata if present
    if frontmatter:
        message["_meta"] = {"frontmatter": frontmatter}

    messages.append(message)

    # Add attached files as additional messages
    for f in files:
        path = f.get("path", "file")
        media_type = f.get("media_type", "application/octet-stream")
        content_b64 = f.get("content_b64", "")
        if content_b64:
            messages.append({
                "role": "user",
                "content": {
                    "type": "resource",
                    "resource": {
                        "uri": f"skill://{skill['name']}/{path}",
                        "mimeType": media_type,
                        "blob": content_b64,
                    },
                },
            })

    return {
        "jsonrpc": "2.0",
        "result": {"messages": messages},
    }
