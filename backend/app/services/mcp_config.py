"""MCP Gateway config bundle generator.

Reads MCP entities from the database, decrypts secrets, and writes a JSON
config bundle to the file path configured by MCP_CONFIG_PATH. The gateway
reads this file on startup and watches for changes.

The bundle contains everything the gateway needs to operate:
- servers (with decrypted auth secrets)
- identities (with PAT hashes for verification)
- teams
- global settings (JWT, origins, etc.)
"""
import json
import logging
import os
import hmac
import hashlib
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import (
    Team, McpServer, McpServerReplica, McpIdentity,
    McpPolicy, McpDlpRule, McpGuardrail, McpSkill, McpSkillVersion,
)
from ..services.mcp_secrets import decrypt_secret, has_secrets_key, _get_fernet
from ..services.settings import get_setting

logger = logging.getLogger(__name__)
settings = get_settings()


def _serialize_datetime(dt) -> Optional[str]:
    """Serialize a datetime to ISO format string, or None."""
    if dt is None:
        return None
    return dt.isoformat()


def _build_server_dict(server: McpServer, replicas: list[McpServerReplica]) -> dict:
    """Build a server dict for the config bundle, decrypting the auth secret."""
    auth_secret = None
    if server.auth_secret_enc and server.auth_type != "none":
        try:
            auth_secret = decrypt_secret(server.auth_secret_enc)
        except (ValueError, RuntimeError):
            logger.error("Failed to decrypt secret for server %s", server.name)

    # Decrypt OAuth client secret if present
    oauth_client_secret = None
    if server.oauth_client_secret_enc:
        try:
            oauth_client_secret = decrypt_secret(server.oauth_client_secret_enc)
        except (ValueError, RuntimeError):
            logger.error("Failed to decrypt OAuth client secret for server %s", server.name)

    # Decrypt OAuth access/refresh tokens if present
    oauth_access_token = None
    if server.oauth_token_enc:
        try:
            oauth_access_token = decrypt_secret(server.oauth_token_enc)
        except (ValueError, RuntimeError):
            logger.error("Failed to decrypt OAuth access token for server %s", server.name)

    oauth_refresh_token = None
    if server.oauth_refresh_token_enc:
        try:
            oauth_refresh_token = decrypt_secret(server.oauth_refresh_token_enc)
        except (ValueError, RuntimeError):
            logger.error("Failed to decrypt OAuth refresh token for server %s", server.name)

    # Decrypt env vars (stored as JSON: {"key": "encrypted_value", ...})
    env_vars: dict[str, str] = {}
    if server.env_vars_json:
        try:
            raw_env = json.loads(server.env_vars_json)
            for k, v in raw_env.items():
                if v and isinstance(v, str):
                    try:
                        env_vars[k] = decrypt_secret(v)
                    except (ValueError, RuntimeError):
                        env_vars[k] = v  # might be plaintext
                else:
                    env_vars[k] = v
        except (json.JSONDecodeError, TypeError):
            logger.error("Failed to parse env_vars_json for server %s", server.name)

    # Parse args_json
    args: list[str] = []
    if server.args_json:
        try:
            args = json.loads(server.args_json)
        except (json.JSONDecodeError, TypeError):
            logger.error("Failed to parse args_json for server %s", server.name)

    # If replicas exist, rewrite URL to the internal HAProxy upstream frontend
    url = server.url
    has_replicas = len(replicas) > 0
    if has_replicas and url:
        # Rewrite to internal HAProxy upstream path
        from urllib.parse import urlparse
        parsed = urlparse(server.url)
        path = parsed.path or "/"
        url = f"http://haproxy:{settings.MCP_UPSTREAM_PORT}/mcp-up/{server.namespace}{path}"

    return {
        "id": server.id,
        "team_id": server.team_id,
        "name": server.name,
        "namespace": server.namespace,
        "display_name": server.display_name,
        "description": server.description,
        "url": url,
        "original_url": server.url,
        "enabled": server.enabled,
        "verify_tls": server.verify_tls,
        "auth_type": server.auth_type,
        "auth_header": server.auth_header,
        "auth_secret": auth_secret,
        "timeout_ms": server.timeout_ms,
        "max_body_bytes": server.max_body_bytes,
        "has_replicas": has_replicas,
        "replica_count": len(replicas),
        # stdio transport
        "transport_type": server.transport_type or "streamable_http",
        "command": server.command,
        "args": args,
        "env_vars": env_vars,
        # marketplace
        "package_manager": server.package_manager,
        "source_package_name": server.source_package_name,
        "installed_version": server.installed_version,
        # OAuth
        "oauth_enabled": server.oauth_enabled or False,
        "oauth_client_id": server.oauth_client_id,
        "oauth_client_secret": oauth_client_secret,
        "oauth_scopes": server.oauth_scopes,
        "oauth_auth_status": server.oauth_auth_status or "not_configured",
        "oauth_access_token": oauth_access_token,
        "oauth_refresh_token": oauth_refresh_token,
        "oauth_token_expires_at": _serialize_datetime(server.oauth_token_expires_at),
        "oauth_auth_server_metadata_url": server.oauth_auth_server_metadata_url,
        "oauth_protected_resource_metadata_url": server.oauth_protected_resource_metadata_url,
    }


def _build_identity_dict(identity: McpIdentity) -> dict:
    """Build an identity dict for the config bundle."""
    return {
        "id": identity.id,
        "team_id": identity.team_id,
        "name": identity.name,
        "description": identity.description,
        "subject": identity.subject,
        "kind": identity.kind,
        "pat_hash": identity.pat_hash,
        "pat_prefix": identity.pat_prefix,
        "jwt_issuer": identity.jwt_issuer,
        "jwt_audience": identity.jwt_audience,
        "jwt_jwks_url": identity.jwt_jwks_url,
        "enabled": identity.enabled,
        "expires_at": _serialize_datetime(identity.expires_at),
    }


def _build_policy_dict(policy: McpPolicy) -> dict:
    """Build a policy dict for the config bundle, including the compiled AST."""
    return {
        "id": policy.id,
        "team_id": policy.team_id,
        "name": policy.name,
        "enabled": policy.enabled,
        "priority": policy.priority,
        "expression": policy.expression,
        "expression_ast": policy.expression_ast,
        "action": policy.action,
        "log": policy.log,
        "no_log": policy.no_log,
    }


def _build_dlp_rule_dict(rule: McpDlpRule) -> dict:
    """Build a DLP rule dict for the config bundle."""
    return {
        "id": rule.id,
        "team_id": rule.team_id,
        "name": rule.name,
        "enabled": rule.enabled,
        "priority": rule.priority,
        "direction": rule.direction,
        "detector": rule.detector,
        "find_regex": rule.find_regex,
        "action": rule.action,
        "token_prefix": rule.token_prefix,
        "token_ttl": rule.token_ttl,
        "apply_to": rule.apply_to,
    }


def _build_guardrail_dict(gr: McpGuardrail) -> dict:
    """Build a guardrail dict for the config bundle."""
    return {
        "id": gr.id,
        "team_id": gr.team_id,
        "name": gr.name,
        "enabled": gr.enabled,
        "priority": gr.priority,
        "direction": gr.direction,
        "pack": gr.pack,
        "find_regex": gr.find_regex,
        "action": gr.action,
    }


def _build_skill_dict(skill: McpSkill, published_version: Optional[McpSkillVersion]) -> dict:
    """Build a skill dict for the config bundle, including published version content."""
    d = {
        "id": skill.id,
        "team_id": skill.team_id,
        "name": skill.name,
        "description": skill.description,
        "enabled": skill.enabled,
        "enable_when": skill.enable_when,
        "enable_when_ast": skill.enable_when_ast,
        "tags": skill.tags,
        "published_version_id": skill.published_version_id,
        "published_body": None,
        "published_frontmatter": None,
        "published_files": None,
    }
    if published_version:
        d["published_body"] = published_version.body
        d["published_frontmatter"] = published_version.frontmatter
        d["published_files"] = published_version.files
    return d


def build_config_bundle(db: Session) -> dict:
    """Build the full config bundle from the database."""
    servers = db.query(McpServer).filter(McpServer.enabled == True).all()  # noqa: E712
    identities = db.query(McpIdentity).filter(McpIdentity.enabled == True).all()  # noqa: E712
    teams = db.query(Team).all()
    policies = db.query(McpPolicy).filter(McpPolicy.enabled == True).all()  # noqa: E712
    dlp_rules = db.query(McpDlpRule).filter(McpDlpRule.enabled == True).all()  # noqa: E712
    guardrails = db.query(McpGuardrail).filter(McpGuardrail.enabled == True).all()  # noqa: E712
    skills = db.query(McpSkill).filter(McpSkill.enabled == True).all()  # noqa: E712

    # Build servers with replicas
    server_list = []
    for server in servers:
        replicas = db.query(McpServerReplica).filter(
            McpServerReplica.server_id == server.id,
            McpServerReplica.enabled == True,  # noqa: E712
        ).all()
        server_list.append(_build_server_dict(server, replicas))

    # Build identities
    identity_list = [_build_identity_dict(i) for i in identities]

    # Build policies
    policy_list = [_build_policy_dict(p) for p in policies]

    # Build DLP rules
    dlp_rule_list = [_build_dlp_rule_dict(r) for r in dlp_rules]

    # Build guardrails
    guardrail_list = [_build_guardrail_dict(g) for g in guardrails]

    # Build skills with published version content
    skill_list = []
    for skill in skills:
        pv = None
        if skill.published_version_id:
            pv = db.get(McpSkillVersion, skill.published_version_id)
        skill_list.append(_build_skill_dict(skill, pv))

    # Global settings
    allowed_origins_str = get_setting(db, "mcp_allowed_origins", settings.MCP_ALLOWED_ORIGINS or "")
    allowed_origins = [o.strip() for o in allowed_origins_str.split(",") if o.strip()] if allowed_origins_str else []

    bundle = {
        "servers": server_list,
        "identities": identity_list,
        "teams": [{"id": t.id, "name": t.name, "slug": t.slug} for t in teams],
        "policies": policy_list,
        "dlp_rules": dlp_rule_list,
        "guardrails": guardrail_list,
        "skills": skill_list,
        "jwt_issuer": get_setting(db, "mcp_jwt_issuer", settings.MCP_JWT_ISSUER or ""),
        "jwt_audience": get_setting(db, "mcp_jwt_audience", settings.MCP_JWT_AUDIENCE or ""),
        "jwt_jwks_url": get_setting(db, "mcp_jwt_jwks_url", settings.MCP_JWT_JWKS_URL or ""),
        "allowed_origins": allowed_origins,
        "log_payloads": get_setting(db, "mcp_log_payloads", str(settings.MCP_LOG_PAYLOADS)).lower() in ("true", "1", "yes"),
        "default_rpm": int(get_setting(db, "mcp_default_rpm", str(settings.MCP_DEFAULT_RPM))),
        "catalog_refresh_seconds": settings.MCP_CATALOG_REFRESH_SECONDS,
        "team_rpm_overrides": _build_team_rpm_overrides(db, teams),
    }

    return bundle


def _build_team_rpm_overrides(db: Session, teams: list[Team]) -> dict:
    """Build per-team RPM overrides from settings."""
    overrides = {}
    for team in teams:
        val = get_setting(db, f"mcp_team_rpm_{team.id}", "")
        if val:
            try:
                overrides[str(team.id)] = int(val)
            except ValueError:
                pass
    return overrides


def _sign_bundle(bundle: dict) -> dict:
    """Sign the config bundle with HMAC-SHA256 if signing key is configured."""
    signing_key = os.environ.get("MCP_CONFIG_SIGNING_KEY", "")
    if not signing_key:
        return bundle
    # Sign the JSON without the _signature field
    payload = json.dumps(bundle, sort_keys=True, default=str).encode("utf-8")
    signature = hmac.new(signing_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    bundle["_signature"] = signature
    return bundle


def _encrypt_bundle_bytes(data: bytes) -> bytes:
    """Encrypt config bundle bytes with Fernet if encryption key is configured.

    Returns plaintext bytes if no key is set (backward compat).
    """
    try:
        f = _get_fernet()
        return f.encrypt(data)
    except Exception as e:
        logger.warning("Config bundle encryption failed (writing plaintext): %s", e)
        return data


def write_config_bundle(db: Session) -> str:
    """Build and write the config bundle to MCP_CONFIG_PATH. Returns the path."""
    bundle = build_config_bundle(db)
    bundle = _sign_bundle(bundle)
    config_path = settings.MCP_CONFIG_PATH

    # Ensure directory exists
    config_dir = os.path.dirname(config_path)
    if config_dir:
        os.makedirs(config_dir, exist_ok=True)

    # Serialize and encrypt
    plaintext = json.dumps(bundle, indent=2, default=str).encode("utf-8")
    encrypted = _encrypt_bundle_bytes(plaintext)

    # Write atomically (write to temp, then rename)
    tmp_path = config_path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(encrypted)
    os.replace(tmp_path, config_path)

    logger.info("Wrote MCP config bundle to %s (%d servers, %d identities)",
                config_path, len(bundle["servers"]), len(bundle["identities"]))
    return config_path


def generate_mcp_bundle_text(db: Session) -> str:
    """Build the config bundle and return it as a comparable JSON string.

    Used by _config_status_data to detect unapplied MCP changes by comparing
    the generated bundle against the .applied copy. Returns the decrypted
    plaintext JSON so comparison is stable (Fernet uses a random IV, so
    ciphertext comparison would always show a diff).
    """
    bundle = build_config_bundle(db)
    bundle = _sign_bundle(bundle)
    return json.dumps(bundle, indent=2, default=str, sort_keys=True)


def read_applied_mcp_bundle() -> str:
    """Read and decrypt the .applied MCP config bundle for comparison.

    Returns empty string if no .applied file exists yet (first apply or
    feature never enabled).
    """
    applied_path = f"{settings.MCP_CONFIG_PATH}.applied"
    if not os.path.exists(applied_path):
        return ""
    with open(applied_path, "rb") as f:
        raw = f.read()
    # Try to decrypt; if decryption fails (no key, corrupted), return raw text
    try:
        f_obj = _get_fernet()
        return f_obj.decrypt(raw).decode("utf-8")
    except Exception:
        return raw.decode("utf-8", errors="replace")


def write_applied_mcp_bundle(db: Session) -> None:
    """Write a .applied copy of the MCP config bundle for change detection.

    Called from write_config after the live bundle is written. Stores the
    decrypted plaintext so _config_status_data can compare with
    generate_mcp_bundle_text without dealing with Fernet's random IV.
    """
    text = generate_mcp_bundle_text(db)
    applied_path = f"{settings.MCP_CONFIG_PATH}.applied"
    applied_dir = os.path.dirname(applied_path)
    if applied_dir:
        os.makedirs(applied_dir, exist_ok=True)
    with open(applied_path, "w") as f:
        f.write(text)


def get_multi_replica_servers(db: Session) -> list[McpServer]:
    """Return enabled servers that have at least one enabled replica."""
    result = []
    for server in db.query(McpServer).filter(McpServer.enabled == True).all():  # noqa: E712
        replica_count = db.query(McpServerReplica).filter(
            McpServerReplica.server_id == server.id,
            McpServerReplica.enabled == True,  # noqa: E712
        ).count()
        if replica_count > 0:
            result.append(server)
    return result
