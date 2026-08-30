from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship

from .base import Base, utcnow


class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    slug = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    members = relationship("UserTeam", back_populates="team", cascade="all, delete-orphan")


class UserTeam(Base):
    __tablename__ = "user_teams"
    __table_args__ = (UniqueConstraint("user_id", "team_id", name="uq_user_team"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)

    team = relationship("Team", back_populates="members")


class McpServer(Base):
    __tablename__ = "mcp_servers"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    display_name = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    url = Column(String, nullable=True)  # nullable for stdio servers
    enabled = Column(Boolean, default=True)
    verify_tls = Column(Boolean, default=True)
    auth_type = Column(String, default="none")  # none | bearer | header | oauth
    auth_header = Column(String, nullable=True)  # default "Authorization"
    auth_secret_enc = Column(Text, nullable=True)  # Fernet ciphertext
    timeout_ms = Column(Integer, default=30000)
    max_body_bytes = Column(Integer, default=1048576)
    namespace = Column(String, nullable=False)  # default = name
    health_status = Column(String, nullable=True)  # healthy | unhealthy | unknown | starting | stopped
    last_seen_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    last_catalog_at = Column(DateTime, nullable=True)
    # stdio transport support
    transport_type = Column(String, default="streamable_http")  # streamable_http | stdio
    command = Column(String, nullable=True)  # e.g. npx, uvx, python
    args_json = Column(Text, nullable=True)  # JSON array of args
    env_vars_json = Column(Text, nullable=True)  # JSON object of env var names (values encrypted)
    # marketplace install tracking
    package_manager = Column(String, nullable=True)  # npm | pypi | none
    source_package_name = Column(String, nullable=True)
    installed_version = Column(String, nullable=True)
    installer_user_id = Column(Integer, nullable=True)
    # upstream OAuth support
    oauth_enabled = Column(Boolean, default=False)
    oauth_client_id = Column(String, nullable=True)
    oauth_client_secret_enc = Column(Text, nullable=True)  # Fernet ciphertext
    oauth_scopes = Column(String, nullable=True)  # space-separated
    oauth_auth_status = Column(String, default="not_configured")  # not_configured | pending | authorized | error
    oauth_token_enc = Column(Text, nullable=True)  # Fernet ciphertext access token
    oauth_refresh_token_enc = Column(Text, nullable=True)  # Fernet ciphertext refresh token
    oauth_token_expires_at = Column(DateTime, nullable=True)
    oauth_auth_server_metadata_url = Column(String, nullable=True)
    oauth_protected_resource_metadata_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    replicas = relationship("McpServerReplica", back_populates="server", cascade="all, delete-orphan")
    team = relationship("Team")


class McpServerReplica(Base):
    __tablename__ = "mcp_server_replicas"
    __table_args__ = (UniqueConstraint("server_id", "url", name="uq_server_replica_url"),)

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    verify_tls = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    server = relationship("McpServer", back_populates="replicas")


class McpIdentity(Base):
    __tablename__ = "mcp_identities"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    subject = Column(String, nullable=True)  # JWT sub or PAT label
    kind = Column(String, default="pat")  # pat | jwt
    pat_hash = Column(String, nullable=True)  # bcrypt/argon2 hash
    pat_prefix = Column(String, nullable=True)  # first 8 chars for UI
    jwt_issuer = Column(String, nullable=True)
    jwt_audience = Column(String, nullable=True)
    jwt_jwks_url = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    last_used_at = Column(DateTime, nullable=True)
    team = relationship("Team")


class McpPolicy(Base):
    __tablename__ = "mcp_policies"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, unique=True, nullable=False)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0)
    expression = Column(Text, nullable=False)
    expression_ast = Column(JSON, nullable=True)
    action = Column(String, default="allow")  # allow | deny | skip_dlp | skip_ratelimit
    log = Column(Boolean, default=True)
    no_log = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    team = relationship("Team")


class McpDlpRule(Base):
    __tablename__ = "mcp_dlp_rules"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0)
    direction = Column(String, default="both")  # request | response | both
    detector = Column(String, nullable=False)  # email|phone|ssn|credit_card|ip|aws_key|private_key|github_token|slack_token|custom
    find_regex = Column(Text, nullable=True)  # if detector=custom
    action = Column(String, default="block")  # block | redact | tokenize
    token_prefix = Column(String, nullable=True)
    token_ttl = Column(Integer, nullable=True)
    apply_to = Column(String, default="json_strings")  # json_strings | all_text
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    team = relationship("Team")


class McpSkill(Base):
    __tablename__ = "mcp_skills"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, unique=True, nullable=False)  # [a-z0-9-]+
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    enable_when = Column(Text, nullable=True)  # Security Rules expression
    enable_when_ast = Column(JSON, nullable=True)
    tags = Column(JSON, default=list, nullable=True)
    published_version_id = Column(Integer, ForeignKey("mcp_skill_versions.id", use_alter=True), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    versions = relationship("McpSkillVersion", back_populates="skill", cascade="all, delete-orphan", foreign_keys="McpSkillVersion.skill_id")
    team = relationship("Team")


class McpSkillVersion(Base):
    __tablename__ = "mcp_skill_versions"
    __table_args__ = (UniqueConstraint("skill_id", "version", name="uq_skill_version"),)

    id = Column(Integer, primary_key=True, index=True)
    skill_id = Column(Integer, ForeignKey("mcp_skills.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    frontmatter = Column(JSON, nullable=True)
    body = Column(Text, nullable=False)  # markdown instructions (SKILL.md body)
    files = Column(JSON, nullable=True)  # [{path, media_type, content_b64}]
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    skill = relationship("McpSkill", back_populates="versions", foreign_keys=[skill_id])


class McpGuardrail(Base):
    __tablename__ = "mcp_guardrails"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0)
    direction = Column(String, default="both")  # request | response | both
    pack = Column(String, default="custom")  # builtin:jailbreak_v1 | builtin:instruction_override | builtin:obfuscation | custom
    find_regex = Column(Text, nullable=True)
    action = Column(String, default="block")  # block | redact | log
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    team = relationship("Team")


class McpInstallation(Base):
    __tablename__ = "mcp_installations"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    package_manager = Column(String, nullable=False)  # npm | pypi
    package_name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    status = Column(String, default="pending")  # pending | installing | completed | failed
    output = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    server = relationship("McpServer")


class McpEvent(Base):
    __tablename__ = "mcp_events"

    id = Column(Integer, primary_key=True, index=True)
    captured_at = Column(DateTime, default=utcnow, index=True)
    request_id = Column(String, nullable=True)
    session_id = Column(String, nullable=True)
    identity_id = Column(Integer, nullable=True, index=True)
    team_id = Column(Integer, nullable=True, index=True)
    server_id = Column(Integer, nullable=True)
    jsonrpc_method = Column(String, nullable=True)
    tool = Column(String, nullable=True)
    resource_uri = Column(String, nullable=True)
    prompt = Column(String, nullable=True)
    action = Column(String, nullable=True)  # allow|deny|dlp_block|dlp_redact|guardrail_block|upstream_error
    status = Column(String, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    bytes_in = Column(Integer, nullable=True)
    bytes_out = Column(Integer, nullable=True)
    dlp_hits = Column(JSON, nullable=True)
    guardrail_hits = Column(JSON, nullable=True)


__all__ = [
    "Team",
    "UserTeam",
    "McpServer",
    "McpServerReplica",
    "McpIdentity",
    "McpPolicy",
    "McpDlpRule",
    "McpSkill",
    "McpSkillVersion",
    "McpGuardrail",
    "McpInstallation",
    "McpEvent",
]
