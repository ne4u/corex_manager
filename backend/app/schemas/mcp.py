from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from ._base import _optional_update


# --- Team ---

class TeamBase(BaseModel):
    name: str
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    description: Optional[str] = None


class TeamCreate(TeamBase):
    pass


TeamUpdate = _optional_update(TeamBase)


class TeamResponse(TeamBase):
    id: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- UserTeam ---

class UserTeamBase(BaseModel):
    user_id: int
    team_id: int


class UserTeamCreate(UserTeamBase):
    pass


class UserTeamResponse(UserTeamBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpServer ---

class McpServerBase(BaseModel):
    team_id: int
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    enabled: bool = True
    verify_tls: bool = True
    auth_type: str = Field(default="none", pattern="^(none|bearer|header|oauth)$")
    auth_header: Optional[str] = None
    auth_secret: Optional[str] = None  # plaintext, write-only; never returned
    timeout_ms: int = 30000
    max_body_bytes: int = 1048576
    namespace: Optional[str] = None
    # stdio transport
    transport_type: str = Field(default="streamable_http", pattern="^(streamable_http|stdio)$")
    command: Optional[str] = None
    args: Optional[List[str]] = None
    env_vars: Optional[Dict[str, str]] = None
    # marketplace
    package_manager: Optional[str] = None
    source_package_name: Optional[str] = None
    # OAuth
    oauth_enabled: bool = False
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None  # write-only
    oauth_scopes: Optional[str] = None
    oauth_auth_server_metadata_url: Optional[str] = None
    oauth_protected_resource_metadata_url: Optional[str] = None


class McpServerCreate(McpServerBase):
    pass


McpServerUpdate = _optional_update(McpServerBase)


class McpServerResponse(BaseModel):
    id: int
    team_id: int
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    enabled: bool
    verify_tls: bool
    auth_type: str
    auth_header: Optional[str] = None
    has_secret: bool = False
    timeout_ms: int
    max_body_bytes: int
    namespace: str
    health_status: Optional[str] = None
    last_seen_at: Optional[datetime] = None
    last_error: Optional[str] = None
    last_catalog_at: Optional[datetime] = None
    transport_type: str = "streamable_http"
    command: Optional[str] = None
    args: Optional[List[str]] = None
    has_env_vars: bool = False
    env_var_names: Optional[List[str]] = None
    package_manager: Optional[str] = None
    source_package_name: Optional[str] = None
    installed_version: Optional[str] = None
    oauth_enabled: bool = False
    oauth_auth_status: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_scopes: Optional[str] = None
    oauth_auth_server_metadata_url: Optional[str] = None
    oauth_protected_resource_metadata_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpServerReplica ---

class McpServerReplicaBase(BaseModel):
    url: str
    enabled: bool = True
    verify_tls: bool = True


class McpServerReplicaCreate(McpServerReplicaBase):
    pass


McpServerReplicaUpdate = _optional_update(McpServerReplicaBase)


class McpServerReplicaResponse(BaseModel):
    id: int
    server_id: int
    url: str
    enabled: bool
    verify_tls: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpIdentity ---

class McpIdentityBase(BaseModel):
    team_id: int
    name: str
    description: Optional[str] = None
    subject: Optional[str] = None
    kind: str = Field(default="pat", pattern="^(pat|jwt)$")
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_jwks_url: Optional[str] = None
    enabled: bool = True
    expires_at: Optional[datetime] = None


class McpIdentityCreate(McpIdentityBase):
    pass


McpIdentityUpdate = _optional_update(McpIdentityBase)


class McpIdentityResponse(BaseModel):
    id: int
    team_id: int
    name: str
    description: Optional[str] = None
    subject: Optional[str] = None
    kind: str
    pat_prefix: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_jwks_url: Optional[str] = None
    enabled: bool
    expires_at: Optional[datetime] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class PatCreateResponse(BaseModel):
    identity_id: int
    pat: str  # plaintext, shown once
    prefix: str


# --- McpPolicy ---

class McpPolicyBase(BaseModel):
    team_id: int
    name: str
    enabled: bool = True
    expression: str
    action: str = Field(default="allow", pattern="^(allow|deny|skip_dlp|skip_ratelimit)$")
    log: bool = True
    no_log: bool = False


class McpPolicyCreate(McpPolicyBase):
    pass


McpPolicyUpdate = _optional_update(McpPolicyBase)


class McpPolicyResponse(BaseModel):
    id: int
    team_id: int
    name: str
    enabled: bool
    priority: int
    expression: str
    expression_ast: Optional[Dict[str, Any]] = None
    action: str
    log: bool
    no_log: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpDlpRule ---

class McpDlpRuleBase(BaseModel):
    team_id: int
    name: str
    enabled: bool = True
    direction: str = Field(default="both", pattern="^(request|response|both)$")
    detector: str = Field(pattern="^(email|phone|ssn|credit_card|ip|aws_key|private_key|github_token|slack_token|custom)$")
    find_regex: Optional[str] = None
    action: str = Field(default="block", pattern="^(block|redact|tokenize)$")
    token_prefix: Optional[str] = None
    token_ttl: Optional[int] = None
    apply_to: str = Field(default="json_strings", pattern="^(json_strings|all_text)$")


class McpDlpRuleCreate(McpDlpRuleBase):
    pass


McpDlpRuleUpdate = _optional_update(McpDlpRuleBase)


class McpDlpRuleResponse(BaseModel):
    id: int
    team_id: int
    name: str
    enabled: bool
    priority: int
    direction: str
    detector: str
    find_regex: Optional[str] = None
    action: str
    token_prefix: Optional[str] = None
    token_ttl: Optional[int] = None
    apply_to: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpSkill ---

class McpSkillBase(BaseModel):
    team_id: int
    name: str = Field(pattern=r"^[a-z0-9-]+$")
    description: Optional[str] = None
    enabled: bool = True
    enable_when: Optional[str] = None
    tags: Optional[List[str]] = None


class McpSkillCreate(McpSkillBase):
    pass


McpSkillUpdate = _optional_update(McpSkillBase)


class McpSkillResponse(BaseModel):
    id: int
    team_id: int
    name: str
    description: Optional[str] = None
    enabled: bool
    enable_when: Optional[str] = None
    enable_when_ast: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    published_version_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpSkillVersion ---

class McpSkillVersionBase(BaseModel):
    frontmatter: Optional[Dict[str, Any]] = None
    body: str
    files: Optional[List[Dict[str, Any]]] = None


class McpSkillVersionCreate(McpSkillVersionBase):
    pass


class McpSkillImportRequest(BaseModel):
    """Request to import a skill from a URL.

    Supported URL formats:
    - Raw SKILL.md URL (e.g. https://raw.githubusercontent.com/owner/repo/main/skills/my-skill/SKILL.md)
    - GitHub shorthand (owner/repo or owner/repo/path/to/skill)
    - Full GitHub URL to a skill directory or repo root
    - URL to a ZIP archive containing SKILL.md at the root or in a skills/ subdir
    """
    url: str = Field(description="URL to import from (raw SKILL.md, GitHub repo, or ZIP archive)")
    team_id: int
    name: Optional[str] = Field(None, description="Override skill name (defaults to frontmatter name or repo name)")
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    auto_publish: bool = True


class McpSkillVersionResponse(BaseModel):
    id: int
    skill_id: int
    version: int
    frontmatter: Optional[Dict[str, Any]] = None
    body: str
    files: Optional[List[Dict[str, Any]]] = None
    created_by: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpGuardrail ---

class McpGuardrailBase(BaseModel):
    team_id: int
    name: str
    enabled: bool = True
    direction: str = Field(default="both", pattern="^(request|response|both)$")
    pack: str = Field(default="custom", pattern="^(builtin:jailbreak_v1|builtin:instruction_override|builtin:obfuscation|custom)$")
    find_regex: Optional[str] = None
    action: str = Field(default="block", pattern="^(block|redact|log)$")


class McpGuardrailCreate(McpGuardrailBase):
    pass


McpGuardrailUpdate = _optional_update(McpGuardrailBase)


class McpGuardrailResponse(BaseModel):
    id: int
    team_id: int
    name: str
    enabled: bool
    priority: int
    direction: str
    pack: str
    find_regex: Optional[str] = None
    action: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpInstallation ---

class McpInstallationResponse(BaseModel):
    id: int
    server_id: int
    package_manager: str
    package_name: str
    version: Optional[str] = None
    status: str
    output: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Marketplace ---

class MarketplaceSearchResult(BaseModel):
    name: str
    description: Optional[str] = None
    version: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None
    keywords: Optional[List[str]] = None
    downloads: Optional[int] = None
    score: Optional[float] = None


class MarketplacePackageDetails(BaseModel):
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None
    keywords: Optional[List[str]] = None
    dependencies: Optional[Dict[str, str]] = None
    readme: Optional[str] = None
    required_env_vars: Optional[List[str]] = None


class MarketplaceInstallRequest(BaseModel):
    package_manager: str = Field(pattern="^(npm|pypi)$")
    package_name: str
    version: Optional[str] = None
    team_id: int
    name: Optional[str] = None  # server name, defaults to package name
    namespace: Optional[str] = None
    display_name: Optional[str] = None
    env_vars: Optional[Dict[str, str]] = None
    custom_args: Optional[List[str]] = None


class MarketplaceUninstallRequest(BaseModel):
    server_id: int


class DiscoverEnvVarsRequest(BaseModel):
    package_manager: str = Field(pattern="^(npm|pypi)$")
    package_name: str


class DiscoverEnvVarsResponse(BaseModel):
    env_vars: List[str] = []


# --- Upstream OAuth ---

class OAuthDiscoverRequest(BaseModel):
    url: str
    transport_type: str = Field(default="streamable_http", pattern="^(streamable_http|stdio)$")


class OAuthDiscoverResponse(BaseModel):
    authorization_servers: Optional[List[str]] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    registration_endpoint: Optional[str] = None
    scopes_supported: Optional[List[str]] = None
    grant_types_supported: Optional[List[str]] = None


class OAuthConfigureRequest(BaseModel):
    client_id: str
    client_secret: str
    scopes: Optional[str] = None
    auth_server_metadata_url: Optional[str] = None
    protected_resource_metadata_url: Optional[str] = None


class OAuthStatusResponse(BaseModel):
    enabled: bool = False
    auth_status: Optional[str] = None
    client_id: Optional[str] = None
    scopes: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    authorization_url: Optional[str] = None


class OAuthAuthorizeResponse(BaseModel):
    authorization_url: str


# --- Skill Export ---

class SkillExportResponse(BaseModel):
    download_url: str
    filename: str


# --- McpEvent ---

class McpEventResponse(BaseModel):
    id: int
    captured_at: datetime
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    identity_id: Optional[int] = None
    team_id: Optional[int] = None
    server_id: Optional[int] = None
    jsonrpc_method: Optional[str] = None
    tool: Optional[str] = None
    resource_uri: Optional[str] = None
    prompt: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    dlp_hits: Optional[Any] = None
    guardrail_hits: Optional[Any] = None
    model_config = ConfigDict(from_attributes=True)


class McpEventListResponse(BaseModel):
    events: List[McpEventResponse]
    total: int


# --- Session ---

class SessionInfo(BaseModel):
    session_id: str
    identity_id: int
    team_id: Optional[int] = None
    created_at: str
    last_activity: Optional[str] = None
    server_sessions: Optional[Dict[str, str]] = None


class SessionListResponse(BaseModel):
    sessions: List[SessionInfo]
    total: int


# --- Config Status ---

class ConfigStatusResponse(BaseModel):
    last_generated: Optional[str] = None
    bundle_size: Optional[int] = None
    config_path: Optional[str] = None


# --- Alert Config ---

class AlertConfigResponse(BaseModel):
    webhook_url: Optional[str] = None
    thresholds: Dict[str, int] = {}


class AlertConfigUpdate(BaseModel):
    webhook_url: Optional[str] = None
    thresholds: Dict[str, int] = {}


class AlertHistoryItem(BaseModel):
    id: int
    event_type: str
    message: str
    created_at: datetime
    webhook_sent: bool = False
    webhook_status: Optional[int] = None


# --- Server Catalog ---

class ServerCatalogResponse(BaseModel):
    server_id: int
    tools: List[Dict[str, Any]] = []
    resources: List[Dict[str, Any]] = []
    prompts: List[Dict[str, Any]] = []
    last_refresh: Optional[str] = None


__all__ = [
    "TeamBase", "TeamCreate", "TeamUpdate", "TeamResponse",
    "UserTeamBase", "UserTeamCreate", "UserTeamResponse",
    "McpServerBase", "McpServerCreate", "McpServerUpdate", "McpServerResponse",
    "McpServerReplicaBase", "McpServerReplicaCreate", "McpServerReplicaUpdate", "McpServerReplicaResponse",
    "McpIdentityBase", "McpIdentityCreate", "McpIdentityUpdate", "McpIdentityResponse",
    "PatCreateResponse",
    "McpPolicyBase", "McpPolicyCreate", "McpPolicyUpdate", "McpPolicyResponse",
    "McpDlpRuleBase", "McpDlpRuleCreate", "McpDlpRuleUpdate", "McpDlpRuleResponse",
    "McpSkillBase", "McpSkillCreate", "McpSkillUpdate", "McpSkillResponse",
    "McpSkillVersionBase", "McpSkillVersionCreate", "McpSkillVersionResponse",
    "McpSkillImportRequest",
    "McpGuardrailBase", "McpGuardrailCreate", "McpGuardrailUpdate", "McpGuardrailResponse",
    "McpInstallationResponse",
    "MarketplaceSearchResult", "MarketplacePackageDetails",
    "MarketplaceInstallRequest", "MarketplaceUninstallRequest",
    "DiscoverEnvVarsRequest", "DiscoverEnvVarsResponse",
    "OAuthDiscoverRequest", "OAuthDiscoverResponse",
    "OAuthConfigureRequest", "OAuthStatusResponse", "OAuthAuthorizeResponse",
    "SkillExportResponse",
    "McpEventResponse", "McpEventListResponse",
    "SessionInfo", "SessionListResponse",
    "ConfigStatusResponse",
    "AlertConfigResponse", "AlertConfigUpdate", "AlertHistoryItem",
    "ServerCatalogResponse",
]
