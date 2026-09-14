from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ._base import _optional_update

# --- Team ---


class TeamBase(BaseModel):
    name: str
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    description: str | None = None


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
    display_name: str | None = None
    description: str | None = None
    url: str | None = None
    enabled: bool = True
    verify_tls: bool = True
    auth_type: str = Field(default="none", pattern="^(none|bearer|header|oauth)$")
    auth_header: str | None = None
    auth_secret: str | None = None  # plaintext, write-only; never returned
    timeout_ms: int = 30000
    max_body_bytes: int = 1048576
    namespace: str | None = None
    # stdio transport
    transport_type: str = Field(default="streamable_http", pattern="^(streamable_http|stdio)$")
    command: str | None = None
    args: list[str] | None = None
    env_vars: dict[str, str] | None = None
    # marketplace
    package_manager: str | None = None
    source_package_name: str | None = None
    # OAuth
    oauth_enabled: bool = False
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None  # write-only
    oauth_scopes: str | None = None
    oauth_auth_server_metadata_url: str | None = None
    oauth_protected_resource_metadata_url: str | None = None


class McpServerCreate(McpServerBase):
    pass


McpServerUpdate = _optional_update(McpServerBase)


class McpServerResponse(BaseModel):
    id: int
    team_id: int
    name: str
    display_name: str | None = None
    description: str | None = None
    url: str | None = None
    enabled: bool
    verify_tls: bool
    auth_type: str
    auth_header: str | None = None
    has_secret: bool = False
    timeout_ms: int
    max_body_bytes: int
    namespace: str
    health_status: str | None = None
    last_seen_at: datetime | None = None
    last_error: str | None = None
    last_catalog_at: datetime | None = None
    transport_type: str = "streamable_http"
    command: str | None = None
    args: list[str] | None = None
    has_env_vars: bool = False
    env_var_names: list[str] | None = None
    package_manager: str | None = None
    source_package_name: str | None = None
    installed_version: str | None = None
    oauth_enabled: bool = False
    oauth_auth_status: str | None = None
    oauth_client_id: str | None = None
    oauth_scopes: str | None = None
    oauth_auth_server_metadata_url: str | None = None
    oauth_protected_resource_metadata_url: str | None = None
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
    description: str | None = None
    subject: str | None = None
    kind: str = Field(default="pat", pattern="^(pat|jwt)$")
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    enabled: bool = True
    expires_at: datetime | None = None
    idp_source: str = Field(default="manual", pattern="^(manual|auth0)$")
    idp_external_id: str | None = None
    idp_user_info: dict[str, Any] | None = None


class McpIdentityCreate(McpIdentityBase):
    pass


McpIdentityUpdate = _optional_update(McpIdentityBase)


class McpIdentityResponse(BaseModel):
    id: int
    team_id: int
    name: str
    description: str | None = None
    subject: str | None = None
    kind: str
    pat_prefix: str | None = None
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    enabled: bool
    expires_at: datetime | None = None
    idp_source: str
    idp_external_id: str | None = None
    idp_user_info: dict[str, Any] | None = None
    created_at: datetime
    last_used_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)


class PatCreateResponse(BaseModel):
    identity_id: int
    pat: str  # plaintext, shown once
    prefix: str


# --- Auth0 IdP sync ---


class McpAuth0SyncRequest(BaseModel):
    team_id: int
    dry_run: bool = False
    require_verified_email: bool = False


class McpAuth0SyncResponse(BaseModel):
    created: int
    updated: int
    skipped: int
    total_users: int
    errors: list[str]
    dry_run: bool
    team_id: int


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
    expression_ast: dict[str, Any] | None = None
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
    detector: str = Field(
        pattern="^(email|phone|ssn|credit_card|ip|aws_key|private_key|github_token|slack_token|custom)$"
    )
    find_regex: str | None = None
    action: str = Field(default="block", pattern="^(block|redact|tokenize)$")
    token_prefix: str | None = None
    token_ttl: int | None = None
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
    find_regex: str | None = None
    action: str
    token_prefix: str | None = None
    token_ttl: int | None = None
    apply_to: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpSkill ---


class McpSkillBase(BaseModel):
    team_id: int
    name: str = Field(pattern=r"^[a-z0-9-]+$")
    description: str | None = None
    enabled: bool = True
    enable_when: str | None = None
    tags: list[str] | None = None


class McpSkillCreate(McpSkillBase):
    pass


McpSkillUpdate = _optional_update(McpSkillBase)


class McpSkillResponse(BaseModel):
    id: int
    team_id: int
    name: str
    description: str | None = None
    enabled: bool
    enable_when: str | None = None
    enable_when_ast: dict[str, Any] | None = None
    tags: list[str] | None = None
    published_version_id: int | None = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpSkillVersion ---


class McpSkillVersionBase(BaseModel):
    frontmatter: dict[str, Any] | None = None
    body: str
    files: list[dict[str, Any]] | None = None


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
    name: str | None = Field(None, description="Override skill name (defaults to frontmatter name or repo name)")
    description: str | None = None
    tags: list[str] | None = None
    auto_publish: bool = True


class McpSkillVersionResponse(BaseModel):
    id: int
    skill_id: int
    version: int
    frontmatter: dict[str, Any] | None = None
    body: str
    files: list[dict[str, Any]] | None = None
    created_by: str | None = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- McpGuardrail ---


class McpGuardrailBase(BaseModel):
    team_id: int
    name: str
    enabled: bool = True
    direction: str = Field(default="both", pattern="^(request|response|both)$")
    pack: str = Field(
        default="custom", pattern="^(builtin:jailbreak_v1|builtin:instruction_override|builtin:obfuscation|custom)$"
    )
    find_regex: str | None = None
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
    find_regex: str | None = None
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
    version: str | None = None
    status: str
    output: str | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# --- Marketplace ---


class MarketplaceSearchResult(BaseModel):
    name: str
    description: str | None = None
    version: str | None = None
    homepage: str | None = None
    repository_url: str | None = None
    author: str | None = None
    license: str | None = None
    keywords: list[str] | None = None
    downloads: int | None = None
    score: float | None = None


class MarketplacePackageDetails(BaseModel):
    name: str
    version: str | None = None
    description: str | None = None
    homepage: str | None = None
    repository_url: str | None = None
    author: str | None = None
    license: str | None = None
    keywords: list[str] | None = None
    dependencies: dict[str, str] | None = None
    readme: str | None = None
    required_env_vars: list[str] | None = None


class MarketplaceInstallRequest(BaseModel):
    package_manager: str = Field(pattern="^(npm|pypi)$")
    package_name: str
    version: str | None = None
    team_id: int
    name: str | None = None  # server name, defaults to package name
    namespace: str | None = None
    display_name: str | None = None
    env_vars: dict[str, str] | None = None
    custom_args: list[str] | None = None


class MarketplaceUninstallRequest(BaseModel):
    server_id: int


class DiscoverEnvVarsRequest(BaseModel):
    package_manager: str = Field(pattern="^(npm|pypi)$")
    package_name: str


class DiscoverEnvVarsResponse(BaseModel):
    env_vars: list[str] = []


# --- Upstream OAuth ---


class OAuthDiscoverRequest(BaseModel):
    url: str
    transport_type: str = Field(default="streamable_http", pattern="^(streamable_http|stdio)$")


class OAuthDiscoverResponse(BaseModel):
    authorization_servers: list[str] | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    registration_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None


class OAuthConfigureRequest(BaseModel):
    client_id: str
    client_secret: str
    scopes: str | None = None
    auth_server_metadata_url: str | None = None
    protected_resource_metadata_url: str | None = None


class OAuthStatusResponse(BaseModel):
    enabled: bool = False
    auth_status: str | None = None
    client_id: str | None = None
    scopes: str | None = None
    token_expires_at: datetime | None = None
    authorization_url: str | None = None


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
    request_id: str | None = None
    session_id: str | None = None
    identity_id: int | None = None
    identity_name: str | None = None
    team_id: int | None = None
    team_name: str | None = None
    server_id: int | None = None
    server_name: str | None = None
    jsonrpc_method: str | None = None
    tool: str | None = None
    resource_uri: str | None = None
    prompt: str | None = None
    action: str | None = None
    status: str | None = None
    latency_ms: int | None = None
    error: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    dlp_hits: Any | None = None
    guardrail_hits: Any | None = None
    model_config = ConfigDict(from_attributes=True)


class McpEventListResponse(BaseModel):
    events: list[McpEventResponse]
    total: int


# --- Session ---


class SessionInfo(BaseModel):
    session_id: str
    identity_id: int
    team_id: int | None = None
    created_at: str
    last_activity: str | None = None
    server_sessions: dict[str, str] | None = None


class SessionListResponse(BaseModel):
    sessions: list[SessionInfo]
    total: int


# --- Config Status ---


class ConfigStatusResponse(BaseModel):
    last_generated: str | None = None
    bundle_size: int | None = None
    config_path: str | None = None


# --- Alert Config ---


class AlertConfigResponse(BaseModel):
    webhook_url: str | None = None
    thresholds: dict[str, int] = {}


class AlertConfigUpdate(BaseModel):
    webhook_url: str | None = None
    thresholds: dict[str, int] = {}


class AlertHistoryItem(BaseModel):
    id: int
    event_type: str
    message: str
    created_at: datetime
    webhook_sent: bool = False
    webhook_status: int | None = None


# --- Server Catalog ---


class ServerCatalogResponse(BaseModel):
    server_id: int
    tools: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    last_refresh: str | None = None


class McpServerTestResponse(BaseModel):
    ok: bool
    error: str | None = None
    tools: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []


# --- Policy Validation ---


class McpPolicyValidateRequest(BaseModel):
    expression: str


class McpPolicyValidateResponse(BaseModel):
    ok: bool
    ast: dict[str, Any] | None = None
    error: str | None = None


# --- Regex Validation (DLP / guardrail custom patterns) ---


class McpRegexValidateRequest(BaseModel):
    pattern: str
    """The regex pattern to validate."""
    flags: str = ""
    """Optional flags: 'i' (case-insensitive), 'm' (multi-line). Defaults to the
    flags the gateway applies (case-insensitive for DLP, case-insensitive +
    multi-line for guardrails)."""


class McpRegexValidateResponse(BaseModel):
    ok: bool
    error: str | None = None
    """Human-readable reason when ok=False (invalid syntax, ReDoS risk, or
    unsupported Rust regex feature)."""
    redos_risk: bool = False
    rust_compatible: bool = True
    """False if the pattern uses features Rust's `regex` crate does not support
    (backreferences, lookaround, possessive quantifiers, atomic groups)."""


# --- Policy Builder Metadata ---


class McpPolicyBuilderServer(BaseModel):
    id: int
    namespace: str
    name: str
    last_catalog_at: str | None = None
    stale: bool = True


class McpPolicyBuilderTeam(BaseModel):
    id: int
    name: str
    slug: str


class McpPolicyBuilderMetadataResponse(BaseModel):
    methods: list[str] = []
    servers: list[McpPolicyBuilderServer] = []
    stale_servers: list[McpPolicyBuilderServer] = []
    tools: list[str] = []
    resources: list[str] = []
    prompts: list[str] = []
    identities: list[str] = []
    identity_kinds: list[str] = []
    teams: list[McpPolicyBuilderTeam] = []
    refreshing: bool = False


# --- Gateway Status ---


class GatewayMetricsSnapshot(BaseModel):
    requests_total: int = 0
    auth_success_total: int = 0
    auth_failure_total: int = 0
    policy_denied_total: int = 0
    rate_limited_total: int = 0
    dlp_blocked_total: int = 0
    guardrail_blocked_total: int = 0
    upstream_errors_total: int = 0
    tools_listed_total: int = 0
    tools_called_total: int = 0
    latency_sum_ms: int = 0
    latency_count: int = 0
    latency_buckets: list[dict[str, Any]] = []
    latency_inf_bucket: int = 0


class GatewayCircuitState(BaseModel):
    server_id: int
    failures: int
    open_until: float


class GatewayCatalogFreshness(BaseModel):
    server_id: int
    fetched_at: float
    tools: int
    resources: int
    prompts: int


class GatewayAlertState(BaseModel):
    event_type: str
    recent_count: int
    threshold: int
    last_alert_ts: float | None = None


class GatewayStatusResponse(BaseModel):
    status: str = "ok"
    configured: bool = False
    backend: str = "python"
    reachable: bool = False
    metrics: GatewayMetricsSnapshot | None = None
    active_sessions: int = 0
    open_circuits: list[GatewayCircuitState] = []
    catalog_freshness: list[GatewayCatalogFreshness] = []
    alerts: list[GatewayAlertState] = []
    error: str | None = None


class ServerHealthResponse(BaseModel):
    server_id: int
    status: str = "unknown"
    error: str | None = None
    checked_at: float | None = None


__all__ = [
    "TeamBase",
    "TeamCreate",
    "TeamUpdate",
    "TeamResponse",
    "UserTeamBase",
    "UserTeamCreate",
    "UserTeamResponse",
    "McpServerBase",
    "McpServerCreate",
    "McpServerUpdate",
    "McpServerResponse",
    "McpServerReplicaBase",
    "McpServerReplicaCreate",
    "McpServerReplicaUpdate",
    "McpServerReplicaResponse",
    "McpIdentityBase",
    "McpIdentityCreate",
    "McpIdentityUpdate",
    "McpIdentityResponse",
    "PatCreateResponse",
    "McpPolicyBase",
    "McpPolicyCreate",
    "McpPolicyUpdate",
    "McpPolicyResponse",
    "McpDlpRuleBase",
    "McpDlpRuleCreate",
    "McpDlpRuleUpdate",
    "McpDlpRuleResponse",
    "McpSkillBase",
    "McpSkillCreate",
    "McpSkillUpdate",
    "McpSkillResponse",
    "McpSkillVersionBase",
    "McpSkillVersionCreate",
    "McpSkillVersionResponse",
    "McpSkillImportRequest",
    "McpGuardrailBase",
    "McpGuardrailCreate",
    "McpGuardrailUpdate",
    "McpGuardrailResponse",
    "McpInstallationResponse",
    "MarketplaceSearchResult",
    "MarketplacePackageDetails",
    "MarketplaceInstallRequest",
    "MarketplaceUninstallRequest",
    "DiscoverEnvVarsRequest",
    "DiscoverEnvVarsResponse",
    "OAuthDiscoverRequest",
    "OAuthDiscoverResponse",
    "OAuthConfigureRequest",
    "OAuthStatusResponse",
    "OAuthAuthorizeResponse",
    "SkillExportResponse",
    "McpEventResponse",
    "McpEventListResponse",
    "SessionInfo",
    "SessionListResponse",
    "ConfigStatusResponse",
    "AlertConfigResponse",
    "AlertConfigUpdate",
    "AlertHistoryItem",
    "ServerCatalogResponse",
    "McpServerTestResponse",
    "McpPolicyValidateRequest",
    "McpPolicyValidateResponse",
    "McpPolicyBuilderServer",
    "McpPolicyBuilderTeam",
    "McpPolicyBuilderMetadataResponse",
    "McpRegexValidateRequest",
    "McpRegexValidateResponse",
    "GatewayMetricsSnapshot",
    "GatewayCircuitState",
    "GatewayCatalogFreshness",
    "GatewayAlertState",
    "GatewayStatusResponse",
    "ServerHealthResponse",
]
