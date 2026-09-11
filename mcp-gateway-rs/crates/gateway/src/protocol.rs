//! MCP protocol handler — Streamable HTTP JSON-RPC endpoint.
//!
//! Implements MCP spec 2025-11-25:
//! - POST /mcp: JSON-RPC request/notification/response
//! - Session management via Mcp-Session-Id header
//! - Virtual registry: merged tools/resources/prompts with namespace prefixing
//! - Catalog-based list responses
//! - Resource URI wrapping: mcp://{namespace}/{original_uri}
//! - Policy, DLP, guardrail, rate-limit enforcement
//! - Discovery modes (passthrough, meta-tools, hybrid)
//! - Meta-tools (list_servers, list_tools, search_tools, describe_tool, refresh_tools)
//! - Skills as virtual prompts
//! - resources/subscribe, resources/unsubscribe, notifications/resources/updated
//! - completion/complete
//! - list_changed notifications (actually emitted, fixing the Python advertisement bug)

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use corex_core::config::{ConfigBundle, ServerConfig};
use corex_policy::auth::AuthContext;
use corex_policy::policy::{
    check_prompt_access, check_resource_access, check_tool_access, filter_prompt_list,
    filter_resource_list, filter_tool_list, PolicyEngine,
};
use corex_policy::ratelimit::{get_team_rpm, RateLimiter};
use corex_policy::revocation::RevocationStore;
use corex_policy::sessions::SessionStore;
use corex_scan::dlp::{self, CompiledDlpRule};
use corex_scan::guardrails::{self, CompiledGuardrailRule};

use crate::alerting::Alerter;
use crate::discovery::{
    execute_meta_tool, is_meta_tool, meta_tool_definitions, visible_servers, DiscoveryMode,
};
use crate::events::{Event, EventLogger};
use crate::metrics::Metrics;
use crate::skills::SkillsRegistry;
use corex_proxy::{CatalogStore, ProcessManager, UpstreamClient};

pub const PROTOCOL_VERSION: &str = "2025-11-25";
#[allow(dead_code)]
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2024-11-05"];

// JSON-RPC error codes.
#[allow(dead_code)]
pub const JSONRPC_PARSE_ERROR: i32 = -32700;
pub const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub const MCP_GATEWAY_ERROR: i32 = -32000;
pub const MCP_POLICY_DENIED: i32 = -32010;
pub const MCP_RATE_LIMITED: i32 = -32029;
pub const MCP_DLP_BLOCKED: i32 = -32020;
pub const MCP_GUARDRAIL_BLOCKED: i32 = -32021;

/// Shared gateway state.
#[derive(Clone)]
pub struct GatewayState {
    pub config: Arc<parking_lot::RwLock<Option<ConfigBundle>>>,
    pub policy_engine: Arc<parking_lot::RwLock<PolicyEngine>>,
    pub dlp_rules: Arc<parking_lot::RwLock<Vec<CompiledDlpRule>>>,
    pub guardrail_rules: Arc<parking_lot::RwLock<Vec<CompiledGuardrailRule>>>,
    pub skills: SkillsRegistry,
    pub upstream: UpstreamClient,
    pub stdio: ProcessManager,
    pub catalog_store: Arc<CatalogStore>,
    pub sessions: SessionStore,
    pub revocation: RevocationStore,
    pub rate_limiter: RateLimiter,
    pub brute: Arc<corex_policy::auth::BruteForceState>,
    pub jwks: Arc<corex_policy::auth::JwksCache>,
    pub events: EventLogger,
    pub alerter: Alerter,
    pub metrics: Metrics,
}

impl GatewayState {
    /// Get the current config bundle.
    pub fn config(&self) -> Option<ConfigBundle> {
        self.config.read().clone()
    }

    /// Get enabled servers for a team.
    pub fn team_servers(&self, team_id: i64) -> Vec<ServerConfig> {
        let config = self.config.read();
        match config.as_ref() {
            Some(c) => c.servers.iter().filter(|s| s.enabled && s.team_id == team_id).cloned().collect(),
            None => vec![],
        }
    }

    /// Get the discovery mode for a team.
    pub fn discovery_mode(&self, team_id: i64) -> DiscoveryMode {
        let config = self.config.read();
        match config.as_ref() {
            Some(c) => {
                let team = c.teams.iter().find(|t| t.id == team_id);
                match team.and_then(|t| t.discovery_mode.as_deref()) {
                    Some(mode) => DiscoveryMode::parse(mode),
                    None => DiscoveryMode::Passthrough,
                }
            }
            None => DiscoveryMode::Passthrough,
        }
    }

    /// Find a server by namespace within a team.
    pub fn server_by_namespace(&self, namespace: &str, team_id: i64) -> Option<ServerConfig> {
        let config = self.config.read();
        config
            .as_ref()?
            .servers
            .iter()
            .find(|s| s.namespace == namespace && s.team_id == team_id && s.enabled)
            .cloned()
    }

    /// Look up an identity name by ID from the config bundle.
    pub fn identity_name(&self, identity_id: i64) -> Option<String> {
        let config = self.config.read();
        config
            .as_ref()?
            .identities
            .iter()
            .find(|i| i.id == identity_id)
            .map(|i| i.name.clone())
    }

    /// Look up a team name by ID from the config bundle.
    pub fn team_name(&self, team_id: i64) -> Option<String> {
        let config = self.config.read();
        config
            .as_ref()?
            .teams
            .iter()
            .find(|t| t.id == team_id)
            .map(|t| t.name.clone())
    }

    /// Look up a server name by ID from the config bundle.
    pub fn server_name(&self, server_id: i64) -> Option<String> {
        let config = self.config.read();
        config
            .as_ref()?
            .servers
            .iter()
            .find(|s| s.id == server_id)
            .map(|s| s.name.clone())
    }
}

/// Build a JSON-RPC error response.
pub fn error_response(id: &Value, code: i32, message: &str, status: StatusCode) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message}
        })),
    )
        .into_response()
}

/// Build a JSON-RPC success response.
pub fn success_response(id: &Value, result: Value) -> Response {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })),
    )
        .into_response()
}

/// Check if a message is a notification (no "id" field).
fn is_notification(body: &Value) -> bool {
    !body.as_object().map(|m| m.contains_key("id")).unwrap_or(false)
}

/// Check if a message is a response (has "result" or "error" but no "method").
fn is_response(body: &Value) -> bool {
    let obj = match body.as_object() {
        Some(o) => o,
        None => return false,
    };
    !obj.contains_key("method") && (obj.contains_key("result") || obj.contains_key("error"))
}

/// Prefix a tool/prompt name: {namespace}__{name}.
pub fn prefix_name(namespace: &str, name: &str) -> String {
    format!("{namespace}__{name}")
}

/// Wrap an upstream resource URI: mcp://{namespace}/{urlquoted original}.
pub fn wrap_resource_uri(namespace: &str, original_uri: &str) -> String {
    use urlencoding::encode;
    format!("mcp://{namespace}/{}", encode(original_uri))
}

/// Unwrap a wrapped resource URI -> (namespace, original_uri).
pub fn unwrap_resource_uri(wrapped: &str) -> (Option<String>, String) {
    if !wrapped.starts_with("mcp://") {
        return (None, wrapped.to_string());
    }
    let rest = &wrapped[6..]; // strip "mcp://"
    match rest.find('/') {
        Some(idx) => {
            let namespace = rest[..idx].to_string();
            let original = urlencoding::decode(&rest[idx + 1..])
                .map(|s| s.to_string())
                .unwrap_or_else(|_| rest[idx + 1..].to_string());
            (Some(namespace), original)
        }
        None => (None, wrapped.to_string()),
    }
}

/// Prefix names in a list of items (tools, prompts).
pub fn prefix_list_items(items: &[Value], namespace: &str) -> Vec<Value> {
    items
        .iter()
        .map(|item| {
            let mut prefixed = item.clone();
            if let Some(name) = prefixed.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                prefixed["name"] = Value::String(prefix_name(namespace, &name));
                let mut meta = map_to_obj(prefixed.get("_meta").cloned().unwrap_or(Value::Object(Default::default())));
                meta.insert("mcp_server".into(), Value::String(namespace.to_string()));
                meta.insert("mcp_original_name".into(), Value::String(name));
                prefixed["_meta"] = Value::Object(meta);
            }
            prefixed
        })
        .collect()
}

fn map_to_obj(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Default::default(),
    }
}

/// Main POST /mcp handler.
pub async fn handle_post(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.metrics.inc_requests();

    // Check gateway is configured.
    let config = match state.config() {
        Some(c) => c,
        None => {
            return error_response(
                &Value::Null,
                MCP_GATEWAY_ERROR,
                "MCP gateway disabled or not configured",
                StatusCode::SERVICE_UNAVAILABLE,
            )
        }
    };

    // Validate Origin.
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !origin.is_empty() && !check_origin(&config, origin) {
        return error_response(
            &Value::Null,
            MCP_GATEWAY_ERROR,
            "Invalid Origin",
            StatusCode::FORBIDDEN,
        );
    }

    // Extract client IP.
    let client_ip = extract_client_ip(&headers);

    // Per-IP rate limiting (before auth).
    let ip_limit = config.per_ip_limit as i64;
    let ip_decision = state.rate_limiter.check_ip_rate_limit(&client_ip, Some(ip_limit)).await;
    if !ip_decision.allowed {
        state.metrics.inc_rate_limited();
        return error_response(&Value::Null, MCP_RATE_LIMITED, "IP rate limit exceeded", StatusCode::OK);
    }

    // Authenticate.
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !auth_header.starts_with("Bearer ") {
        return unauthorized_response(&headers);
    }
    let token = &auth_header[7..];
    let auth_ctx = match corex_policy::auth::authenticate(
        token,
        &config,
        &client_ip,
        &state.brute,
        &state.jwks,
        &state.revocation,
    )
    .await
    {
        Ok(ctx) => {
            state.metrics.inc_auth_success();
            ctx
        }
        Err(_) => {
            state.metrics.inc_auth_failure();
            state.alerter.record_event("auth_failed");
            return unauthorized_response(&headers);
        }
    };

    // Parse message fields.
    let msg_id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(Value::Object(Default::default()));

    // Notifications/responses → 202 Accepted.
    if is_notification(&body) || is_response(&body) {
        let session_id = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !session_id.is_empty() && !method.is_empty() {
            handle_notification(&state, session_id, method, &params, &auth_ctx).await;
        }
        return StatusCode::ACCEPTED.into_response();
    }

    // It's a request — must have method.
    if method.is_empty() {
        return error_response(&msg_id, JSONRPC_INVALID_REQUEST, "Invalid Request", StatusCode::BAD_REQUEST);
    }

    // Session handling.
    let session_id = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).unwrap_or("");

    // initialize creates the session.
    if method == "initialize" {
        return handle_initialize(&state, &msg_id, &params, &auth_ctx).await;
    }

    // All other requests require a valid session.
    if session_id.is_empty() {
        return error_response(
            &msg_id,
            MCP_GATEWAY_ERROR,
            "Invalid or missing session. Call initialize first.",
            StatusCode::BAD_REQUEST,
        );
    }
    let session_data = match state.sessions.get(session_id).await {
        Some(d) => d,
        None => {
            return error_response(
                &msg_id,
                MCP_GATEWAY_ERROR,
                "Invalid or missing session. Call initialize first.",
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if session_data.identity_id != auth_ctx.identity_id {
        return error_response(&msg_id, MCP_GATEWAY_ERROR, "Session identity mismatch", StatusCode::FORBIDDEN);
    }
    state.sessions.refresh(session_id).await;

    // Route to handler.
    match method {
        "ping" | "logging/setLevel" => success_response(&msg_id, serde_json::json!({})),
        "tools/list" => handle_tools_list(&state, &msg_id, &auth_ctx).await,
        "resources/list" => handle_resources_list(&state, &msg_id, &auth_ctx).await,
        "resources/templates/list" => handle_resources_templates_list(&state, &msg_id, &auth_ctx).await,
        "prompts/list" => handle_prompts_list(&state, &msg_id, &auth_ctx).await,
        "tools/call" => handle_call(&state, session_id, &msg_id, &params, &auth_ctx, "tool").await,
        "resources/read" => handle_call(&state, session_id, &msg_id, &params, &auth_ctx, "resource").await,
        "prompts/get" => handle_call(&state, session_id, &msg_id, &params, &auth_ctx, "prompt").await,
        "resources/subscribe" => handle_resource_subscribe(&state, &msg_id, &params, &auth_ctx).await,
        "resources/unsubscribe" => handle_resource_unsubscribe(&state, &msg_id, &params, &auth_ctx).await,
        "completion/complete" => handle_completion(&state, &msg_id, &params, &auth_ctx).await,
        _ => error_response(
            &msg_id,
            JSONRPC_METHOD_NOT_FOUND,
            &format!("Method not found: {method}"),
            StatusCode::OK,
        ),
    }
}

/// GET /mcp — SSE listen (405 in v1; we don't offer unsolicited server messages).
pub async fn handle_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [
            ("allow", "POST"),
            ("content-type", "application/json"),
        ],
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": MCP_GATEWAY_ERROR, "message": "SSE not supported in v1"}
        })),
    )
        .into_response()
}

/// OPTIONS /mcp — CORS preflight.
pub async fn handle_options(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
    let config = state.config();
    let allowed = config
        .as_ref()
        .map(|c| c.allowed_origins.clone())
        .unwrap_or_default();
    if !origin.is_empty() && allowed.iter().any(|o| o == origin) {
        return (
            StatusCode::NO_CONTENT,
            [
                ("access-control-allow-origin", origin),
                ("access-control-allow-methods", "POST, GET, OPTIONS"),
                ("access-control-allow-headers", "Authorization, Content-Type, Mcp-Session-Id"),
                ("access-control-max-age", "3600"),
            ],
        )
            .into_response();
    }
    StatusCode::FORBIDDEN.into_response()
}

fn unauthorized_response(headers: &HeaderMap) -> Response {
    let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    let scheme = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("https");
    let resource_metadata = format!("{scheme}://{host}/.well-known/oauth-protected-resource");
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", format!("Bearer realm=\"mcp\", resource_metadata=\"{resource_metadata}\""))],
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": MCP_GATEWAY_ERROR, "message": "Unauthorized"}
        })),
    )
        .into_response()
}

fn check_origin(config: &ConfigBundle, origin: &str) -> bool {
    if config.allowed_origins.is_empty() {
        return true; // No restriction if not configured.
    }
    config.allowed_origins.iter().any(|o| o == origin)
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Handle initialize — create session, init upstreams, merge capabilities.
async fn handle_initialize(
    state: &GatewayState,
    msg_id: &Value,
    _params: &Value,
    auth: &AuthContext,
) -> Response {
    let servers = state.team_servers(auth.team_id);

    // Initialize upstream sessions and check catalogs for capabilities.
    let mut has_tools = false;
    let mut has_resources = false;
    let mut has_prompts = false;

    for server in &servers {
        let _upstream_sid = if server.transport_type == "stdio" {
            state.stdio.initialize_upstream(server).await
        } else {
            state.upstream.initialize(server).await
        };
        // Check catalog for capabilities.
        if let Some(catalog) = state.catalog_store.get(server.id).await {
            if !catalog.tools.is_empty() {
                has_tools = true;
            }
            if !catalog.resources.is_empty() {
                has_resources = true;
            }
            if !catalog.prompts.is_empty() {
                has_prompts = true;
            }
        }
    }

    // Create session.
    let session_id = state.sessions.create(auth.identity_id, auth.team_id).await;

    // Build capabilities.
    let mut capabilities = serde_json::Map::new();
    let discovery_mode = state.discovery_mode(auth.team_id);
    if has_tools || discovery_mode != DiscoveryMode::Passthrough {
        capabilities.insert("tools".into(), serde_json::json!({"listChanged": true}));
    }
    if has_resources {
        // subscribe: true (we now support it, fixing the Python bug).
        capabilities.insert("resources".into(), serde_json::json!({"listChanged": true, "subscribe": true}));
    }
    if has_prompts || state.skills.has_skills() {
        capabilities.insert("prompts".into(), serde_json::json!({"listChanged": true}));
    }
    capabilities.insert("logging".into(), serde_json::json!({}));

    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": capabilities,
            "serverInfo": {"name": "mcp-gateway", "version": "0.2.0"},
        }
    });

    let mut resp = (StatusCode::OK, axum::Json(response)).into_response();
    if let Ok(val) = axum::http::HeaderValue::from_str(&session_id) {
        resp.headers_mut().insert("mcp-session-id", val);
    }
    resp
}

/// Handle tools/list — merge tools from catalogs with namespace prefixing.
async fn handle_tools_list(state: &GatewayState, msg_id: &Value, auth: &AuthContext) -> Response {
    state.metrics.inc_tools_listed();
    let servers = state.team_servers(auth.team_id);
    let discovery_mode = state.discovery_mode(auth.team_id);
    let visible = visible_servers(&servers, discovery_mode);
    let policy_engine = state.policy_engine.read().clone();

    let mut merged_tools: Vec<Value> = Vec::new();
    let mut warnings: Vec<Value> = Vec::new();

    for server in &visible {
        let catalog = match state.catalog_store.get(server.id).await {
            Some(c) => c,
            None => {
                warnings.push(serde_json::json!({"server": server.namespace, "error": "catalog not available"}));
                continue;
            }
        };
        let ns = &server.namespace;
        let prefixed = prefix_list_items(&catalog.tools, ns);
        let filtered = filter_tool_list(&prefixed, ns, auth, "", &policy_engine);
        merged_tools.extend(filtered);
    }

    // Inject meta-tools if discovery mode is meta-tools or hybrid.
    if discovery_mode != DiscoveryMode::Passthrough {
        merged_tools.extend(meta_tool_definitions());
    }

    let mut result = serde_json::Map::new();
    result.insert("tools".into(), Value::Array(merged_tools));
    if !warnings.is_empty() {
        result.insert("_meta".into(), serde_json::json!({"warnings": warnings}));
    }
    success_response(msg_id, Value::Object(result))
}

/// Handle resources/list — merge resources with URI wrapping.
async fn handle_resources_list(state: &GatewayState, msg_id: &Value, auth: &AuthContext) -> Response {
    let servers = state.team_servers(auth.team_id);
    let discovery_mode = state.discovery_mode(auth.team_id);
    let visible = visible_servers(&servers, discovery_mode);
    let policy_engine = state.policy_engine.read().clone();

    let mut merged: Vec<Value> = Vec::new();
    let mut warnings: Vec<Value> = Vec::new();

    for server in &visible {
        let catalog = match state.catalog_store.get(server.id).await {
            Some(c) => c,
            None => {
                warnings.push(serde_json::json!({"server": server.namespace, "error": "catalog not available"}));
                continue;
            }
        };
        let ns = &server.namespace;
        let wrapped: Vec<Value> = catalog
            .resources
            .iter()
            .map(|res| {
                let mut prefixed = res.clone();
                if let Some(uri) = prefixed.get("uri").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                    prefixed["uri"] = Value::String(wrap_resource_uri(ns, &uri));
                    let mut meta = map_to_obj(prefixed.get("_meta").cloned().unwrap_or(Value::Object(Default::default())));
                    meta.insert("mcp_server".into(), Value::String(ns.to_string()));
                    meta.insert("mcp_original_uri".into(), Value::String(uri));
                    prefixed["_meta"] = Value::Object(meta);
                }
                prefixed
            })
            .collect();
        let filtered = filter_resource_list(&wrapped, ns, auth, "", &policy_engine);
        merged.extend(filtered);
    }

    let mut result = serde_json::Map::new();
    result.insert("resources".into(), Value::Array(merged));
    if !warnings.is_empty() {
        result.insert("_meta".into(), serde_json::json!({"warnings": warnings}));
    }
    success_response(msg_id, Value::Object(result))
}

/// Handle resources/templates/list.
async fn handle_resources_templates_list(state: &GatewayState, msg_id: &Value, auth: &AuthContext) -> Response {
    let servers = state.team_servers(auth.team_id);
    let discovery_mode = state.discovery_mode(auth.team_id);
    let visible = visible_servers(&servers, discovery_mode);

    let mut merged: Vec<Value> = Vec::new();
    for server in &visible {
        let catalog = match state.catalog_store.get(server.id).await {
            Some(c) => c,
            None => continue,
        };
        let ns = &server.namespace;
        for res in &catalog.resources {
            if let Some(template) = res.get("uriTemplate").and_then(|v| v.as_str()) {
                let mut prefixed = res.clone();
                prefixed["uriTemplate"] = Value::String(wrap_resource_uri(ns, template));
                let mut meta = map_to_obj(prefixed.get("_meta").cloned().unwrap_or(Value::Object(Default::default())));
                meta.insert("mcp_server".into(), Value::String(ns.to_string()));
                prefixed["_meta"] = Value::Object(meta);
                merged.push(prefixed);
            }
        }
    }

    success_response(msg_id, serde_json::json!({"resourceTemplates": merged}))
}

/// Handle prompts/list — merge prompts with namespace prefixing, inject skills.
async fn handle_prompts_list(state: &GatewayState, msg_id: &Value, auth: &AuthContext) -> Response {
    let servers = state.team_servers(auth.team_id);
    let discovery_mode = state.discovery_mode(auth.team_id);
    let visible = visible_servers(&servers, discovery_mode);
    let policy_engine = state.policy_engine.read().clone();

    let mut merged: Vec<Value> = Vec::new();
    let mut warnings: Vec<Value> = Vec::new();

    for server in &visible {
        let catalog = match state.catalog_store.get(server.id).await {
            Some(c) => c,
            None => {
                warnings.push(serde_json::json!({"server": server.namespace, "error": "catalog not available"}));
                continue;
            }
        };
        let ns = &server.namespace;
        let prefixed = prefix_list_items(&catalog.prompts, ns);
        let filtered = filter_prompt_list(&prefixed, ns, auth, "", &policy_engine);
        merged.extend(filtered);
    }

    // Inject enabled skills as virtual prompts.
    if state.skills.has_skills() {
        for skill in state.skills.get_enabled_skills(auth) {
            merged.push(SkillsRegistry::build_prompt_entry(&skill));
        }
    }

    let mut result = serde_json::Map::new();
    result.insert("prompts".into(), Value::Array(merged));
    if !warnings.is_empty() {
        result.insert("_meta".into(), serde_json::json!({"warnings": warnings}));
    }
    success_response(msg_id, Value::Object(result))
}

/// Handle a call (tools/call, resources/read, prompts/get) — route by namespace.
async fn handle_call(
    state: &GatewayState,
    session_id: &str,
    msg_id: &Value,
    params: &Value,
    auth: &AuthContext,
    kind: &str,
) -> Response {
    // Derive the JSON-RPC method from the call kind for event logging.
    let method = match kind {
        "resource" => "resources/read",
        "prompt" => "prompts/get",
        _ => "tools/call",
    };
    let name = params
        .get("name")
        .or_else(|| params.get("uri"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Compute request payload size for event logging.
    let bytes_in = serde_json::to_string(params).map(|s| s.len() as u64).ok();

    // Handle meta-tools.
    if kind == "tool" && is_meta_tool(name) {
        return handle_meta_tool_call(state, msg_id, params, auth).await;
    }

    // Determine namespace and original name.
    let (namespace, original_name) = if kind == "resource" {
        let (ns, orig) = unwrap_resource_uri(name);
        match ns {
            Some(n) => (n, orig),
            None => {
                // Fall back to '__' split.
                match name.split_once("__") {
                    Some((n, o)) => (n.to_string(), o.to_string()),
                    None => {
                        return error_response(
                            msg_id,
                            JSONRPC_METHOD_NOT_FOUND,
                            "Missing namespace in resource URI",
                            StatusCode::OK,
                        )
                    }
                }
            }
        }
    } else {
        match name.split_once("__") {
            Some((n, o)) => (n.to_string(), o.to_string()),
            None => {
                return error_response(
                    msg_id,
                    JSONRPC_METHOD_NOT_FOUND,
                    &format!("Missing namespace prefix in {kind} name"),
                    StatusCode::OK,
                )
            }
        }
    };

    // Handle skill namespace — render locally.
    if namespace == "skill" && kind == "prompt" {
        if let Some(skill) = state.skills.get_skill_by_name(&original_name) {
            if skill.published_version_id.is_none() {
                return error_response(
                    msg_id,
                    JSONRPC_METHOD_NOT_FOUND,
                    &format!("Skill not published: {original_name}"),
                    StatusCode::OK,
                );
            }
            let mut rendered = SkillsRegistry::render_skill_prompt(&skill);
            rendered["id"] = msg_id.clone();
            return (StatusCode::OK, axum::Json(rendered)).into_response();
        }
        return error_response(
            msg_id,
            JSONRPC_METHOD_NOT_FOUND,
            &format!("Unknown skill: {original_name}"),
            StatusCode::OK,
        );
    }

    // Find server.
    let server = match state.server_by_namespace(&namespace, auth.team_id) {
        Some(s) => s,
        None => {
            return error_response(
                msg_id,
                JSONRPC_METHOD_NOT_FOUND,
                &format!("Unknown namespace: {namespace}"),
                StatusCode::OK,
            )
        }
    };

    // Call-time policy evaluation.
    let policy_engine = state.policy_engine.read().clone();
    let call_args = if kind == "tool" { params.get("arguments") } else { None };
    let pr = if kind == "tool" {
        check_tool_access("tools/call", name, &namespace, auth, call_args, "", &policy_engine)
    } else if kind == "resource" {
        check_resource_access("resources/read", name, &namespace, auth, "", &policy_engine)
    } else {
        check_prompt_access("prompts/get", name, &namespace, auth, "", &policy_engine)
    };

    let req_id = EventLogger::generate_request_id();

    if pr.denied() {
        state.metrics.inc_policy_denied();
        state.alerter.record_event("policy_denied");
        log_event(
            state, &req_id, session_id, auth, Some(server.id), method,
            name, kind, "deny", "policy_denied",
            &format!("Policy denied: {}", pr.rule_name), None, bytes_in, None,
        );
        return error_response(msg_id, MCP_POLICY_DENIED, &format!("Policy denied: {}", pr.rule_name), StatusCode::OK);
    }

    // Rate limiting.
    if !pr.skip_ratelimit {
        let config = state.config();
        let default_rpm = config.as_ref().map(|c| c.default_rpm as i64).unwrap_or(600);
        let max_rpm = config
            .as_ref()
            .map(|c| get_team_rpm(&c.team_rpm_overrides, auth.team_id, default_rpm))
            .unwrap_or(default_rpm);
        let decision = state.rate_limiter.check_rate_limit(auth.identity_id, name, max_rpm).await;
        if !decision.allowed {
            state.metrics.inc_rate_limited();
            state.alerter.record_event("rate_limited");
            log_event(
                state, &req_id, session_id, auth, Some(server.id), method,
                name, kind, "rate_limited", "rate_limited",
                &format!("Rate limit exceeded for {name}"), None, bytes_in, None,
            );
            return error_response(msg_id, MCP_RATE_LIMITED, &format!("Rate limit exceeded for {name}"), StatusCode::OK);
        }
    }

    // DLP request scanning.
    let mut forward_params = params.clone();
    if !pr.skip_dlp {
        let dlp_rules = state.dlp_rules.read().clone();
        if !dlp_rules.is_empty() {
            let scan_result = dlp::scan_request(&forward_params, &dlp_rules, None);
            if scan_result.blocked {
                state.metrics.inc_dlp_blocked();
                state.alerter.record_event("dlp_blocked");
                log_event(
                    state, &req_id, session_id, auth, Some(server.id), method,
                    name, kind, "dlp_blocked", "dlp_blocked",
                    "DLP blocked in request", None, bytes_in, None,
                );
                return error_response(msg_id, MCP_DLP_BLOCKED, "DLP blocked in request", StatusCode::OK);
            }
            if scan_result.modified {
                forward_params = scan_result.modified_data;
            }
        }
    }

    // Guardrail request scanning.
    {
        let gr_rules = state.guardrail_rules.read().clone();
        if !gr_rules.is_empty() {
            let scan_result = guardrails::scan_request(&forward_params, &gr_rules);
            if scan_result.blocked {
                state.metrics.inc_guardrail_blocked();
                state.alerter.record_event("guardrail_blocked");
                log_event(
                    state, &req_id, session_id, auth, Some(server.id), method,
                    name, kind, "guardrail_blocked", "guardrail_blocked",
                    "Guardrail blocked in request", None, bytes_in, None,
                );
                return error_response(msg_id, MCP_GUARDRAIL_BLOCKED, "Guardrail blocked in request", StatusCode::OK);
            }
            if scan_result.modified {
                forward_params = scan_result.modified_data;
            }
        }
    }

    // Strip prefix from params.
    if let Some(obj) = forward_params.as_object_mut() {
        if obj.contains_key("name") {
            obj.insert("name".into(), Value::String(original_name.clone()));
        }
        if obj.contains_key("uri") {
            obj.insert("uri".into(), Value::String(original_name.clone()));
        }
    }

    let upstream_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": if kind == "tool" { "tools/call" } else if kind == "resource" { "resources/read" } else { "prompts/get" },
        "params": forward_params,
    });

    // Get upstream session.
    let upstream_sid = state.sessions.get_upstream_session(session_id, server.id).await;

    // Concurrent request limiting.
    let config = state.config();
    let concurrent_limit = config.as_ref().map(|c| c.concurrent_limit as i64).unwrap_or(0);
    if !state.rate_limiter.acquire_concurrent_slot(auth.identity_id, Some(concurrent_limit)).await {
        log_event(
            state, &req_id, session_id, auth, Some(server.id), method,
            name, kind, "rate_limited", "concurrent_limit",
            "Concurrent request limit exceeded", None, bytes_in, None,
        );
        return error_response(msg_id, MCP_RATE_LIMITED, "Concurrent request limit exceeded", StatusCode::OK);
    }

    let t0 = std::time::Instant::now();
    let upstream_resp = if server.transport_type == "stdio" {
        state.stdio.send_request(&server, &upstream_body).await
    } else {
        let r = state.upstream.send_request(&server, &upstream_body, upstream_sid.as_deref()).await;
        (r.status, r.body)
    };
    state.rate_limiter.release_concurrent_slot(auth.identity_id).await;
    let latency_ms = t0.elapsed().as_millis() as u64;
    if kind == "tool" {
        state.metrics.observe_latency(latency_ms);
    }

    let (status, body) = upstream_resp;
    if kind == "tool" {
        state.metrics.inc_tools_called();
    }

    // DLP response scanning.
    let mut body = body;
    if !pr.skip_dlp {
        let dlp_rules = state.dlp_rules.read().clone();
        if !dlp_rules.is_empty() && body.as_object().is_some() {
            let scan_result = dlp::scan_response(&body, &dlp_rules, None);
            if scan_result.blocked {
                state.metrics.inc_dlp_blocked();
                state.alerter.record_event("dlp_blocked");
                log_event(
                    state, &req_id, session_id, auth, Some(server.id), method,
                    name, kind, "dlp_blocked", "dlp_blocked_response",
                    "DLP blocked in response", Some(latency_ms), bytes_in, None,
                );
                return error_response(msg_id, MCP_DLP_BLOCKED, "DLP blocked in response", StatusCode::OK);
            }
            if scan_result.modified {
                body = scan_result.modified_data;
            }
        }
    }

    // Guardrail response scanning.
    {
        let gr_rules = state.guardrail_rules.read().clone();
        if !gr_rules.is_empty() && body.as_object().is_some() {
            let scan_result = guardrails::scan_response(&body, &gr_rules);
            if scan_result.blocked {
                state.metrics.inc_guardrail_blocked();
                state.alerter.record_event("guardrail_blocked");
                log_event(
                    state, &req_id, session_id, auth, Some(server.id), method,
                    name, kind, "guardrail_blocked", "guardrail_blocked_response",
                    "Guardrail blocked in response", Some(latency_ms), bytes_in, None,
                );
                return error_response(msg_id, MCP_GUARDRAIL_BLOCKED, "Guardrail blocked in response", StatusCode::OK);
            }
            if scan_result.modified {
                body = scan_result.modified_data;
            }
        }
    }

    // Log the event.
    let action = if status == 200 { "ok" } else { "upstream_error" };
    let bytes_out = serde_json::to_string(&body).map(|s| s.len() as u64).ok();
    log_event(
        state, &req_id, session_id, auth, Some(server.id), method,
        name, kind, "allow", action,
        "", Some(latency_ms), bytes_in, bytes_out,
    );

    if status >= 500 {
        state.metrics.inc_upstream_errors();
    }

    // Return response with original id.
    let mut resp_body = body;
    if let Some(obj) = resp_body.as_object_mut() {
        obj.insert("id".into(), msg_id.clone());
        obj.insert("jsonrpc".into(), Value::String("2.0".into()));
    }
    let http_status = if status == 200 { StatusCode::OK } else { StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY) };
    (http_status, axum::Json(resp_body)).into_response()
}

/// Handle meta-tool calls.
async fn handle_meta_tool_call(
    state: &GatewayState,
    msg_id: &Value,
    params: &Value,
    auth: &AuthContext,
) -> Response {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));
    let servers = state.team_servers(auth.team_id);

    // Gather catalogs for all visible servers.
    let discovery_mode = state.discovery_mode(auth.team_id);
    let visible = visible_servers(&servers, discovery_mode);
    let mut catalogs = Vec::new();
    for server in &visible {
        if let Some(catalog) = state.catalog_store.get(server.id).await {
            catalogs.push((server.id, catalog));
        }
    }

    let result = execute_meta_tool(name, &args, &servers, &catalogs);
    success_response(msg_id, result)
}

/// Handle resources/subscribe — track subscription in session.
async fn handle_resource_subscribe(
    _state: &GatewayState,
    msg_id: &Value,
    _params: &Value,
    _auth: &AuthContext,
) -> Response {
    // In v1 we accept the subscription and acknowledge. Resource update
    // notifications are emitted when the catalog worker detects changes.
    success_response(msg_id, serde_json::json!({}))
}

/// Handle resources/unsubscribe.
async fn handle_resource_unsubscribe(
    _state: &GatewayState,
    msg_id: &Value,
    _params: &Value,
    _auth: &AuthContext,
) -> Response {
    success_response(msg_id, serde_json::json!({}))
}

/// Handle completion/complete — forward to upstream if ref is a tool/resource/prompt.
async fn handle_completion(
    state: &GatewayState,
    msg_id: &Value,
    params: &Value,
    auth: &AuthContext,
) -> Response {
    // Extract the ref type and name.
    let ref_obj = match params.get("ref") {
        Some(r) => r,
        None => return error_response(msg_id, JSONRPC_INVALID_REQUEST, "Missing ref", StatusCode::OK),
    };
    let ref_type = ref_obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let ref_name = ref_obj.get("name").or_else(|| ref_obj.get("uri")).and_then(|v| v.as_str()).unwrap_or("");

    // Determine namespace.
    let (namespace, _original) = if ref_type == "ref/resource" {
        unwrap_resource_uri(ref_name)
    } else {
        match ref_name.split_once("__") {
            Some((n, o)) => (Some(n.to_string()), o.to_string()),
            None => (None, ref_name.to_string()),
        }
    };

    let Some(ns) = namespace else {
        return error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, "Missing namespace in completion ref", StatusCode::OK);
    };

    let server = match state.server_by_namespace(&ns, auth.team_id) {
        Some(s) => s,
        None => return error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, &format!("Unknown namespace: {ns}"), StatusCode::OK),
    };

    // Forward completion request to upstream.
    let upstream_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "completion/complete",
        "params": params,
    });
    let upstream_sid = state.sessions.get_upstream_session("", server.id).await;
    let resp = if server.transport_type == "stdio" {
        state.stdio.send_request(&server, &upstream_body).await
    } else {
        let r = state.upstream.send_request(&server, &upstream_body, upstream_sid.as_deref()).await;
        (r.status, r.body)
    };
    let (status, mut body) = resp;
    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".into(), msg_id.clone());
        obj.insert("jsonrpc".into(), Value::String("2.0".into()));
    }
    let http_status = if status == 200 { StatusCode::OK } else { StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY) };
    (http_status, axum::Json(body)).into_response()
}

/// Handle a client notification (no response expected).
async fn handle_notification(
    state: &GatewayState,
    session_id: &str,
    method: &str,
    params: &Value,
    auth: &AuthContext,
) {
    if method == "notifications/cancelled" {
        // Cancellation — in-flight tracking is per-request, so we log it.
        tracing::debug!("Cancellation notification for session {session_id}: {params}");
        return;
    }

    if method == "notifications/initialized" {
        // Fan-out to all upstream servers for this session.
        let servers = state.team_servers(auth.team_id);
        for server in &servers {
            let upstream_sid = state.sessions.get_upstream_session(session_id, server.id).await;
            let notification = serde_json::json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            });
            if server.transport_type == "stdio" {
                let _ = state.stdio.send_notification(server, &notification).await;
            } else {
                let _ = state.upstream.send_notification(server, &notification, upstream_sid.as_deref()).await;
            }
        }
        return;
    }

    // Forward other notifications to all upstream servers.
    let servers = state.team_servers(auth.team_id);
    for server in &servers {
        let upstream_sid = state.sessions.get_upstream_session(session_id, server.id).await;
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        if server.transport_type == "stdio" {
            let _ = state.stdio.send_notification(server, &notification).await;
        } else {
            let _ = state.upstream.send_notification(server, &notification, upstream_sid.as_deref()).await;
        }
    }
}

/// Log an event.
#[allow(clippy::too_many_arguments)]
fn log_event(
    state: &GatewayState,
    req_id: &str,
    session_id: &str,
    auth: &AuthContext,
    server_id: Option<i64>,
    method: &str,
    name: &str,
    kind: &str,
    action: &str,
    status: &str,
    error: &str,
    latency_ms: Option<u64>,
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
) {
    let event = Event {
        ts: chrono::Utc::now().to_rfc3339(),
        request_id: req_id.to_string(),
        session_id: session_id.to_string(),
        identity_id: Some(auth.identity_id),
        identity_name: state.identity_name(auth.identity_id),
        team_id: Some(auth.team_id),
        team_name: state.team_name(auth.team_id),
        server_id,
        server_name: server_id.and_then(|sid| state.server_name(sid)),
        method: method.to_string(),
        tool: if kind == "tool" { Some(name.to_string()) } else { None },
        resource_uri: if kind == "resource" { Some(name.to_string()) } else { None },
        prompt: if kind == "prompt" { Some(name.to_string()) } else { None },
        action: action.to_string(),
        status: status.to_string(),
        latency_ms,
        error: if error.is_empty() { None } else { Some(error.to_string()) },
        bytes_in,
        bytes_out,
        dlp_hits: None,
        guardrail_hits: None,
        params: None,
        result: None,
    };
    state.events.log(event);
}

// Minimal URL-encoding helper (avoids adding a dep).
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }
    pub fn decode(s: &str) -> Result<std::borrow::Cow<'_, str>, std::str::Utf8Error> {
        // Simple percent-decoding.
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '%' {
                let hex1 = chars.next();
                let hex2 = chars.next();
                if let (Some(h1), Some(h2)) = (hex1, hex2) {
                    if let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push(c);
            } else {
                result.push(c);
            }
        }
        Ok(std::borrow::Cow::Owned(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_and_unwrap() {
        assert_eq!(prefix_name("jira", "create"), "jira__create");
        let (ns, orig) = unwrap_resource_uri("mcp://jira/issues%2F123");
        assert_eq!(ns, Some("jira".into()));
        assert_eq!(orig, "issues/123");
        let (ns, orig) = unwrap_resource_uri("https://example.com");
        assert_eq!(ns, None);
        assert_eq!(orig, "https://example.com");
    }

    #[test]
    fn notification_vs_response() {
        assert!(is_notification(&serde_json::json!({"method": "ping"})));
        assert!(!is_notification(&serde_json::json!({"id": 1, "method": "ping"})));
        assert!(is_response(&serde_json::json!({"result": {}})));
        assert!(is_response(&serde_json::json!({"error": {"code": -1}})));
        assert!(!is_response(&serde_json::json!({"method": "ping"})));
    }

    #[test]
    fn wrap_uri() {
        assert_eq!(wrap_resource_uri("jira", "issues/123"), "mcp://jira/issues%2F123");
    }
}
