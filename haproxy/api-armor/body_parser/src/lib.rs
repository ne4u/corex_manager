//! API Armor body parser — HAProxy Lua module.
//!
//! This module is called via `http-request lua.api_body_parse` when the
//! `is_api_armor` ACL matches. It reads `txn.api_body` (set from `req.body`
//! in the HAProxy config), parses it based on content type, and sets txn
//! variables for GraphQL metrics, schema validation status, and auth info.
//!
//! The parsed body structure is also available for the schema_validator and
//! jwt_validator crates via the `ParsedBody` type.

use mlua::prelude::*;
use haproxy_api::{Action, Core, LogLevel, Txn};
use api_armor_graphql::analyze;
use api_armor_schema_validator::validate as validate_schema;
use api_armor_jwt_validator::{validate_jwt_with_claims, validate_api_key, extract_bearer_token};

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock, OnceLock};
use std::time::SystemTime;

/// Map a short variable name to the full HAProxy txn variable name.
fn var_name(short: &str) -> String {
    match short {
        "req_fp_method" => "txn.req_fp.method".to_string(),
        "req_fp_path" => "txn.req_fp.path".to_string(),
        "req_fp_ctype" => "txn.req_fp.ctype".to_string(),
        "req_fp_param_keys" => "txn.req_fp.param_keys".to_string(),
        "req_fp_param_types" => "txn.req_fp.param_types".to_string(),
        "req_fp_path_depth" => "txn.req_fp.path_depth".to_string(),
        "req_fp_hdr_count" => "txn.req_fp.hdr_count".to_string(),
        "req_fp_body_depth" => "txn.req_fp.body_depth".to_string(),
        "req_fp_full" => "txn.req_fp".to_string(),
        _ => format!("txn.{}", short),
    }
}

/// Read a transaction variable using the short name.
fn tget<T: FromLua>(txn: &Txn, name: &str) -> LuaResult<T> {
    txn.get_var(&var_name(name))
}

/// Write a transaction variable using the short name.
fn tset<T: IntoLua>(txn: &Txn, name: &str, val: T) -> LuaResult<()> {
    txn.set_var(&var_name(name), val)
}

/// Read a request header by name (case-insensitive).
fn header(txn: &Txn, name: &str) -> String {
    let raw = txn.f.get_str("req_hdrs", ()).unwrap_or_default();
    let target = name.to_ascii_lowercase();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == target {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

/// Register the Lua functions with HAProxy.
pub fn register(lua: &Lua) -> LuaResult<()> {
    let core = Core::new(lua)?;
    core.register_action(
        "api_body_parse",
        &[Action::HttpReq],
        0,
        parse_body_lua,
    )?;
    Ok(())
}

/// Parsed body structure — shared between body_parser, schema_validator, jwt_validator.
#[derive(Debug, Clone, Default)]
pub struct ParsedBody {
    pub content_type: String,
    pub is_json: bool,
    pub is_graphql: bool,
    pub is_form: bool,
    pub raw: String,
    pub json: Option<serde_json::Value>,
    pub form_params: Vec<(String, String)>,
}

impl ParsedBody {
    /// Parse a body string given a content type.
    pub fn parse(body: &str, content_type: &str) -> Self {
        let mut result = ParsedBody {
            content_type: content_type.to_string(),
            raw: body.to_string(),
            ..Default::default()
        };

        if content_type.contains("application/graphql") {
            result.is_graphql = true;
        } else if content_type.contains("application/json") {
            result.is_json = true;
            result.json = serde_json::from_str(body).ok();
        } else if content_type.contains("application/x-www-form-urlencoded") {
            result.is_form = true;
            result.form_params = parse_form_body(body);
        }

        result
    }

    /// Get a JSON field value by key (top-level only).
    pub fn get_json_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.json
            .as_ref()
            .and_then(|v| v.get(key))
    }
}

// ---------------------------------------------------------------------------
// Runtime data cache (schema index, auth policies, profiles, API keys)
// ---------------------------------------------------------------------------

fn api_armor_dir() -> String {
    std::env::var("API_ARMOR_DIR").unwrap_or_else(|_| "/app/data/api-armor".to_string())
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct SchemaEntry {
    id: i64,
    name: String,
    method: String,
    path_pattern: String,
    file: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct SchemaIndex {
    schemas: Vec<SchemaEntry>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct AuthPolicy {
    id: i64,
    name: String,
    auth_type: Option<String>,
    jwt_algorithm: Option<String>,
    jwt_secret_env: Option<String>,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    jwt_claim_headers: Option<Vec<String>>,
    api_key_header: Option<String>,
    api_key_list_id: Option<i64>,
    api_key_list_name: Option<String>,
    on_failure: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct AuthPoliciesFile {
    policies: Vec<AuthPolicy>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct Profile {
    id: i64,
    method: String,
    path: String,
    dimensions: serde_json::Value,
    status_codes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct ProfilesFile {
    profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Default)]
struct ApiArmorData {
    schema_index: SchemaIndex,
    auth_policies: HashMap<i64, AuthPolicy>,
    profiles: Vec<Profile>,
    api_keys: HashMap<String, Vec<String>>,
    schema_mtime: Option<SystemTime>,
    schema_size: u64,
    auth_mtime: Option<SystemTime>,
    auth_size: u64,
    profiles_mtime: Option<SystemTime>,
    profiles_size: u64,
}

fn load_data() -> Arc<RwLock<ApiArmorData>> {
    static DATA: OnceLock<Arc<RwLock<ApiArmorData>>> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut data = ApiArmorData::default();
        reload_if_changed(&mut data);
        Arc::new(RwLock::new(data))
    }).clone()
}

fn reload_if_changed(data: &mut ApiArmorData) {
    let dir = api_armor_dir();

    // Schema index
    let schema_path = Path::new(&dir).join("schema-index.json");
    if let Ok(meta) = fs::metadata(&schema_path) {
        let mtime = meta.modified().ok();
        let size = meta.len();
        if data.schema_mtime.is_none() || mtime != data.schema_mtime || size != data.schema_size {
            if let Ok(text) = fs::read_to_string(&schema_path) {
                if let Ok(index) = serde_json::from_str::<SchemaIndex>(&text) {
                    data.schema_index = index;
                    data.schema_mtime = mtime;
                    data.schema_size = size;
                }
            }
        }
    }

    // Auth policies
    let auth_path = Path::new(&dir).join("auth-policies.json");
    if let Ok(meta) = fs::metadata(&auth_path) {
        let mtime = meta.modified().ok();
        let size = meta.len();
        if data.auth_mtime.is_none() || mtime != data.auth_mtime || size != data.auth_size {
            if let Ok(text) = fs::read_to_string(&auth_path) {
                if let Ok(file) = serde_json::from_str::<AuthPoliciesFile>(&text) {
                    data.auth_policies.clear();
                    for p in file.policies {
                        data.auth_policies.insert(p.id, p);
                    }
                    data.auth_mtime = mtime;
                    data.auth_size = size;
                    // Reload API key lists referenced by policies.
                    data.api_keys.clear();
                    for (_, p) in &data.auth_policies {
                        if let Some(name) = &p.api_key_list_name {
                            let list_path = Path::new(&dir).join("api-keys").join(format!("{}.lst", safe_name(name)));
                            if let Ok(text) = fs::read_to_string(&list_path) {
                                let keys: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                                data.api_keys.insert(name.clone(), keys);
                            }
                        }
                    }
                }
            }
        }
    }

    // Profiles
    let profiles_path = Path::new(&dir).join("profiles.json");
    if let Ok(meta) = fs::metadata(&profiles_path) {
        let mtime = meta.modified().ok();
        let size = meta.len();
        if data.profiles_mtime.is_none() || mtime != data.profiles_mtime || size != data.profiles_size {
            if let Ok(text) = fs::read_to_string(&profiles_path) {
                if let Ok(file) = serde_json::from_str::<ProfilesFile>(&text) {
                    data.profiles = file.profiles;
                    data.profiles_mtime = mtime;
                    data.profiles_size = size;
                }
            }
        }
    }
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    if pat.len() != path.len() {
        return false;
    }
    for (p, v) in pat.iter().zip(path.iter()) {
        if p.starts_with(':') {
            continue;
        }
        if p != v {
            return false;
        }
    }
    true
}

fn normalize_path(path: &str) -> String {
    // Replace numeric/UUID/Mongo ObjectId segments with :id, mirroring Python profiler.
    let mut parts: Vec<String> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part.parse::<i64>().is_ok() || part.parse::<u64>().is_ok() {
            parts.push(":id".to_string());
        } else if is_uuid(part) || is_objectid(part) {
            parts.push(":id".to_string());
        } else {
            parts.push(part.to_string());
        }
    }
    format!("/{}", parts.join("/"))
}

fn is_uuid(s: &str) -> bool {
    let re = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != re.len() {
        return false;
    }
    parts.iter().zip(re.iter()).all(|(p, &len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_objectid(s: &str) -> bool {
    s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn read_schema_file(file: &str) -> Option<String> {
    let path = Path::new(&api_armor_dir()).join(file);
    fs::read_to_string(&path).ok()
}

fn find_schema_json(method: &str, path: &str) -> Option<String> {
    let data = load_data();
    // Try a cheap read lock; if mtime changed, upgrade and reload.
    {
        let mut guard = data.write().unwrap();
        reload_if_changed(&mut *guard);
    }
    let guard = data.read().unwrap();
    for entry in &guard.schema_index.schemas {
        if entry.method.eq_ignore_ascii_case(method) && path_matches(&entry.path_pattern, path) {
            return read_schema_file(&entry.file);
        }
    }
    None
}

fn find_auth_policy(policy_id: i64) -> Option<AuthPolicy> {
    let data = load_data();
    {
        let mut guard = data.write().unwrap();
        reload_if_changed(&mut *guard);
    }
    let guard = data.read().unwrap();
    guard.auth_policies.get(&policy_id).cloned()
}

fn api_key_list(name: &str) -> Option<Vec<String>> {
    let data = load_data();
    {
        let mut guard = data.write().unwrap();
        reload_if_changed(&mut *guard);
    }
    let guard = data.read().unwrap();
    guard.api_keys.get(name).cloned()
}

fn find_profile(method: &str, path: &str) -> Option<Profile> {
    let norm = normalize_path(path);
    let data = load_data();
    {
        let mut guard = data.write().unwrap();
        reload_if_changed(&mut *guard);
    }
    let guard = data.read().unwrap();
    for p in &guard.profiles {
        if p.method.eq_ignore_ascii_case(method) && p.path == norm {
            return Some(p.clone());
        }
    }
    None
}

fn is_value_in_set(value: &serde_json::Value, allowed: &serde_json::Value) -> bool {
    match allowed {
        serde_json::Value::Array(arr) => arr.contains(value),
        serde_json::Value::String(s) => value.as_str() == Some(s),
        _ => false,
    }
}

/// Read and validate auth, then set txn.auth.* variables.
fn validate_and_set_auth(txn: &Txn, _method: &str, _path: &str) -> LuaResult<()> {
    // Default: no auth
    tset(txn, "auth_valid", true)?;
    tset(txn, "auth_type", "n")?;
    tset(txn, "auth_error", "")?;

    // Clear any previous claim vars by setting known empty ones.
    for claim in &["sub", "iss", "aud"] {
        let _ = tset(txn, &format!("auth.claim_{}", claim), "");
    }

    let policy_id: i64 = tget(txn, "api_auth_policy_id").unwrap_or(0);
    let _ = txn.log(LogLevel::Debug, format!("api_body_parse auth: policy_id={policy_id}"));
    if policy_id == 0 {
        return Ok(());
    }

    let Some(policy) = find_auth_policy(policy_id) else {
        tset(txn, "auth_valid", false)?;
        tset(txn, "auth_type", "n")?;
        tset(txn, "auth_error", "auth policy not found")?;
        return Ok(());
    };

    let auth_header: String = header(txn, "Authorization");

    match policy.auth_type.as_deref() {
        Some("jwt") => {
            let _ = txn.log(LogLevel::Debug, format!("api_body_parse jwt: auth_header='{}'", auth_header));
            if let Some(token) = extract_bearer_token(&auth_header) {
                let secret = policy
                    .jwt_secret_env
                    .as_deref()
                    .and_then(|env| std::env::var(env).ok())
                    .unwrap_or_default();
                if secret.is_empty() {
                    tset(txn, "auth_valid", false)?;
                    tset(txn, "auth_type", "jwt")?;
                    tset(txn, "auth_error", "JWT secret not configured")?;
                    return Ok(());
                }
                let iss = policy.jwt_issuer.as_deref();
                let aud = policy.jwt_audience.as_deref();
                let result = validate_jwt_with_claims(&token, &secret, iss, aud);
                let _ = txn.log(LogLevel::Debug, format!("api_body_parse jwt: valid={} error='{}'", result.valid, result.error));
                tset(txn, "auth_valid", result.valid)?;
                tset(txn, "auth_type", "jwt")?;
                if !result.error.is_empty() {
                    tset(txn, "auth_error", result.error)?;
                } else {
                    tset(txn, "auth_error", "")?;
                }
                if let serde_json::Value::Object(claims) = &result.claims {
                    for (key, val) in claims {
                        if let Some(s) = val.as_str() {
                            let _ = tset(txn, &format!("auth.claim_{}", key), s);
                        } else {
                            let _ = tset(txn, &format!("auth.claim_{}", key), val.to_string());
                        }
                    }
                }
            } else {
                let _ = txn.log(LogLevel::Debug, "api_body_parse jwt: no bearer token extracted");
                tset(txn, "auth_valid", false)?;
                tset(txn, "auth_type", "jwt")?;
                tset(txn, "auth_error", "invalid authorization header")?;
            }
        }
        Some("api_key") => {
            let key = if let Some(header) = &policy.api_key_header {
                crate::header(txn, header.as_str())
            } else {
                // Fallback: treat the raw Authorization header as the key.
                auth_header
            };
            let list_name = policy.api_key_list_name.as_deref().unwrap_or("");
            let valid_keys = api_key_list(list_name).unwrap_or_default();
            let result = validate_api_key(&key, &valid_keys);
            tset(txn, "auth_valid", result.valid)?;
            tset(txn, "auth_type", "api_key")?;
            if !result.error.is_empty() {
                tset(txn, "auth_error", result.error)?;
            } else {
                tset(txn, "auth_error", "")?;
            }
        }
        _ => {
            // Unknown or none auth type — allow through.
            tset(txn, "auth_valid", true)?;
            tset(txn, "auth_type", "n")?;
            tset(txn, "auth_error", "")?;
        }
    }

    Ok(())
}

/// Check the request against the learned profile and set txn.api.profile_anomaly.
fn check_profile_anomaly(
    txn: &Txn,
    method: &str,
    path: &str,
    content_type: &str,
    auth_type: &str,
) -> LuaResult<bool> {
    let Some(profile) = find_profile(method, path) else {
        tset(txn, "api.profile_anomaly", false)?;
        return Ok(false);
    };

    let dimensions = match profile.dimensions.as_object() {
        Some(d) => d,
        None => {
            tset(txn, "api.profile_anomaly", false)?;
            return Ok(false);
        }
    };

    let mut anomalous = false;

    // Build a JSON-like observation to compare with learned values.
    let observed = serde_json::json!({
        "content_type": content_type,
        "auth_type": auth_type,
    });

    for (dim, allowed) in dimensions {
        if let Some(value) = observed.get(dim) {
            if !is_value_in_set(value, allowed) {
                // Also support the Python format: {"values": [...], "count": n}
                let values = match allowed.get("values") {
                    Some(v) => v,
                    None => allowed,
                };
                if !is_value_in_set(value, values) {
                    anomalous = true;
                    break;
                }
            }
        }
    }

    // Body structure dimension: compare top_keys set.
    if !anomalous {
        if let Some(body_structure) = dimensions.get("body_structure") {
            let top_keys: String = tget(txn, "req_fp_param_keys").unwrap_or_default();
            let keys: Vec<&str> = top_keys.split(',').filter(|s| !s.is_empty()).collect();
            let value = serde_json::json!(keys);
            if !is_value_in_set(&value, body_structure) {
                anomalous = true;
            }
        }
    }

    let _ = txn.log(LogLevel::Debug, format!("api_body_parse profile: method={method} path={path} content_type={content_type} auth_type={auth_type} anomalous={anomalous}"));
    tset(txn, "api.profile_anomaly", anomalous)?;
    Ok(anomalous)
}

/// Parse a form-urlencoded body into key-value pairs.
fn parse_form_body(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.trim();
            let value = parts.next().unwrap_or("").trim();
            // URL decode (basic: + → space, %XX → byte)
            let decoded_key = url_decode(key);
            let decoded_value = url_decode(value);
            if !decoded_key.is_empty() {
                Some((decoded_key, decoded_value))
            } else {
                None
            }
        })
        .collect()
}

/// Basic URL decoder.
fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => result.push(' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    result.push(byte as char);
                    i += 2;
                } else {
                    result.push('%');
                }
            }
            c => result.push(c as char),
        }
        i += 1;
    }
    result
}

/// Lua action: api_body_parse(txn)
/// Reads txn.api_body and txn.req_fp.ctype, parses the body, and sets txn variables.
fn parse_body_lua(_lua: &Lua, txn: Txn) -> LuaResult<()> {
    // Borrow the txn for the helper helpers; all sub-calls take &Txn.
    let txn = &txn;

    // Get the body and content type from txn
    let body: String = tget(txn, "api_body").unwrap_or_default();
    let content_type: String = header(txn, "content-type");

    let parsed = ParsedBody::parse(&body, &content_type);

    // GraphQL analysis
    if parsed.is_graphql || (parsed.is_json && parsed.get_json_field("query").is_some()) {
        let query = if parsed.is_graphql {
            &body
        } else {
            parsed.get_json_field("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
        };

        let analysis = analyze(query);
        tset(txn, "gql_operation", analysis.operation.clone())?;
        tset(txn, "gql_depth", analysis.depth)?;
        tset(txn, "gql_complexity", analysis.complexity)?;
        tset(txn, "gql_field_count", analysis.field_count)?;
        tset(txn, "gql_alias_count", analysis.alias_count)?;
        tset(txn, "gql_fragment_count", analysis.fragment_count)?;
        tset(txn, "gql_query_hash", analysis.query_hash.clone())?;
        tset(txn, "gql_valid", analysis.valid)?;
        if !analysis.error.is_empty() {
            tset(txn, "gql_error", analysis.error.clone())?;
        }
    } else {
        // Not a GraphQL request; set safe defaults so security-rule
        // expressions like `graphql.valid = false` don't match non-GraphQL traffic.
        tset(txn, "gql_operation", "")?;
        tset(txn, "gql_depth", 0i32)?;
        tset(txn, "gql_complexity", 0i32)?;
        tset(txn, "gql_field_count", 0i32)?;
        tset(txn, "gql_alias_count", 0i32)?;
        tset(txn, "gql_fragment_count", 0i32)?;
        tset(txn, "gql_query_hash", "")?;
        tset(txn, "gql_valid", true)?;
    }

    // Per-endpoint schema lookup and validation
    let method: String = txn.f.get_str("method", ()).unwrap_or_else(|_| "GET".to_string());
    let path: String = txn.f.get_str("path", ()).unwrap_or_else(|_| "/".to_string());
    let schema_json = if !method.is_empty() && !path.is_empty() {
        find_schema_json(&method, &path).unwrap_or_default()
    } else {
        String::new()
    };
    tset(txn, "api_schema", schema_json.clone())?;

    if !schema_json.is_empty() && parsed.json.is_some() {
        if let Ok(schema) = serde_json::from_str::<serde_json::Value>(&schema_json) {
            let result = validate_schema(parsed.json.as_ref().unwrap(), &schema);
            tset(txn, "api_schema_valid", result.valid)?;
            let errors = result.errors.join("; ");
            tset(txn, "api_schema_errors", errors)?;
        } else {
            tset(txn, "api_schema_valid", true)?;
            tset(txn, "api_schema_errors", "")?;
        }
    } else {
        tset(txn, "api_schema_valid", true)?;
        tset(txn, "api_schema_errors", "")?;
    }

    // Auth validation
    validate_and_set_auth(&txn, &method, &path)?;

    // Profile / behavioral anomaly check
    let auth_type: String = tget(txn, "auth_type").unwrap_or_else(|_| "n".to_string());
    check_profile_anomaly(&txn, &method, &path, &content_type, &auth_type)?;

    // Write profiling data to the API Armor profiling log.
    // This is a JSON line per request, tailed by the ApiArmorProfiler sampler
    // in the backend. The log path is read from the API_ARMOR_PROFILING_LOG_PATH
    // env var (set in the HAProxy container's environment).
    write_profiling_log(&txn, &parsed, &content_type)?;

    Ok(())
}

/// Write a JSON line to the API Armor profiling log.
/// Contains all dimensions for multi-dimensional behavioral profiling.
fn write_profiling_log(txn: &Txn, parsed: &ParsedBody, content_type: &str) -> LuaResult<()> {
    use std::io::Write;

    // Profiling/log data is only needed when the backend sampler is learning
    // schemas or profiles. Either flag enables the log write.
    let profiling_enabled = std::env::var("API_ARMOR_PROFILING_LEARNING_ENABLED")
        .unwrap_or_else(|_| "0".to_string()) == "1";
    let schema_enabled = std::env::var("API_ARMOR_SCHEMA_LEARNING_ENABLED")
        .unwrap_or_else(|_| "0".to_string()) == "1";
    if !profiling_enabled && !schema_enabled {
        return Ok(());
    }

    let log_path = std::env::var("API_ARMOR_PROFILING_LOG_PATH")
        .unwrap_or_else(|_| "/app/data/api-armor/profiling.log".to_string());

    // Build the profiling JSON line. Read our own txn vars and fall back to
    // HAProxy fetches when req_fp sub-fields are not set.
    let method: String = txn.f.get_str("method", ()).unwrap_or_else(|_| "GET".to_string());
    let path: String = txn.f.get_str("path", ()).unwrap_or_else(|_| "/".to_string());
    let auth_type: String = tget(txn, "auth_type").unwrap_or("n".to_string());
    let auth_valid: bool = tget(txn, "auth_valid").unwrap_or(true);
    let schema_valid: bool = tget(txn, "api_schema_valid").unwrap_or(true);
    let profile_anomaly: bool = tget(txn, "api.profile_anomaly").unwrap_or(false);
    let req_fp_partial: String = tget(txn, "req_fp_partial").unwrap_or_default();
    let req_fp_param_keys: String = tget(txn, "req_fp_param_keys").unwrap_or_default();
    let req_fp_param_types: String = tget(txn, "req_fp_param_types").unwrap_or_default();
    let req_fp_path_depth: i64 = tget(txn, "req_fp_path_depth").unwrap_or(0);
    let req_fp_hdr_count: i64 = tget(txn, "req_fp_hdr_count").unwrap_or(0);
    let req_fp_body_depth: i64 = tget(txn, "req_fp_body_depth").unwrap_or(0);

    let mut profile = serde_json::json!({
        "ts": chrono_now(),
        "method": method,
        "path": path,
        "content_type": content_type,
        "auth_type": auth_type,
        "auth_valid": auth_valid,
        "schema_valid": schema_valid,
        "profile_anomaly": profile_anomaly,
        "req_fp": req_fp_partial,
        "req_fp_ctype": content_type,
        "req_fp_param_keys": req_fp_param_keys,
        "req_fp_param_types": req_fp_param_types,
        "req_fp_path_depth": req_fp_path_depth,
        "req_fp_hdr_count": req_fp_hdr_count,
        "req_fp_body_depth": req_fp_body_depth,
    });

    // Add GraphQL dimensions if present
    let gql_operation: String = tget(txn, "gql_operation").unwrap_or_default();
    if !gql_operation.is_empty() {
        let gql_query_hash: String = tget(txn, "gql_query_hash").unwrap_or_default();
        profile["graphql"] = serde_json::json!({
            "operation": gql_operation,
            "depth": tget::<i64>(txn, "gql_depth").unwrap_or(0),
            "complexity": tget::<i64>(txn, "gql_complexity").unwrap_or(0),
            "field_count": tget::<i64>(txn, "gql_field_count").unwrap_or(0),
            "alias_count": tget::<i64>(txn, "gql_alias_count").unwrap_or(0),
            "fragment_count": tget::<i64>(txn, "gql_fragment_count").unwrap_or(0),
            "query_hash": gql_query_hash,
            "valid": tget::<bool>(txn, "gql_valid").unwrap_or(true),
        });
    }

    // Add body structure dimensions if JSON
    if let Some(json) = &parsed.json {
        profile["body_structure"] = serde_json::json!({
            "is_json": true,
            "top_keys": json.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        });

        // Include a truncated body sample for schema learning.
        let max_bytes: usize = std::env::var("API_ARMOR_PROFILE_LOG_MAX_BODY_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096);
        let mut sample = json.clone();
        truncate_body_sample(&mut sample, max_bytes);
        profile["body_sample"] = sample;
    }

    // Write to log file (append mode, one JSON line per request)
    // Use open with append to avoid locking overhead
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let line = serde_json::to_string(&profile).unwrap_or_default();
        let _ = writeln!(file, "{}", line);
    }

    Ok(())
}

/// Recursively truncate string values in a JSON sample to avoid huge log lines.
fn truncate_body_sample(value: &mut serde_json::Value, max_bytes: usize) {
    match value {
        serde_json::Value::String(s) => {
            if s.len() > max_bytes {
                *s = s.chars().take(max_bytes).collect();
            }
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                truncate_body_sample(v, max_bytes);
            }
        }
        serde_json::Value::Array(arr) => {
            // Only keep the first item and truncate it; we don't need the whole array.
            if arr.len() > 1 {
                arr.truncate(1);
            }
            for v in arr.iter_mut() {
                truncate_body_sample(v, max_bytes);
            }
        }
        _ => {}
    }
}

/// Get current timestamp as ISO 8601 string.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

// The `register` function at the top of this file is the public entry point
// called by the `module` crate's `luaopen_haproxy_api_armor_module` function.
// No `#[mlua::lua_module]` here — only the `module` crate has the cdylib entry.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_body() {
        let body = r#"{"name": "test", "age": 30}"#;
        let parsed = ParsedBody::parse(body, "application/json");
        assert!(parsed.is_json);
        assert!(parsed.json.is_some());
        assert_eq!(parsed.get_json_field("name").unwrap(), "test");
    }

    #[test]
    fn test_parse_form_body() {
        let body = "name=test&age=30";
        let parsed = ParsedBody::parse(body, "application/x-www-form-urlencoded");
        assert!(parsed.is_form);
        assert_eq!(parsed.form_params.len(), 2);
        assert_eq!(parsed.form_params[0].0, "name");
        assert_eq!(parsed.form_params[0].1, "test");
    }

    #[test]
    fn test_parse_graphql_body() {
        let body = "{ user { id } }";
        let parsed = ParsedBody::parse(body, "application/graphql");
        assert!(parsed.is_graphql);
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("test%20value"), "test value");
        assert_eq!(url_decode("no%2Fslash"), "no/slash");
    }

    #[test]
    fn test_path_matches() {
        assert!(path_matches("/api/v1/users", "/api/v1/users"));
        assert!(path_matches("/api/v1/users/:id", "/api/v1/users/42"));
        assert!(!path_matches("/api/v1/users/:id", "/api/v1/users"));
        assert!(!path_matches("/api/v1/users/:id", "/api/v1/users/42/details"));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/api/v1/users"), "/api/v1/users");
        assert_eq!(normalize_path("/api/v1/users/42"), "/api/v1/users/:id");
        assert_eq!(normalize_path("/api/v1/orders/abcd1234-abcd-1234-abcd-1234abcd1234"), "/api/v1/orders/:id");
        assert_eq!(normalize_path("/api/v1/items/507f1f77bcf86cd799439011"), "/api/v1/items/:id");
    }

    #[test]
    fn test_is_uuid_and_objectid() {
        assert!(is_uuid("abcd1234-abcd-1234-abcd-1234abcd1234"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(is_objectid("507f1f77bcf86cd799439011"));
        assert!(!is_objectid("507f1f77bcf86cd79943901"));
    }

    #[test]
    fn test_truncate_body_sample() {
        let mut value = serde_json::json!({"name": "a".repeat(100)});
        truncate_body_sample(&mut value, 10);
        assert_eq!(value["name"].as_str().unwrap().len(), 10);
    }
}
