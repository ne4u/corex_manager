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
use api_armor_graphql::analyze;
use api_armor_schema_validator::validate as validate_schema;

/// Register the Lua functions with HAProxy.
pub fn register(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let parse_fn = lua.create_function(parse_body_lua)?;
    globals.set("api_body_parse", parse_fn)?;
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

/// Lua function: api_body_parse(txn)
/// Reads txn.api_body and txn.req_fp.ctype, parses the body, and sets txn variables.
fn parse_body_lua(_lua: &Lua, txn: LuaTable) -> LuaResult<()> {
    // Get the body and content type from txn
    let body: String = txn.get("api_body").unwrap_or_default();
    let content_type: String = txn.get("req_fp_ctype").unwrap_or_default();

    if body.is_empty() {
        return Ok(());
    }

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
        txn.set("gql_operation", analysis.operation.clone())?;
        txn.set("gql_depth", analysis.depth)?;
        txn.set("gql_complexity", analysis.complexity)?;
        txn.set("gql_field_count", analysis.field_count)?;
        txn.set("gql_alias_count", analysis.alias_count)?;
        txn.set("gql_fragment_count", analysis.fragment_count)?;
        txn.set("gql_query_hash", analysis.query_hash.clone())?;
        txn.set("gql_valid", analysis.valid)?;
        if !analysis.error.is_empty() {
            txn.set("gql_error", analysis.error.clone())?;
        }
    }

    // Schema validation — check JSON body against schema if available
    // For now, schema is loaded from a txn variable set by the HAProxy config
    // (Phase 3 will add per-endpoint schema lookup). If no schema is set,
    // validation passes (valid=true, errors="").
    let schema_json: String = txn.get("api_schema").unwrap_or_default();
    if !schema_json.is_empty() && parsed.json.is_some() {
        if let Ok(schema) = serde_json::from_str::<serde_json::Value>(&schema_json) {
            let result = validate_schema(parsed.json.as_ref().unwrap(), &schema);
            txn.set("api_schema_valid", result.valid)?;
            let errors = result.errors.join("; ");
            txn.set("api_schema_errors", errors)?;
        } else {
            txn.set("api_schema_valid", true)?;
            txn.set("api_schema_errors", "")?;
        }
    } else {
        txn.set("api_schema_valid", true)?;
        txn.set("api_schema_errors", "")?;
    }

    // Auth validation placeholder (Phase 4)
    txn.set("auth_valid", true)?;
    txn.set("auth_type", "n")?;
    txn.set("auth_error", "")?;

    // Write profiling data to the API Armor profiling log.
    // This is a JSON line per request, tailed by the ApiArmorProfiler sampler
    // in the backend. The log path is read from the API_ARMOR_PROFILING_LOG_PATH
    // env var (set in the HAProxy container's environment).
    write_profiling_log(&txn, &parsed, &content_type)?;

    Ok(())
}

/// Write a JSON line to the API Armor profiling log.
/// Contains all dimensions for multi-dimensional behavioral profiling.
fn write_profiling_log(txn: &LuaTable, parsed: &ParsedBody, content_type: &str) -> LuaResult<()> {
    use std::io::Write;

    let log_path = std::env::var("API_ARMOR_PROFILING_LOG_PATH")
        .unwrap_or_else(|_| "/app/data/api-armor/profiling.log".to_string());

    // Build the profiling JSON line
    let mut profile = serde_json::json!({
        "ts": chrono_now(),
        "method": txn.get::<String>("req_fp_method").unwrap_or_default(),
        "path": txn.get::<String>("req_fp_path").unwrap_or_default(),
        "content_type": content_type,
        "auth_type": txn.get::<String>("auth_type").unwrap_or_else(|_| "n".to_string()),
        "auth_valid": txn.get::<bool>("auth_valid").unwrap_or(true),
        "schema_valid": txn.get::<bool>("api_schema_valid").unwrap_or(true),
        "req_fp": txn.get::<String>("req_fp_full").unwrap_or_default(),
        "req_fp_ctype": txn.get::<String>("req_fp_ctype").unwrap_or_default(),
        "req_fp_param_keys": txn.get::<String>("req_fp_param_keys").unwrap_or_default(),
        "req_fp_param_types": txn.get::<String>("req_fp_param_types").unwrap_or_default(),
        "req_fp_path_depth": txn.get::<i64>("req_fp_path_depth").unwrap_or(0),
        "req_fp_hdr_count": txn.get::<i64>("req_fp_hdr_count").unwrap_or(0),
        "req_fp_body_depth": txn.get::<i64>("req_fp_body_depth").unwrap_or(0),
    });

    // Add GraphQL dimensions if present
    let gql_operation: String = txn.get("gql_operation").unwrap_or_default();
    if !gql_operation.is_empty() {
        profile["graphql"] = serde_json::json!({
            "operation": gql_operation,
            "depth": txn.get::<i64>("gql_depth").unwrap_or(0),
            "complexity": txn.get::<i64>("gql_complexity").unwrap_or(0),
            "field_count": txn.get::<i64>("gql_field_count").unwrap_or(0),
            "alias_count": txn.get::<i64>("gql_alias_count").unwrap_or(0),
            "fragment_count": txn.get::<i64>("gql_fragment_count").unwrap_or(0),
            "query_hash": txn.get::<String>("gql_query_hash").unwrap_or_default(),
            "valid": txn.get::<bool>("gql_valid").unwrap_or(true),
        });
    }

    // Add body structure dimensions if JSON
    if let Some(json) = &parsed.json {
        profile["body_structure"] = serde_json::json!({
            "is_json": true,
            "top_keys": json.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        });
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
}
