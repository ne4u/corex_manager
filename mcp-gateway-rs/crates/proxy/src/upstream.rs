//! Upstream MCP client — reqwest-based Streamable HTTP client.
//!
//! Mirrors `mcp-gateway/upstream.py`:
//! - Per-server reqwest clients with SSRF validation.
//! - `initialize` → extract `Mcp-Session-Id`.
//! - `send_request` / `send_notification` with auth headers + session ID.
//! - SSE response unwrapping (`text/event-stream` → last JSON-RPC message).
//! - Same-origin 307/308 redirect handling (one hop, SSRF-checked).
//! - `fetch_catalog` (paginated tools/resources/prompts).
//! - Circuit breaker integration.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use corex_core::config::ServerConfig;
use corex_core::ssrf::SsrfPolicy;

use crate::circuit_breaker::CircuitBreaker;

/// MCP protocol version advertised to upstreams.
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// Result of an upstream request: (status, body, headers).
pub struct UpstreamResponse {
    pub status: u16,
    pub body: Value,
    pub headers: HeaderMap,
    pub upstream_session_id: Option<String>,
}

/// A JSON-RPC error body.
pub fn error_body(code: i32, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "error": {"code": code, "message": message}
    })
}

/// Per-server HTTP client cache.
#[derive(Clone)]
pub struct UpstreamClient {
    clients: Arc<Mutex<HashMap<i64, reqwest::Client>>>,
    breaker: CircuitBreaker,
    ssrf: SsrfPolicy,
}

impl UpstreamClient {
    pub fn new(breaker: CircuitBreaker, ssrf: SsrfPolicy) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            breaker,
            ssrf,
        }
    }

    /// Borrow the circuit breaker (for status inspection).
    pub fn breaker(&self) -> &CircuitBreaker {
        &self.breaker
    }

    fn get_client(&self, server: &ServerConfig) -> reqwest::Client {
        let sid = server.id;
        if let Some(c) = self.clients.lock().get(&sid) {
            return c.clone();
        }
        let timeout = std::time::Duration::from_millis(server.timeout_ms as u64);
        let connect = std::time::Duration::from_secs(10);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(connect)
            .redirect(reqwest::redirect::Policy::none()) // SSRF-safe: handle manually
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        self.clients.lock().insert(sid, client.clone());
        client
    }

    fn build_headers(&self, server: &ServerConfig, upstream_session_id: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("accept", HeaderValue::from_static("application/json, text/event-stream"));
        let auth_type = server.auth_type.as_deref().unwrap_or("none");
        if auth_type == "bearer" {
            if let Some(secret) = &server.auth_secret {
                if let Ok(v) = HeaderValue::from_str(&format!("Bearer {secret}")) {
                    headers.insert("authorization", v);
                }
            }
        } else if auth_type == "header" {
            if let Some(secret) = &server.auth_secret {
                let name = server.auth_header.as_deref().unwrap_or("Authorization");
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(secret),
                ) {
                    headers.insert(n, v);
                }
            }
        }
        if let Some(sid) = upstream_session_id {
            if let Ok(v) = HeaderValue::from_str(sid) {
                headers.insert("mcp-session-id", v);
            }
        }
        headers
    }

    /// Send an initialize request; returns the upstream session ID (or "" for
    /// stateless servers, or None on failure).
    pub async fn initialize(&self, server: &ServerConfig) -> Option<String> {
        let url = server.url.as_deref()?;
        let (safe, reason) = self.ssrf.is_url_safe(url).await;
        if !safe {
            tracing::error!("SSRF blocked upstream URL {url}: {reason}");
            return None;
        }
        if !self.breaker.check(server.id) {
            tracing::warn!("Circuit breaker open for server {}, skipping initialize", server.name);
            return None;
        }
        let client = self.get_client(server);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-gateway", "version": "0.1.0"},
            }
        });
        let headers = self.build_headers(server, None);
        match self.post_with_redirect(&client, url, body, &headers).await {
            Ok(resp) => {
                if resp.status == 200 {
                    self.breaker.record_success(server.id);
                    let sid = resp
                        .upstream_session_id
                        .clone()
                        .unwrap_or_default();
                    Some(sid)
                } else {
                    tracing::warn!("Upstream initialize returned {} for {url}", resp.status);
                    self.breaker.record_failure(server.id);
                    None
                }
            }
            Err(e) => {
                tracing::error!("Upstream initialize failed for {url}: {e}");
                self.breaker.record_failure(server.id);
                None
            }
        }
    }

    /// Send a JSON-RPC request to an upstream server.
    pub async fn send_request(
        &self,
        server: &ServerConfig,
        message: &Value,
        upstream_session_id: Option<&str>,
    ) -> UpstreamResponse {
        let url = match server.url.as_deref() {
            Some(u) => u,
            None => {
                return UpstreamResponse {
                    status: 502,
                    body: error_body(-32000, "No upstream URL configured"),
                    headers: HeaderMap::new(),
                    upstream_session_id: None,
                };
            }
        };
        let (safe, reason) = self.ssrf.is_url_safe(url).await;
        if !safe {
            tracing::error!("SSRF blocked upstream URL {url}: {reason}");
            return UpstreamResponse {
                status: 403,
                body: error_body(-32000, &format!("Upstream blocked: {reason}")),
                headers: HeaderMap::new(),
                upstream_session_id: None,
            };
        }
        if !self.breaker.check(server.id) {
            return UpstreamResponse {
                status: 503,
                body: error_body(-32000, "Upstream circuit breaker open"),
                headers: HeaderMap::new(),
                upstream_session_id: None,
            };
        }
        let client = self.get_client(server);
        let headers = self.build_headers(server, upstream_session_id);
        match self.post_with_redirect(&client, url, message.clone(), &headers).await {
            Ok(resp) => {
                if resp.status < 500 {
                    self.breaker.record_success(server.id);
                } else {
                    self.breaker.record_failure(server.id);
                }
                resp
            }
            Err(e) => {
                tracing::error!("Upstream request failed for {url}: {e}");
                self.breaker.record_failure(server.id);
                let status = if e.is_timeout() { 504 } else { 502 };
                UpstreamResponse {
                    status,
                    body: error_body(-32000, &format!("Upstream error: {e}")),
                    headers: HeaderMap::new(),
                    upstream_session_id: None,
                }
            }
        }
    }

    /// Send a JSON-RPC notification (no response expected). Returns status code.
    pub async fn send_notification(
        &self,
        server: &ServerConfig,
        message: &Value,
        upstream_session_id: Option<&str>,
    ) -> u16 {
        let Some(url) = server.url.as_deref() else { return 502 };
        let (safe, reason) = self.ssrf.is_url_safe(url).await;
        if !safe {
            tracing::error!("SSRF blocked upstream URL {url}: {reason}");
            return 403;
        }
        let client = self.get_client(server);
        let headers = self.build_headers(server, upstream_session_id);
        match self.post_with_redirect(&client, url, message.clone(), &headers).await {
            Ok(resp) => resp.status,
            Err(e) => {
                tracing::error!("Upstream notification failed for {url}: {e}");
                502
            }
        }
    }

    /// POST with one same-origin 307/308 redirect (SSRF-checked).
    async fn post_with_redirect(
        &self,
        client: &reqwest::Client,
        url: &str,
        body: Value,
        headers: &HeaderMap,
    ) -> Result<UpstreamResponse, reqwest::Error> {
        let resp = client.post(url).headers(headers.clone()).json(&body).send().await?;
        let status = resp.status().as_u16();
        // Handle one same-origin 307/308 redirect.
        if status == 307 || status == 308 {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                let new_url = resolve_url(url, loc);
                if is_same_origin(url, &new_url) {
                    let (safe, _) = self.ssrf.is_url_safe(&new_url).await;
                    if safe {
                        return Box::pin(self.post_with_redirect(client, &new_url, body, headers)).await;
                    }
                }
            }
        }
        let upstream_session_id = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let headers_out = resp.headers().clone();
        let text = resp.text().await?;
        let body = parse_response_body(&content_type, &text);
        Ok(UpstreamResponse { status, body, headers: headers_out, upstream_session_id })
    }

    /// Fetch the full catalog (tools, resources, prompts) from an upstream.
    pub async fn fetch_catalog(
        &self,
        server: &ServerConfig,
        upstream_session_id: Option<&str>,
    ) -> Option<Catalog> {
        let tools = self.fetch_list(server, "tools/list", "tools", upstream_session_id).await;
        let resources = self
            .fetch_list(server, "resources/list", "resources", upstream_session_id)
            .await;
        let prompts = self
            .fetch_list(server, "prompts/list", "prompts", upstream_session_id)
            .await;
        if tools.is_none() && resources.is_none() && prompts.is_none() {
            return None;
        }
        Some(Catalog {
            tools: tools.unwrap_or_default(),
            resources: resources.unwrap_or_default(),
            prompts: prompts.unwrap_or_default(),
            fetched_at: now_secs(),
        })
    }

    async fn fetch_list(
        &self,
        server: &ServerConfig,
        method: &str,
        key: &str,
        upstream_session_id: Option<&str>,
    ) -> Option<Vec<Value>> {
        let url = server.url.as_deref()?;
        let (safe, _) = self.ssrf.is_url_safe(url).await;
        if !safe {
            return None;
        }
        let client = self.get_client(server);
        let headers = self.build_headers(server, upstream_session_id);
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut req_id = 1i64;
        loop {
            let mut params = serde_json::Map::new();
            if let Some(c) = &cursor {
                params.insert("cursor".into(), Value::String(c.clone()));
            }
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params,
            });
            let resp = match self.post_with_redirect(&client, url, body, &headers).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Upstream {url} failed on {method}: {e}");
                    return None;
                }
            };
            if resp.status != 200 {
                return None;
            }
            let result = resp.body.get("result")?;
            if let Some(arr) = result.get(key).and_then(|v| v.as_array()) {
                items.extend(arr.iter().cloned());
            }
            cursor = result.get("nextCursor").and_then(|v| v.as_str()).map(|s| s.to_string());
            if cursor.is_none() {
                break;
            }
            req_id += 1;
        }
        Some(items)
    }

    /// Close all cached clients (on shutdown).
    pub fn close_all(&self) {
        self.clients.lock().clear();
    }
}

/// Catalog data fetched from an upstream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Catalog {
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub fetched_at: f64,
}

/// Parse an upstream response body, unwrapping SSE framing if present.
fn parse_response_body(content_type: &str, text: &str) -> Value {
    if content_type.contains("text/event-stream") {
        // Take the last `data:` line that parses as JSON (final response).
        for line in text.lines().rev() {
            if let Some(raw) = line.strip_prefix("data:").map(|s| s.trim()) {
                if let Ok(v) = serde_json::from_str::<Value>(raw) {
                    return v;
                }
            }
        }
        return Value::String(text.to_string());
    }
    if content_type.contains("application/json") {
        return serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()));
    }
    Value::String(text.to_string())
}

fn resolve_url(base: &str, location: &str) -> String {
    match url::Url::parse(base) {
        Ok(base_url) => base_url.join(location).map(|u| u.to_string()).unwrap_or_else(|_| location.to_string()),
        Err(_) => location.to_string(),
    }
}

fn is_same_origin(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(a), url::Url::parse(b)) else { return false };
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port() == b.port()
}

fn now_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sse_takes_last_data() {
        let ct = "text/event-stream";
        let text = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
        let v = parse_response_body(ct, text);
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn parse_json_body() {
        let v = parse_response_body("application/json", r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn parse_text_fallback() {
        let v = parse_response_body("text/plain", "hello");
        assert_eq!(v, Value::String("hello".into()));
    }

    #[test]
    fn same_origin_check() {
        assert!(is_same_origin("https://up.example.com/mcp", "https://up.example.com/mcp/"));
        assert!(!is_same_origin("https://up.example.com/mcp", "http://up.example.com/mcp"));
        assert!(!is_same_origin("https://up.example.com/mcp", "https://evil.com/mcp"));
    }

    #[test]
    fn resolve_relative() {
        assert_eq!(
            resolve_url("https://up.example.com/mcp", "/mcp/"),
            "https://up.example.com/mcp/"
        );
    }
}
