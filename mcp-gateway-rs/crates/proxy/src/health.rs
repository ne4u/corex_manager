//! Health checker — periodic upstream health pings, stored in Valkey.
//!
//! Mirrors `mcp-gateway/health.py`:
//! - `mcp:gw:health:<id>` — JSON `{server_id, status, error, checked_at}` (TTL = interval*3).
//! - HTTP servers: ping request; stdio servers: process-alive check.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use corex_core::config::ServerConfig;
use corex_policy::valkey::ValkeyClient;

use crate::stdio::ProcessManager;
use crate::upstream::UpstreamClient;

const HEALTH_CHECK_TIMEOUT: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub server_id: i64,
    pub status: String, // "healthy" | "unhealthy" | "stopped" | "unknown"
    pub error: Option<String>,
    pub checked_at: f64,
}

impl HealthStatus {
    pub fn unknown(server_id: i64) -> Self {
        Self { server_id, status: "unknown".into(), error: None, checked_at: 0.0 }
    }
}

/// Background health checker.
pub struct HealthChecker {
    valkey: Option<ValkeyClient>,
    http: UpstreamClient,
    stdio: ProcessManager,
    interval: u64,
    shutdown: Arc<tokio::sync::Notify>,
}

impl HealthChecker {
    pub fn new(
        valkey: Option<ValkeyClient>,
        http: UpstreamClient,
        stdio: ProcessManager,
        interval: u64,
    ) -> Self {
        Self {
            valkey,
            http,
            stdio,
            interval,
            shutdown: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Run the health check loop until `stop()` is called.
    pub async fn run(&self, servers: Vec<ServerConfig>) {
        loop {
            self.check_all(&servers).await;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(self.interval)) => {}
                _ = self.shutdown.notified() => break,
            }
        }
    }

    /// Stop the health checker.
    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }

    async fn check_all(&self, servers: &[ServerConfig]) {
        let tasks: Vec<_> = servers
            .iter()
            .filter(|s| s.enabled)
            .map(|s| self.check_server(s.clone()))
            .collect();
        futures::future::join_all(tasks).await;
    }

    async fn check_server(&self, server: ServerConfig) {
        let sid = server.id;
        let (status, error) = if server.transport_type == "stdio" {
            if self.stdio.is_healthy(sid).await {
                ("healthy".to_string(), None)
            } else {
                ("stopped".to_string(), Some("Process not running".into()))
            }
        } else {
            self.check_http(&server).await
        };
        let health = HealthStatus {
            server_id: sid,
            status,
            error,
            checked_at: now_secs(),
        };
        if let Some(c) = &self.valkey {
            let payload = serde_json::to_string(&health).unwrap_or_else(|_| "{}".into());
            let _ = c.setex(&format!("health:{sid}"), self.interval * 3, &payload).await;
        }
    }

    async fn check_http(&self, server: &ServerConfig) -> (String, Option<String>) {
        if server.url.is_none() {
            return ("unknown".into(), Some("No URL configured".into()));
        }
        let ping = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "ping",
            "params": {},
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(HEALTH_CHECK_TIMEOUT),
            self.http.send_request(server, &ping, None),
        )
        .await;
        match result {
            Ok(resp) => {
                if resp.status == 200 {
                    if resp.body.get("error").is_some() {
                        return (
                            "unhealthy".into(),
                            Some(format!("JSON-RPC error: {}", resp.body["error"])),
                        );
                    }
                    return ("healthy".into(), None);
                }
                ("unhealthy".into(), Some(format!("HTTP {}", resp.status)))
            }
            Err(_) => ("unhealthy".into(), Some("Timeout".into())),
        }
    }

    /// Get cached health status for a server (from Valkey).
    pub async fn get_status(&self, server_id: i64) -> HealthStatus {
        let Some(c) = &self.valkey else { return HealthStatus::unknown(server_id) };
        match c.get(&format!("health:{server_id}")).await {
            Ok(Some(raw)) => serde_json::from_str(&raw).unwrap_or_else(|_| HealthStatus::unknown(server_id)),
            _ => HealthStatus::unknown(server_id),
        }
    }
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
    fn health_status_unknown() {
        let s = HealthStatus::unknown(1);
        assert_eq!(s.status, "unknown");
        assert_eq!(s.server_id, 1);
    }

    #[tokio::test]
    async fn get_status_no_valkey_returns_unknown() {
        let http = UpstreamClient::new(
            crate::circuit_breaker::CircuitBreaker::new(),
            corex_core::ssrf::SsrfPolicy::default(),
        );
        let stdio = ProcessManager::new();
        let hc = HealthChecker::new(None, http, stdio, 30);
        let s = hc.get_status(1).await;
        assert_eq!(s.status, "unknown");
    }
}
