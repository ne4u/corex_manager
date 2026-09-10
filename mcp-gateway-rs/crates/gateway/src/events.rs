//! NDJSON event logger with 2-file rotation.
//!
//! Mirrors `mcp-gateway/events.py` but with 2-file rotation (not 10):
//! - Active file: `MCP_EVENTS_LOG_PATH` (default `data/mcp/events.ndjson`).
//! - Rotated copy: `{path}.1` (overwritten on rotation).
//! - When the active file exceeds `max_bytes`, it rotates to `.1`.
//! - One NDJSON line per RPC with method, tool, identity, team, server, etc.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;

const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024; // 100 MB per file

/// Event record written as one NDJSON line.
#[derive(Debug, Serialize)]
pub struct Event {
    pub ts: String,
    pub request_id: String,
    pub session_id: String,
    pub identity_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_name: Option<String>,
    pub team_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_name: Option<String>,
    pub server_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    pub method: String,
    pub tool: Option<String>,
    pub resource_uri: Option<String>,
    pub prompt: Option<String>,
    pub action: String,
    pub status: String,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub dlp_hits: Option<serde_json::Value>,
    pub guardrail_hits: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

/// Thread-safe event logger with 2-file rotation.
#[derive(Clone)]
pub struct EventLogger {
    inner: Arc<Mutex<EventLoggerInner>>,
    log_payloads: bool,
}

struct EventLoggerInner {
    path: PathBuf,
    rotated_path: PathBuf,
    max_bytes: u64,
    current_size: u64,
}

impl EventLogger {
    pub fn new() -> Self {
        let path_str = std::env::var("MCP_EVENTS_LOG_PATH").unwrap_or_else(|_| "data/mcp/events.ndjson".into());
        let path = PathBuf::from(&path_str);
        let rotated_path = PathBuf::from(format!("{path_str}.1"));
        let max_bytes = std::env::var("MCP_EVENTS_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_BYTES);
        let log_payloads = std::env::var("MCP_LOG_PAYLOADS")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        let current_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            inner: Arc::new(Mutex::new(EventLoggerInner {
                path,
                rotated_path,
                max_bytes,
                current_size,
            })),
            log_payloads,
        }
    }

    /// Generate a unique request ID (16 hex chars).
    pub fn generate_request_id() -> String {
        use uuid::Uuid;
        Uuid::new_v4().simple().to_string()[..16].to_string()
    }

    /// Write a single NDJSON event line.
    pub fn log(&self, mut event: Event) {
        // Strip params/result if not logging payloads.
        if !self.log_payloads {
            event.params = None;
            event.result = None;
        }
        let line = match serde_json::to_string(&event) {
            Ok(s) => s + "\n",
            Err(e) => {
                tracing::warn!("Failed to serialize event: {e}");
                return;
            }
        };
        let line_bytes = line.len() as u64;
        let mut inner = self.inner.lock();
        // Check rotation.
        if inner.current_size + line_bytes > inner.max_bytes {
            // Rotate: move current → rotated (overwrite).
            let _ = std::fs::rename(&inner.path, &inner.rotated_path)
                .or_else(|_| {
                    // Cross-device rename fails; fall back to copy + truncate.
                    std::fs::copy(&inner.path, &inner.rotated_path)
                        .and_then(|_| std::fs::write(&inner.path, ""))
                });
            inner.current_size = 0;
        }
        // Ensure parent dir exists.
        if let Some(parent) = inner.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Append.
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    tracing::warn!("Failed to write MCP event log: {e}");
                }
            }
            Err(e) => tracing::warn!("Failed to open MCP event log: {e}"),
        }
        inner.current_size += line_bytes;
    }
}

impl Default for EventLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_16_hex() {
        let id = EventLogger::generate_request_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn event_serializes_to_ndjson() {
        let e = Event {
            ts: "2025-01-01T00:00:00Z".into(),
            request_id: "abc123".into(),
            session_id: "sess1".into(),
            identity_id: Some(1),
            identity_name: Some("ci-bot".into()),
            team_id: Some(1),
            team_name: Some("Engineering".into()),
            server_id: Some(1),
            server_name: Some("jira".into()),
            method: "tools/call".into(),
            tool: Some("jira__create".into()),
            resource_uri: None,
            prompt: None,
            action: "allow".into(),
            status: "ok".into(),
            latency_ms: Some(42),
            error: None,
            bytes_in: None,
            bytes_out: Some(1024),
            dlp_hits: None,
            guardrail_hits: None,
            params: None,
            result: None,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"method\":\"tools/call\""));
        assert!(s.contains("\"tool\":\"jira__create\""));
        assert!(s.contains("\"identity_name\":\"ci-bot\""));
        assert!(s.contains("\"team_name\":\"Engineering\""));
        assert!(s.contains("\"server_name\":\"jira\""));
    }
}
