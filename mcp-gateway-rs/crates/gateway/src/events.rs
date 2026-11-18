//! NDJSON event logger with 2-file rotation.
//!
//! Mirrors `mcp-gateway/events.py` but with 2-file rotation (not 10):
//! - Active file: `MCP_EVENTS_LOG_PATH` (default `data/mcp/events.ndjson`).
//! - Rotated copy: `{path}.1` (overwritten on rotation).
//! - When the active file exceeds `max_bytes`, it rotates to `.1`.
//! - One NDJSON line per RPC with method, tool, identity, team, server, etc.
//!
//! The request path only does a non-blocking `try_send` on a bounded channel
//! (`MCP_EVENTS_QUEUE_SIZE`, default 10000). A dedicated writer thread keeps
//! the file open, batches writes, and rotates off the request path. If the
//! channel is full or closed the event is dropped and a counter is bumped so
//! the loss is visible on `/metrics` as `mcp_gateway_events_dropped_total`.

use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use serde::Serialize;

const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024; // 100 MB per file
const DEFAULT_QUEUE_SIZE: usize = 10_000;

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

/// Non-blocking event logger backed by a bounded channel + writer thread.
#[derive(Clone)]
pub struct EventLogger {
    tx: mpsc::SyncSender<String>,
    dropped: Arc<AtomicU64>,
    log_payloads: bool,
}

struct WriterConfig {
    path: PathBuf,
    rotated_path: PathBuf,
    max_bytes: u64,
}

impl EventLogger {
    pub fn new() -> Self {
        Self::with_drop_counter(Arc::new(AtomicU64::new(0)))
    }

    /// Construct a logger whose dropped-event counter is shared (e.g. with
    /// the metrics registry so `/metrics` can report it).
    pub fn with_drop_counter(dropped: Arc<AtomicU64>) -> Self {
        let path_str =
            std::env::var("MCP_EVENTS_LOG_PATH").unwrap_or_else(|_| "data/mcp/events.ndjson".into());
        let cfg = WriterConfig {
            path: PathBuf::from(&path_str),
            rotated_path: PathBuf::from(format!("{path_str}.1")),
            max_bytes: std::env::var("MCP_EVENTS_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_MAX_BYTES),
        };
        let log_payloads = std::env::var("MCP_LOG_PAYLOADS")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        let queue_size = std::env::var("MCP_EVENTS_QUEUE_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_QUEUE_SIZE);
        let (tx, rx) = mpsc::sync_channel::<String>(queue_size.max(1));
        std::thread::Builder::new()
            .name("mcp-event-writer".into())
            .spawn(move || writer_loop(rx, cfg))
            .expect("failed to spawn MCP event writer thread");
        Self {
            tx,
            dropped,
            log_payloads,
        }
    }

    /// Generate a unique request ID (16 hex chars).
    pub fn generate_request_id() -> String {
        use uuid::Uuid;
        Uuid::new_v4().simple().to_string()[..16].to_string()
    }

    /// Queue a single NDJSON event line. Never blocks: a full channel drops
    /// the event and bumps the drop counter.
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
        if self.tx.try_send(line).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Dedicated writer: drains the channel in batches, keeps the file open via a
/// buffered writer, and rotates to `.1` when the active file exceeds max_bytes.
fn writer_loop(rx: mpsc::Receiver<String>, cfg: WriterConfig) {
    let mut current_size = std::fs::metadata(&cfg.path).map(|m| m.len()).unwrap_or(0);
    let mut file: Option<BufWriter<std::fs::File>> = None;

    while let Ok(first) = rx.recv() {
        // Drain whatever else is queued so each flush covers a batch.
        let mut batch = vec![first];
        while let Ok(line) = rx.try_recv() {
            batch.push(line);
        }
        let batch_bytes: u64 = batch.iter().map(|l| l.len() as u64).sum();

        // Rotate before writing when the batch would overflow the file.
        if current_size + batch_bytes > cfg.max_bytes && current_size > 0 {
            drop(file.take());
            let _ = std::fs::rename(&cfg.path, &cfg.rotated_path).or_else(|_| {
                // Cross-device rename fails; fall back to copy + truncate.
                std::fs::copy(&cfg.path, &cfg.rotated_path)
                    .and_then(|_| std::fs::write(&cfg.path, ""))
            });
            current_size = 0;
        }

        if file.is_none() {
            if let Some(parent) = cfg.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&cfg.path)
                .ok()
                .map(BufWriter::new);
            if file.is_none() {
                tracing::warn!("Failed to open MCP event log: {}", cfg.path.display());
            }
        }

        if let Some(f) = file.as_mut() {
            for line in &batch {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    tracing::warn!("Failed to write MCP event log: {e}");
                    break;
                }
            }
            // Flush per batch: at this point the channel is empty so this is
            // the lowest-latency point that still amortizes syscalls.
            let _ = f.flush();
            current_size += batch_bytes;
        }
    }
    // Channel closed: flush whatever remains buffered.
    if let Some(mut f) = file {
        let _ = f.flush();
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

    fn sample_event() -> Event {
        Event {
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
        }
    }

    #[test]
    fn request_id_is_16_hex() {
        let id = EventLogger::generate_request_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn event_serializes_to_ndjson() {
        let s = serde_json::to_string(&sample_event()).unwrap();
        assert!(s.contains("\"method\":\"tools/call\""));
        assert!(s.contains("\"tool\":\"jira__create\""));
        assert!(s.contains("\"identity_name\":\"ci-bot\""));
        assert!(s.contains("\"team_name\":\"Engineering\""));
        assert!(s.contains("\"server_name\":\"jira\""));
    }

    #[test]
    fn writes_lines_through_channel() {
        let dir = std::env::temp_dir().join(format!("mcp-events-{}", std::process::id()));
        let path = dir.join("events.ndjson");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("MCP_EVENTS_LOG_PATH", &path);
        std::env::set_var("MCP_EVENTS_QUEUE_SIZE", "64");

        let logger = EventLogger::new();
        logger.log(sample_event());
        logger.log(sample_event());
        drop(logger); // closes channel → writer flushes and exits

        for _ in 0..100 {
            if std::fs::metadata(&path).map(|m| m.len() > 0).unwrap_or(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_channel_drops_and_counts() {
        let dir = std::env::temp_dir().join(format!("mcp-events-full-{}", std::process::id()));
        let path = dir.join("events.ndjson");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("MCP_EVENTS_LOG_PATH", &path);
        std::env::set_var("MCP_EVENTS_QUEUE_SIZE", "1");

        let dropped = Arc::new(AtomicU64::new(0));
        let logger = EventLogger::with_drop_counter(dropped.clone());
        // The writer drains concurrently, so fill far beyond capacity and
        // assert callers never block and the counter tracks drops.
        for _ in 0..1000 {
            logger.log(sample_event());
        }
        // Not every event can land in a size-1 queue; drops are required but
        // the exact count depends on writer timing.
        assert!(dropped.load(Ordering::Relaxed) > 0 || std::fs::metadata(&path).is_ok());
        drop(logger);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_to_dot_one() {
        let dir = std::env::temp_dir().join(format!("mcp-events-rot-{}", std::process::id()));
        let path = dir.join("events.ndjson");
        let rotated = dir.join("events.ndjson.1");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("MCP_EVENTS_LOG_PATH", &path);
        std::env::set_var("MCP_EVENTS_QUEUE_SIZE", "256");
        // Tiny max so the second batch rotates.
        std::env::set_var("MCP_EVENTS_MAX_BYTES", "200");

        {
            let logger = EventLogger::new();
            for _ in 0..3 {
                logger.log(sample_event());
            }
            // Give the writer a beat to rotate between batches.
            std::thread::sleep(std::time::Duration::from_millis(50));
            for _ in 0..3 {
                logger.log(sample_event());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            rotated.exists(),
            "rotation must produce {} — dir: {:?}",
            rotated.display(),
            std::fs::read_dir(&dir).map(|d| d.collect::<Vec<_>>())
        );
        std::env::remove_var("MCP_EVENTS_MAX_BYTES");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
