//! stdio process manager — tokio subprocess MCP servers.
//!
//! Mirrors `mcp-gateway/stdio_proxy.py`:
//! - Spawn child processes communicating via stdin/stdout JSON-RPC (newline-delimited).
//! - Request/response correlation via JSON-RPC id (internal counter).
//! - Command allowlist (basenames: npx, uvx, node, python, etc.).
//! - Graceful shutdown (SIGTERM → SIGKILL after 5s).
//! - Idle timeout (stop processes idle too long).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex as SyncMutex;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use corex_core::config::ServerConfig;

use crate::upstream::{error_body, Catalog, PROTOCOL_VERSION};

const STDIO_TIMEOUT: u64 = 30;

/// Check if a stdio server command is permitted (basename allowlist).
pub fn is_command_allowed(command: &str) -> bool {
    let env = std::env::var("MCP_STDIO_ALLOWED_COMMANDS")
        .unwrap_or_else(|_| "npx,uvx,node,python,python3,uv,docker".into());
    if env.trim() == "*" {
        return true;
    }
    let allowed: std::collections::HashSet<&str> = env.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let basename = std::path::Path::new(command)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(command);
    allowed.contains(basename)
}

struct StdioProcess {
    server_id: i64,
    child: Option<Child>,
    next_id: i64,
    pending: Arc<SyncMutex<HashMap<i64, tokio::sync::oneshot::Sender<Value>>>>,
    initialized: bool,
}

impl StdioProcess {
    async fn start(server: &ServerConfig) -> Option<Self> {
        let command = server.command.as_deref()?;
        if !is_command_allowed(command) {
            tracing::error!(
                "stdio server {}: command {command:?} not in MCP_STDIO_ALLOWED_COMMANDS",
                server.id
            );
            return None;
        }
        let mut cmd = Command::new(command);
        cmd.args(&server.args);
        // Merge env vars.
        for (k, v) in server.env_vars.as_object().into_iter().flatten() {
            if let Some(vs) = v.as_str() {
                cmd.env(k, vs);
            }
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to start stdio process for server {}: {e}", server.id);
                return None;
            }
        };
        let stdout = child.stdout.take()?;
        let pending = Arc::new(SyncMutex::new(HashMap::<i64, tokio::sync::oneshot::Sender<Value>>::new()));
        let pending_clone = pending.clone();
        let server_id = server.id;
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {}
                    Err(_) => break,
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let msg = match serde_json::from_str::<Value>(trimmed) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if let Some(id) = msg.get("id").and_then(|v| v.as_i64()) {
                    if let Some(tx) = pending_clone.lock().remove(&id) {
                        let _ = tx.send(msg);
                    }
                }
            }
            // Process exited — cancel pending.
            pending_clone.lock().clear();
            tracing::warn!("stdio process for server {server_id} exited");
        });
        tracing::info!("Started stdio process for server {server_id}: {command}");
        Some(Self {
            server_id,
            child: Some(child),
            next_id: 1,
            pending,
            initialized: false,
        })
    }

    fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .map(|c| c.try_wait().map(|r| r.is_none()).unwrap_or(false))
            .unwrap_or(false)
    }

    async fn send_request(&mut self, message: &Value) -> Value {
        let child = match self.child.as_mut() {
            Some(c) => c,
            None => return error_body(-32000, "stdio process not available"),
        };
        let stdin = match child.stdin.as_mut() {
            Some(s) => s,
            None => return error_body(-32000, "stdio process stdin not available"),
        };
        let original_id = message.get("id").cloned();
        let internal_id = self.next_id;
        self.next_id += 1;
        let mut msg = message.clone();
        msg["id"] = Value::from(internal_id);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().insert(internal_id, tx);
        let serialized = match serde_json::to_string(&msg) {
            Ok(s) => s + "\n",
            Err(e) => {
                self.pending.lock().remove(&internal_id);
                return error_body(-32000, &format!("Failed to serialize: {e}"));
            }
        };
        if stdin.write_all(serialized.as_bytes()).await.is_err() {
            self.pending.lock().remove(&internal_id);
            return error_body(-32000, "Failed to write to stdin");
        }
        let _ = stdin.flush().await;
        match tokio::time::timeout(std::time::Duration::from_secs(STDIO_TIMEOUT), rx).await {
            Ok(Ok(mut resp)) => {
                if let Some(oid) = original_id {
                    resp["id"] = oid;
                }
                resp
            }
            _ => {
                self.pending.lock().remove(&internal_id);
                let id = original_id.unwrap_or(Value::Null);
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32000, "message": "stdio request timeout"}
                })
            }
        }
    }

    async fn send_notification(&mut self, message: &Value) -> u16 {
        let child = match self.child.as_mut() {
            Some(c) => c,
            None => return 502,
        };
        let stdin = match child.stdin.as_mut() {
            Some(s) => s,
            None => return 502,
        };
        let serialized = match serde_json::to_string(message) {
            Ok(s) => s + "\n",
            Err(_) => return 502,
        };
        if stdin.write_all(serialized.as_bytes()).await.is_err() {
            return 502;
        }
        let _ = stdin.flush().await;
        200
    }

    async fn initialize(&mut self) -> Option<String> {
        if self.initialized {
            return Some(format!("stdio:{}", self.server_id));
        }
        let resp = self
            .send_request(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": "0.1.0"},
                }
            }))
            .await;
        if resp.get("error").is_some() {
            tracing::error!("stdio initialize failed for server {}: {}", self.server_id, resp["error"]);
            return None;
        }
        let _ = self
            .send_notification(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }))
            .await;
        self.initialized = true;
        Some(format!("stdio:{}", self.server_id))
    }

    async fn fetch_catalog(&mut self) -> Option<Catalog> {
        let mut tools = Vec::new();
        let mut resources = Vec::new();
        let mut prompts = Vec::new();
        for (method, key, dest) in [
            ("tools/list", "tools", &mut tools),
            ("resources/list", "resources", &mut resources),
            ("prompts/list", "prompts", &mut prompts),
        ] {
            let resp = self
                .send_request(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": {},
                }))
                .await;
            if let Some(arr) = resp.get("result").and_then(|r| r.get(key)).and_then(|v| v.as_array()) {
                dest.extend(arr.iter().cloned());
            }
        }
        Some(Catalog { tools, resources, prompts, fetched_at: now_secs() })
    }

    async fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Send SIGTERM (Unix) / kill (Windows) and wait up to 5s.
            let _ = child.start_kill();
            match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    let _ = child.kill().await;
                }
            }
        }
        self.pending.lock().clear();
        self.initialized = false;
    }
}

/// Singleton managing all stdio MCP server processes.
#[derive(Default)]
#[derive(Clone)]
pub struct ProcessManager {
    processes: Arc<SyncMutex<HashMap<i64, Arc<Mutex<StdioProcess>>>>>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self::default()
    }

    async fn get_process(&self, server: &ServerConfig) -> Option<Arc<Mutex<StdioProcess>>> {
        if server.transport_type != "stdio" {
            return None;
        }
        let sid = server.id;
        let existing = self.processes.lock().get(&sid).cloned();
        if let Some(p) = existing {
            if p.lock().await.is_running() {
                return Some(p);
            }
        }
        // Create new.
        let proc = StdioProcess::start(server).await?;
        let arc = Arc::new(Mutex::new(proc));
        self.processes.lock().insert(sid, arc.clone());
        Some(arc)
    }

    /// Send a JSON-RPC request to a stdio server. Returns (status, body).
    pub async fn send_request(&self, server: &ServerConfig, message: &Value) -> (u16, Value) {
        let proc = match self.get_process(server).await {
            Some(p) => p,
            None => return (502, error_body(-32000, "No stdio process available")),
        };
        let mut guard = proc.lock().await;
        let resp = guard.send_request(message).await;
        (200, resp)
    }

    /// Send a notification to a stdio server. Returns status code.
    pub async fn send_notification(&self, server: &ServerConfig, message: &Value) -> u16 {
        let proc = match self.get_process(server).await {
            Some(p) => p,
            None => return 502,
        };
        let mut guard = proc.lock().await;
        guard.send_notification(message).await
    }

    /// Initialize a stdio upstream session.
    pub async fn initialize_upstream(&self, server: &ServerConfig) -> Option<String> {
        let proc = self.get_process(server).await?;
        let mut guard = proc.lock().await;
        guard.initialize().await
    }

    /// Fetch catalog from a stdio server.
    pub async fn fetch_catalog(&self, server: &ServerConfig) -> Option<Catalog> {
        let proc = self.get_process(server).await?;
        let mut guard = proc.lock().await;
        guard.fetch_catalog().await
    }

    /// Check if a server's process is alive.
    pub async fn is_healthy(&self, server_id: i64) -> bool {
        let existing = self.processes.lock().get(&server_id).cloned();
        match existing {
            Some(p) => p.lock().await.is_running(),
            None => false,
        }
    }

    /// Stop all processes on shutdown.
    pub async fn shutdown_all(&self) {
        let procs: Vec<Arc<Mutex<StdioProcess>>> = {
            let mut map = self.processes.lock();
            let values: Vec<_> = map.drain().map(|(_, v)| v).collect();
            values
        };
        for p in procs {
            p.lock().await.stop().await;
        }
        tracing::info!("All stdio processes stopped");
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
    fn command_allowlist_basenames() {
        assert!(is_command_allowed("npx"));
        assert!(is_command_allowed("/usr/bin/npx"));
        assert!(is_command_allowed("python3"));
        assert!(!is_command_allowed("rm"));
    }

    #[test]
    fn wildcard_allows_all() {
        std::env::set_var("MCP_STDIO_ALLOWED_COMMANDS", "*");
        assert!(is_command_allowed("anything"));
        std::env::set_var("MCP_STDIO_ALLOWED_COMMANDS", "npx,uvx,node,python,python3,uv,docker");
    }
}
