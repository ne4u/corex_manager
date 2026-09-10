//! Session manager — Valkey-backed, `mcp:gw:` prefixed.
//!
//! Mirrors `mcp-gateway/sessions.py`:
//! - Key: `mcp:gw:sess:<id>`
//! - Value: JSON `{identity_id, team_id, created_at, upstreams: {server_id: sid}}`
//! - TTL: 1 hour sliding (refreshed on each request)

use crate::valkey::ValkeyClient;
use serde::{Deserialize, Serialize};

pub const SESSION_TTL: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub identity_id: i64,
    pub team_id: i64,
    pub created_at: f64,
    #[serde(default)]
    pub upstreams: std::collections::BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct SessionStore {
    client: Option<ValkeyClient>,
}

impl SessionStore {
    pub fn new(client: Option<ValkeyClient>) -> Self {
        Self { client }
    }

    /// Create a new session, store in Valkey, return session ID.
    pub async fn create(&self, identity_id: i64, team_id: i64) -> String {
        let session_id = generate_session_id();
        let data = SessionData {
            identity_id,
            team_id,
            created_at: now_secs(),
            upstreams: Default::default(),
        };
        if let Some(c) = &self.client {
            let payload = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());
            let _ = c.setex(&format!("sess:{session_id}"), SESSION_TTL, &payload).await;
        }
        session_id
    }

    /// Retrieve session data. Returns None if not found, expired, or Valkey down.
    pub async fn get(&self, session_id: &str) -> Option<SessionData> {
        if session_id.is_empty() {
            return None;
        }
        let c = self.client.as_ref()?;
        let raw = c.get(&format!("sess:{session_id}")).await.ok()??;
        serde_json::from_str(&raw).ok()
    }

    /// Slide the TTL forward.
    pub async fn refresh(&self, session_id: &str) {
        if let Some(c) = &self.client {
            let _ = c.expire(&format!("sess:{session_id}"), SESSION_TTL).await;
        }
    }

    /// Delete a session.
    pub async fn delete(&self, session_id: &str) {
        if let Some(c) = &self.client {
            let _ = c.del(&format!("sess:{session_id}")).await;
        }
    }

    /// Store the upstream MCP session ID for a given server.
    pub async fn set_upstream_session(&self, session_id: &str, server_id: i64, upstream_sid: &str) {
        let Some(c) = &self.client else { return };
        if let Some(mut data) = self.get(session_id).await {
            data.upstreams.insert(server_id.to_string(), upstream_sid.to_string());
            let payload = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());
            let _ = c.setex(&format!("sess:{session_id}"), SESSION_TTL, &payload).await;
        }
    }

    /// Get the stored upstream session ID for a server.
    pub async fn get_upstream_session(&self, session_id: &str, server_id: i64) -> Option<String> {
        self.get(session_id)
            .await
            .and_then(|d| d.upstreams.get(&server_id.to_string()).cloned())
    }

    /// Check if a session exists and is valid.
    pub async fn validate(&self, session_id: &str) -> bool {
        self.get(session_id).await.is_some()
    }

    /// Count active sessions (best-effort; 0 if Valkey is unavailable).
    pub async fn active_count(&self) -> usize {
        let Some(c) = &self.client else { return 0 };
        c.scan_count("sess:*", 100).await.unwrap_or(0)
    }
}

fn generate_session_id() -> String {
    // 32 bytes of randomness, URL-safe base64 (no padding) ≈ 43 chars.
    use base64::Engine;
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
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

    #[tokio::test]
    async fn no_valkey_returns_none_get() {
        let store = SessionStore::new(None);
        // create still returns an id (best-effort), but get returns None.
        let id = store.create(1, 1).await;
        assert!(!id.is_empty());
        assert!(store.get(&id).await.is_none());
        assert!(!store.validate(&id).await);
    }

    #[test]
    fn session_data_serializes() {
        let d = SessionData {
            identity_id: 1,
            team_id: 2,
            created_at: 1000.0,
            upstreams: Default::default(),
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(s.contains("\"identity_id\":1"));
        let back: SessionData = serde_json::from_str(&s).unwrap();
        assert_eq!(back.identity_id, 1);
    }

    #[test]
    fn session_id_is_url_safe() {
        let id = generate_session_id();
        assert!(id.len() >= 40);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn json_helper() {
        // Sanity: serde_json round-trips session data.
        let d = SessionData {
            identity_id: 1, team_id: 2, created_at: 1.0, upstreams: Default::default(),
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(serde_json::from_str::<SessionData>(&s).is_ok());
    }
}
