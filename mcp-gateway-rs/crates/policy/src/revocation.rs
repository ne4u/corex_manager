//! Token revocation / blocklist — Valkey-backed, `mcp:gw:` prefixed.
//!
//! Mirrors `mcp-gateway/revocation.py` semantics:
//! - `mcp:gw:rev:jti:{jti}` — individual JWT revocation (TTL = token lifetime)
//! - `mcp:gw:rev:identity:{id}` — identity-level revocation (timestamp cutoff)
//!
//! Fail-open when Valkey is unavailable (availability over strictness, matching
//! the Python gateway).

use crate::valkey::ValkeyClient;

#[derive(Clone)]
pub struct RevocationStore {
    client: Option<ValkeyClient>,
}

impl RevocationStore {
    pub fn new(client: Option<ValkeyClient>) -> Self {
        Self { client }
    }

    /// Revoke a specific JWT by its jti claim.
    pub async fn revoke_jti(&self, jti: &str, ttl_seconds: u64) -> bool {
        let Some(c) = &self.client else { return false };
        match c.setex(&format!("rev:jti:{jti}"), ttl_seconds, "1").await {
            Ok(_) => true,
            Err(e) => {
                ValkeyClient::log_failure("revoke_jti", &e);
                false
            }
        }
    }

    /// Revoke all tokens for an identity.
    pub async fn revoke_identity(&self, identity_id: i64) -> bool {
        let Some(c) = &self.client else { return false };
        let ts = chrono::Utc::now().timestamp();
        match c.set(&format!("rev:identity:{identity_id}"), &ts.to_string()).await {
            Ok(_) => true,
            Err(e) => {
                ValkeyClient::log_failure("revoke_identity", &e);
                false
            }
        }
    }

    /// Check if a JWT jti has been revoked.
    pub async fn is_jti_revoked(&self, jti: &str) -> bool {
        if jti.is_empty() {
            return false;
        }
        let Some(c) = &self.client else { return false };
        c.exists(&format!("rev:jti:{jti}")).await.unwrap_or(false)
    }

    /// Check if an identity has been revoked at the identity level.
    pub async fn is_identity_revoked(&self, identity_id: i64) -> bool {
        let Some(c) = &self.client else { return false };
        c.exists(&format!("rev:identity:{identity_id}")).await.unwrap_or(false)
    }

    /// Check if a token is still valid (not revoked). Returns `true` if valid.
    /// Fail-open (returns true) when Valkey is unavailable.
    pub async fn is_token_valid(&self, identity_id: i64, jti: Option<&str>) -> bool {
        if self.client.is_none() {
            return true;
        }
        if self.is_identity_revoked(identity_id).await {
            return false;
        }
        if let Some(j) = jti {
            if self.is_jti_revoked(j).await {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fail_open_without_valkey() {
        let store = RevocationStore::new(None);
        // No Valkey → fail-open (token considered valid).
        assert!(store.is_token_valid(1, Some("jti-1")).await);
        assert!(!store.revoke_jti("jti-1", 3600).await);
        assert!(!store.revoke_identity(1).await);
    }
}
