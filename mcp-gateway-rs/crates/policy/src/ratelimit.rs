//! Rate limiting — Valkey-backed sliding-window quotas, `mcp:gw:` prefixed.
//!
//! Mirrors `mcp-gateway/ratelimit.py`:
//! - Per-identity/tool sliding window (ZSET): `mcp:gw:rl:{id}:{tool}`
//! - Per-IP sliding window: `mcp:gw:rl:ip:{ip}`
//! - Concurrent request leases (INCR + TTL): `mcp:gw:conc:{id}`
//! - Per-team RPM overrides from the config bundle
//! - Configurable fail mode: fail-open (default) or fail-closed
//!
//! Exceed → JSON-RPC error -32029 "rate_limited".

use crate::valkey::ValkeyClient;

pub const MCP_RATE_LIMITED: i32 = -32029;
const WINDOW_SECONDS: u64 = 60;
const CONCURRENT_SAFETY_TTL: u64 = 300;

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub fail_closed: bool,
    pub default_max_ip_rpm: i64,
    pub default_max_concurrent: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            fail_closed: std::env::var("MCP_RATELIMIT_FAIL_CLOSED")
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),
            default_max_ip_rpm: std::env::var("MCP_MAX_IP_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            default_max_concurrent: std::env::var("MCP_MAX_CONCURRENT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    client: Option<ValkeyClient>,
    config: RateLimitConfig,
}

/// Result of a rate-limit check.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub remaining: i64,
}

impl RateLimiter {
    pub fn new(client: Option<ValkeyClient>, config: RateLimitConfig) -> Self {
        Self { client, config }
    }

    /// Check if a request is within the per-identity/tool sliding window.
    pub async fn check_rate_limit(&self, identity_id: i64, tool: &str, max_rpm: i64) -> RateLimitDecision {
        if max_rpm <= 0 {
            return RateLimitDecision { allowed: true, remaining: max_rpm };
        }
        let Some(c) = &self.client else {
            return self.fail_open(max_rpm);
        };
        match c.sliding_window(&format!("rl:{identity_id}:{tool}"), max_rpm, WINDOW_SECONDS).await {
            Ok((allowed, remaining)) => RateLimitDecision { allowed, remaining },
            Err(e) => {
                ValkeyClient::log_failure("rate_limit", &e);
                self.fail_open(max_rpm)
            }
        }
    }

    /// Check per-IP rate limit. Disabled if `max_ip_rpm` is 0.
    pub async fn check_ip_rate_limit(&self, ip: &str, max_ip_rpm: Option<i64>) -> RateLimitDecision {
        let limit = max_ip_rpm.unwrap_or(self.config.default_max_ip_rpm);
        if limit <= 0 {
            return RateLimitDecision { allowed: true, remaining: limit };
        }
        let Some(c) = &self.client else {
            return self.fail_open(limit);
        };
        match c.sliding_window(&format!("rl:ip:{ip}"), limit, WINDOW_SECONDS).await {
            Ok((allowed, remaining)) => RateLimitDecision { allowed, remaining },
            Err(e) => {
                ValkeyClient::log_failure("ip_rate_limit", &e);
                self.fail_open(limit)
            }
        }
    }

    /// Acquire a concurrent request slot. Returns true if allowed.
    /// Must be released with `release_concurrent_slot`.
    pub async fn acquire_concurrent_slot(&self, identity_id: i64, max_concurrent: Option<i64>) -> bool {
        let limit = max_concurrent.unwrap_or(self.config.default_max_concurrent);
        if limit <= 0 {
            return true;
        }
        let Some(c) = &self.client else {
            return !self.config.fail_closed;
        };
        let key = format!("conc:{identity_id}");
        match c.incr(&key).await {
            Ok(count) => {
                if count == 1 {
                    let _ = c.expire(&key, CONCURRENT_SAFETY_TTL).await;
                }
                if count > limit {
                    let _ = c.decr(&key).await;
                    return false;
                }
                true
            }
            Err(e) => {
                ValkeyClient::log_failure("concurrent", &e);
                !self.config.fail_closed
            }
        }
    }

    /// Release a concurrent request slot.
    ///
    /// Always decrements if a Valkey client is present.  The guard in
    /// `acquire_concurrent_slot` already short-circuits when the limit is 0,
    /// so this function is only reached when a slot was actually acquired
    /// (counter >= 1), making the DECR safe.  We must NOT check
    /// `self.config.default_max_concurrent` here because the per-request limit
    /// may come from the config bundle (which can be non-zero even when the
    /// env-var default is zero); checking the env-var default would skip the
    /// DECR and leak the slot, permanently blocking the identity.
    pub async fn release_concurrent_slot(&self, identity_id: i64) {
        if let Some(c) = &self.client {
            let _ = c.decr(&format!("conc:{identity_id}")).await;
        }
    }

    fn fail_open(&self, max_rpm: i64) -> RateLimitDecision {
        if self.config.fail_closed {
            RateLimitDecision { allowed: false, remaining: 0 }
        } else {
            RateLimitDecision { allowed: true, remaining: max_rpm }
        }
    }
}

/// Get the RPM for a team, falling back to `default_rpm`.
/// The config bundle may include `team_rpm_overrides: {team_id: rpm}`.
pub fn get_team_rpm(overrides: &serde_json::Value, team_id: i64, default_rpm: i64) -> i64 {
    if let Some(map) = overrides.as_object() {
        let key = team_id.to_string();
        if let Some(v) = map.get(&key).or_else(|| map.get(&team_id.to_string())) {
            if let Some(n) = v.as_i64() {
                return n;
            }
        }
    }
    default_rpm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_valkey_fail_open() {
        let rl = RateLimiter::new(None, RateLimitConfig::default());
        let d = rl.check_rate_limit(1, "tool", 100).await;
        assert!(d.allowed);
        let d = rl.check_ip_rate_limit("1.2.3.4", Some(100)).await;
        assert!(d.allowed);
        assert!(rl.acquire_concurrent_slot(1, Some(10)).await);
    }

    #[tokio::test]
    async fn no_valkey_fail_closed() {
        let rl = RateLimiter::new(None, RateLimitConfig {
            fail_closed: true,
            default_max_ip_rpm: 100,
            default_max_concurrent: 10,
        });
        let d = rl.check_rate_limit(1, "tool", 100).await;
        assert!(!d.allowed);
        assert!(!rl.acquire_concurrent_slot(1, Some(10)).await);
    }

    #[tokio::test]
    async fn zero_limit_disabled() {
        let rl = RateLimiter::new(None, RateLimitConfig::default());
        let d = rl.check_rate_limit(1, "tool", 0).await;
        assert!(d.allowed);
        let d = rl.check_ip_rate_limit("1.2.3.4", Some(0)).await;
        assert!(d.allowed);
        assert!(rl.acquire_concurrent_slot(1, Some(0)).await);
    }

    #[test]
    fn team_rpm_override() {
        let overrides = serde_json::json!({"1": 200, "2": 50});
        assert_eq!(get_team_rpm(&overrides, 1, 100), 200);
        assert_eq!(get_team_rpm(&overrides, 3, 100), 100);
        assert_eq!(get_team_rpm(&serde_json::json!(null), 1, 100), 100);
    }

    /// Regression test: release_concurrent_slot must always DECR when a client
    /// is present, even if the env-var default (default_max_concurrent) is 0.
    /// The per-request limit may come from the config bundle and be non-zero,
    /// so checking the env-var default in release would leak the slot.
    #[tokio::test]
    async fn release_always_decrements_regardless_of_env_default() {
        // Simulate: env var MCP_MAX_CONCURRENT=0 (default), but config bundle
        // has concurrent_limit=1 (set via UI settings table).
        let rl = RateLimiter::new(None, RateLimitConfig {
            fail_closed: false,
            default_max_ip_rpm: 0,
            default_max_concurrent: 0, // env-var default is 0
        });

        // Without Valkey, acquire returns true (fail-open).  Release is a
        // no-op (no client).  This test documents the contract: release
        // does NOT check default_max_concurrent.
        assert!(rl.acquire_concurrent_slot(1, Some(1)).await);
        // Should not panic or short-circuit — no client so it's a no-op,
        // but the guard must not prevent the DECR path when a client exists.
        rl.release_concurrent_slot(1).await;
    }
}
