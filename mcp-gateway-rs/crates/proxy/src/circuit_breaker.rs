//! Circuit breaker — per-server failure tracking with open/half-open states.
//!
//! Mirrors `mcp-gateway/upstream.py` circuit breaker:
//! - After `failure_threshold` failures, the circuit opens for `reset_seconds`.
//! - While open, requests are short-circuited (503).
//! - After `reset_seconds`, the circuit half-opens (one request allowed); a
//!   success closes it, a failure re-opens it.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
struct CbState {
    failures: u32,
    open_until: f64,
}

/// Per-server circuit breaker.
#[derive(Clone)]
pub struct CircuitBreaker {
    states: Arc<Mutex<HashMap<i64, CbState>>>,
    failure_threshold: u32,
    reset_seconds: f64,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        let threshold = std::env::var("MCP_CB_FAILURE_THRESHOLD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let reset = std::env::var("MCP_CB_RESET_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        Self {
            states: Arc::new(Mutex::new(HashMap::new())),
            failure_threshold: threshold,
            reset_seconds: reset as f64,
        }
    }

    /// Returns true if the request should proceed (closed or half-open).
    pub fn check(&self, server_id: i64) -> bool {
        let now = now_secs();
        let states = self.states.lock();
        !matches!(states.get(&server_id), Some(s) if s.open_until > now)
    }

    /// Returns true if the circuit is currently open.
    pub fn is_open(&self, server_id: i64) -> bool {
        !self.check(server_id)
    }

    /// Record a success — reset the circuit.
    pub fn record_success(&self, server_id: i64) {
        self.states.lock().remove(&server_id);
    }

    /// Record a failure — may trip the circuit.
    pub fn record_failure(&self, server_id: i64) {
        let now = now_secs();
        let mut states = self.states.lock();
        let s = states.entry(server_id).or_insert(CbState { failures: 0, open_until: 0.0 });
        s.failures += 1;
        if s.failures >= self.failure_threshold {
            s.open_until = now + self.reset_seconds;
            tracing::warn!(
                "Circuit breaker opened for server {server_id} ({} failures)",
                s.failures
            );
        }
    }

    /// Snapshot all currently-open circuit breakers as `(server_id, failures, open_until)`.
    pub fn open_circuits(&self) -> Vec<(i64, u32, f64)> {
        let now = now_secs();
        self.states
            .lock()
            .iter()
            .filter(|(_, s)| s.open_until > now)
            .map(|(id, s)| (*id, s.failures, s.open_until))
            .collect()
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

    fn make_cb(threshold: u32, reset: f64) -> CircuitBreaker {
        CircuitBreaker {
            states: Arc::new(Mutex::new(HashMap::new())),
            failure_threshold: threshold,
            reset_seconds: reset,
        }
    }

    #[test]
    fn opens_after_threshold() {
        let cb = make_cb(3, 60.0);
        assert!(cb.check(1));
        cb.record_failure(1);
        cb.record_failure(1);
        assert!(cb.check(1)); // not yet open
        cb.record_failure(1);
        assert!(!cb.check(1)); // open
        assert!(cb.is_open(1));
    }

    #[test]
    fn success_resets() {
        let cb = make_cb(2, 60.0);
        cb.record_failure(1);
        cb.record_failure(1);
        assert!(!cb.check(1));
        cb.record_success(1);
        assert!(cb.check(1));
    }

    #[test]
    fn independent_per_server() {
        let cb = make_cb(1, 60.0);
        cb.record_failure(1);
        assert!(!cb.check(1));
        assert!(cb.check(2));
    }
}
