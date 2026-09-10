//! Alerting — threshold-based security event alerts.
//!
//! Mirrors `mcp-gateway/alerting.py`:
//! - Monitors security events (guardrail_blocked, dlp_blocked, policy_denied,
//!   auth_failed, rate_limited).
//! - Triggers alerts when count exceeds threshold within a sliding window.
//! - Alert delivery: webhook (MCP_ALERT_WEBHOOK_URL) + log (always).
//! - Cooldown prevents alert storms.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

const ALERT_WINDOW: f64 = 60.0;
const ALERT_COOLDOWN: f64 = 300.0;

#[derive(Clone)]
pub struct Alerter {
    inner: Arc<Mutex<AlertInner>>,
    webhook_url: Option<String>,
    webhook_timeout: u64,
    client: reqwest::Client,
}

struct AlertInner {
    thresholds: HashMap<String, usize>,
    counters: HashMap<String, Vec<f64>>,
    last_alert: HashMap<String, f64>,
}

/// Serializable snapshot of one alert type's recent state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlertSnapshot {
    pub event_type: String,
    pub recent_count: usize,
    pub threshold: usize,
    pub last_alert_ts: Option<f64>,
}

impl Alerter {
    pub fn new() -> Self {
        let webhook_url = std::env::var("MCP_ALERT_WEBHOOK_URL").ok().filter(|s| !s.is_empty());
        let webhook_timeout = std::env::var("MCP_ALERT_WEBHOOK_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let mut thresholds = HashMap::new();
        thresholds.insert(
            "guardrail_blocked".into(),
            std::env::var("MCP_ALERT_GUARDRAIL_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        );
        thresholds.insert(
            "dlp_blocked".into(),
            std::env::var("MCP_ALERT_DLP_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        );
        thresholds.insert(
            "policy_denied".into(),
            std::env::var("MCP_ALERT_POLICY_DENY_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
        );
        thresholds.insert(
            "auth_failed".into(),
            std::env::var("MCP_ALERT_AUTH_FAIL_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        );
        thresholds.insert(
            "rate_limited".into(),
            std::env::var("MCP_ALERT_RATELIMIT_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
        );
        Self {
            inner: Arc::new(Mutex::new(AlertInner {
                thresholds,
                counters: HashMap::new(),
                last_alert: HashMap::new(),
            })),
            webhook_url,
            webhook_timeout,
            client: reqwest::Client::new(),
        }
    }

    /// Record a security event and check if alert threshold is exceeded.
    pub fn record_event(&self, event_type: &str) {
        let mut inner = self.inner.lock();
        let threshold = match inner.thresholds.get(event_type) {
            Some(&t) if t > 0 => t,
            _ => return,
        };
        let now = now_secs();
        let cutoff = now - ALERT_WINDOW;
        let timestamps = inner.counters.entry(event_type.to_string()).or_default();
        timestamps.retain(|t| *t > cutoff);
        timestamps.push(now);
        let count = timestamps.len();
        if count >= threshold {
            let last = *inner.last_alert.get(event_type).unwrap_or(&0.0);
            if now - last > ALERT_COOLDOWN {
                inner.last_alert.insert(event_type.to_string(), now);
                drop(inner);
                self.send_alert(event_type, count, threshold);
            }
        }
    }

    /// Snapshot recent alert state: `(event_type, recent_count, threshold, last_alert_ts)`.
    pub fn snapshot(&self) -> Vec<AlertSnapshot> {
        let inner = self.inner.lock();
        let now = now_secs();
        let cutoff = now - ALERT_WINDOW;
        inner
            .thresholds
            .iter()
            .map(|(event_type, &threshold)| {
                let count = inner
                    .counters
                    .get(event_type)
                    .map(|ts| ts.iter().filter(|t| **t > cutoff).count())
                    .unwrap_or(0);
                let last_alert = inner.last_alert.get(event_type).copied().unwrap_or(0.0);
                AlertSnapshot {
                    event_type: event_type.clone(),
                    recent_count: count,
                    threshold,
                    last_alert_ts: if last_alert > 0.0 { Some(last_alert) } else { None },
                }
            })
            .collect()
    }

    fn send_alert(&self, event_type: &str, count: usize, threshold: usize) {
        let message = format!(
            "MCP Gateway Alert: {event_type} threshold exceeded — \
             {count} events in {ALERT_WINDOW}s (threshold: {threshold})"
        );
        tracing::warn!("{message}");
        if let Some(url) = &self.webhook_url {
            let payload = serde_json::json!({
                "text": message,
                "event_type": event_type,
                "count": count,
                "threshold": threshold,
                "window_seconds": ALERT_WINDOW,
                "timestamp": now_secs(),
            });
            let url = url.clone();
            let client = self.client.clone();
            let timeout = self.webhook_timeout;
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(timeout),
                    client.post(&url).json(&payload).send(),
                )
                .await;
            });
        }
    }
}

impl Default for Alerter {
    fn default() -> Self {
        Self::new()
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
    fn records_and_checks_threshold() {
        let alerter = Alerter {
            inner: Arc::new(Mutex::new(AlertInner {
                thresholds: {
                    let mut m = HashMap::new();
                    m.insert("test".into(), 3usize);
                    m
                },
                counters: HashMap::new(),
                last_alert: HashMap::new(),
            })),
            webhook_url: None,
            webhook_timeout: 5,
            client: reqwest::Client::new(),
        };
        alerter.record_event("test");
        alerter.record_event("test");
        // Not yet at threshold (3).
        assert_eq!(alerter.inner.lock().counters.get("test").map(|v| v.len()), Some(2));
        alerter.record_event("test");
        // Threshold reached — last_alert should be set.
        assert!(alerter.inner.lock().last_alert.contains_key("test"));
    }

    #[test]
    fn unknown_event_ignored() {
        let alerter = Alerter::new();
        alerter.record_event("unknown_type");
        // No crash, no counter.
        assert!(alerter.inner.lock().counters.is_empty());
    }
}
