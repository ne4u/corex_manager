//! Prometheus `/metrics` endpoint.
//!
//! Maintains atomic counters for gateway operations and renders them in
//! Prometheus text exposition format.  Also tracks a latency histogram for
//! `tools/call` requests so the UI can show real-time p50/p99 without
//! querying the events database.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Latency histogram bucket boundaries in milliseconds.
const LATENCY_BUCKETS: &[f64] = &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0];

#[derive(Clone)]
pub struct Metrics {
    requests_total: Arc<AtomicU64>,
    auth_success_total: Arc<AtomicU64>,
    auth_failure_total: Arc<AtomicU64>,
    policy_denied_total: Arc<AtomicU64>,
    rate_limited_total: Arc<AtomicU64>,
    dlp_blocked_total: Arc<AtomicU64>,
    guardrail_blocked_total: Arc<AtomicU64>,
    upstream_errors_total: Arc<AtomicU64>,
    tools_listed_total: Arc<AtomicU64>,
    tools_called_total: Arc<AtomicU64>,
    // Latency histogram for tools/call (cumulative bucket counts).
    latency_buckets: Arc<[AtomicU64; 11]>, // 10 boundaries + +Inf
    latency_sum: Arc<AtomicU64>,
    latency_count: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(AtomicU64::new(0)),
            auth_success_total: Arc::new(AtomicU64::new(0)),
            auth_failure_total: Arc::new(AtomicU64::new(0)),
            policy_denied_total: Arc::new(AtomicU64::new(0)),
            rate_limited_total: Arc::new(AtomicU64::new(0)),
            dlp_blocked_total: Arc::new(AtomicU64::new(0)),
            guardrail_blocked_total: Arc::new(AtomicU64::new(0)),
            upstream_errors_total: Arc::new(AtomicU64::new(0)),
            tools_listed_total: Arc::new(AtomicU64::new(0)),
            tools_called_total: Arc::new(AtomicU64::new(0)),
            latency_buckets: Arc::new([
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0),
            ]),
            latency_sum: Arc::new(AtomicU64::new(0)),
            latency_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn inc_requests(&self) { self.requests_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_auth_success(&self) { self.auth_success_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_auth_failure(&self) { self.auth_failure_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_policy_denied(&self) { self.policy_denied_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_rate_limited(&self) { self.rate_limited_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_dlp_blocked(&self) { self.dlp_blocked_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_guardrail_blocked(&self) { self.guardrail_blocked_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_upstream_errors(&self) { self.upstream_errors_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_tools_listed(&self) { self.tools_listed_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_tools_called(&self) { self.tools_called_total.fetch_add(1, Ordering::Relaxed); }

    /// Observe a tools/call latency in milliseconds.
    pub fn observe_latency(&self, latency_ms: u64) {
        self.latency_sum.fetch_add(latency_ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        // Increment the appropriate cumulative bucket.
        for (i, &boundary) in LATENCY_BUCKETS.iter().enumerate() {
            if (latency_ms as f64) <= boundary {
                self.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // +Inf bucket.
        self.latency_buckets[LATENCY_BUCKETS.len()].fetch_add(1, Ordering::Relaxed);
    }

    /// Render metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let counters = [
            ("mcp_gateway_requests_total", self.requests_total.load(Ordering::Relaxed)),
            ("mcp_gateway_auth_success_total", self.auth_success_total.load(Ordering::Relaxed)),
            ("mcp_gateway_auth_failure_total", self.auth_failure_total.load(Ordering::Relaxed)),
            ("mcp_gateway_policy_denied_total", self.policy_denied_total.load(Ordering::Relaxed)),
            ("mcp_gateway_rate_limited_total", self.rate_limited_total.load(Ordering::Relaxed)),
            ("mcp_gateway_dlp_blocked_total", self.dlp_blocked_total.load(Ordering::Relaxed)),
            ("mcp_gateway_guardrail_blocked_total", self.guardrail_blocked_total.load(Ordering::Relaxed)),
            ("mcp_gateway_upstream_errors_total", self.upstream_errors_total.load(Ordering::Relaxed)),
            ("mcp_gateway_tools_listed_total", self.tools_listed_total.load(Ordering::Relaxed)),
            ("mcp_gateway_tools_called_total", self.tools_called_total.load(Ordering::Relaxed)),
        ];
        for (name, value) in &counters {
            out.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
        }

        // Latency histogram.
        let count = self.latency_count.load(Ordering::Relaxed);
        let sum = self.latency_sum.load(Ordering::Relaxed);
        out.push_str("# TYPE mcp_gateway_tools_call_latency_ms histogram\n");
        for (i, &boundary) in LATENCY_BUCKETS.iter().enumerate() {
            let bucket_count = self.latency_buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "mcp_gateway_tools_call_latency_ms_bucket{{le=\"{boundary}\"}} {bucket_count}\n"
            ));
        }
        let inf_count = self.latency_buckets[LATENCY_BUCKETS.len()].load(Ordering::Relaxed);
        out.push_str(&format!(
            "mcp_gateway_tools_call_latency_ms_bucket{{le=\"+Inf\"}} {inf_count}\n"
        ));
        out.push_str(&format!("mcp_gateway_tools_call_latency_ms_sum {sum}\n"));
        out.push_str(&format!("mcp_gateway_tools_call_latency_ms_count {count}\n"));

        out
    }

    /// Snapshot the counters as a map (for JSON API consumption).
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            auth_success_total: self.auth_success_total.load(Ordering::Relaxed),
            auth_failure_total: self.auth_failure_total.load(Ordering::Relaxed),
            policy_denied_total: self.policy_denied_total.load(Ordering::Relaxed),
            rate_limited_total: self.rate_limited_total.load(Ordering::Relaxed),
            dlp_blocked_total: self.dlp_blocked_total.load(Ordering::Relaxed),
            guardrail_blocked_total: self.guardrail_blocked_total.load(Ordering::Relaxed),
            upstream_errors_total: self.upstream_errors_total.load(Ordering::Relaxed),
            tools_listed_total: self.tools_listed_total.load(Ordering::Relaxed),
            tools_called_total: self.tools_called_total.load(Ordering::Relaxed),
            latency_sum_ms: self.latency_sum.load(Ordering::Relaxed),
            latency_count: self.latency_count.load(Ordering::Relaxed),
            latency_buckets: LATENCY_BUCKETS
                .iter()
                .enumerate()
                .map(|(i, &b)| (b, self.latency_buckets[i].load(Ordering::Relaxed)))
                .collect(),
            latency_inf_bucket: self.latency_buckets[LATENCY_BUCKETS.len()].load(Ordering::Relaxed),
        }
    }
}

/// Serializable snapshot of all metrics counters for the JSON status API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub auth_success_total: u64,
    pub auth_failure_total: u64,
    pub policy_denied_total: u64,
    pub rate_limited_total: u64,
    pub dlp_blocked_total: u64,
    pub guardrail_blocked_total: u64,
    pub upstream_errors_total: u64,
    pub tools_listed_total: u64,
    pub tools_called_total: u64,
    pub latency_sum_ms: u64,
    pub latency_count: u64,
    pub latency_buckets: Vec<(f64, u64)>,
    pub latency_inf_bucket: u64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_prometheus_format() {
        let m = Metrics::new();
        m.inc_requests();
        m.inc_requests();
        m.inc_tools_called();
        let output = m.render();
        assert!(output.contains("mcp_gateway_requests_total 2"));
        assert!(output.contains("mcp_gateway_tools_called_total 1"));
        assert!(output.contains("# TYPE mcp_gateway_requests_total counter"));
    }

    #[test]
    fn latency_histogram_buckets() {
        let m = Metrics::new();
        m.observe_latency(5);   // <= 5ms bucket
        m.observe_latency(50);  // <= 50ms bucket
        m.observe_latency(500); // <= 500ms bucket
        m.observe_latency(9999); // +Inf bucket
        let output = m.render();
        assert!(output.contains("mcp_gateway_tools_call_latency_ms_count 4"));
        assert!(output.contains("mcp_gateway_tools_call_latency_ms_sum 10554"));
        assert!(output.contains("le=\"5\""));
        assert!(output.contains("le=\"50\""));
        assert!(output.contains("le=\"500\""));
        assert!(output.contains("le=\"+Inf\""));
    }

    #[test]
    fn snapshot_serializes() {
        let m = Metrics::new();
        m.inc_requests();
        m.observe_latency(42);
        let s = m.snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.latency_count, 1);
        assert_eq!(s.latency_sum_ms, 42);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"requests_total\":1"));
    }
}
