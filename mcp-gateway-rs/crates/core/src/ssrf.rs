//! SSRF protection — validates upstream URLs.
//!
//! Blocks loopback, link-local (cloud metadata 169.254.169.254), multicast,
//! reserved, and unspecified addresses. Private/RFC1918 ranges are ALLOWED by
//! default (internal upstreams are the norm); set `MCP_SSRF_BLOCK_PRIVATE=true`
//! for strict mode. Mirrors `mcp-gateway/ssrf.py`.

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use url::Url;

/// SSRF policy state (allowlists + flags).
#[derive(Clone)]
pub struct SsrfPolicy {
    inner: Arc<RwLock<SsrfState>>,
}

#[derive(Clone)]
struct SsrfState {
    enabled: bool,
    block_private: bool,
    allowed_ips: Vec<String>,
    allowed_hosts: Vec<String>,
    dynamic_allowed: Vec<String>,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SsrfState {
                enabled: env_flag("MCP_SSRF_PROTECTION", true),
                block_private: env_flag("MCP_SSRF_BLOCK_PRIVATE", false),
                allowed_ips: Vec::new(),
                allowed_hosts: Vec::new(),
                dynamic_allowed: Vec::new(),
            })),
        }
    }
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

impl SsrfPolicy {
    pub fn from_env() -> Self {
        let policy = Self::default();
        // Parse MCP_UPSTREAM_ALLOWLIST=ip,host,...
        if let Ok(env) = std::env::var("MCP_UPSTREAM_ALLOWLIST") {
            let mut state = policy.inner.write();
            for entry in env.split(',') {
                let entry = entry.trim().to_lowercase();
                if entry.is_empty() {
                    continue;
                }
                if entry.parse::<IpAddr>().is_ok() {
                    state.allowed_ips.push(entry);
                } else {
                    state.allowed_hosts.push(entry);
                }
            }
        }
        policy
    }

    /// Replace the dynamic allowlist with hostnames/IPs from upstream URLs.
    /// Called by the config loader each time the bundle is reloaded.
    pub fn update_allowed_upstreams(&self, urls: impl IntoIterator<Item = String>) {
        let mut allowed = Vec::new();
        for url in urls {
            if let Ok(parsed) = Url::parse(&url) {
                if let Some(host) = parsed.host_str() {
                    allowed.push(host.to_lowercase());
                }
            }
        }
        self.inner.write().dynamic_allowed = allowed;
    }

    /// Validate a URL. Returns `(safe, reason)`.
    pub async fn is_url_safe(&self, url: &str) -> (bool, String) {
        let state: SsrfState = (*self.inner.read()).clone();

        if !state.enabled {
            return (true, "SSRF protection disabled".into());
        }

        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return (false, format!("Invalid URL: {e}")),
        };

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return (false, format!("Blocked scheme: {scheme}"));
        }

        let host = match parsed.host_str() {
            Some(h) => h.to_lowercase(),
            None => return (false, "No hostname in URL".into()),
        };

        let literal_ip: Option<IpAddr> = host.parse().ok();

        // Admin-registered / bundle upstreams are trusted, except link-local /
        // loopback / unspecified literals are always blocked.
        let is_allowed_host = state.allowed_hosts.contains(&host)
            || state.dynamic_allowed.contains(&host);
        if is_allowed_host {
            if let Some(ip) = literal_ip {
                if is_always_blocked(ip) && !state.allowed_ips.contains(&host) {
                    return (false, format!("Blocked IP: {host}"));
                }
            }
            return (true, String::new());
        }

        if let Some(ip) = literal_ip {
            if is_blocked_ip(ip, state.block_private, &state.allowed_ips) {
                return (false, format!("Blocked IP: {host}"));
            }
        } else {
            // Hostname — resolve and check all IPs.
            let host_clone = host.clone();
            let ips = tokio::task::spawn_blocking(move || resolve_hostname(&host_clone))
                .await
                .unwrap_or_default();
            for ip in ips {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    if is_blocked_ip(ip, state.block_private, &state.allowed_ips) {
                        return (false, format!("Hostname {host} resolves to blocked IP: {ip}"));
                    }
                }
            }
        }

        (true, String::new())
    }
}

fn resolve_hostname(hostname: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    match (hostname, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

fn is_always_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || is_ipv6_link_local(v6) || v6.is_unspecified()
        }
    }
}

fn is_blocked_ip(ip: IpAddr, block_private: bool, allowed_ips: &[String]) -> bool {
    let ip_str = ip.to_string();
    if allowed_ips.contains(&ip_str) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if block_private && v4.is_private() {
                return true;
            }
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || is_ipv4_reserved(v4)
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if block_private && is_ipv6_ula(v6) {
                return true;
            }
            v6.is_loopback()
                || is_ipv6_link_local(v6)
                || v6.is_multicast()
                || v6.is_unspecified()
        }
    }
}

/// IPv4 reserved = 240.0.0.0/4 (matches Python `ipaddress.is_reserved`).
fn is_ipv4_reserved(v4: std::net::Ipv4Addr) -> bool {
    v4.octets()[0] >= 240
}

/// IPv6 unique-local fc00::/7 (private equivalent).
fn is_ipv6_ula(v6: std::net::Ipv6Addr) -> bool {
    let seg0 = v6.segments()[0];
    (seg0 & 0xfe00) == 0xfc00
}

/// IPv6 link-local: fe80::/10. std doesn't expose this directly.
fn is_ipv6_link_local(v6: std::net::Ipv6Addr) -> bool {
    let seg0 = v6.segments()[0];
    (seg0 & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SsrfPolicy {
        // Fresh policy with SSRF enabled, private allowed.
        SsrfPolicy {
            inner: Arc::new(RwLock::new(SsrfState {
                enabled: true,
                block_private: false,
                allowed_ips: Vec::new(),
                allowed_hosts: Vec::new(),
                dynamic_allowed: Vec::new(),
            })),
        }
    }

    #[tokio::test]
    async fn loopback_blocked() {
        let p = policy();
        let (safe, _) = p.is_url_safe("http://127.0.0.1/mcp").await;
        assert!(!safe, "loopback must be blocked");
        let (safe, _) = p.is_url_safe("http://localhost/mcp").await;
        assert!(!safe, "localhost resolves to loopback");
    }

    #[tokio::test]
    async fn link_local_metadata_blocked() {
        let p = policy();
        let (safe, _) = p.is_url_safe("http://169.254.169.254/latest/meta-data").await;
        assert!(!safe, "cloud metadata must be blocked");
    }

    #[tokio::test]
    async fn private_allowed_by_default() {
        let p = policy();
        // 10.0.0.1 is private; default policy allows it.
        let (safe, _) = p.is_url_safe("http://10.0.0.1/mcp").await;
        assert!(safe, "private IP allowed by default");
    }

    #[tokio::test]
    async fn bad_scheme_blocked() {
        let p = policy();
        let (safe, _) = p.is_url_safe("file:///etc/passwd").await;
        assert!(!safe);
    }

    #[tokio::test]
    async fn dynamic_allowlist_trusts_hostname() {
        let p = policy();
        p.update_allowed_upstreams(["http://mcp-server.internal/mcp".into()]);
        // mcp-server.internal won't resolve in tests, but it's in the dynamic
        // allowlist so it should be trusted without resolution.
        let (safe, reason) = p.is_url_safe("http://mcp-server.internal/mcp").await;
        assert!(safe, "dynamic-allowed host must be trusted: {reason}");
    }
}
