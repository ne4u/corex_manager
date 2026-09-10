//! MCP Gateway — Rust/Axum entry point.
//!
//! Loads the encrypted config bundle from a watched file, starts the catalog
//! worker and health checker, and serves the Streamable HTTP MCP endpoint.

use std::sync::Arc;

use parking_lot::RwLock;
use tracing_subscriber::EnvFilter;

use corex_core::config::ConfigBundle;
use corex_core::crypto;
use corex_policy::auth::{BruteForceState, JwksCache};
use corex_policy::ratelimit::{RateLimitConfig, RateLimiter};
use corex_policy::revocation::RevocationStore;
use corex_policy::sessions::SessionStore;
use corex_proxy::{CatalogStore, CircuitBreaker, HealthChecker, ProcessManager, UpstreamClient};
use corex_scan::dlp;
use corex_scan::guardrails;

mod alerting;
mod discovery;
mod events;
mod metrics;
mod protocol;
mod server;
mod skills;

use crate::protocol::GatewayState;
use crate::server::build_router;

#[tokio::main]
async fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("MCP Gateway (Rust) starting");

    // Load config bundle from watched file.
    let config_path = std::env::var("MCP_CONFIG_PATH").unwrap_or_else(|_| "data/mcp/config.bundle.json".into());
    let secrets_key = std::env::var("MCP_SECRETS_KEY").expect("MCP_SECRETS_KEY required");

    let config = load_config(&config_path, &secrets_key);
    let config_arc = Arc::new(RwLock::new(Some(config.clone())));

    // Connect to Valkey (optional — degrades gracefully).
    let valkey = corex_policy::valkey::ValkeyClient::connect().await.ok();

    // Initialize shared state.
    let policy_engine = corex_policy::policy::PolicyEngine::load_sorted(&config.policies);
    let dlp_rules = dlp::compile_rules(&config.dlp_rules);
    let guardrail_rules = guardrails::compile_rules(&config.guardrails);

    let skills = skills::SkillsRegistry::new();
    skills.load(&config.skills);

    let ssrf = corex_core::ssrf::SsrfPolicy::from_env();
    let breaker = CircuitBreaker::new();
    let upstream = UpstreamClient::new(breaker, ssrf);
    let stdio = ProcessManager::new();

    let catalog_store = Arc::new(CatalogStore::new(valkey.clone()));
    let sessions = SessionStore::new(valkey.clone());
    let revocation = RevocationStore::new(valkey.clone());
    let rate_limiter = RateLimiter::new(valkey, RateLimitConfig::default());

    let state = GatewayState {
        config: config_arc,
        policy_engine: Arc::new(RwLock::new(policy_engine)),
        dlp_rules: Arc::new(RwLock::new(dlp_rules)),
        guardrail_rules: Arc::new(RwLock::new(guardrail_rules)),
        skills,
        upstream: upstream.clone(),
        stdio: stdio.clone(),
        catalog_store: catalog_store.clone(),
        sessions,
        revocation,
        rate_limiter,
        brute: Arc::new(BruteForceState::new()),
        jwks: Arc::new(JwksCache::new()),
        events: events::EventLogger::new(),
        alerter: alerting::Alerter::new(),
        metrics: metrics::Metrics::new(),
    };

    // Start catalog worker.
    let catalog_servers = config.servers.clone();
    let catalog_refresh = config.catalog_refresh_seconds.max(30) as u64;
    let catalog_store_clone = catalog_store.clone();
    let upstream_clone = upstream.clone();
    tokio::spawn(async move {
        let worker = corex_proxy::CatalogWorker::new(
            catalog_store_clone,
            upstream_clone,
            ProcessManager::new(),
            catalog_refresh,
        );
        worker.run(catalog_servers).await;
    });

    // Start health checker.
    let health_servers = config.servers.clone();
    let health_interval = std::env::var("MCP_HEALTH_CHECK_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let health_upstream = state.upstream.clone();
    let health_stdio = ProcessManager::new();
    let health_valkey = corex_policy::valkey::ValkeyClient::connect().await.ok();
    tokio::spawn(async move {
        let checker = HealthChecker::new(health_valkey, health_upstream, health_stdio, health_interval);
        checker.run(health_servers).await;
    });

    // Start config file watcher.
    let config_arc_clone = state.config.clone();
    let secrets_key_clone = secrets_key.clone();
    let config_path_clone = config_path.clone();
    tokio::spawn(async move {
        watch_config(config_path_clone, secrets_key_clone, config_arc_clone).await;
    });

    // Build router and serve.
    let bind_addr = std::env::var("MCP_GATEWAY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.expect("failed to bind");
    tracing::info!("MCP Gateway listening on {bind_addr}");
    axum::serve(listener, router).await.expect("server error");
}

/// Load the config bundle from a file, decrypting if needed.
fn load_config(path: &str, secrets_key: &str) -> ConfigBundle {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("Failed to read config bundle from {path}: {e}; starting unconfigured");
            return ConfigBundle::default();
        }
    };

    // Check if the data is an AES-256-GCM binary envelope (version byte 0x01).
    if !raw.is_empty() && raw[0] == 0x01 {
        match crypto::decrypt_bundle(Some(secrets_key), &raw) {
            Ok((plaintext, _)) => {
                let inner: ConfigBundle = serde_json::from_slice(&plaintext).unwrap_or_default();
                tracing::info!("Loaded encrypted config bundle from {path}");
                return inner;
            }
            Err(e) => {
                tracing::error!("Failed to decrypt config bundle: {e}");
                return ConfigBundle::default();
            }
        }
    }

    // Detect legacy Fernet tokens (version byte 0x80).
    if !raw.is_empty() && raw[0] == 0x80 {
        tracing::error!(
            "Legacy Fernet config bundle detected at {path}; \
             the Rust gateway requires the AES-256-GCM format (config.bundle.json). \
             Ensure the backend has regenerated the bundle."
        );
        return ConfigBundle::default();
    }

    // Plain JSON config (dev mode, no encryption key).
    let config: ConfigBundle = match serde_json::from_slice(&raw) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to parse config bundle from {path}: {e}");
            return ConfigBundle::default();
        }
    };
    tracing::info!("Loaded plain config bundle from {path}");
    config
}

/// Watch the config file for changes and hot-reload.
async fn watch_config(
    path: String,
    secrets_key: String,
    config_arc: Arc<RwLock<Option<ConfigBundle>>>,
) {
    let mut last_mtime = std::fs::metadata(&path).map(|m| m.modified().ok()).ok().flatten();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let current_mtime = match std::fs::metadata(&path).map(|m| m.modified().ok()).ok().flatten() {
            Some(m) => m,
            None => continue,
        };
        if Some(current_mtime) != last_mtime {
            last_mtime = Some(current_mtime);
            tracing::info!("Config file changed, reloading: {path}");
            let config = load_config(&path, &secrets_key);
            *config_arc.write() = Some(config);
        }
    }
}
