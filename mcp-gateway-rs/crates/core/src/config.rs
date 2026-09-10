//! Config bundle: serde structs + loader + file watch.
//!
//! The bundle is produced by the backend (`mcp_secrets.py`/`mcp_config.py`) and
//! read here. On disk it is either plaintext JSON or the AES-256-GCM envelope
//! (see `crypto`). An optional HMAC `_sig` field is verified when a signing
//! key is set.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::crypto;
use crate::error::GatewayError;

/// The full config bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigBundle {
    /// Schema version (greenfield contract; absent on legacy bundles).
    #[serde(default)]
    pub version: Option<u32>,

    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub identities: Vec<IdentityConfig>,
    #[serde(default)]
    pub teams: Vec<TeamConfig>,
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    #[serde(default)]
    pub dlp_rules: Vec<DlpRuleConfig>,
    #[serde(default)]
    pub guardrails: Vec<GuardrailConfig>,
    #[serde(default)]
    pub skills: Vec<SkillConfig>,

    #[serde(default)]
    pub jwt_issuer: Option<String>,
    #[serde(default)]
    pub jwt_audience: Option<String>,
    #[serde(default)]
    pub jwt_jwks_url: Option<String>,

    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub log_payloads: bool,
    #[serde(default)]
    pub default_rpm: u32,
    #[serde(default)]
    pub per_ip_limit: u32,
    #[serde(default)]
    pub concurrent_limit: u32,
    #[serde(default)]
    pub catalog_refresh_seconds: u32,

    /// Per-team RPM overrides: `{team_id: rpm}`.
    #[serde(default)]
    pub team_rpm_overrides: Value,

    /// HMAC signature (removed after verification).
    #[serde(default, rename = "_sig")]
    pub sig: Option<String>,
    /// Legacy HMAC signature field name (Python gateway).
    #[serde(default, rename = "_signature")]
    pub legacy_sig: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerConfig {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, rename = "original_url")]
    pub original_url: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    #[serde(default)]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub auth_secret: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u32,
    #[serde(default)]
    pub has_replicas: bool,
    #[serde(default)]
    pub replica_count: u32,
    #[serde(default = "default_transport")]
    pub transport_type: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env_vars: Value,
    /// Marketplace metadata (carried, not used for proxying).
    #[serde(default)]
    pub package_manager: Option<String>,
    #[serde(default)]
    pub source_package_name: Option<String>,
    #[serde(default)]
    pub installed_version: Option<String>,
    /// Discovery: expose this server's tools directly in meta-tools mode.
    #[serde(default)]
    pub expose: Option<bool>,
    // OAuth fields are carried for completeness but the gateway does not broker.
    #[serde(default)]
    pub oauth_enabled: bool,
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
    #[serde(default)]
    pub oauth_scopes: Option<String>,
    #[serde(default)]
    pub oauth_access_token: Option<String>,
    #[serde(default)]
    pub oauth_refresh_token: Option<String>,
}

impl ServerConfig {
    pub fn is_stdio(&self) -> bool {
        self.transport_type == "stdio"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub subject: String,
    /// "pat" | "jwt"
    pub kind: String,
    #[serde(default)]
    pub pat_hash: Option<String>,
    #[serde(default)]
    pub pat_prefix: Option<String>,
    #[serde(default)]
    pub jwt_issuer: Option<String>,
    #[serde(default)]
    pub jwt_audience: Option<String>,
    #[serde(default)]
    pub jwt_jwks_url: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub idp_source: Option<String>,
    #[serde(default)]
    pub idp_external_id: Option<String>,
    #[serde(default)]
    pub idp_user_info: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamConfig {
    pub id: i64,
    pub name: String,
    pub slug: String,
    /// Discovery mode: "passthrough" (default) | "meta_tools".
    #[serde(default)]
    pub discovery_mode: Option<String>,
}

impl TeamConfig {
    pub fn discovery_mode(&self) -> DiscoveryMode {
        match self.discovery_mode.as_deref() {
            Some("meta_tools") => DiscoveryMode::MetaTools,
            _ => DiscoveryMode::Passthrough,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    Passthrough,
    MetaTools,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub priority: i32,
    pub expression: String,
    #[serde(default)]
    pub expression_ast: Option<Value>,
    /// "allow" | "deny" | "skip_dlp" | "skip_ratelimit"
    pub action: String,
    #[serde(default = "default_true")]
    pub log: bool,
    #[serde(default)]
    pub no_log: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DlpRuleConfig {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub priority: i32,
    /// "request" | "response" | "both"
    pub direction: String,
    /// Built-in detector id (e.g. "credit_card") or empty for custom regex.
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub find_regex: Option<String>,
    /// "block" | "redact" | "tokenize"
    pub action: String,
    #[serde(default)]
    pub token_prefix: Option<String>,
    #[serde(default)]
    pub token_ttl: Option<u32>,
    /// "string_values" | "all_text"
    #[serde(default)]
    pub apply_to: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GuardrailConfig {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub priority: i32,
    pub direction: String,
    /// Built-in pack id (e.g. "builtin:jailbreak_v1") or empty for custom.
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub find_regex: Option<String>,
    /// "block" | "redact" | "log" | "fence"
    pub action: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillConfig {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub enable_when: Option<String>,
    #[serde(default)]
    pub enable_when_ast: Option<Value>,
    #[serde(default)]
    pub tags: Option<Value>,
    #[serde(default)]
    pub published_version_id: Option<i64>,
    #[serde(default)]
    pub published_body: Option<String>,
    #[serde(default)]
    pub published_frontmatter: Option<Value>,
    #[serde(default)]
    pub published_files: Option<Value>,
}

fn default_true() -> bool {
    true
}
fn default_timeout_ms() -> u32 {
    30000
}
fn default_max_body_bytes() -> u32 {
    1_048_576
}
fn default_transport() -> String {
    "streamable_http".to_string()
}

/// Thread-safe holder for the live config bundle.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<RwLock<ConfigBundle>>,
    path: PathBuf,
    encryption_key: Option<String>,
    signing_key: Option<String>,
}

impl ConfigStore {
    pub fn new(
        path: impl Into<PathBuf>,
        encryption_key: Option<String>,
        signing_key: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConfigBundle::default())),
            path: path.into(),
            encryption_key,
            signing_key,
        }
    }

    /// Load (or reload) the bundle from disk if the file changed.
    /// Returns the loaded bundle. On failure, keeps the previous bundle and
    /// logs the error.
    pub fn reload(&self) -> ConfigBundle {
        match self.load_from_disk() {
            Ok(bundle) => {
                let n_servers = bundle.servers.len();
                let n_identities = bundle.identities.len();
                *self.inner.write() = bundle.clone();
                info!(
                    "Loaded MCP config: {} servers, {} identities",
                    n_servers, n_identities
                );
                bundle
            }
            Err(e) => {
                warn!("Failed to load MCP config (keeping previous): {e}");
                self.inner.read().clone()
            }
        }
    }

    /// Read the current cached bundle (no disk I/O).
    pub fn get(&self) -> ConfigBundle {
        self.inner.read().clone()
    }

    pub fn is_configured(&self) -> bool {
        !self.get().servers.is_empty()
    }

    pub fn enabled_servers(&self) -> Vec<ServerConfig> {
        self.get()
            .servers
            .into_iter()
            .filter(|s| s.enabled)
            .collect()
    }

    pub fn team_servers(&self, team_id: i64) -> Vec<ServerConfig> {
        self.enabled_servers()
            .into_iter()
            .filter(|s| s.team_id == team_id)
            .collect()
    }

    pub fn server_by_namespace(&self, ns: &str) -> Option<ServerConfig> {
        self.enabled_servers()
            .into_iter()
            .find(|s| s.namespace == ns)
    }

    pub fn check_origin(&self, origin: &str) -> bool {
        let allowed = &self.get().allowed_origins;
        if origin.is_empty() {
            return true; // non-browser clients
        }
        if allowed.is_empty() {
            return false;
        }
        allowed.iter().any(|o| o == origin)
    }

    fn load_from_disk(&self) -> Result<ConfigBundle, GatewayError> {
        let raw = std::fs::read(&self.path).map_err(|e| {
            GatewayError::server_error(format!("read config {}: {e}", self.path.display()))
        })?;

        // Decrypt (envelope or plaintext fallback).
        let (plaintext, _was_encrypted) =
            crypto::decrypt_bundle(self.encryption_key.as_deref(), &raw)?;

        // Parse JSON.
        let mut bundle: ConfigBundle = serde_json::from_slice(&plaintext)?;

        // Verify HMAC signature if a signing key is configured.
        if let Some(sk) = self.signing_key.as_deref() {
            let sig = bundle.sig.take().or_else(|| bundle.legacy_sig.take());
            if let Some(sig) = sig {
                // Recompute the canonical JSON without the signature fields.
                let canonical = canonical_json_without_sig(&plaintext);
                if !crypto::verify_bundle_sig(sk, canonical.as_bytes(), &sig) {
                    return Err(GatewayError::server_error(
                        "config bundle signature verification FAILED",
                    ));
                }
                info!("MCP config bundle signature verified");
            } else {
                warn!("Signing key set but bundle has no _sig/_signature — accepting");
            }
        }

        Ok(bundle)
    }
}

/// Produce a canonical JSON string (sorted keys, no whitespace) with `_sig`
/// and `_signature` fields removed, for HMAC verification.
fn canonical_json_without_sig(plaintext: &[u8]) -> String {
    let mut value: Value = match serde_json::from_slice(plaintext) {
        Ok(v) => v,
        Err(_) => return String::from_utf8_lossy(plaintext).into_owned(),
    };
    if let Value::Object(ref mut map) = value {
        map.remove("_sig");
        map.remove("_signature");
    }
    // serde_json with sorted keys requires manual handling; canonicalize by
    // sorting object keys recursively.
    canonicalize_value(&value).to_string()
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<(String, Value)> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (k, v) in pairs {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        other => other.clone(),
    }
}

/// Spawn a background task that watches the config file for changes and
/// reloads on mtime/modify events.
pub fn spawn_watcher(store: ConfigStore) -> tokio::task::JoinHandle<()> {
    let path = store.path.clone();
    tokio::spawn(async move {
        use notify::{EventKind, RecursiveMode, Watcher};
        let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Result<notify::Event>>(16);
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.blocking_send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!("config file watcher failed to start: {e}");
                return;
            }
        };
        if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
            warn!("config file watch failed: {e}");
            return;
        }
        // Initial load.
        store.reload();
        loop {
            match rx.recv().await {
                Some(Ok(event)) => {
                    if matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        // Small debounce: drain further events.
                        while rx.try_recv().is_ok() {}
                        store.reload();
                    }
                }
                Some(Err(e)) => warn!("config watch error: {e}"),
                None => break,
            }
        }
    })
}

/// Read the config path from env, returning a sensible default.
pub fn config_path_from_env() -> PathBuf {
    Path::new(
        &std::env::var("MCP_CONFIG_PATH").unwrap_or_else(|_| "/app/data/mcp/config.json".into()),
    )
    .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> &'static str {
        r#"{
            "version": 1,
            "servers": [
                {"id":1,"team_id":1,"name":"jira","namespace":"jira","url":"https://up.example.com/mcp","enabled":true,"verify_tls":true,"auth_type":"bearer","auth_header":"Authorization","auth_secret":"s","timeout_ms":30000,"max_body_bytes":1048576,"transport_type":"streamable_http","expose":true}
            ],
            "identities": [
                {"id":1,"team_id":1,"name":"ci","subject":"ci","kind":"pat","pat_hash":"$2b$xx","enabled":true}
            ],
            "teams": [{"id":1,"name":"Eng","slug":"eng","discovery_mode":"meta_tools"}],
            "policies": [],
            "dlp_rules": [],
            "guardrails": [],
            "skills": [],
            "allowed_origins": ["https://app.example.com"],
            "log_payloads": false,
            "default_rpm": 600,
            "per_ip_limit": 0,
            "concurrent_limit": 0,
            "catalog_refresh_seconds": 60
        }"#
    }

    #[test]
    fn parse_bundle() {
        let bundle: ConfigBundle = serde_json::from_str(sample_bundle()).unwrap();
        assert_eq!(bundle.servers.len(), 1);
        assert_eq!(bundle.servers[0].namespace, "jira");
        assert!(bundle.servers[0].expose == Some(true));
        assert!(!bundle.servers[0].is_stdio());
        assert_eq!(bundle.identities.len(), 1);
        assert_eq!(bundle.teams[0].discovery_mode(), DiscoveryMode::MetaTools);
        assert_eq!(bundle.version, Some(1));
    }

    #[test]
    fn origin_check() {
        let bundle: ConfigBundle = serde_json::from_str(sample_bundle()).unwrap();
        let store = ConfigStore::new("/nonexistent", None, None);
        *store.inner.write() = bundle;
        assert!(store.check_origin("https://app.example.com"));
        assert!(!store.check_origin("https://evil.com"));
        assert!(store.check_origin("")); // non-browser
    }

    #[test]
    fn team_servers_filtered() {
        let bundle: ConfigBundle = serde_json::from_str(sample_bundle()).unwrap();
        let store = ConfigStore::new("/nonexistent", None, None);
        *store.inner.write() = bundle;
        assert_eq!(store.team_servers(1).len(), 1);
        assert_eq!(store.team_servers(99).len(), 0);
        assert!(store.server_by_namespace("jira").is_some());
        assert!(store.server_by_namespace("nope").is_none());
    }

    #[test]
    fn encrypted_bundle_round_trip() {
        let tmp = std::env::temp_dir().join("corex_core_config_test.json");
        let secret = "round-trip-secret";
        let plaintext = sample_bundle().as_bytes().to_vec();
        let ct = crypto::encrypt_bundle(secret, &plaintext).unwrap();
        std::fs::write(&tmp, &ct).unwrap();
        let store = ConfigStore::new(&tmp, Some(secret.into()), None);
        let loaded = store.load_from_disk().unwrap();
        assert_eq!(loaded.servers.len(), 1);
        assert_eq!(loaded.teams[0].discovery_mode(), DiscoveryMode::MetaTools);
        let _ = std::fs::remove_file(&tmp);
    }
}
