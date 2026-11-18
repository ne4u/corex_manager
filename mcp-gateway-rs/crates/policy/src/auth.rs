//! Auth module — PAT (bcrypt) and JWT (JWKS resource server).
//!
//! Mirrors `mcp-gateway/auth.py`:
//! 1. PAT format `mcp_<hex>.<secret>` → lookup prefix, verify bcrypt, check
//!    enabled/expiry, check revocation.
//! 2. Else JWT → validate via JWKS, check iss/aud/exp, map sub → identity.
//! 3. Else → 401.
//!
//! Brute-force lockout is in-memory per instance (60s window, 10 failures,
//! 5-min lockout), matching the Python gateway.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use corex_core::config::{ConfigBundle, IdentityConfig};

/// JSON-RPC error code for auth failures (HTTP 401 with WWW-Authenticate).
pub const MCP_UNAUTHORIZED: i32 = -32001;

const AUTH_FAIL_WINDOW: u64 = 60;
const AUTH_FAIL_THRESHOLD: usize = 10;
const AUTH_LOCKOUT_SECONDS: i64 = 300;
const JWKS_TTL: u64 = 300;
const AUTH_CACHE_DEFAULT_TTL_SECONDS: u64 = 60;
const AUTH_CACHE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct AuthError(pub String);

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub identity_id: i64,
    pub team_id: i64,
    pub name: String,
    pub subject: String,
    pub kind: String, // "pat" | "jwt"
    pub claims: serde_json::Value,
}

/// In-memory brute-force state (per instance).
#[derive(Default)]
pub struct BruteForceState {
    fail_counts: Mutex<HashMap<String, Vec<f64>>>,
    lockouts: Mutex<HashMap<String, f64>>,
}

impl BruteForceState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an IP is locked out. Returns `Some(lockout_until_epoch)` if locked.
    pub fn check(&self, ip: &str) -> Option<f64> {
        if ip.is_empty() {
            return None;
        }
        let now = now_secs();
        let lockouts = self.lockouts.lock();
        let until = *lockouts.get(ip).unwrap_or(&0.0);
        if until > now {
            Some(until)
        } else {
            None
        }
    }

    pub fn record_failure(&self, ip: &str) {
        if ip.is_empty() {
            return;
        }
        let now = now_secs();
        let cutoff = now - AUTH_FAIL_WINDOW as f64;
        let mut counts = self.fail_counts.lock();
        let failures = counts.entry(ip.to_string()).or_default();
        failures.retain(|t| *t > cutoff);
        failures.push(now);
        if failures.len() >= AUTH_FAIL_THRESHOLD {
            let until = now + AUTH_LOCKOUT_SECONDS as f64;
            self.lockouts.lock().insert(ip.to_string(), until);
            tracing::warn!(
                "Auth brute-force lockout for {ip} ({} failures in {AUTH_FAIL_WINDOW}s)",
                failures.len()
            );
        }
    }

    pub fn record_success(&self, ip: &str) {
        if ip.is_empty() {
            return;
        }
        self.fail_counts.lock().remove(ip);
        self.lockouts.lock().remove(ip);
    }
}

/// JWKS cache entry.
struct JwksEntry {
    keys: Vec<Jwk>,
    fetched_at: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    #[allow(dead_code)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    crv: Option<String>,
}

/// JWKS cache (URL → entry).
#[derive(Default)]
pub struct JwksCache {
    inner: Mutex<HashMap<String, JwksEntry>>,
}

impl JwksCache {
    pub fn new() -> Self {
        Self::default()
    }

    async fn fetch(&self, jwks_url: &str) -> Result<Vec<Jwk>, AuthError> {
        let now = now_secs();
        {
            let cache = self.inner.lock();
            if let Some(entry) = cache.get(jwks_url) {
                if now - entry.fetched_at < JWKS_TTL as f64 {
                    return Ok(entry.keys.clone());
                }
            }
        }

        let resp = reqwest::get(jwks_url)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch JWKS from {jwks_url}: {e}");
                AuthError("Cannot fetch JWKS".into())
            })?
            .json::<JwksResponse>()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse JWKS from {jwks_url}: {e}");
                AuthError("Cannot parse JWKS".into())
            })?;

        let keys = resp.keys;
        self.inner.lock().insert(
            jwks_url.to_string(),
            JwksEntry { keys: keys.clone(), fetched_at: now },
        );
        Ok(keys)
    }
}

/// Successful-verify memo for bearer tokens (PAT and JWT).
///
/// bcrypt::verify at cost 12 is ~200 ms of CPU — far too expensive to run on
/// every request. This cache memoizes a *successful* verify keyed by the
/// SHA-256 of the token (the raw token is never stored). Entries expire after
/// `MCP_AUTH_CACHE_TTL_SECONDS` (default 60 s) and the whole cache is cleared
/// on config reload, so a rotated hash or disabled identity cannot keep
/// passing. Revocation is still checked against Valkey on every request,
/// including cache hits.
///
/// Concurrent misses for the same token share a single verify (single-flight)
/// so a thundering herd cannot stack up bcrypt work.
#[derive(Clone)]
pub struct AuthCache {
    verified: Arc<RwLock<HashMap<String, (AuthContext, Instant)>>>,
    inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Result<AuthContext, AuthError>>>>>>,
    ttl: Duration,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl Default for AuthCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthCache {
    pub fn new() -> Self {
        Self::with_counters(Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
    }

    /// Construct a cache whose hit/miss counters are shared (e.g. with the
    /// metrics registry so `/metrics` can report them).
    pub fn with_counters(hits: Arc<AtomicU64>, misses: Arc<AtomicU64>) -> Self {
        let ttl_secs = std::env::var("MCP_AUTH_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(AUTH_CACHE_DEFAULT_TTL_SECONDS);
        Self {
            verified: Arc::new(RwLock::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
            hits,
            misses,
        }
    }

    /// Drop all cached verifies. Called after every successful config reload.
    pub fn clear(&self) {
        self.verified.write().clear();
        self.inflight.lock().clear();
    }

    /// (hits, misses) counters for the metrics endpoint.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Return a cached verify result, or run `verify` once and cache it.
    /// Only successful verifies are cached — failures are never memoized so
    /// brute-force accounting stays accurate.
    async fn get_or_verify<F, Fut>(&self, token: &str, verify: F) -> Result<AuthContext, AuthError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<AuthContext, AuthError>>,
    {
        let key = sha256_hex(token);

        // Fast path — fresh entry.
        if let Some((ctx, ts)) = self.verified.read().get(&key) {
            if ts.elapsed() < self.ttl {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(ctx.clone());
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);

        // Single-flight: concurrent misses for the same token share one verify.
        let cell = {
            let mut m = self.inflight.lock();
            m.entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new()))
                .clone()
        };
        let result = cell.get_or_init(|| verify()).await.clone();
        self.inflight.lock().remove(&key);

        match result {
            Ok(ctx) => {
                let mut m = self.verified.write();
                if m.len() >= AUTH_CACHE_MAX_ENTRIES {
                    m.clear();
                }
                m.insert(key, (ctx.clone(), Instant::now()));
                Ok(ctx)
            }
            Err(e) => Err(e),
        }
    }
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Authenticate a bearer token.
///
/// Verification is memoized in `cache` (SHA-256 keyed, TTL, cleared on config
/// reload). Revocation is deliberately NOT checked here — the caller batches
/// the `rev:*` EXISTS commands into the same Valkey round trip as the session
/// fetch so every request, including cache hits, is still revocation-checked.
pub async fn authenticate(
    token: &str,
    config: &ConfigBundle,
    client_ip: &str,
    brute: &BruteForceState,
    jwks: &JwksCache,
    cache: &AuthCache,
) -> Result<AuthContext, AuthError> {
    if let Some(until) = brute.check(client_ip) {
        return Err(AuthError(format!(
            "Too many auth failures from {client_ip}, locked until {until}"
        )));
    }

    match cache.get_or_verify(token, || verify_token(token, config, jwks)).await {
        Ok(ctx) => {
            brute.record_success(client_ip);
            Ok(ctx)
        }
        Err(e) => {
            brute.record_failure(client_ip);
            Err(e)
        }
    }
}

/// Verify a bearer token against the config bundle (no revocation, no
/// brute-force accounting — those stay in `authenticate`).
async fn verify_token(
    token: &str,
    config: &ConfigBundle,
    jwks: &JwksCache,
) -> Result<AuthContext, AuthError> {
    if is_pat(token) {
        let (prefix, _) = parse_pat(token);
        if let Some(ident) = pat_candidate(prefix, &config.identities) {
            // bcrypt::verify is CPU-bound (~200 ms at cost 12) — keep it off the
            // async workers.
            let hash = ident.pat_hash.clone().unwrap_or_default();
            let token_owned = token.to_string();
            let ok = tokio::task::spawn_blocking(move || {
                bcrypt::verify(&token_owned, &hash).unwrap_or(false)
            })
            .await
            .unwrap_or(false);
            if ok {
                return Ok(AuthContext {
                    identity_id: ident.id,
                    team_id: ident.team_id,
                    name: ident.name.clone(),
                    subject: if ident.subject.is_empty() { ident.name.clone() } else { ident.subject.clone() },
                    kind: "pat".into(),
                    claims: serde_json::Value::Null,
                });
            }
        }
        return Err(AuthError("Invalid or expired PAT".into()));
    }

    match verify_jwt(
        token,
        &config.identities,
        config.jwt_issuer.as_deref(),
        config.jwt_audience.as_deref(),
        config.jwt_jwks_url.as_deref(),
        jwks,
    )
    .await
    {
        Some((ident, claims)) => Ok(AuthContext {
            identity_id: ident.id,
            team_id: ident.team_id,
            name: ident.name.clone(),
            subject: if ident.subject.is_empty() { ident.name.clone() } else { ident.subject.clone() },
            kind: "jwt".into(),
            claims,
        }),
        None => Err(AuthError("Invalid or expired JWT".into())),
    }
}

fn is_pat(token: &str) -> bool {
    token.starts_with("mcp_") && token.contains('.')
}

fn parse_pat(token: &str) -> (&str, &str) {
    let idx = token.find('.').unwrap();
    (&token[..idx], &token[idx + 1..])
}

/// Find the enabled, unexpired PAT identity for a prefix. The bcrypt check of
/// `ident.pat_hash` against the token is the caller's job (runs on the
/// blocking pool).
fn pat_candidate<'a>(prefix: &str, identities: &'a [IdentityConfig]) -> Option<&'a IdentityConfig> {
    for ident in identities {
        if ident.kind != "pat" {
            continue;
        }
        if ident.pat_prefix.as_deref() != Some(prefix) {
            continue;
        }
        if !ident.enabled {
            return None;
        }
        if let Some(exp) = &ident.expires_at {
            if is_expired(exp) {
                return None;
            }
        }
        return Some(ident);
    }
    None
}

fn is_expired(expires_at: &str) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .ok()
        .map(|dt| {
            let utc: DateTime<Utc> = dt.with_timezone(&Utc);
            Utc::now() > utc
        })
        .unwrap_or(false)
}

async fn verify_jwt(
    token: &str,
    identities: &[IdentityConfig],
    global_issuer: Option<&str>,
    global_audience: Option<&str>,
    global_jwks_url: Option<&str>,
    jwks: &JwksCache,
) -> Option<(IdentityConfig, serde_json::Value)> {
    // Decode unverified header + payload.
    let header = jsonwebtoken::decode_header(token).ok()?;
    let kid = header.kid;

    // Decode without verification to extract sub/iss/aud.
    let mut unverified = Validation::new(jsonwebtoken::Algorithm::RS256);
    unverified.insecure_disable_signature_validation();
    unverified.validate_exp = false;
    let unverified_payload = jsonwebtoken::decode::<serde_json::Value>(token, &DecodingKey::from_secret(&[]), &unverified).ok()?;
    let payload_value = unverified_payload.claims;
    let sub = payload_value.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let iss = payload_value.get("iss").and_then(|v| v.as_str()).unwrap_or("");

    // Find matching identity by subject or issuer.
    let mut target: Option<&IdentityConfig> = None;
    let mut jwks_url = global_jwks_url.map(|s| s.to_string());
    let mut expected_issuer = global_issuer.map(|s| s.to_string());
    let mut expected_audience = global_audience.map(|s| s.to_string());

    for ident in identities {
        if ident.kind != "jwt" {
            continue;
        }
        if !ident.subject.is_empty() && ident.subject == sub {
            target = Some(ident);
            if let Some(u) = &ident.jwt_jwks_url { jwks_url = Some(u.clone()); }
            if let Some(i) = &ident.jwt_issuer { expected_issuer = Some(i.clone()); }
            if let Some(a) = &ident.jwt_audience { expected_audience = Some(a.clone()); }
            break;
        }
        if let Some(i) = &ident.jwt_issuer {
            if i == iss {
                target = Some(ident);
                if let Some(u) = &ident.jwt_jwks_url { jwks_url = Some(u.clone()); }
                if let Some(i2) = &ident.jwt_issuer { expected_issuer = Some(i2.clone()); }
                if let Some(a) = &ident.jwt_audience { expected_audience = Some(a.clone()); }
                break;
            }
        }
    }

    let target = target?;
    if !target.enabled {
        return None;
    }
    if let Some(exp) = &target.expires_at {
        if is_expired(exp) {
            return None;
        }
    }

    let jwks_url = jwks_url?;
    let keys = jwks.fetch(&jwks_url).await.ok()?;
    let jwk = keys.iter().find(|k| kid.as_deref().is_some() && k.kid.as_deref() == kid.as_deref())
        .or_else(|| keys.first())?;

    let decoding_key = jwk_to_decoding_key(jwk)?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    if let Some(iss) = &expected_issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = &expected_audience {
        validation.set_audience(&[aud]);
    }
    // Only accept RS256/ES256.
    validation.algorithms = vec![Algorithm::RS256, Algorithm::ES256];

    match decode::<serde_json::Value>(token, &decoding_key, &validation) {
        Ok(data) => Some((target.clone(), data.claims)),
        Err(e) => {
            tracing::warn!("JWT validation failed: {e}");
            None
        }
    }
}

fn jwk_to_decoding_key(jwk: &Jwk) -> Option<DecodingKey> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_deref()?;
            let e = jwk.e.as_deref()?;
            DecodingKey::from_rsa_components(n, e).ok()
        }
        "EC" => {
            let x = jwk.x.as_deref()?;
            let y = jwk.y.as_deref()?;
            DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
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
    use corex_core::config::IdentityConfig;

    fn pat_identity(prefix: &str, hash: &str, enabled: bool) -> IdentityConfig {
        IdentityConfig {
            id: 1, team_id: 1, name: "ci".into(), description: None,
            subject: "ci".into(), kind: "pat".into(),
            pat_hash: Some(hash.into()), pat_prefix: Some(prefix.into()),
            jwt_issuer: None, jwt_audience: None, jwt_jwks_url: None,
            enabled, expires_at: None, idp_source: None, idp_external_id: None, idp_user_info: None,
        }
    }

    #[test]
    fn pat_detection() {
        assert!(is_pat("mcp_abc123.secret"));
        assert!(!is_pat("eyJhbGci.payload.sig"));
    }

    #[test]
    fn pat_parse() {
        let (p, s) = parse_pat("mcp_abc.def");
        assert_eq!(p, "mcp_abc");
        assert_eq!(s, "def");
    }

    #[test]
    fn pat_verify_bcrypt() {
        // bcrypt hash for "mcp_test.secretvalue" — generate inline.
        let token = "mcp_test.secretvalue";
        let hash = bcrypt::hash(token, 4).unwrap();
        let idents = vec![pat_identity("mcp_test", &hash, true)];
        let found = pat_candidate("mcp_test", &idents);
        assert!(found.is_some());
        assert!(bcrypt::verify(token, found.unwrap().pat_hash.as_deref().unwrap()).unwrap_or(false));
        // Wrong prefix.
        assert!(pat_candidate("mcp_other", &idents).is_none());
        // Disabled.
        let idents2 = vec![pat_identity("mcp_test", &hash, false)];
        assert!(pat_candidate("mcp_test", &idents2).is_none());
    }

    #[tokio::test]
    async fn auth_cache_hit_skips_verify() {
        let token = "mcp_test.secretvalue";
        let hash = bcrypt::hash(token, 4).unwrap();
        let config = ConfigBundle {
            identities: vec![pat_identity("mcp_test", &hash, true)],
            ..Default::default()
        };
        let cache = AuthCache::new();
        let brute = BruteForceState::new();
        let jwks = JwksCache::new();

        // First call verifies and caches.
        let ctx = authenticate(token, &config, "", &brute, &jwks, &cache)
            .await
            .unwrap();
        assert_eq!(ctx.identity_id, 1);
        assert_eq!(cache.stats(), (0, 1));

        // Second call with an EMPTY config would fail a real verify — a cache
        // hit proves no verify ran.
        let empty = ConfigBundle::default();
        let ctx2 = authenticate(token, &empty, "", &brute, &jwks, &cache)
            .await
            .unwrap();
        assert_eq!(ctx2.identity_id, 1);
        assert_eq!(cache.stats(), (1, 1));
    }

    #[tokio::test]
    async fn auth_cache_wrong_token_fails_and_is_not_cached() {
        let hash = bcrypt::hash("mcp_test.secretvalue", 4).unwrap();
        let config = ConfigBundle {
            identities: vec![pat_identity("mcp_test", &hash, true)],
            ..Default::default()
        };
        let cache = AuthCache::new();
        let brute = BruteForceState::new();
        let jwks = JwksCache::new();

        assert!(authenticate("mcp_test.wrong", &config, "", &brute, &jwks, &cache)
            .await
            .is_err());
        // Failures are never cached — map stays empty, miss count grows.
        assert!(cache.verified.read().is_empty());
        assert_eq!(cache.stats(), (0, 1));
    }

    #[tokio::test]
    async fn auth_cache_clear_drops_entries() {
        let token = "mcp_test.secretvalue";
        let hash = bcrypt::hash(token, 4).unwrap();
        let config = ConfigBundle {
            identities: vec![pat_identity("mcp_test", &hash, true)],
            ..Default::default()
        };
        let cache = AuthCache::new();
        let brute = BruteForceState::new();
        let jwks = JwksCache::new();

        authenticate(token, &config, "", &brute, &jwks, &cache)
            .await
            .unwrap();
        cache.clear();
        // After clear (config reload), an empty bundle fails again.
        let empty = ConfigBundle::default();
        assert!(authenticate(token, &empty, "", &brute, &jwks, &cache)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn auth_cache_single_flight_one_verify() {
        // Concurrent misses for the same token must share one verify closure.
        let counter = Arc::new(AtomicU64::new(0));
        let cache = AuthCache::new();
        let ctx = AuthContext {
            identity_id: 7, team_id: 2, name: "ci".into(), subject: "ci".into(),
            kind: "pat".into(), claims: serde_json::Value::Null,
        };
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let counter = counter.clone();
            let ctx = ctx.clone();
            handles.push(tokio::spawn(async move {
                let counter = counter.clone();
                cache
                    .get_or_verify("mcp_x.secret", || {
                        let ctx = ctx.clone();
                        async move {
                            counter.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            Ok(ctx)
                        }
                    })
                    .await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1, "single-flight must run one verify");
    }

    #[test]
    fn brute_force_lockout() {
        let bf = BruteForceState::new();
        assert!(bf.check("1.2.3.4").is_none());
        for _ in 0..AUTH_FAIL_THRESHOLD {
            bf.record_failure("1.2.3.4");
        }
        assert!(bf.check("1.2.3.4").is_some());
        // Different IP not locked.
        assert!(bf.check("5.6.7.8").is_none());
        // Success clears.
        bf.record_success("1.2.3.4");
        assert!(bf.check("1.2.3.4").is_none());
    }

    #[test]
    fn is_expired_checks() {
        assert!(is_expired("2000-01-01T00:00:00Z"));
        assert!(!is_expired("2999-01-01T00:00:00Z"));
        assert!(!is_expired("not-a-date")); // unparseable → not expired (conservative)
    }
}
