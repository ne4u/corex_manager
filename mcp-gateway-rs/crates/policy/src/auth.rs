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

use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use parking_lot::Mutex;
use serde::Deserialize;

use corex_core::config::{ConfigBundle, IdentityConfig};

use crate::revocation::RevocationStore;

/// JSON-RPC error code for auth failures (HTTP 401 with WWW-Authenticate).
pub const MCP_UNAUTHORIZED: i32 = -32001;

const AUTH_FAIL_WINDOW: u64 = 60;
const AUTH_FAIL_THRESHOLD: usize = 10;
const AUTH_LOCKOUT_SECONDS: i64 = 300;
const JWKS_TTL: u64 = 300;

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

/// Authenticate a bearer token.
pub async fn authenticate(
    token: &str,
    config: &ConfigBundle,
    client_ip: &str,
    brute: &BruteForceState,
    jwks: &JwksCache,
    revocation: &RevocationStore,
) -> Result<AuthContext, AuthError> {
    if let Some(until) = brute.check(client_ip) {
        return Err(AuthError(format!(
            "Too many auth failures from {client_ip}, locked until {until}"
        )));
    }

    if is_pat(token) {
        let (prefix, _) = parse_pat(token);
        if let Some(ident) = verify_pat(prefix, token, &config.identities) {
            if !revocation.is_token_valid(ident.id, None).await {
                brute.record_failure(client_ip);
                return Err(AuthError("Identity revoked".into()));
            }
            brute.record_success(client_ip);
            return Ok(AuthContext {
                identity_id: ident.id,
                team_id: ident.team_id,
                name: ident.name.clone(),
                subject: if ident.subject.is_empty() { ident.name.clone() } else { ident.subject.clone() },
                kind: "pat".into(),
                claims: serde_json::Value::Null,
            });
        }
        brute.record_failure(client_ip);
        return Err(AuthError("Invalid or expired PAT".into()));
    }

    // Try JWT.
    match verify_jwt(token, &config.identities, config.jwt_issuer.as_deref(), config.jwt_audience.as_deref(), config.jwt_jwks_url.as_deref(), jwks).await {
        Some((ident, claims)) => {
            let jti = claims.get("jti").and_then(|v| v.as_str()).map(|s| s.to_string());
            if !revocation.is_token_valid(ident.id, jti.as_deref()).await {
                brute.record_failure(client_ip);
                return Err(AuthError("Token revoked".into()));
            }
            brute.record_success(client_ip);
            Ok(AuthContext {
                identity_id: ident.id,
                team_id: ident.team_id,
                name: ident.name.clone(),
                subject: if ident.subject.is_empty() { ident.name.clone() } else { ident.subject.clone() },
                kind: "jwt".into(),
                claims,
            })
        }
        None => {
            brute.record_failure(client_ip);
            Err(AuthError("Invalid or expired JWT".into()))
        }
    }
}

fn is_pat(token: &str) -> bool {
    token.starts_with("mcp_") && token.contains('.')
}

fn parse_pat(token: &str) -> (&str, &str) {
    let idx = token.find('.').unwrap();
    (&token[..idx], &token[idx + 1..])
}

fn verify_pat<'a>(prefix: &str, token: &str, identities: &'a [IdentityConfig]) -> Option<&'a IdentityConfig> {
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
        let Some(hash) = &ident.pat_hash else { return None };
        // bcrypt::verify expects the full token (prefix.secret) and the hash.
        if bcrypt::verify(token, hash).unwrap_or(false) {
            return Some(ident);
        }
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
        let found = verify_pat("mcp_test", token, &idents);
        assert!(found.is_some());
        // Wrong prefix.
        assert!(verify_pat("mcp_other", token, &idents).is_none());
        // Disabled.
        let idents2 = vec![pat_identity("mcp_test", &hash, false)];
        assert!(verify_pat("mcp_test", token, &idents2).is_none());
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
