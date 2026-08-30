//! API Armor JWT validator — JWT and API key validation at the proxy layer.
//!
//! Validates JWT tokens (HS256, HS384, HS512) and API keys. The validator is
//! called from body_parser's api_body_parse function. RS256/ES256 validation
//! requires JWKS URL support (Phase 4b).
//!
//! JWT format: header.payload.signature
//! - header: JSON with alg + typ
//! - payload: JSON with claims (sub, iss, aud, exp, iat, etc.)
//! - signature: HMAC-SHA256(header.payload, secret) base64url-encoded

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use base64::{Engine as _, engine::general_purpose};

/// Register the Lua functions with HAProxy.
pub fn register(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let _ = globals;
    Ok(())
}

// Re-export mlua for the register function
use mlua::prelude::*;

/// JWT validation result.
#[derive(Debug, Clone, Default)]
pub struct JwtResult {
    pub valid: bool,
    pub claims: serde_json::Value,
    pub error: String,
    pub auth_type: String,  // "jwt" or "api_key" or "n" (none)
}

impl JwtResult {
    pub fn valid(claims: serde_json::Value) -> Self {
        JwtResult {
            valid: true,
            claims,
            auth_type: "jwt".to_string(),
            ..Default::default()
        }
    }

    pub fn invalid(error: impl Into<String>) -> Self {
        JwtResult {
            valid: false,
            error: error.into(),
            auth_type: "jwt".to_string(),
            ..Default::default()
        }
    }
}

/// API key validation result.
#[derive(Debug, Clone, Default)]
pub struct ApiKeyResult {
    pub valid: bool,
    pub error: String,
    pub auth_type: String,
}

/// Validate a JWT token with the given HMAC secret.
/// Supports HS256, HS384, HS512 algorithms.
pub fn validate_jwt(token: &str, secret: &str) -> JwtResult {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return JwtResult::invalid("invalid token format");
    }

    // Decode header
    let header_json = match decode_base64url(parts[0]) {
        Ok(json) => json,
        Err(e) => return JwtResult::invalid(format!("invalid header encoding: {}", e)),
    };

    let header: serde_json::Value = match serde_json::from_slice(&header_json) {
        Ok(v) => v,
        Err(e) => return JwtResult::invalid(format!("invalid header JSON: {}", e)),
    };

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = match decode_base64url(parts[2]) {
        Ok(s) => s,
        Err(e) => return JwtResult::invalid(format!("invalid signature encoding: {}", e)),
    };

    let expected_signature = match alg {
        "HS256" => hmac_sha256(signing_input.as_bytes(), secret.as_bytes()),
        "HS384" => hmac_sha384(signing_input.as_bytes(), secret.as_bytes()),
        "HS512" => hmac_sha512(signing_input.as_bytes(), secret.as_bytes()),
        "none" => {
            // No signature — only valid for none algorithm (insecure, usually rejected)
            return JwtResult::invalid("none algorithm not allowed");
        }
        _ => {
            return JwtResult::invalid(format!("unsupported algorithm: {}", alg));
        }
    };

    if !constant_time_eq(&expected_signature, &signature) {
        return JwtResult::invalid("signature verification failed");
    }

    // Decode payload
    let payload_json = match decode_base64url(parts[1]) {
        Ok(json) => json,
        Err(e) => return JwtResult::invalid(format!("invalid payload encoding: {}", e)),
    };

    let claims: serde_json::Value = match serde_json::from_slice(&payload_json) {
        Ok(v) => v,
        Err(e) => return JwtResult::invalid(format!("invalid payload JSON: {}", e)),
    };

    // Check expiration
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if now > exp {
            return JwtResult::invalid("token expired");
        }
    }

    JwtResult::valid(claims)
}

/// Validate a JWT token with additional claim checks (issuer, audience).
pub fn validate_jwt_with_claims(
    token: &str,
    secret: &str,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
) -> JwtResult {
    let mut result = validate_jwt(token, secret);
    if !result.valid {
        return result;
    }

    // Check issuer
    if let Some(expected_iss) = expected_issuer {
        let actual_iss = result.claims.get("iss").and_then(|v| v.as_str());
        if actual_iss != Some(expected_iss) {
            result.valid = false;
            result.error = format!("invalid issuer: expected {}, got {:?}", expected_iss, actual_iss);
            return result;
        }
    }

    // Check audience
    if let Some(expected_aud) = expected_audience {
        let actual_aud = result.claims.get("aud");
        let aud_match = match actual_aud {
            Some(serde_json::Value::String(s)) => s == expected_aud,
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
            _ => false,
        };
        if !aud_match {
            result.valid = false;
            result.error = format!("invalid audience: expected {}", expected_aud);
            return result;
        }
    }

    result
}

/// Validate an API key against a list of valid keys.
pub fn validate_api_key(key: &str, valid_keys: &[String]) -> ApiKeyResult {
    for valid_key in valid_keys {
        if constant_time_eq(key.as_bytes(), valid_key.as_bytes()) {
            return ApiKeyResult {
                valid: true,
                auth_type: "api_key".to_string(),
                ..Default::default()
            };
        }
    }
    ApiKeyResult {
        valid: false,
        error: "invalid API key".to_string(),
        auth_type: "api_key".to_string(),
    }
}

/// Extract a JWT token from an Authorization header value.
/// Supports "Bearer <token>" and raw token formats.
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    let trimmed = auth_header.trim();
    if trimmed.starts_with("Bearer ") {
        Some(trimmed[7..].trim())
    } else if trimmed.starts_with("bearer ") {
        Some(trimmed[7..].trim())
    } else if !trimmed.is_empty() && !trimmed.contains(' ') {
        // Raw token (no Bearer prefix)
        Some(trimmed)
    } else {
        None
    }
}

/// Detect the auth type from an Authorization header.
/// Returns "jwt", "api_key", or "n" (none).
pub fn detect_auth_type(auth_header: &str, api_key_header: Option<&str>) -> String {
    if auth_header.starts_with("Bearer ") || auth_header.starts_with("bearer ") {
        // Could be JWT or Bearer API key — check if it looks like a JWT (3 dot-separated parts)
        let token = &auth_header[7..].trim();
        if token.split('.').count() == 3 {
            return "jwt".to_string();
        }
        return "api_key".to_string();
    }
    if let Some(api_key_hdr) = api_key_header {
        if !api_key_hdr.is_empty() {
            return "api_key".to_string();
        }
    }
    "n".to_string()
}

// --- Internal helpers ---

fn hmac_sha256(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key error");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha384(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC key error");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha512(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC key error");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| e.to_string())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(payload: &str, secret: &str) -> String {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = hmac_sha256(signing_input.as_bytes(), secret.as_bytes());
        let sig_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&sig);
        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    #[test]
    fn test_validate_valid_jwt() {
        let payload = r#"{"sub":"user-123","iss":"test-issuer","aud":"test-audience"}"#;
        let token = make_jwt(payload, "secret123");
        let result = validate_jwt(&token, "secret123");
        assert!(result.valid);
        assert_eq!(result.claims.get("sub").unwrap(), "user-123");
    }

    #[test]
    fn test_validate_wrong_secret() {
        let payload = r#"{"sub":"user-123"}"#;
        let token = make_jwt(payload, "secret123");
        let result = validate_jwt(&token, "wrong-secret");
        assert!(!result.valid);
        assert!(result.error.contains("signature"));
    }

    #[test]
    fn test_validate_expired_jwt() {
        let payload = r#"{"sub":"user-123","exp":1}"#;
        let token = make_jwt(payload, "secret123");
        let result = validate_jwt(&token, "secret123");
        assert!(!result.valid);
        assert!(result.error.contains("expired"));
    }

    #[test]
    fn test_validate_with_issuer_check() {
        let payload = r#"{"sub":"user-123","iss":"correct-issuer"}"#;
        let token = make_jwt(payload, "secret123");
        let result = validate_jwt_with_claims(&token, "secret123", Some("correct-issuer"), None);
        assert!(result.valid);

        let result = validate_jwt_with_claims(&token, "secret123", Some("wrong-issuer"), None);
        assert!(!result.valid);
        assert!(result.error.contains("issuer"));
    }

    #[test]
    fn test_validate_with_audience_check() {
        let payload = r#"{"sub":"user-123","aud":"my-api"}"#;
        let token = make_jwt(payload, "secret123");
        let result = validate_jwt_with_claims(&token, "secret123", None, Some("my-api"));
        assert!(result.valid);

        let result = validate_jwt_with_claims(&token, "secret123", None, Some("wrong-api"));
        assert!(!result.valid);
        assert!(result.error.contains("audience"));
    }

    #[test]
    fn test_validate_invalid_format() {
        let result = validate_jwt("not.a.jwt.token", "secret");
        assert!(!result.valid);
        assert!(result.error.contains("format"));
    }

    #[test]
    fn test_validate_none_algorithm() {
        let header = general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"user-123"}"#);
        let token = format!("{}.{}.", header, payload);
        let result = validate_jwt(&token, "secret");
        assert!(!result.valid);
        assert!(result.error.contains("none"));
    }

    #[test]
    fn test_validate_api_key_valid() {
        let keys = vec!["key1".to_string(), "key2".to_string(), "key3".to_string()];
        let result = validate_api_key("key2", &keys);
        assert!(result.valid);
        assert_eq!(result.auth_type, "api_key");
    }

    #[test]
    fn test_validate_api_key_invalid() {
        let keys = vec!["key1".to_string(), "key2".to_string()];
        let result = validate_api_key("wrong-key", &keys);
        assert!(!result.valid);
        assert!(result.error.contains("invalid API key"));
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("Basic abc123"), None);
    }

    #[test]
    fn test_detect_auth_type() {
        assert_eq!(detect_auth_type("Bearer a.b.c", None), "jwt");
        assert_eq!(detect_auth_type("Bearer simplekey", None), "api_key");
        assert_eq!(detect_auth_type("", Some("my-api-key")), "api_key");
        assert_eq!(detect_auth_type("", None), "n");
    }
}
