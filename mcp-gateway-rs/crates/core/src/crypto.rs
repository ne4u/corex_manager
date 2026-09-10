//! Bundle envelope crypto: AES-256-GCM encryption + HMAC-SHA256 signing.
//!
//! Envelope format (binary, on disk):
//!   [1 byte version=0x01][12-byte nonce][ciphertext + 16-byte GCM tag]
//!
//! Key derivation: HKDF-SHA256 from `MCP_SECRETS_KEY`,
//!   salt = b"mcp-gateway-secrets", info = b"mcp-gateway-bundle" -> 32-byte AES key.
//!
//! HMAC signature: a `_sig` field in the plaintext JSON, computed as
//! HMAC-SHA256(key, canonical-JSON-without-`_sig`). The signing key is derived
//! separately via HKDF with info = b"mcp-gateway-sig".
//!
//! When `MCP_SECRETS_KEY` is unset, the bundle is plaintext JSON (dev mode).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::GatewayError;

type HmacSha256 = Hmac<Sha256>;

const ENVELOPE_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const SALT: &[u8] = b"mcp-gateway-secrets";
const ENC_INFO: &[u8] = b"mcp-gateway-bundle";
const SIG_INFO: &[u8] = b"mcp-gateway-sig";

/// Fernet ciphertexts start with this byte (0x80). Used to detect the legacy
/// format during the dual-read migration window.
const FERNET_VERSION_BYTE: u8 = 0x80;

/// Derive the 32-byte AES-256-GCM key from the configured secret.
pub fn derive_encryption_key(secret: &str) -> [u8; 32] {
    hkdf_sha256(SALT, secret.as_bytes(), ENC_INFO)
}

/// Derive the 32-byte HMAC signing key from the configured secret.
pub fn derive_signing_key(secret: &str) -> [u8; 32] {
    hkdf_sha256(SALT, secret.as_bytes(), SIG_INFO)
}

/// HKDF-SHA256 (RFC 5869): extract-then-expand to 32 bytes.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Expand: OKM = T(1) || T(2) || ... where T(i) = HMAC(PRK, T(i-1) || info || i)
    // 32 bytes = 1 block of SHA-256.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk).expect("hmac accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    let okm = mac.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm[..32]);
    out
}

/// Encrypt a plaintext bundle into the binary envelope.
pub fn encrypt_bundle(secret: &str, plaintext: &[u8]) -> Result<Vec<u8>, GatewayError> {
    let key = derive_encryption_key(secret);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| GatewayError::server_error(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| GatewayError::server_error(format!("AES-GCM encrypt: {e}")))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a bundle. Detects the envelope by the version byte, falls back to
/// plaintext JSON. Returns `(plaintext_bytes, was_encrypted)`.
///
/// Legacy Fernet ciphertexts (version byte 0x80) are detected but not handled
/// here — see [`is_fernet`]; the dual-read migration path is added separately.
pub fn decrypt_bundle(secret: Option<&str>, data: &[u8]) -> Result<(Vec<u8>, bool), GatewayError> {
    if data.is_empty() {
        return Err(GatewayError::server_error("empty bundle"));
    }

    // Plaintext JSON fallback (no key, or unencrypted dev bundle).
    if data[0] != ENVELOPE_VERSION {
        if is_fernet(data) {
            return Err(GatewayError::server_error(
                "legacy Fernet bundle detected; Fernet dual-read not yet enabled",
            ));
        }
        // Assume plaintext JSON.
        return Ok((data.to_vec(), false));
    }

    let secret = secret.ok_or_else(|| {
        GatewayError::server_error("encrypted bundle but MCP_SECRETS_KEY is unset")
    })?;

    if data.len() < 1 + NONCE_LEN + GCM_TAG_LEN {
        return Err(GatewayError::server_error("truncated envelope"));
    }
    let nonce = Nonce::from_slice(&data[1..1 + NONCE_LEN]);
    let ciphertext = &data[1 + NONCE_LEN..];

    let key = derive_encryption_key(secret);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| GatewayError::server_error(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GatewayError::server_error("AES-GCM decrypt failed (wrong key or corrupted)"))?;

    Ok((plaintext, true))
}

/// True if `data` looks like a legacy Fernet token (starts with 0x80).
pub fn is_fernet(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == FERNET_VERSION_BYTE
}

/// Compute the HMAC-SHA256 signature hex for a canonical JSON bundle.
///
/// `canonical_json` must be the JSON with sorted keys and the `_sig` field
/// removed (or absent). Returns a lowercase hex string.
pub fn sign_bundle(secret: &str, canonical_json: &[u8]) -> String {
    let key = derive_signing_key(secret);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("hmac accepts any key length");
    mac.update(canonical_json);
    hex_encode(&mac.finalize().into_bytes())
}

/// Verify a signature against canonical JSON. Constant-time via `hmac`.
pub fn verify_bundle_sig(secret: &str, canonical_json: &[u8], expected_hex: &str) -> bool {
    let computed = sign_bundle(secret, canonical_json);
    // Constant-time-ish compare (length-checked first; hmac crate doesn't expose
    // a slice compare here, so use a simple byte-wise guard).
    if computed.len() != expected_hex.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in computed.bytes().zip(expected_hex.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// SHA-256 of a value, returned as lowercase hex (used for `args_digest`).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic() {
        let a = derive_encryption_key("secret");
        let b = derive_encryption_key("secret");
        assert_eq!(a, b);
        let c = derive_encryption_key("other");
        assert_ne!(a, c);
        // Encryption and signing keys differ (different info).
        assert_ne!(derive_encryption_key("s"), derive_signing_key("s"));
    }

    #[test]
    fn envelope_round_trip() {
        let secret = "test-secret-key";
        let plaintext = br#"{"servers":[],"version":1}"#;
        let ct = encrypt_bundle(secret, plaintext).unwrap();
        assert_eq!(ct[0], ENVELOPE_VERSION);
        assert_eq!(ct.len(), 1 + NONCE_LEN + plaintext.len() + GCM_TAG_LEN);
        let (pt, was_enc) = decrypt_bundle(Some(secret), &ct).unwrap();
        assert!(was_enc);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn plaintext_fallback() {
        let plaintext = br#"{"servers":[]}"#;
        let (pt, was_enc) = decrypt_bundle(None, plaintext).unwrap();
        assert!(!was_enc);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt_bundle("key-a", b"data").unwrap();
        assert!(decrypt_bundle(Some("key-b"), &ct).is_err());
    }

    #[test]
    fn fernet_detected() {
        // Fernet tokens start with 0x80.
        assert!(is_fernet(&[0x80, 0x00, 0x01]));
        assert!(!is_fernet(&[0x01, 0x02]));
    }

    #[test]
    fn sign_and_verify() {
        let secret = "signing-secret";
        let canonical = br#"{"a":1,"b":2}"#;
        let sig = sign_bundle(secret, canonical);
        assert!(verify_bundle_sig(secret, canonical, &sig));
        assert!(!verify_bundle_sig(secret, b"tampered", &sig));
        assert!(!verify_bundle_sig("other", canonical, &sig));
    }

    #[test]
    fn sha256_hex_known() {
        // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
