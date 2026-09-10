//! Cross-compatibility test: the Rust AES-GCM envelope + HMAC signature must be
//! readable by the Python backend (`mcp_secrets.py`) and vice versa.
//!
//! Invokes Python as a subprocess so it is self-contained for CI, provided the
//! backend source tree is present (it is, in this repo).

use corex_core::crypto;
use std::process::Command;

const SECRET: &str = "cross-test-secret";
const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");
// CARGO_MANIFEST_DIR is .../mcp-gateway-rs/crates/core ; backend is 3 levels up.
fn backend_root() -> String {
    let manifest = std::path::Path::new(REPO_ROOT);
    let core = manifest.parent().unwrap(); // crates/
    let rs = core.parent().unwrap(); // mcp-gateway-rs/
    let repo = rs.parent().unwrap(); // corex_manager/
    repo.join("backend").to_str().unwrap().to_string()
}

/// Minimal env for the backend `Settings` to construct (SECRET_KEY is required).
fn python_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("MCP_SECRETS_KEY", SECRET),
        ("SECRET_KEY", "test-secret-key-at-least-32-bytes-long-xx"),
        ("DATABASE_URL", "sqlite:///tmp/corex_cross_test.db"),
    ]
}

#[test]
fn python_decrypts_rust_envelope() {
    let pt = br#"{"servers":[],"version":1}"#;
    let ct = crypto::encrypt_bundle(SECRET, pt).unwrap();
    let tmp = std::env::temp_dir().join("corex_rust_envelope.bin");
    std::fs::write(&tmp, &ct).unwrap();

    let script = format!(
        r#"
import sys
sys.path.insert(0, {backend:?})
from app.services.mcp_secrets import decrypt_bundle_aesgcm
data = open({tmp:?}, "rb").read()
pt = decrypt_bundle_aesgcm(data)
assert pt == b'{{"servers":[],"version":1}}', pt
print("OK")
"#,
        backend = backend_root(),
        tmp = tmp.display()
    );

    let out = Command::new("python")
        .arg("-c")
        .arg(&script)
        .envs(python_env())
        .output()
        .expect("python not available");
    assert!(out.status.success(), "python decrypt failed: {}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn python_verifies_rust_signature() {
    let canonical = b"{\"a\":1,\"b\":2}";
    let sig = crypto::sign_bundle(SECRET, canonical);

    let script = format!(
        r#"
import sys
sys.path.insert(0, {backend:?})
from app.services.mcp_secrets import verify_bundle_sig_aesgcm
assert verify_bundle_sig_aesgcm(b'{{"a":1,"b":2}}', {sig:?})
print("OK")
"#,
        backend = backend_root(),
        sig = sig
    );

    let out = Command::new("python")
        .arg("-c")
        .arg(&script)
        .envs(python_env())
        .output()
        .expect("python not available");
    assert!(out.status.success(), "python verify failed: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn rust_decrypts_python_envelope() {
    let pt = br#"{"servers":[],"version":1}"#;
    let tmp = std::env::temp_dir().join("corex_py_envelope.bin");

    let script = format!(
        r#"
import sys
sys.path.insert(0, {backend:?})
from app.services.mcp_secrets import encrypt_bundle_aesgcm
ct = encrypt_bundle_aesgcm(b'{{"servers":[],"version":1}}')
open({tmp:?}, "wb").write(ct)
print("OK")
"#,
        backend = backend_root(),
        tmp = tmp.display()
    );

    let out = Command::new("python")
        .arg("-c")
        .arg(&script)
        .envs(python_env())
        .output()
        .expect("python not available");
    assert!(out.status.success(), "python encrypt failed: {}", String::from_utf8_lossy(&out.stderr));

    let ct = std::fs::read(&tmp).unwrap();
    let (decrypted, was_enc) = crypto::decrypt_bundle(Some(SECRET), &ct).unwrap();
    assert!(was_enc);
    assert_eq!(decrypted, pt);
    let _ = std::fs::remove_file(&tmp);
}
