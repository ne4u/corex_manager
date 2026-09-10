"""Fernet encryption helpers for MCP gateway secrets.

Uses a dedicated MCP_SECRETS_KEY (separate from SECRET_KEY which is for GUI JWTs).
Derives a Fernet key via PBKDF2-SHA256 from the configured key.

Also provides AES-256-GCM bundle envelope helpers (`encrypt_bundle_aesgcm` /
`decrypt_bundle_aesgcm`) for the Rust gateway's greenfield bundle format.
The envelope is: [1 byte version=0x01][12-byte nonce][ciphertext + 16-byte GCM tag],
with the AES key derived via HKDF-SHA256 (salt=b"mcp-gateway-secrets",
info=b"mcp-gateway-bundle"). HMAC signing uses a separate HKDF-derived key
(info=b"mcp-gateway-sig") and is emitted as the `_sig` JSON field.
"""
import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from ..core.config import get_settings

logger = logging.getLogger(__name__)

_fernet: Optional[Fernet] = None

# AES-GCM bundle envelope constants (must match the Rust gateway's `core/crypto.rs`).
_BUNDLE_VERSION = 0x01
_BUNDLE_SALT = b"mcp-gateway-secrets"
_BUNDLE_ENC_INFO = b"mcp-gateway-bundle"
_BUNDLE_SIG_INFO = b"mcp-gateway-sig"


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet

    settings = get_settings()
    key = settings.MCP_SECRETS_KEY or os.environ.get("MCP_SECRETS_KEY")
    if not key:
        raise RuntimeError(
            "MCP_SECRETS_KEY is not set. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    # Derive a 32-byte Fernet key via PBKDF2
    derived = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), b"mcp-gateway-secrets", 100_000, dklen=32)
    fernet_key = base64.urlsafe_b64encode(derived)
    _fernet = Fernet(fernet_key)
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret string, return Fernet ciphertext as str."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext, return plaintext str."""
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt MCP secret — wrong key or corrupted data")
        raise ValueError("Secret decryption failed")


def has_secrets_key() -> bool:
    """Check if MCP_SECRETS_KEY is configured."""
    settings = get_settings()
    return bool(settings.MCP_SECRETS_KEY or os.environ.get("MCP_SECRETS_KEY"))


# ---------------------------------------------------------------------------
# AES-256-GCM bundle envelope (Rust gateway format)
# ---------------------------------------------------------------------------

def _get_bundle_secret() -> str:
    settings = get_settings()
    return settings.MCP_SECRETS_KEY or os.environ.get("MCP_SECRETS_KEY") or ""


def _derive_bundle_key(info: bytes) -> bytes:
    """HKDF-SHA256 -> 32-byte key from MCP_SECRETS_KEY."""
    secret = _get_bundle_secret().encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_BUNDLE_SALT,
        info=info,
    ).derive(secret)


def encrypt_bundle_aesgcm(plaintext: bytes) -> bytes:
    """Encrypt a plaintext bundle into the binary AES-256-GCM envelope.

    Envelope: [0x01][12-byte nonce][ciphertext + 16-byte GCM tag].
    """
    key = _derive_bundle_key(_BUNDLE_ENC_INFO)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return bytes([_BUNDLE_VERSION]) + nonce + ciphertext


def decrypt_bundle_aesgcm(data: bytes) -> bytes:
    """Decrypt an AES-256-GCM envelope. Raises ValueError on failure."""
    if not data or data[0] != _BUNDLE_VERSION:
        raise ValueError("not an AES-GCM envelope")
    if len(data) < 1 + 12 + 16:
        raise ValueError("truncated envelope")
    nonce = data[1:13]
    ciphertext = data[13:]
    key = _derive_bundle_key(_BUNDLE_ENC_INFO)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("AES-GCM decrypt failed (wrong key or corrupted)")


def is_aesgcm_envelope(data: bytes) -> bool:
    """True if `data` starts with the AES-GCM version byte (0x01)."""
    return bool(data) and data[0] == _BUNDLE_VERSION


def sign_bundle_aesgcm(canonical_json: bytes) -> str:
    """HMAC-SHA256 signature (hex) over canonical JSON, using the HKDF sig key."""
    key = _derive_bundle_key(_BUNDLE_SIG_INFO)
    return _hmac.new(key, canonical_json, hashlib.sha256).hexdigest()


def verify_bundle_sig_aesgcm(canonical_json: bytes, expected_hex: str) -> bool:
    """Constant-time HMAC verification."""
    computed = sign_bundle_aesgcm(canonical_json)
    return _hmac.compare_digest(computed, expected_hex)


def canonical_bundle_json(bundle: dict) -> bytes:
    """Serialize `bundle` with sorted keys and no signature fields, for HMAC."""
    payload = {k: v for k, v in bundle.items() if k not in ("_sig", "_signature")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
