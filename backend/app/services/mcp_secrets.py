"""Fernet encryption helpers for MCP gateway secrets.

Uses a dedicated MCP_SECRETS_KEY (separate from SECRET_KEY which is for GUI JWTs).
Derives a Fernet key via PBKDF2-SHA256 from the configured key.
"""
import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from ..core.config import get_settings

logger = logging.getLogger(__name__)

_fernet: Optional[Fernet] = None


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
