"""Tests for the _cv captcha cookie client-binding hash.

The binding hash ties a solved captcha cookie to the client (IP + User-Agent
+ JA4 TLS fingerprint) so a leaked cookie cannot be replayed from a different
client. The hash is computed identically in Python (compute_cv_binding_hash)
and in HAProxy Lua (captcha_ctx.lua:compute_cv_binding_hash).
"""
import hashlib

from app.services.captcha_providers import compute_cv_binding_hash


def test_binding_hash_deterministic():
    """Same inputs always produce the same hash."""
    h1 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    h2 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    assert h1 == h2


def test_binding_hash_format():
    """Hash is 32 lowercase hex chars (128 bits of SHA-256)."""
    h = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    assert len(h) == 32
    assert all(c in "0123456789abcdef" for c in h)


def test_binding_hash_matches_manual_sha256():
    """Verify the exact algorithm: sha256(f"{ip}\n{ua}\n{ja4}")[:32]."""
    ip, ua, ja4 = "1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6"
    expected = hashlib.sha256(f"{ip}\n{ua}\n{ja4}".encode()).hexdigest()[:32]
    assert compute_cv_binding_hash(ip, ua, ja4) == expected


def test_binding_hash_differs_on_ip():
    """Different IP → different hash (replay from different client fails)."""
    h1 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    h2 = compute_cv_binding_hash("5.6.7.8", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    assert h1 != h2


def test_binding_hash_differs_on_ua():
    """Different User-Agent → different hash."""
    h1 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    h2 = compute_cv_binding_hash("1.2.3.4", "curl/8.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    assert h1 != h2


def test_binding_hash_differs_on_ja4():
    """Different JA4 fingerprint → different hash."""
    h1 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    h2 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d2016h2_aaaaaaabbbbb_ccccccccdddd")
    assert h1 != h2


def test_binding_hash_empty_components():
    """Empty/missing components are represented as empty strings and still
    produce a valid, deterministic hash. This covers plaintext listeners
    (no JA4) and clients with no User-Agent."""
    h = compute_cv_binding_hash("", "", "")
    assert len(h) == 32
    expected = hashlib.sha256(b"\n\n").hexdigest()[:32]
    assert h == expected


def test_binding_hash_empty_ja4_matches_plaintext():
    """When JA4 is empty (plaintext listener or JA4 disabled), the hash
    still works — both sides use empty string for the JA4 component."""
    h_with_ja4 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "t13d1516h2_8daaf6152771_b186095e22b6")
    h_no_ja4 = compute_cv_binding_hash("1.2.3.4", "Mozilla/5.0", "")
    assert h_with_ja4 != h_no_ja4
