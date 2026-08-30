"""Auth module for MCP Gateway — PAT and JWT (resource server).

Validates `Authorization: Bearer <token>`:
1. If token matches `mcp_<hex>.<secret>` PAT format → lookup prefix in config,
   verify bcrypt hash, check enabled/expiry.
2. Else treat as JWT → validate via JWKS, check iss/aud/exp, map sub → identity.
3. Else → 401 with WWW-Authenticate header.
"""
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import bcrypt
import jwt
import httpx

try:
    from .revocation import is_token_valid
except ImportError:
    from revocation import is_token_valid

logger = logging.getLogger(__name__)

# --- Brute-force protection ---
_auth_fail_counts: dict[str, list[float]] = {}
_AUTH_FAIL_WINDOW = 60  # 60-second sliding window
_AUTH_FAIL_THRESHOLD = 10  # max failures per IP before lockout
_AUTH_LOCKOUT_SECONDS = 300  # 5-minute lockout
_auth_lockouts: dict[str, float] = {}


class AuthError(Exception):
    """Raised when authentication fails."""
    def __init__(self, message: str = "Unauthorized"):
        self.message = message
        super().__init__(message)


class AuthContext:
    """Resolved identity context attached to an authenticated request."""
    def __init__(
        self,
        identity_id: int,
        team_id: int,
        name: str,
        subject: str,
        kind: str,
        claims: Optional[dict] = None,
    ):
        self.identity_id = identity_id
        self.team_id = team_id
        self.name = name
        self.subject = subject
        self.kind = kind  # "pat" | "jwt"
        self.claims = claims or {}

    def to_dict(self) -> dict:
        return {
            "identity_id": self.identity_id,
            "team_id": self.team_id,
            "name": self.name,
            "subject": self.subject,
            "kind": self.kind,
            "claims": self.claims,
        }


# --- JWKS cache ---
_jwks_cache: dict[str, dict] = {}  # url -> {"keys": [...], "fetched_at": float}
_JWKS_TTL = 300  # 5 minutes


async def _fetch_jwks(jwks_url: str) -> dict:
    """Fetch and cache JWKS from a URL."""
    now = time.time()
    cached = _jwks_cache.get(jwks_url)
    if cached and (now - cached["fetched_at"]) < _JWKS_TTL:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(jwks_url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error("Failed to fetch JWKS from %s: %s", jwks_url, e)
        if cached:
            return cached  # stale cache is better than nothing
        raise AuthError("Cannot fetch JWKS")

    entry = {"keys": data.get("keys", []), "fetched_at": now}
    _jwks_cache[jwks_url] = entry
    return entry


def _get_signing_key(jwks_data: dict, kid: Optional[str]) -> Any:
    """Find the signing key in JWKS by kid."""
    from jwt import PyJWK
    keys = jwks_data.get("keys", [])
    if not keys:
        raise AuthError("No keys in JWKS")
    for key in keys:
        if kid is None or key.get("kid") == kid:
            return PyJWK(key)
    raise AuthError(f"No matching key for kid={kid}")


def _is_pat(token: str) -> bool:
    """Check if token looks like a PAT: mcp_<hex>.<secret>."""
    return token.startswith("mcp_") and "." in token


def _parse_pat(token: str) -> tuple[str, str]:
    """Split PAT into (prefix, secret). prefix = mcp_<hex>."""
    idx = token.index(".")
    return token[:idx], token[idx + 1:]


def _verify_pat(prefix: str, token: str, identities: list[dict]) -> Optional[dict]:
    """Verify PAT against configured identities. Returns identity dict or None."""
    for ident in identities:
        if ident.get("kind") != "pat":
            continue
        if ident.get("pat_prefix") != prefix:
            continue
        if not ident.get("enabled", True):
            return None
        expires_at = ident.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return None
        pat_hash = ident.get("pat_hash")
        if not pat_hash:
            return None
        try:
            if bcrypt.checkpw(token.encode("utf-8"), pat_hash.encode("utf-8")):
                return ident
        except Exception:
            continue
    return None


async def _verify_jwt(
    token: str,
    identities: list[dict],
    global_issuer: Optional[str],
    global_audience: Optional[str],
    global_jwks_url: Optional[str],
) -> Optional[dict]:
    """Verify JWT and map to identity. Returns identity dict or None."""
    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None

    kid = unverified_header.get("kid")
    sub = unverified_payload.get("sub")
    iss = unverified_payload.get("iss")
    aud = unverified_payload.get("aud")

    # Find matching identity by subject or issuer
    target_identity = None
    jwks_url = global_jwks_url
    expected_issuer = global_issuer
    expected_audience = global_audience

    for ident in identities:
        if ident.get("kind") != "jwt":
            continue
        if ident.get("subject") and ident["subject"] == sub:
            target_identity = ident
            if ident.get("jwt_jwks_url"):
                jwks_url = ident["jwt_jwks_url"]
            if ident.get("jwt_issuer"):
                expected_issuer = ident["jwt_issuer"]
            if ident.get("jwt_audience"):
                expected_audience = ident["jwt_audience"]
            break
        if ident.get("jwt_issuer") and ident["jwt_issuer"] == iss:
            target_identity = ident
            if ident.get("jwt_jwks_url"):
                jwks_url = ident["jwt_jwks_url"]
            if ident.get("jwt_issuer"):
                expected_issuer = ident["jwt_issuer"]
            if ident.get("jwt_audience"):
                expected_audience = ident["jwt_audience"]
            break

    if not target_identity:
        # Default deny unknown subjects
        return None

    if not target_identity.get("enabled", True):
        return None

    expires_at = target_identity.get("expires_at")
    if expires_at:
        exp = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            return None

    if not jwks_url:
        logger.error("No JWKS URL configured for JWT identity %s", target_identity.get("name"))
        return None

    jwks_data = await _fetch_jwks(jwks_url)
    signing_key = _get_signing_key(jwks_data, kid)

    decode_options = {
        "verify_exp": True,
        "verify_iss": bool(expected_issuer),
        "verify_aud": bool(expected_audience),
    }
    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            issuer=expected_issuer,
            audience=expected_audience,
            options=decode_options,
        )
    except Exception as e:
        logger.warning("JWT validation failed: %s", e)
        return None

    target_identity["_claims"] = payload
    return target_identity


def _check_brute_force(ip: str) -> None:
    """Check if an IP is locked out due to auth failures. Raises AuthError if locked."""
    import time
    now = time.time()
    lockout_until = _auth_lockouts.get(ip, 0)
    if lockout_until > now:
        raise AuthError(f"Too many auth failures from {ip}, locked until {lockout_until}")


def _record_auth_failure(ip: str) -> None:
    """Record an auth failure for brute-force detection."""
    import time
    now = time.time()
    cutoff = now - _AUTH_FAIL_WINDOW
    failures = _auth_fail_counts.get(ip, [])
    failures = [t for t in failures if t > cutoff]
    failures.append(now)
    _auth_fail_counts[ip] = failures
    if len(failures) >= _AUTH_FAIL_THRESHOLD:
        _auth_lockouts[ip] = now + _AUTH_LOCKOUT_SECONDS
        logger.warning("Auth brute-force lockout for %s (%d failures in %ds)",
                       ip, len(failures), _AUTH_FAIL_WINDOW)


def _record_auth_success(ip: str) -> None:
    """Clear auth failure count on successful auth."""
    _auth_fail_counts.pop(ip, None)
    _auth_lockouts.pop(ip, None)


async def authenticate(
    token: str,
    config: dict,
    client_ip: str = "",
) -> AuthContext:
    """Authenticate a bearer token. Raises AuthError on failure."""
    # Brute-force check
    if client_ip:
        _check_brute_force(client_ip)

    identities = config.get("identities", [])
    global_issuer = config.get("jwt_issuer")
    global_audience = config.get("jwt_audience")
    global_jwks_url = config.get("jwt_jwks_url")

    if _is_pat(token):
        prefix, _ = _parse_pat(token)
        ident = _verify_pat(prefix, token, identities)
        if ident is None:
            if client_ip:
                _record_auth_failure(client_ip)
            raise AuthError("Invalid or expired PAT")
        # Check revocation
        if not is_token_valid(ident["id"]):
            if client_ip:
                _record_auth_failure(client_ip)
            raise AuthError("Identity revoked")
        if client_ip:
            _record_auth_success(client_ip)
        return AuthContext(
            identity_id=ident["id"],
            team_id=ident["team_id"],
            name=ident["name"],
            subject=ident.get("subject") or ident["name"],
            kind="pat",
        )

    # Try JWT
    ident = await _verify_jwt(token, identities, global_issuer, global_audience, global_jwks_url)
    if ident is None:
        if client_ip:
            _record_auth_failure(client_ip)
        raise AuthError("Invalid or expired JWT")

    # Check revocation (by jti if available)
    jti = ident.get("_claims", {}).get("jti") if isinstance(ident.get("_claims"), dict) else None
    if not is_token_valid(ident["id"], jti):
        if client_ip:
            _record_auth_failure(client_ip)
        raise AuthError("Token revoked")

    if client_ip:
        _record_auth_success(client_ip)
    return AuthContext(
        identity_id=ident["id"],
        team_id=ident["team_id"],
        name=ident["name"],
        subject=ident.get("subject") or ident["name"],
        kind="jwt",
        claims=ident.get("_claims", {}),
    )
