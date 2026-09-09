"""Auth0 IdP integration for MCP identities.

Fetches users from the Auth0 Management API and idempotently provisions them
as McpIdentity rows. The created identities are JWT-kind so the MCP gateway can
validate Auth0 access tokens against them.
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.mcp import McpIdentity

logger = logging.getLogger(__name__)

# Cache for Auth0 Management API access token.
# {domain: {"token": str, "expires_at": float}}
_token_cache: Dict[str, Dict[str, Any]] = {}


def _get_setting_or_raise(name: str) -> str:
    settings = get_settings()
    value = getattr(settings, name, None)
    if not value:
        raise ValueError(f"{name} is not configured")
    return value


def _management_audience(domain: str) -> str:
    """Auth0 Management API audience for a tenant domain."""
    return f"https://{domain}/api/v2/"


def _get_management_token(domain: str, client_id: str, client_secret: str) -> str:
    """Return a valid Auth0 Management API token, fetching a new one if needed."""
    cached = _token_cache.get(domain)
    if cached and cached.get("expires_at", 0) > time.time() + 60:
        return cached["token"]

    audience = _management_audience(domain)
    url = f"https://{domain}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
    }
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(url, json=payload)
        if resp.status_code != 200:
            raise RuntimeError(f"Auth0 token request failed: {resp.status_code} {resp.text}")
        data = resp.json()

    token = data.get("access_token")
    expires_in = data.get("expires_in", 86400)
    if not token:
        raise RuntimeError("Auth0 token response missing access_token")

    _token_cache[domain] = {
        "token": token,
        "expires_at": time.time() + expires_in,
    }
    return token


def _paginated_get(domain: str, token: str, path: str, per_page: int = 100) -> List[Dict[str, Any]]:
    """Fetch all pages from an Auth0 Management API GET endpoint."""
    base = f"https://{domain}/api/v2"
    results: List[Dict[str, Any]] = []
    page = 0
    with httpx.Client(timeout=30.0) as client:
        while True:
            url = f"{base}{path}"
            params = {"per_page": per_page, "page": page}
            headers = {"Authorization": f"Bearer {token}"}
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Auth0 API request failed: {resp.status_code} {resp.text}")
            data = resp.json()
            if not isinstance(data, list):
                raise RuntimeError(f"Unexpected Auth0 API response: {data}")
            if not data:
                break
            results.extend(data)
            if len(data) < per_page:
                break
            page += 1
    return results


def _build_user_name(user: Dict[str, Any]) -> str:
    """Derive a display name for the McpIdentity from an Auth0 user profile."""
    name = (
        user.get("email")
        or user.get("name")
        or user.get("nickname")
        or user.get("user_id")
        or "auth0-user"
    )
    # Auth0 user_ids contain characters like "|" and ":" that we do not want in a name.
    return re.sub(r"[^a-zA-Z0-9._@+-]", "-", name).strip("-")[:120]


def _is_auth0_user_enabled(user: Dict[str, Any]) -> bool:
    """An identity should be disabled if the Auth0 user is blocked or,
    when require_verified_email is requested, the email is not verified."""
    if user.get("blocked"):
        return False
    return True


def _build_user_info(user: Dict[str, Any]) -> Dict[str, Any]:
    """Store a sanitized, useful subset of the Auth0 profile."""
    return {
        "user_id": user.get("user_id"),
        "email": user.get("email"),
        "email_verified": user.get("email_verified", False),
        "name": user.get("name"),
        "nickname": user.get("nickname"),
        "picture": user.get("picture"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "last_login": user.get("last_login"),
        "logins_count": user.get("logins_count"),
        "app_metadata": user.get("app_metadata") if isinstance(user.get("app_metadata"), dict) else None,
        "user_metadata": user.get("user_metadata") if isinstance(user.get("user_metadata"), dict) else None,
    }


def _identity_issuer(domain: str) -> str:
    """Auth0 OIDC issuer for a tenant domain."""
    return f"https://{domain}/"


def _identity_jwks_url(domain: str) -> str:
    return f"https://{domain}/.well-known/jwks.json"


def sync_auth0_identities(
    db: Session,
    team_id: int,
    dry_run: bool = False,
    require_verified_email: bool = False,
) -> Dict[str, Any]:
    """Fetch Auth0 users and create/update McpIdentity rows under the given team.

    Returns a summary dict with created/updated/skipped counts and any errors.
    """
    settings = get_settings()
    domain = settings.AUTH0_DOMAIN
    client_id = settings.AUTH0_CLIENT_ID
    client_secret = settings.AUTH0_CLIENT_SECRET
    audience = settings.AUTH0_MCP_AUDIENCE

    missing = [k for k, v in {
        "AUTH0_DOMAIN": domain,
        "AUTH0_CLIENT_ID": client_id,
        "AUTH0_CLIENT_SECRET": client_secret,
        "AUTH0_MCP_AUDIENCE": audience,
    }.items() if not v]
    if missing:
        raise ValueError(f"Auth0 integration is not fully configured. Missing: {', '.join(missing)}")

    token = _get_management_token(domain, client_id, client_secret)
    issuer = _identity_issuer(domain)
    jwks_url = _identity_jwks_url(domain)

    users = _paginated_get(domain, token, "/users")

    created = 0
    updated = 0
    skipped = 0
    errors: List[str] = []

    for user in users:
        user_id = user.get("user_id")
        if not user_id:
            skipped += 1
            continue

        if require_verified_email and not user.get("email_verified"):
            skipped += 1
            continue

        name = _build_user_name(user)
        # If no useful display name, fall back to the user_id with safe characters.
        if not name:
            name = re.sub(r"[^a-zA-Z0-9._-]", "-", user_id)[:120]

        existing = (
            db.query(McpIdentity)
            .filter(
                McpIdentity.team_id == team_id,
                McpIdentity.idp_source == "auth0",
                McpIdentity.idp_external_id == user_id,
            )
            .first()
        )

        user_info = _build_user_info(user)

        enabled = _is_auth0_user_enabled(user) and (not require_verified_email or bool(user.get("email_verified")))

        if existing:
            changed = False
            if existing.name != name:
                existing.name = name
                changed = True
            if existing.subject != user_id:
                existing.subject = user_id
                changed = True
            if existing.description != "Synced from Auth0":
                existing.description = "Synced from Auth0"
                changed = True
            if existing.jwt_issuer != issuer:
                existing.jwt_issuer = issuer
                changed = True
            if existing.jwt_audience != audience:
                existing.jwt_audience = audience
                changed = True
            if existing.jwt_jwks_url != jwks_url:
                existing.jwt_jwks_url = jwks_url
                changed = True
            if existing.idp_user_info != user_info:
                existing.idp_user_info = user_info
                changed = True
            if existing.kind != "jwt":
                existing.kind = "jwt"
                changed = True
            if existing.enabled != enabled:
                existing.enabled = enabled
                changed = True
            if changed and not dry_run:
                db.add(existing)
                db.commit()
                db.refresh(existing)
                updated += 1
            else:
                skipped += 1
        else:
            if not dry_run:
                try:
                    obj = McpIdentity(
                        team_id=team_id,
                        name=name,
                        description="Synced from Auth0",
                        subject=user_id,
                        kind="jwt",
                        jwt_issuer=issuer,
                        jwt_audience=audience,
                        jwt_jwks_url=jwks_url,
                        enabled=enabled,
                        idp_source="auth0",
                        idp_external_id=user_id,
                        idp_user_info=user_info,
                    )
                    db.add(obj)
                    db.commit()
                    db.refresh(obj)
                    created += 1
                except Exception as e:
                    logger.exception("Failed to create Auth0 McpIdentity for %s", user_id)
                    errors.append(f"{user_id}: {e}")
            else:
                created += 1  # Count what would be created in dry run.

    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "dry_run": dry_run,
        "team_id": team_id,
        "total_users": len(users),
    }
