"""Middleware that blocks API access when a user's password has expired.

The JWT issued at login carries a ``pwd_exp`` boolean claim computed from the
configured rotation policy. This middleware decodes the Bearer token (no DB
hit) and, when ``pwd_exp`` is true, rejects all requests except a whitelist of
auth/session/password endpoints needed to perform the forced password change.

This is a defense-in-depth backstop: the frontend also shows a blocking modal.
If the claim is absent (tokens issued before this feature shipped) the
request is allowed through — the next token refresh will add the claim.
"""
import json
import re

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .security import decode_access_token

# Endpoints always allowed even when the password is expired. Matched against
# the path with the /api/v1 prefix stripped. Patterns are regexes anchored to
# the full path.
_WHITELIST_PATTERNS: list[re.Pattern] = [
    re.compile(r"^/auth/token$"),
    re.compile(r"^/auth/change-password$"),
    re.compile(r"^/auth/logout$"),
    re.compile(r"^/auth/refresh$"),
    re.compile(r"^/auth/session$"),
    re.compile(r"^/auth/me$"),
    re.compile(r"^/auth/preferences$"),
    re.compile(r"^/auth/totp/"),
    re.compile(r"^/health$"),
    re.compile(r"^/system/health$"),
]

_API_PREFIX = "/api/v1"


def _is_whitelisted(path: str) -> bool:
    if path.startswith(_API_PREFIX):
        path = path[len(_API_PREFIX):]
    return any(p.search(path) for p in _WHITELIST_PATTERNS)


class PasswordExpiryMiddleware(BaseHTTPMiddleware):
    """Return 403 ``password_change_required`` for non-auth endpoints when the
    JWT ``pwd_exp`` claim is true.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Only gate API paths; static assets and non-API routes pass through.
        if not path.startswith(_API_PREFIX):
            return await call_next(request)
        if _is_whitelisted(path):
            return await call_next(request)

        auth = request.headers.get("authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return await call_next(request)

        token = auth.split(" ", 1)[1]
        payload = decode_access_token(token)
        if not payload:
            return await call_next(request)

        if payload.get("pwd_exp") is True:
            return JSONResponse(
                status_code=403,
                content={"detail": "password_change_required"},
            )

        return await call_next(request)
