import time
from collections import OrderedDict

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.security import decode_access_token
from ..core.valkey_client import check_rate_limit, is_token_revoked
from ..core.config import get_settings
from ..models.models import User, UserTeam, Team

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


ROLE_LEVEL = {
    "viewer": 1,
    "operator": 2,
    "admin": 3,
}

# ---------------------------------------------------------------------------
# In-process user lookup cache (short-lived LRU keyed by username).
# Eliminates the per-request SELECT user query for repeated authentications
# (e.g. the MCP server's fixed admin JWT). The cached User is a detached
# instance merged into the current session via db.merge(load=False), which
# avoids a DB round-trip while keeping the object usable for column access.
# ---------------------------------------------------------------------------
_user_cache: "OrderedDict[str, tuple[float, User]]" = OrderedDict()
_USER_CACHE_TTL = 30  # seconds
_USER_CACHE_MAX = 256


def _get_user_cached(db: Session, username: str) -> User | None:
    """Look up a user by username with a short-lived in-process cache."""
    now = time.time()
    cached = _user_cache.get(username)
    if cached is not None:
        ts, cached_user = cached
        if now - ts < _USER_CACHE_TTL:
            return db.merge(cached_user, load=False)
        _user_cache.pop(username, None)
    user = db.query(User).filter(User.username == username).first()
    if user is not None:
        db.expunge(user)
        _user_cache[username] = (now, user)
        if len(_user_cache) > _USER_CACHE_MAX:
            _user_cache.popitem(last=False)
        return db.merge(user, load=False)
    return user


def _is_service_call(request: Request) -> bool:
    """True if this is an in-process MCP service call (skip revocation check)."""
    token = settings.MCP_SERVICE_TOKEN
    if not token:
        return False
    return request.headers.get("x-mcp-service-token") == token


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    username = payload.get("sub")
    if _is_service_call(request):
        # In-process MCP service calls use a fixed admin JWT that is never
        # revoked — skip the Valkey round-trip and use the user cache to
        # avoid a per-request DB query.
        user = _get_user_cached(db, username)
    else:
        if is_token_revoked(token):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def rate_limit(request: Request, user: User = Depends(get_current_user)) -> User:
    if request.method == "GET":
        return user
    # Bypass rate limiting for in-process MCP server calls (service token)
    if settings.MCP_SERVICE_TOKEN and request.headers.get("X-MCP-Service-Token") == settings.MCP_SERVICE_TOKEN:
        return user
    path = request.url.path or "unknown"
    key = f"{user.username}:{request.client.host or 'unknown'}:{request.method}:{path}"
    if not check_rate_limit(key, settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return user


def rate_limit_by_ip(request: Request) -> None:
    key = request.client.host or "unknown"
    if not check_rate_limit(key, settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def require_role(min_role: str):
    def _role_guard(user: User = Depends(get_current_user)) -> User:
        level = ROLE_LEVEL.get(user.role, 0)
        required = ROLE_LEVEL.get(min_role, 0)
        if level < required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {min_role} role or higher",
            )
        return user

    return _role_guard


require_admin = require_role("admin")
require_write = require_role("operator")


def get_or_404(db: Session, model, id: int):
    """Fetch a single row by id or raise 404."""
    obj = db.query(model).filter(model.id == id).first()
    if not obj:
        raise HTTPException(status_code=404, detail=f"{model.__name__} not found")
    return obj


def require_team_access(team_id: int):
    """Return a dependency that checks the current user has access to the given team.

    Admins always pass. Operators/viewers must have a UserTeam membership.
    """
    def _guard(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if user.is_admin or user.role == "admin":
            return user
        membership = db.query(UserTeam).filter(
            UserTeam.user_id == user.id,
            UserTeam.team_id == team_id,
        ).first()
        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this team",
            )
        return user

    return _guard


def get_user_team_ids(db: Session, user: User) -> list[int]:
    """Return list of team IDs the user belongs to (admin = all teams)."""
    if user.is_admin or user.role == "admin":
        return [t.id for t in db.query(Team).all()]
    return [
        m.team_id for m in
        db.query(UserTeam).filter(UserTeam.user_id == user.id).all()
    ]
