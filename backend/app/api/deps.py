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


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    if is_token_revoked(token):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    username = payload.get("sub")
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
