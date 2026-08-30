"""Back-compat re-export of shared route dependencies from api.deps."""
from ..api.deps import (  # noqa: F401
    get_current_user,
    get_or_404,
    oauth2_scheme,
    rate_limit,
    rate_limit_by_ip,
    require_admin,
    require_role,
    require_write,
)

__all__ = [
    "get_current_user",
    "get_or_404",
    "oauth2_scheme",
    "rate_limit",
    "rate_limit_by_ip",
    "require_admin",
    "require_role",
    "require_write",
]
