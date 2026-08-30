from fastapi import APIRouter

from .api_armor import router as api_armor_router
from .audit import router as audit_router
from .auth import router as auth_router
from .backends import router as backends_router
from .cache import router as cache_router
from .captcha import router as captcha_router
from .certificates import router as certificates_router
from .ciphers import router as ciphers_router
from .config import router as config_router
from .error_pages import router as error_pages_router
from .fcgi import router as fcgi_router
from .headers import router as headers_router
from .listeners import router as listeners_router
from .logging import router as logging_router
from .page_protect import router as page_protect_router
from .rate_limits import router as rate_limits_router
from .redirects import router as redirects_router
from .resp_transform import router as resp_transform_router
from .risk_rules import router as risk_rules_router
from .risk_rulesets import router as risk_rulesets_router
from .security_lists import router as security_lists_router
from .security_rules import router as security_rules_router
from .settings import router as settings_router
from .system import router as system_router
from .tasks import router as tasks_router
from .users import router as users_router
from .waf import router as waf_router
from .mcp import router as mcp_router


def build_v1_router() -> APIRouter:
    """Assemble the /api/v1 router from all domain routers."""
    router = APIRouter()
    router.include_router(api_armor_router)
    router.include_router(audit_router)
    router.include_router(auth_router)
    router.include_router(backends_router)
    router.include_router(certificates_router)
    router.include_router(cache_router)
    router.include_router(captcha_router)
    router.include_router(ciphers_router)
    router.include_router(config_router)
    router.include_router(error_pages_router)
    router.include_router(fcgi_router)
    router.include_router(headers_router)
    router.include_router(listeners_router)
    router.include_router(logging_router)
    router.include_router(page_protect_router)
    router.include_router(rate_limits_router)
    router.include_router(redirects_router)
    router.include_router(resp_transform_router)
    router.include_router(risk_rules_router)
    router.include_router(risk_rulesets_router)
    router.include_router(security_lists_router)
    router.include_router(security_rules_router)
    router.include_router(settings_router)
    router.include_router(system_router)
    router.include_router(tasks_router)
    router.include_router(users_router)
    router.include_router(waf_router)
    router.include_router(mcp_router)
    return router
