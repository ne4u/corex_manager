import logging

from ..core.config import get_settings
from .runtime import get_runtime

logger = logging.getLogger(__name__)
settings = get_settings()


def restart_coraza_spoa() -> bool:
    """Restart the coraza-spoa container/pod via the runtime backend if available."""
    if not settings.CORAZA_SPOA_AUTO_RESTART:
        logger.info("Coraza SPOA auto-restart is disabled")
        return False
    runtime = get_runtime()
    return runtime.restart_coraza()
