import logging
from typing import Optional

from ..core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _find_coraza_container(client):
    """Locate the coraza-spoa container by compose service label or name."""
    try:
        for container in client.containers.list():
            labels = container.labels or {}
            if labels.get("com.docker.compose.service") == "coraza-spoa":
                return container
            if "coraza-spoa" in container.name:
                return container
    except Exception as exc:
        logger.warning("Could not list containers: %s", exc)
    return None


def restart_coraza_spoa() -> bool:
    """Restart the coraza-spoa container via the Docker API if available."""
    if not settings.CORAZA_SPOA_AUTO_RESTART:
        logger.info("Coraza SPOA auto-restart is disabled")
        return False
    try:
        import docker
        client = docker.from_env()
        container = _find_coraza_container(client)
        if not container:
            logger.warning("coraza-spoa container not found")
            return False
        logger.info("Restarting coraza-spoa container: %s", container.name)
        container.restart(timeout=10)
        logger.info("coraza-spoa container restarted successfully")
        return True
    except Exception as exc:
        logger.error("Failed to restart coraza-spoa: %s", exc)
        return False
