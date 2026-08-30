import logging

logger = logging.getLogger(__name__)


class BackgroundServiceRegistry:
    """Central registry for background services with a unified start/stop lifecycle."""

    def __init__(self):
        self._services = []

    def register(self, service, *, condition=lambda: True):
        """Register a service with an optional start condition."""
        self._services.append((service, condition))
        return service

    def start_all(self):
        for service, condition in self._services:
            if condition():
                try:
                    service.start()
                except Exception:
                    logger.exception("Failed to start background service %s", service)

    def stop_all(self):
        for service, _ in reversed(self._services):
            try:
                service.stop()
            except Exception:
                logger.exception("Failed to stop background service %s", service)
