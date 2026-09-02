"""Runtime backend factory.

Selects the appropriate ``RuntimeBackend`` implementation based on the
``COREX_RUNTIME`` setting:

- ``auto`` (default): detects at startup:
    1. If ``KUBERNETES_SERVICE_HOST`` env var is set AND the K8s service
       account token exists → ``kubernetes``.
    2. Elif ``/var/run/docker.sock`` exists → ``docker``.
    3. Else → ``none`` (graceful degradation).
- ``docker``: use the Docker SDK.
- ``kubernetes``: use the Kubernetes API.
- ``none``: no runtime (all operations return unavailable; callers fall
  back to local binaries where applicable).

The factory caches the singleton instance for the process lifetime.
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Optional

from ...core.config import get_settings
from .base import RuntimeBackend

logger = logging.getLogger(__name__)


class _NullRuntime(RuntimeBackend):
    """No-op runtime backend — all operations return unavailable."""

    def validate_haproxy_config(self, config_path: str) -> tuple[bool, str]:
        return False, "haproxy container check failed: no runtime backend"

    def haproxy_version_verbose(self) -> Optional[str]:
        return None

    def haproxy_logs(
        self,
        tail: Optional[int] = None,
        since: Optional[int] = None,
        timestamps: bool = False,
    ) -> str:
        return ""

    def restart_coraza(self) -> bool:
        return False

    def validate_vcl(self, vcl_container_path: str) -> tuple[bool, str]:
        return False, "Varnish container not available (no runtime backend)"

    def reload_vcl(self, vcl_container_path: str) -> bool:
        return False

    def purge_vcl(self, ban_expr: str) -> bool:
        return False

    def purge_all(self) -> bool:
        return False

    def varnish_stats(self) -> dict:
        return {}

    def is_available(self) -> bool:
        return False

    def describe(self) -> dict:
        return {"available": False, "error": "No runtime backend configured", "type": "none"}


def _detect_runtime() -> str:
    """Auto-detect the runtime backend.

    Returns one of "kubernetes", "docker", or "none".
    """
    # Check for Kubernetes in-cluster environment
    k8s_service_host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    k8s_sa_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if k8s_service_host and os.path.exists(k8s_sa_token):
        return "kubernetes"

    # Check for Docker socket
    if os.path.exists("/var/run/docker.sock"):
        return "docker"

    return "none"


@lru_cache()
def get_runtime() -> RuntimeBackend:
    """Return the singleton RuntimeBackend instance for this process."""
    settings = get_settings()
    mode = getattr(settings, "COREX_RUNTIME", "auto")

    if mode == "auto":
        mode = _detect_runtime()
        logger.info("COREX_RUNTIME=auto detected runtime: %s", mode)

    if mode == "docker":
        from .docker_runtime import DockerRuntime
        return DockerRuntime()
    elif mode == "kubernetes":
        from .kubernetes_runtime import KubernetesRuntime
        return KubernetesRuntime()
    else:
        logger.info("Using null runtime backend (no container management)")
        return _NullRuntime()


__all__ = ["RuntimeBackend", "get_runtime"]
