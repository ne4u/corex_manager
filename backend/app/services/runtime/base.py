"""Runtime backend abstraction.

Provides a unified interface for interacting with sibling containers (HAProxy,
Coraza SPOA, Varnish) regardless of whether the deployment uses Docker Compose
or Kubernetes. The backend is selected at startup via ``COREX_RUNTIME`` (see
``__init__.py``).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class RuntimeBackend(ABC):
    """Abstract interface for container/pod management operations.

    All methods cover the five Docker-SDK call sites that were previously
    scattered across ``services/haproxy.py``, ``services/varnish.py``,
    ``services/coraza_watcher.py``, ``services/page_protect_sampler.py``, and
    ``api/v1/system.py``. Each implementation (DockerRuntime, KubernetesRuntime)
    provides the same semantics behind this interface.
    """

    # ------------------------------------------------------------------
    # HAProxy operations
    # ------------------------------------------------------------------

    @abstractmethod
    def validate_haproxy_config(self, config_path: str) -> tuple[bool, str]:
        """Run ``haproxy -c -f <config_path>`` in the HAProxy container/pod.

        Returns (is_valid, output). On failure where the runtime itself is
        unavailable, returns (False, "haproxy container check failed: ...")
        so the caller can fall back to a local haproxy binary.
        """

    @abstractmethod
    def haproxy_version_verbose(self) -> Optional[str]:
        """Run ``haproxy -vv`` in the HAProxy container/pod.

        Returns the stdout output, or None if unavailable.
        """

    @abstractmethod
    def haproxy_logs(
        self,
        tail: Optional[int] = None,
        since: Optional[int] = None,
        timestamps: bool = False,
    ) -> str:
        """Fetch HAProxy stdout logs.

        Args:
            tail: Number of most recent lines to fetch (None = all).
            since: Unix timestamp; fetch logs since this time (None = all).
            timestamps: Prepend a timestamp to each line.

        Returns the log text (decoded UTF-8). Returns empty string if
        unavailable.
        """

    # ------------------------------------------------------------------
    # Coraza operations
    # ------------------------------------------------------------------

    @abstractmethod
    def restart_coraza(self) -> bool:
        """Restart the Coraza SPOA workload. Returns True on success."""

    # ------------------------------------------------------------------
    # Varnish operations
    # ------------------------------------------------------------------

    @abstractmethod
    def validate_vcl(self, vcl_container_path: str) -> tuple[bool, str]:
        """Run ``varnishd -C -f <vcl_container_path>`` in the Varnish container/pod.

        Returns (is_valid, output).
        """

    @abstractmethod
    def reload_vcl(self, vcl_container_path: str) -> bool:
        """Reload the VCL in the running Varnish container/pod.

        Args:
            vcl_container_path: Path to the VCL file as seen inside the
                Varnish container/pod.

        Returns True on success.
        """

    @abstractmethod
    def purge_vcl(self, ban_expr: str) -> bool:
        """Run ``varnishadm ban "<ban_expr>"`` in the Varnish container/pod.

        Returns True on success.
        """

    @abstractmethod
    def purge_all(self) -> bool:
        """Ban all cached objects in Varnish. Returns True on success."""

    @abstractmethod
    def varnish_stats(self) -> dict:
        """Run ``varnishstat -j`` in the Varnish container/pod.

        Returns a dict of parsed counters, or empty dict if unavailable.
        """

    # ------------------------------------------------------------------
    # Health / introspection
    # ------------------------------------------------------------------

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the runtime backend is reachable and ready."""

    @abstractmethod
    def describe(self) -> dict:
        """Return a dict describing the runtime for health endpoints.

        Expected keys: ``available`` (bool), ``error`` (str or None),
        ``type`` (str: "docker" / "kubernetes" / "none").
        """
