"""Docker runtime backend — extracted verbatim from the original inline code.

This implementation preserves the exact behavior of the original Docker SDK
calls that were scattered across five modules. The extraction is behavioral-
preserving: the same ``docker.from_env()``, ``container.exec_run()``,
``container.restart()``, and ``container.logs()`` calls with the same
arguments are used.
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Optional

from ..config import get_settings
from .base import RuntimeBackend

logger = logging.getLogger(__name__)
settings = get_settings()

try:
    import docker
except ImportError:  # pragma: no cover
    docker = None  # type: ignore


class DockerRuntime(RuntimeBackend):
    """Runtime backend using the Docker SDK (docker.from_env)."""

    # ------------------------------------------------------------------
    # HAProxy operations
    # ------------------------------------------------------------------

    def validate_haproxy_config(self, config_path: str) -> tuple[bool, str]:
        """Run haproxy -c inside the running haproxy container via the Docker SDK.

        Wraps ``container.exec_run`` in a thread with a 30-second timeout because
        the Docker SDK's exec_run has no native timeout parameter and can hang
        indefinitely if the container or haproxy process is unresponsive.

        Note: we deliberately avoid the ``with ThreadPoolExecutor`` context manager
        because its ``__exit__`` calls ``shutdown(wait=True)``, which blocks until
        the worker thread finishes — defeating the timeout. Instead we use
        ``shutdown(wait=False)`` on timeout so the main thread can continue while
        the orphaned daemon thread cleans up on process exit.
        """
        if docker is None:
            return False, "haproxy container check failed: docker SDK not installed"
        container_name = os.environ.get("HAPROXY_CONTAINER_NAME", "haproxy")

        def _run() -> tuple[int, str]:
            print(f"[DOCKER_CHECK] creating docker client", flush=True)
            client = docker.from_env()
            print(f"[DOCKER_CHECK] getting container: {container_name}", flush=True)
            container = client.containers.get(container_name)
            print(f"[DOCKER_CHECK] calling exec_run: haproxy -c -f {config_path}", flush=True)
            ec, output = container.exec_run(f"haproxy -c -f {config_path}")
            print(f"[DOCKER_CHECK] exec_run returned: ec={ec}", flush=True)
            return ec, (output or b"").decode().strip()

        import concurrent.futures
        print("[DOCKER_CHECK] starting thread pool", flush=True)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_run)
        try:
            print("[DOCKER_CHECK] waiting for result (30s timeout)", flush=True)
            ec, output = future.result(timeout=30)
            executor.shutdown(wait=True)
            print(f"[DOCKER_CHECK] result: ec={ec}", flush=True)
            return ec == 0, output
        except concurrent.futures.TimeoutExpired:
            executor.shutdown(wait=False)
            print("[DOCKER_CHECK] TIMED OUT after 30s", flush=True)
            return False, "haproxy -c timed out after 30s in container"
        except Exception as e:
            executor.shutdown(wait=False)
            print(f"[DOCKER_CHECK] exception: {e}", flush=True)
            return False, f"haproxy container check failed: {e}"

    def haproxy_version_verbose(self) -> Optional[str]:
        """Run haproxy -vv in the haproxy container via the Docker SDK."""
        if docker is None:
            return None
        try:
            client = docker.from_env()
            container_name = os.environ.get("HAPROXY_CONTAINER_NAME", "haproxy")
            container = client.containers.get(container_name)
            ec, out = container.exec_run("haproxy -vv")
            output = (out or b"").decode("utf-8", errors="replace")
            return output if output else None
        except Exception:
            return None

    def haproxy_logs(
        self,
        tail: Optional[int] = None,
        since: Optional[int] = None,
        timestamps: bool = False,
    ) -> str:
        """Fetch HAProxy stdout logs via the Docker SDK."""
        if docker is None:
            return ""
        try:
            client = docker.from_env()
            container_name = getattr(settings, "HAPROXY_CONTAINER_NAME", "haproxy")
            container = client.containers.get(container_name)
            raw = container.logs(tail=tail, since=since, timestamps=timestamps)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            return raw or ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Coraza operations
    # ------------------------------------------------------------------

    def restart_coraza(self) -> bool:
        """Restart the coraza-spoa container via the Docker API if available."""
        if docker is None:
            return False
        try:
            client = docker.from_env()
            container = self._find_coraza_container(client)
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

    @staticmethod
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

    # ------------------------------------------------------------------
    # Varnish operations
    # ------------------------------------------------------------------

    def _get_varnish_container(self):
        """Get the Varnish Docker container, or None if unavailable."""
        if docker is None:
            return None
        try:
            client = docker.from_env()
            container_name = os.environ.get("VARNISH_CONTAINER_NAME", settings.VARNISH_CONTAINER_NAME)
            return client.containers.get(container_name)
        except Exception as e:
            logger.debug("Varnish container not available: %s", e)
            return None

    def validate_vcl(self, vcl_container_path: str) -> tuple[bool, str]:
        """Validate VCL syntax using varnishd -C in the Varnish container."""
        container = self._get_varnish_container()
        if container is None:
            return False, "Varnish container not available"
        try:
            ec, output = container.exec_run(f"varnishd -C -f {vcl_container_path}")
            decoded = (output or b"").decode("utf-8", errors="replace").strip()
            return ec == 0, decoded
        except Exception as e:
            return False, f"VCL validation via container failed: {e}"

    def reload_vcl(self, vcl_container_path: str) -> bool:
        """Reload the VCL in the running Varnish container."""
        container = self._get_varnish_container()
        if container is None:
            logger.warning("Varnish container not available, VCL written but not reloaded")
            return False

        # Try varnishreload first (simpler, available in official images)
        try:
            ec, output = container.exec_run("varnishreload")
            if ec == 0:
                return True
            logger.warning("varnishreload failed: %s", (output or b"").decode("utf-8", errors="replace"))
        except Exception as e:
            logger.warning("varnishreload failed: %s", e)

        # Fallback: varnishadm vcl.load + vcl.use. The VCL label must be unique —
        # Varnish rejects vcl.load for a name that is already loaded, so derive a
        # fresh label from the current time for every reload.
        try:
            label = f"reload_{int(time.time() * 1000)}"
            ec, output = container.exec_run(f"varnishadm vcl.load {label} {vcl_container_path}")
            if ec != 0:
                logger.error("varnishadm vcl.load failed: %s", (output or b"").decode("utf-8", errors="replace"))
                return False
            ec, output = container.exec_run(f"varnishadm vcl.use {label}")
            if ec != 0:
                logger.error("varnishadm vcl.use failed: %s", (output or b"").decode("utf-8", errors="replace"))
                return False
            return True
        except Exception as e:
            logger.error("varnishadm reload failed: %s", e)
            return False

    def purge_vcl(self, ban_expr: str) -> bool:
        """Run varnishadm ban in the Varnish container."""
        container = self._get_varnish_container()
        if container is None:
            logger.warning("Varnish container not available, cannot purge backend")
            return False
        try:
            ec, output = container.exec_run(f'varnishadm ban "{ban_expr}"')
            if ec == 0:
                return True
            logger.warning("varnishadm ban failed: %s", (output or b"").decode("utf-8", errors="replace"))
        except Exception as e:
            logger.warning("varnishadm ban failed: %s", e)
        return False

    def purge_all(self) -> bool:
        """Purge (ban) all cached objects in the disk cache."""
        container = self._get_varnish_container()
        if container is None:
            logger.warning("Varnish container not available, cannot purge all")
            return False
        try:
            ec, output = container.exec_run('varnishadm ban "obj.http.X-Cache-Backend ~ .*"')
            if ec == 0:
                return True
            logger.warning("varnishadm ban all failed: %s", (output or b"").decode("utf-8", errors="replace"))
        except Exception as e:
            logger.warning("varnishadm ban all failed: %s", e)
        return False

    def varnish_stats(self) -> dict:
        """Fetch disk cache statistics via varnishstat -j."""
        import json as _json

        container = self._get_varnish_container()
        if container is None:
            return {}
        try:
            ec, output = container.exec_run("varnishstat -j")
            if ec != 0:
                logger.warning("varnishstat failed: %s", (output or b"").decode("utf-8", errors="replace"))
                return {}
            data = _json.loads((output or b"").decode("utf-8", errors="replace"))
            counters = data.get("counters", {})
            result: dict = {}
            for key in (
                "MAIN.cache_hit", "MAIN.cache_miss", "MAIN.cache_hit_grace",
                "MAIN.cache_hitpass", "MAIN.cache_hitmiss",
                "MAIN.n_object", "MAIN.n_lru_nuked", "MAIN.n_expired",
                "MAIN.threads", "MAIN.sess_conn", "MAIN.client_req",
                "MAIN.backend_req", "MAIN.fetch_head", "MAIN.fetch_length",
                "MAIN.fetch_chunked", "MAIN.bans", "MAIN.bans_completed",
                "MAIN.s_resp_bodybytes", "MAIN.b_resp_bodybytes",
            ):
                if key in counters:
                    val = counters[key].get("value", 0)
                    result[key] = val
            for key in list(counters.keys()):
                if key.startswith("MAIN.s0.") or key.startswith("SMF."):
                    result[key] = counters[key].get("value", 0)
            return result
        except Exception as e:
            logger.warning("varnishstat failed: %s", e)
            return {}

    # ------------------------------------------------------------------
    # Health / introspection
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the Docker daemon is reachable and the HAProxy container exists."""
        if docker is None:
            return False
        try:
            client = docker.from_env()
            container_name = getattr(settings, "HAPROXY_CONTAINER_NAME", "haproxy")
            client.containers.get(container_name)
            return True
        except Exception:
            return False

    def describe(self) -> dict:
        """Return a dict describing the Docker runtime for health endpoints."""
        if docker is None:
            return {"available": False, "error": "Docker SDK not installed", "type": "docker"}
        try:
            client = docker.from_env()
            container_name = getattr(settings, "HAPROXY_CONTAINER_NAME", "haproxy")
            client.containers.get(container_name)
            return {"available": True, "error": None, "type": "docker"}
        except Exception as exc:
            return {"available": False, "error": str(exc), "type": "docker"}
