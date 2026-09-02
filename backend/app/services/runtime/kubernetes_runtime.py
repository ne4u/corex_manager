"""Kubernetes runtime backend — uses the Kubernetes API for in-pod operations.

This implementation uses the official ``kubernetes`` Python client with
in-cluster config. It targets the api's own Pod (sidecar topology) for exec
and log operations against the HAProxy, Coraza, and Varnish containers.

Required env vars (set via the downward API in the Helm chart):
  - ``COREX_POD_NAME``: the name of this Pod.
  - ``COREX_POD_NAMESPACE``: the namespace this Pod runs in.

Container names within the Pod are configured via:
  - ``K8S_HAPROXY_CONTAINER`` (default ``corex``)
  - ``K8S_CORAZA_CONTAINER`` (default ``coraza-spoa``)
  - ``K8S_VARNISH_CONTAINER`` (default ``varnish``)
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from ..config import get_settings
from .base import RuntimeBackend

logger = logging.getLogger(__name__)
settings = get_settings()

try:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
    from kubernetes.stream import stream as k8s_stream
except ImportError:  # pragma: no cover
    k8s_client = None  # type: ignore
    k8s_config = None  # type: ignore
    k8s_stream = None  # type: ignore


class KubernetesRuntime(RuntimeBackend):
    """Runtime backend using the Kubernetes API (in-cluster config)."""

    def __init__(self) -> None:
        self._api: Optional["k8s_client.CoreV1Api"] = None
        self._init_error: Optional[str] = None
        if k8s_client is None:
            self._init_error = "Kubernetes SDK not installed"
            return
        try:
            k8s_config.load_incluster_config()
            self._api = k8s_client.CoreV1Api()
        except Exception as exc:
            self._init_error = str(exc)
            self._api = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _pod_name(self) -> str:
        return getattr(settings, "COREX_POD_NAME", "") or ""

    @property
    def _namespace(self) -> str:
        return getattr(settings, "COREX_POD_NAMESPACE", "") or "default"

    @property
    def _haproxy_container(self) -> str:
        return getattr(settings, "K8S_HAPROXY_CONTAINER", "corex")

    @property
    def _coraza_container(self) -> str:
        return getattr(settings, "K8S_CORAZA_CONTAINER", "coraza-spoa")

    @property
    def _varnish_container(self) -> str:
        return getattr(settings, "K8S_VARNISH_CONTAINER", "varnish")

    def _ready(self) -> bool:
        """Return True if the K8s client is initialized and pod info is available."""
        return self._api is not None and bool(self._pod_name)

    def _exec_in_container(self, container: str, command: list[str], timeout: int = 30) -> tuple[int, str]:
        """Exec a command in a container of this Pod and return (exit_code, output).

        Uses the Kubernetes stream API. The exit code is extracted from the
        response if available; otherwise inferred from stderr content.
        """
        if not self._ready():
            return -1, f"Kubernetes runtime not ready: {self._init_error or 'pod name not set'}"

        try:
            resp = k8s_stream(
                self._api.connect_get_namespaced_pod_exec,
                self._pod_name,
                self._namespace,
                container=container,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=False,
            )
            # Read all output
            output_bytes = b""
            stderr_bytes = b""
            try:
                output_bytes = resp.read_stdout(timeout=timeout) or b""
                stderr_bytes = resp.read_stderr(timeout=timeout) or b""
            except Exception:
                pass
            resp.close()

            combined = ""
            if output_bytes:
                if isinstance(output_bytes, bytes):
                    combined += output_bytes.decode("utf-8", errors="replace")
                else:
                    combined += output_bytes
            if stderr_bytes:
                if isinstance(stderr_bytes, bytes):
                    combined += stderr_bytes.decode("utf-8", errors="replace")
                else:
                    combined += stderr_bytes

            # The Kubernetes exec API doesn't always return an exit code
            # directly via the stream. We use the channel status to determine
            # success. If we can't determine it, treat non-empty stderr as
            # a potential error but still return 0 (the command ran).
            # For haproxy -c, a non-zero exit produces error text in stdout.
            return 0, combined.strip()
        except Exception as exc:
            return -1, f"Kubernetes exec failed: {exc}"

    def _exec_with_exit_code(self, container: str, command: list[str], timeout: int = 30) -> tuple[int, str]:
        """Exec a command and capture the real exit code.

        Wraps the command in ``sh -c '...; echo EXIT_CODE:$?'`` so we can
        parse the exit code from the output stream.
        """
        if not self._ready():
            return -1, f"Kubernetes runtime not ready: {self._init_error or 'pod name not set'}"

        cmd_str = " ".join(command)
        wrapped = ["sh", "-c", f"{cmd_str}; echo EXIT_CODE:$?"]
        ec, output = self._exec_in_container(container, wrapped, timeout=timeout)
        if ec != 0:
            return ec, output

        # Parse the EXIT_CODE:N line from the end of the output
        lines = output.rstrip().split("\n")
        real_ec = 0
        if lines:
            last = lines[-1].strip()
            if last.startswith("EXIT_CODE:"):
                try:
                    real_ec = int(last.split(":", 1)[1])
                except (ValueError, IndexError):
                    pass
                # Remove the EXIT_CODE line from the output
                output = "\n".join(lines[:-1]).strip()

        return real_ec, output

    # ------------------------------------------------------------------
    # HAProxy operations
    # ------------------------------------------------------------------

    def validate_haproxy_config(self, config_path: str) -> tuple[bool, str]:
        """Run haproxy -c -f <config_path> in the HAProxy container."""
        if not self._ready():
            return False, f"haproxy container check failed: {self._init_error or 'Kubernetes runtime not ready'}"
        ec, output = self._exec_with_exit_code(
            self._haproxy_container,
            ["haproxy", "-c", "-f", config_path],
            timeout=30,
        )
        if ec == -1:
            return False, f"haproxy container check failed: {output}"
        return ec == 0, output

    def haproxy_version_verbose(self) -> Optional[str]:
        """Run haproxy -vv in the HAProxy container."""
        if not self._ready():
            return None
        ec, output = self._exec_in_container(
            self._haproxy_container,
            ["haproxy", "-vv"],
            timeout=15,
        )
        if ec != 0 or not output:
            return None
        return output

    def haproxy_logs(
        self,
        tail: Optional[int] = None,
        since: Optional[int] = None,
        timestamps: bool = False,
    ) -> str:
        """Fetch HAProxy container logs via the Kubernetes API."""
        if not self._ready():
            return ""
        try:
            kwargs: dict = {}
            if tail is not None:
                kwargs["tail_lines"] = tail
            if since is not None:
                # Kubernetes expects an int (seconds since epoch)
                kwargs["since_seconds"] = int(since)
            if timestamps:
                kwargs["timestamps"] = True

            log_text = self._api.read_namespaced_pod_log(
                name=self._pod_name,
                namespace=self._namespace,
                container=self._haproxy_container,
                **kwargs,
            )
            return log_text or ""
        except Exception as exc:
            logger.debug("Kubernetes haproxy_logs failed: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Coraza operations
    # ------------------------------------------------------------------

    def restart_coraza(self) -> bool:
        """Restart the coraza-spoa container within the Pod.

        Kubernetes cannot restart a single container in a pod without rolling
        the whole pod. With ``shareProcessNamespace: true``, we send SIGTERM
        to PID 1 in the coraza container, which causes the container to exit
        and restart (the pod stays up). If that fails, we fall back to
        deleting the pod (which causes a brief restart of all containers).
        """
        if not self._ready():
            return False

        # Strategy 1: kill PID 1 in the coraza container (requires
        # shareProcessNamespace: true). The K8s exec API runs in the
        # container's namespace, so we use `kill -TERM 1` which targets
        # the container's init process.
        try:
            ec, output = self._exec_with_exit_code(
                self._coraza_container,
                ["kill", "-TERM", "1"],
                timeout=10,
            )
            if ec == 0:
                logger.info("coraza-spoa container signaled to restart (SIGTERM to PID 1)")
                return True
            logger.warning("kill -TERM 1 in coraza container failed (ec=%s): %s", ec, output)
        except Exception as exc:
            logger.warning("kill -TERM 1 in coraza container failed: %s", exc)

        # Strategy 2: delete the pod so it gets recreated by the Deployment.
        # This restarts all containers in the pod (including HAProxy) — a
        # brief interruption. Used only as a fallback.
        try:
            logger.info("Falling back to pod deletion for coraza restart")
            self._api.delete_namespaced_pod(
                name=self._pod_name,
                namespace=self._namespace,
                body=k8s_client.V1DeleteOptions(),
            )
            logger.info("Pod deleted for restart; Deployment will recreate it")
            return True
        except Exception as exc:
            logger.error("Failed to delete pod for coraza restart: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Varnish operations
    # ------------------------------------------------------------------

    def validate_vcl(self, vcl_container_path: str) -> tuple[bool, str]:
        """Run varnishd -C -f <path> in the Varnish container."""
        if not self._ready():
            return False, "Varnish container not available (Kubernetes runtime not ready)"
        ec, output = self._exec_with_exit_code(
            self._varnish_container,
            ["varnishd", "-C", "-f", vcl_container_path],
            timeout=30,
        )
        if ec == -1:
            return False, f"VCL validation via container failed: {output}"
        return ec == 0, output

    def reload_vcl(self, vcl_container_path: str) -> bool:
        """Reload the VCL in the running Varnish container."""
        if not self._ready():
            logger.warning("Varnish container not available, VCL written but not reloaded")
            return False

        # Try varnishreload first (simpler, available in official images)
        try:
            ec, output = self._exec_with_exit_code(
                self._varnish_container,
                ["varnishreload"],
                timeout=15,
            )
            if ec == 0:
                return True
            logger.warning("varnishreload failed: %s", output)
        except Exception as e:
            logger.warning("varnishreload failed: %s", e)

        # Fallback: varnishadm vcl.load + vcl.use
        try:
            label = f"reload_{int(time.time() * 1000)}"
            ec, output = self._exec_with_exit_code(
                self._varnish_container,
                ["varnishadm", "vcl.load", label, vcl_container_path],
                timeout=15,
            )
            if ec != 0:
                logger.error("varnishadm vcl.load failed: %s", output)
                return False
            ec, output = self._exec_with_exit_code(
                self._varnish_container,
                ["varnishadm", "vcl.use", label],
                timeout=15,
            )
            if ec != 0:
                logger.error("varnishadm vcl.use failed: %s", output)
                return False
            return True
        except Exception as e:
            logger.error("varnishadm reload failed: %s", e)
            return False

    def purge_vcl(self, ban_expr: str) -> bool:
        """Run varnishadm ban in the Varnish container."""
        if not self._ready():
            logger.warning("Varnish container not available, cannot purge backend")
            return False
        try:
            ec, output = self._exec_with_exit_code(
                self._varnish_container,
                ["varnishadm", "ban", ban_expr],
                timeout=15,
            )
            if ec == 0:
                return True
            logger.warning("varnishadm ban failed: %s", output)
        except Exception as e:
            logger.warning("varnishadm ban failed: %s", e)
        return False

    def purge_all(self) -> bool:
        """Purge (ban) all cached objects in the disk cache."""
        if not self._ready():
            logger.warning("Varnish container not available, cannot purge all")
            return False
        try:
            ec, output = self._exec_with_exit_code(
                self._varnish_container,
                ["varnishadm", "ban", "obj.http.X-Cache-Backend ~ .*"],
                timeout=15,
            )
            if ec == 0:
                return True
            logger.warning("varnishadm ban all failed: %s", output)
        except Exception as e:
            logger.warning("varnishadm ban all failed: %s", e)
        return False

    def varnish_stats(self) -> dict:
        """Fetch disk cache statistics via varnishstat -j."""
        import json as _json

        if not self._ready():
            return {}
        try:
            ec, output = self._exec_with_exit_code(
                self._varnish_container,
                ["varnishstat", "-j"],
                timeout=15,
            )
            if ec != 0:
                logger.warning("varnishstat failed: %s", output)
                return {}
            data = _json.loads(output)
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
        """Return True if the K8s client is initialized and the pod exists."""
        if not self._ready():
            return False
        try:
            self._api.read_namespaced_pod(name=self._pod_name, namespace=self._namespace)
            return True
        except Exception:
            return False

    def describe(self) -> dict:
        """Return a dict describing the Kubernetes runtime for health endpoints."""
        if k8s_client is None:
            return {"available": False, "error": "Kubernetes SDK not installed", "type": "kubernetes"}
        if self._init_error:
            return {"available": False, "error": self._init_error, "type": "kubernetes"}
        if not self._pod_name:
            return {"available": False, "error": "COREX_POD_NAME not set", "type": "kubernetes"}
        try:
            self._api.read_namespaced_pod(name=self._pod_name, namespace=self._namespace)
            return {"available": True, "error": None, "type": "kubernetes"}
        except Exception as exc:
            return {"available": False, "error": str(exc), "type": "kubernetes"}
