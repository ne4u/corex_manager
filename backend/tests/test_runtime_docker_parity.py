"""Parity tests: verify that DockerRuntime produces the same behavior as the
original inline Docker SDK calls.

These tests ensure that the extraction of Docker SDK logic into the
DockerRuntime class did not change any behavior. They mock the Docker SDK
at the same level the original code did and verify the same return values
and call patterns.

Prime Directive: Docker Compose Must Not Break.
"""
import sys
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


@pytest.fixture
def mock_docker_sdk(monkeypatch):
    """Inject a mock docker module so DockerRuntime can use it.

    Patches the module-level `docker` variable in docker_runtime.py directly,
    since it was imported at module load time and won't pick up sys.modules
    changes.
    """
    mock_container = MagicMock()
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container
    mock_docker_mod = MagicMock()
    mock_docker_mod.from_env.return_value = mock_client

    monkeypatch.setitem(sys.modules, "docker", mock_docker_mod)

    # Patch the module-level docker variable in docker_runtime
    import app.services.runtime.docker_runtime as dr_module
    monkeypatch.setattr(dr_module, "docker", mock_docker_mod)

    # Clear the runtime cache so DockerRuntime is re-instantiated
    from app.services.runtime import get_runtime
    get_runtime.cache_clear()

    return mock_docker_mod, mock_client, mock_container


class TestDockerRuntimeHaproxyValidation:
    """Verify DockerRuntime.validate_haproxy_config matches original behavior."""

    def test_returns_true_on_exit_code_zero(self, mock_docker_sdk):
        """When exec_run returns ec=0, validation succeeds."""
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (0, b"Configuration valid")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        ok, output = rt.validate_haproxy_config("/tmp/test.cfg")

        assert ok is True
        assert output == "Configuration valid"
        mock_container.exec_run.assert_called_once_with("haproxy -c -f /tmp/test.cfg")

    def test_returns_false_on_nonzero_exit_code(self, mock_docker_sdk):
        """When exec_run returns ec=1, validation fails with the error output."""
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (1, b"Syntax error on line 5")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        ok, output = rt.validate_haproxy_config("/tmp/test.cfg")

        assert ok is False
        assert "Syntax error" in output

    def test_returns_failure_message_when_docker_not_installed(self, monkeypatch):
        """When docker SDK is not installed, returns the same failure prefix
        as the original code so the caller can fall back to local haproxy."""
        # Patch the module-level docker variable to None
        import app.services.runtime.docker_runtime as dr_module
        monkeypatch.setattr(dr_module, "docker", None)

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        ok, output = rt.validate_haproxy_config("/tmp/test.cfg")

        assert ok is False
        assert output.startswith("haproxy container check failed")


class TestDockerRuntimeHaproxyVersion:
    """Verify DockerRuntime.haproxy_version_verbose matches original behavior."""

    def test_returns_output_on_success(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (0, b"HAProxy version 2.8.0\nFeature: geoip2")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        result = rt.haproxy_version_verbose()

        assert result is not None
        assert "geoip2" in result
        mock_container.exec_run.assert_called_once_with("haproxy -vv")

    def test_returns_none_on_exception(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.side_effect = Exception("connection refused")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        result = rt.haproxy_version_verbose()

        assert result is None


class TestDockerRuntimeCorazaRestart:
    """Verify DockerRuntime.restart_coraza matches original behavior."""

    def test_finds_and_restarts_container_by_label(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk

        # Create a container with the compose service label
        labeled_container = MagicMock()
        labeled_container.name = "corex_coraza-spoa_1"
        labeled_container.labels = {"com.docker.compose.service": "coraza-spoa"}

        other_container = MagicMock()
        other_container.name = "corex_api_1"
        other_container.labels = {"com.docker.compose.service": "api"}

        mock_client.containers.list.return_value = [other_container, labeled_container]

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        result = rt.restart_coraza()

        assert result is True
        labeled_container.restart.assert_called_once_with(timeout=10)

    def test_finds_container_by_name_fallback(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk

        named_container = MagicMock()
        named_container.name = "my-coraza-spoa-instance"
        named_container.labels = {}

        mock_client.containers.list.return_value = [named_container]

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        result = rt.restart_coraza()

        assert result is True
        named_container.restart.assert_called_once_with(timeout=10)

    def test_returns_false_when_container_not_found(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_client.containers.list.return_value = []

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        result = rt.restart_coraza()

        assert result is False


class TestDockerRuntimeVarnish:
    """Verify DockerRuntime Varnish operations match original behavior."""

    def test_validate_vcl_success(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (0, b"")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        ok, output = rt.validate_vcl("/app/data/_validate.vcl")

        assert ok is True
        mock_container.exec_run.assert_called_once_with("varnishd -C -f /app/data/_validate.vcl")

    def test_validate_vcl_failure(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (1, b"VCL syntax error")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        ok, output = rt.validate_vcl("/app/data/_validate.vcl")

        assert ok is False
        assert "VCL syntax error" in output

    def test_purge_all_calls_varnishadm_ban(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (0, b"")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        result = rt.purge_all()

        assert result is True
        mock_container.exec_run.assert_called_once_with(
            'varnishadm ban "obj.http.X-Cache-Backend ~ .*"'
        )

    def test_purge_vcl_with_ban_expr(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_container.exec_run.return_value = (0, b"")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        ban_expr = 'obj.http.X-Cache-Backend == "my_backend"'
        result = rt.purge_vcl(ban_expr)

        assert result is True
        # The DockerRuntime wraps the ban_expr in double quotes, matching
        # the original code's f'varnishadm ban "{ban_expr}"' pattern.
        mock_container.exec_run.assert_called_once_with(
            f'varnishadm ban "{ban_expr}"'
        )


class TestDockerRuntimeHealth:
    """Verify DockerRuntime health/describe methods."""

    def test_is_available_true_when_container_exists(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        assert rt.is_available() is True

    def test_is_available_false_on_exception(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk
        mock_client.containers.get.side_effect = Exception("not found")

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        assert rt.is_available() is False

    def test_describe_returns_docker_type(self, mock_docker_sdk):
        mock_docker, mock_client, mock_container = mock_docker_sdk

        from app.services.runtime.docker_runtime import DockerRuntime
        rt = DockerRuntime()
        desc = rt.describe()

        assert desc["type"] == "docker"
        assert desc["available"] is True
        assert desc["error"] is None


class TestRuntimeAutoDetection:
    """Verify the auto-detection logic selects the right runtime."""

    def test_detects_kubernetes_when_sa_token_exists(self, monkeypatch):
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
        monkeypatch.setattr("os.path.exists", lambda p: "serviceaccount" in p)

        from app.services.runtime import _detect_runtime
        assert _detect_runtime() == "kubernetes"

    def test_detects_docker_when_sock_exists(self, monkeypatch):
        monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)

        def mock_exists(p):
            return p == "/var/run/docker.sock"

        monkeypatch.setattr("os.path.exists", mock_exists)

        from app.services.runtime import _detect_runtime
        assert _detect_runtime() == "docker"

    def test_detects_none_when_nothing_available(self, monkeypatch):
        monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
        monkeypatch.setattr("os.path.exists", lambda p: False)

        from app.services.runtime import _detect_runtime
        assert _detect_runtime() == "none"


class TestNullRuntime:
    """Verify the null runtime gracefully degrades."""

    def test_all_operations_return_unavailable(self):
        from app.services.runtime import _NullRuntime

        rt = _NullRuntime()
        assert rt.is_available() is False
        assert rt.restart_coraza() is False
        assert rt.purge_all() is False
        assert rt.varnish_stats() == {}
        assert rt.haproxy_logs() == ""
        assert rt.haproxy_version_verbose() is None

        ok, msg = rt.validate_haproxy_config("/tmp/test.cfg")
        assert ok is False
        assert "failed" in msg

        desc = rt.describe()
        assert desc["type"] == "none"
        assert desc["available"] is False
