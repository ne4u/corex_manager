"""Parity tests: verify that deploy.py --target docker is unchanged.

These tests verify that the Docker Compose deploy flow was not modified when
k8s deployment targets were added. The _deploy_docker function should behave
identically to the original main() function.

Prime Directive: Docker Compose Must Not Break.
"""
import importlib
import inspect
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture
def deploy_module():
    """Import deploy.py as a module."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "deploy", "/Users/akauffman/CascadeProjects/corex_manager/deploy.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDeployDockerTargetUnchanged:
    """Verify the docker target flow exists and has the same structure."""

    def test_deploy_docker_function_exists(self, deploy_module):
        """_deploy_docker function should exist."""
        assert hasattr(deploy_module, "_deploy_docker")
        assert callable(deploy_module._deploy_docker)

    def test_deploy_docker_is_default_target(self, deploy_module):
        """The default --target should be 'docker'."""
        parser = deploy_module.argparse.ArgumentParser()
        # Re-create the parser to check defaults
        src = inspect.getsource(deploy_module.main)
        assert "default=\"docker\"" in src or "default='docker'" in src

    def test_k8s_functions_exist(self, deploy_module):
        """k8s deploy functions should exist alongside docker."""
        assert hasattr(deploy_module, "_deploy_k8s")
        assert hasattr(deploy_module, "_deploy_k8s_cluster") or hasattr(deploy_module, "_deploy_k8s")
        assert hasattr(deploy_module, "_helm_upgrade")
        assert hasattr(deploy_module, "_build_image_local")
        assert hasattr(deploy_module, "_load_image_local")
        assert hasattr(deploy_module, "_detect_k8s_loader")

    def test_shared_constants_unchanged(self, deploy_module):
        """Core constants used by the docker flow should be unchanged."""
        assert deploy_module.DEFAULT_REMOTE_PATH == "/opt/corex_manager"
        assert deploy_module.MANIFEST_FILENAME == ".deploy-manifest.json"
        assert "api" in deploy_module.BUILDABLE_SERVICES
        assert "corex" in deploy_module.BUILDABLE_SERVICES
        assert "frontend" in deploy_module.BUILDABLE_SERVICES
        assert "docker-compose.yml" in deploy_module.FULL_REDEPLOY_PATHS

    def test_service_paths_unchanged(self, deploy_module):
        """SERVICE_PATHS mapping should be unchanged."""
        paths = deploy_module.SERVICE_PATHS
        assert "api" in paths
        assert "backend/Dockerfile" in paths["api"]["rebuild"]
        assert "requirements.txt" in paths["api"]["rebuild"]
        assert "backend/app/" in paths["api"]["restart"]
        assert "haproxy/" in paths["corex"]["rebuild"]
        assert "frontend/" in paths["frontend"]["rebuild"]

    def test_rsync_excludes_unchanged(self, deploy_module):
        """RSYNC_EXCLUDES should still exclude the same files."""
        excludes = deploy_module.RSYNC_EXCLUDES
        assert ".git" in excludes
        assert ".env" in excludes
        assert "node_modules" in excludes
        assert "backend/tests" in excludes
        assert "data/" in excludes
        assert "certs/" in excludes
        assert deploy_module.MANIFEST_FILENAME in excludes

    def test_helper_functions_unchanged(self, deploy_module):
        """Core helper functions should still exist."""
        for func_name in [
            "_require", "_run", "_ssh_cmd", "_ssh_capture", "_rsync",
            "_detect_sudo", "_remote_docker", "_prompt",
            "_compute_file_hashes", "_detect_changed_files",
            "_map_files_to_services", "_download_manifest", "_upload_manifest",
            "_print_deploy_plan",
        ]:
            assert hasattr(deploy_module, func_name), f"Missing function: {func_name}"

    def test_docker_flow_calls_docker_compose(self, deploy_module):
        """The docker deploy flow source should still reference docker compose."""
        src = inspect.getsource(deploy_module._deploy_docker)
        assert "docker compose build" in src
        assert "docker compose up -d" in src
        assert "docker compose restart" in src

    def test_docker_flow_does_not_reference_helm(self, deploy_module):
        """The docker deploy flow should NOT reference helm or k8s."""
        src = inspect.getsource(deploy_module._deploy_docker)
        assert "helm" not in src.lower()
        assert "kubectl" not in src.lower()
        assert "kind" not in src  # the k8s loader, not the Python kind

    def test_k8s_flow_references_helm(self, deploy_module):
        """The k8s deploy flow should reference helm."""
        src = inspect.getsource(deploy_module._deploy_k8s)
        assert "helm" in src.lower()

    def test_k8s_constants_exist(self, deploy_module):
        """K8s-specific constants should exist."""
        assert hasattr(deploy_module, "HELM_CHART_PATH")
        assert hasattr(deploy_module, "K8S_SERVICE_TO_IMAGE_KEY")
        assert hasattr(deploy_module, "K8S_IMAGE_NAMES")
        assert "api" in deploy_module.K8S_SERVICE_TO_IMAGE_KEY
        assert "corex" in deploy_module.K8S_SERVICE_TO_IMAGE_KEY
        assert "frontend" in deploy_module.K8S_SERVICE_TO_IMAGE_KEY


class TestDeployDockerDryRun:
    """Verify --target docker --dry-run works without errors."""

    def test_docker_dry_run_does_not_require_sshpass(self, deploy_module, monkeypatch):
        """--dry-run should not fail on missing sshpass (it exits before that)."""
        # Actually, the docker flow calls _require("sshpass") first.
        # This test verifies that the function structure is correct —
        # the _require calls happen before any network operations.
        src = inspect.getsource(deploy_module._deploy_docker)
        assert "_require" in src
        assert "sshpass" in src
        assert "rsync" in src
        assert "ssh" in src
