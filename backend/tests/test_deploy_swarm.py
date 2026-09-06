"""Tests for the Docker Swarm deploy target in deploy.py.

Covers:
- _deploy_swarm function exists
- argparse accepts --target swarm
- Swarm constants are correct
- _stack_cmd builds the right command
- _detect_swarm_active exists
- SWARM_IMAGE_NAMES mapping is correct
"""
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import deploy


class TestSwarmDeployFunction:
    def test_deploy_swarm_exists(self):
        assert hasattr(deploy, "_deploy_swarm")
        assert callable(deploy._deploy_swarm)

    def test_deploy_swarm_signature(self):
        sig = inspect.signature(deploy._deploy_swarm)
        params = list(sig.parameters.keys())
        assert params == ["args"]
        assert sig.return_annotation == int

    def test_detect_swarm_active_exists(self):
        assert hasattr(deploy, "_detect_swarm_active")
        assert callable(deploy._detect_swarm_active)

    def test_stack_cmd_exists(self):
        assert hasattr(deploy, "_stack_cmd")
        assert callable(deploy._stack_cmd)


class TestSwarmConstants:
    def test_swarm_stack_file(self):
        assert deploy.SWARM_STACK_FILE == "docker-swarm.yml"

    def test_swarm_image_names(self):
        assert "api" in deploy.SWARM_IMAGE_NAMES
        assert "corex" in deploy.SWARM_IMAGE_NAMES
        assert "frontend" in deploy.SWARM_IMAGE_NAMES
        assert deploy.SWARM_IMAGE_NAMES["api"] == "corex-api"
        assert deploy.SWARM_IMAGE_NAMES["corex"] == "corex-haproxy"
        assert deploy.SWARM_IMAGE_NAMES["frontend"] == "corex-frontend"

    def test_swarm_full_redeploy_paths(self):
        assert "docker-swarm.yml" in deploy.SWARM_FULL_REDEPLOY_PATHS
        assert ".env.example" in deploy.SWARM_FULL_REDEPLOY_PATHS

    def test_swarm_optional_image_names(self):
        assert "mcp-gateway" in deploy.SWARM_OPTIONAL_IMAGE_NAMES
        assert "mcp-server" in deploy.SWARM_OPTIONAL_IMAGE_NAMES


class TestStackCmd:
    def test_stack_cmd_basic(self):
        cmd = deploy._stack_cmd("corex")
        assert "docker stack deploy" in cmd
        assert "docker-swarm.yml" in cmd
        assert "corex" in cmd

    def test_stack_cmd_with_args(self):
        cmd = deploy._stack_cmd("corex", "--with-registry-auth")
        assert "--with-registry-auth" in cmd

    def test_stack_cmd_different_name(self):
        cmd = deploy._stack_cmd("mystack")
        assert "mystack" in cmd


class TestSwarmArgparse:
    def test_swarm_in_target_choices(self):
        """The argparse --target should accept 'swarm'."""
        import argparse
        src = inspect.getsource(deploy.main)
        assert '"swarm"' in src or "'swarm'" in src

    def test_stack_name_arg_exists(self):
        """--stack-name should be an argparse argument."""
        src = inspect.getsource(deploy.main)
        assert "--stack-name" in src

    def test_registry_arg_exists(self):
        """--registry should be an argparse argument."""
        src = inspect.getsource(deploy.main)
        assert "--registry" in src

    def test_swarm_dispatch(self):
        """main() should dispatch to _deploy_swarm for --target swarm."""
        src = inspect.getsource(deploy.main)
        assert "_deploy_swarm" in src
        assert 'args.target == "swarm"' in src


class TestSwarmDeployFlow:
    def test_swarm_flow_does_not_use_compose(self):
        """The swarm deploy flow should NOT use docker compose."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "docker compose" not in src
        assert "_compose_cmd" not in src

    def test_swarm_flow_uses_stack_deploy(self):
        """The swarm deploy flow should use docker stack deploy."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "docker stack deploy" in src or "_stack_cmd" in src

    def test_swarm_flow_checks_swarm_active(self):
        """The swarm deploy flow should check that Swarm is active."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "_detect_swarm_active" in src

    def test_swarm_flow_does_not_reference_helm(self):
        """The swarm deploy flow should NOT reference helm or k8s."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "helm" not in src.lower()
        assert "kubectl" not in src.lower()

    def test_swarm_flow_builds_images(self):
        """The swarm deploy flow should build images on remote."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "docker build" in src

    def test_swarm_flow_uploads_manifest(self):
        """The swarm deploy flow should upload a deploy manifest."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "_upload_manifest" in src
        assert '"target": "swarm"' in src or "'target': 'swarm'" in src or '"target": "swarm"' in src

    def test_swarm_flow_sets_swarm_env(self):
        """The swarm deploy flow should set SWARM_MODE=true in the stack env."""
        src = inspect.getsource(deploy._deploy_swarm)
        assert "SWARM_MODE=true" in src
