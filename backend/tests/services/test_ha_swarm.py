"""Tests for Swarm-aware HA behavior.

Covers:
- generate_keepalived_config() returns empty when SWARM_MODE=true
- get_ha_health() skips keepalived state in Swarm mode
- get_ha_health() includes swarm_mode in response
- get_ha_config() includes swarm_mode in response
- is_ha_enabled() still works in Swarm mode
- generate_peers_section() works in Swarm mode
"""
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from app.services import ha as ha_service
from app.services.ha import HaproxyInstance


class TestSwarmKeepalived:
    def test_keepalived_empty_when_swarm_mode(self):
        """keepalived config should be empty in Swarm mode even when HA is on."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                assert ha_service.generate_keepalived_config(None) == ""

    def test_keepalived_generated_when_not_swarm(self):
        """keepalived config should be generated when HA is on and not in Swarm mode."""
        settings_map = {
            'keepalived_vip': '10.0.0.100',
            'keepalived_virtual_router_id': '51',
            'keepalived_priority': '100',
            'keepalived_interface': 'eth0',
            'keepalived_auth_password': 'secret',
            'keepalived_peer_addresses': '10.0.0.2',
            'keepalived_advert_int': '1',
            'keepalived_preempt': 'true',
            'keepalived_track_script': '',
        }
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', False):
                with patch.object(ha_service, '_get_keepalived_setting', side_effect=lambda db, k, d: settings_map.get(k, d)):
                    config = ha_service.generate_keepalived_config(None)
                    assert config != ""
                    assert "vrrp_instance" in config

    def test_keepalived_empty_when_ha_disabled_in_swarm(self):
        """keepalived config should be empty when HA is off, regardless of Swarm mode."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=False):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                assert ha_service.generate_keepalived_config(None) == ""


class TestSwarmHealth:
    def test_health_includes_swarm_mode(self):
        """get_ha_health() should include swarm_mode in the response."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[]):
                    health = ha_service.get_ha_health(None)
                    assert health["swarm_mode"] is True

    def test_health_swarm_mode_false_when_not_swarm(self):
        """get_ha_health() should report swarm_mode=False when not in Swarm."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', False):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[]):
                    health = ha_service.get_ha_health(None)
                    assert health["swarm_mode"] is False

    def test_health_skips_keepalived_in_swarm(self):
        """get_ha_health() should not read keepalived state in Swarm mode."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                    HaproxyInstance("corex", "https://corex:5555/v3"),
                ]):
                    with patch.object(ha_service.dataplane, 'get_info', return_value={"status": "ok", "data": {"version": "3.4"}}):
                        with patch.object(ha_service, '_read_keepalived_state', return_value="MASTER") as mock_read:
                            health = ha_service.get_ha_health(None)
                            # keepalived_state should be None (not read in Swarm mode)
                            assert health["haproxy_instances"][0]["keepalived_state"] is None
                            # _read_keepalived_state should NOT have been called
                            mock_read.assert_not_called()

    def test_health_reads_keepalived_when_not_swarm(self):
        """get_ha_health() should read keepalived state when not in Swarm mode."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', False):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                    HaproxyInstance("corex", "https://corex:5555/v3"),
                ]):
                    with patch.object(ha_service.dataplane, 'get_info', return_value={"status": "ok", "data": {"version": "3.4"}}):
                        with patch.object(ha_service, '_read_keepalived_state', return_value="MASTER") as mock_read:
                            health = ha_service.get_ha_health(None)
                            assert health["haproxy_instances"][0]["keepalived_state"] == "MASTER"
                            mock_read.assert_called_once()


class TestSwarmConfig:
    # Default settings map for get_ha_config mocking
    _CONFIG_DEFAULTS = {
        'keepalived_vip': '',
        'keepalived_virtual_router_id': '51',
        'keepalived_priority': '100',
        'keepalived_interface': 'eth0',
        'keepalived_auth_password': '',
        'keepalived_peer_addresses': '',
        'keepalived_advert_int': '1',
        'keepalived_preempt': 'true',
        'keepalived_track_script': '',
        'ha_topology': 'single',
        'haproxy_ha_replicas': '1',
        'valkey_ha_replicas': '1',
        'coraza_ha_replicas': '1',
        'valkey_sentinel_enabled': 'false',
        'valkey_sentinel_hosts': '',
        'valkey_sentinel_service': 'mymaster',
    }

    def test_config_includes_swarm_mode(self):
        """get_ha_config() should include swarm_mode in the response."""
        mock_db = MagicMock()
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[]):
                    with patch.object(ha_service, '_get_keepalived_setting', side_effect=lambda db, k, d: self._CONFIG_DEFAULTS.get(k, d)):
                        config = ha_service.get_ha_config(mock_db)
                        assert config["swarm_mode"] is True

    def test_config_swarm_mode_false_when_not_swarm(self):
        """get_ha_config() should report swarm_mode=False when not in Swarm."""
        mock_db = MagicMock()
        with patch.object(ha_service, 'is_ha_enabled', return_value=False):
            with patch.object(ha_service.settings, 'SWARM_MODE', False):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[]):
                    with patch.object(ha_service, '_get_keepalived_setting', side_effect=lambda db, k, d: self._CONFIG_DEFAULTS.get(k, d)):
                        config = ha_service.get_ha_config(mock_db)
                        assert config["swarm_mode"] is False


class TestSwarmPeers:
    def test_peers_section_works_in_swarm_mode(self):
        """generate_peers_section() should still work in Swarm mode (stick-table sync)."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                    HaproxyInstance("corex", "https://corex:5555/v3"),
                    HaproxyInstance("corex2", "https://corex:5555/v3"),
                ]):
                    with patch.object(ha_service.settings, 'HAPROXY_PEER_PORT', 10000):
                        result = ha_service.generate_peers_section(None)
                        assert "peers corex-peers" in result
                        # In Swarm, both instances use the same service DNS name
                        assert "corex" in result

    def test_maybe_peers_works_in_swarm_mode(self):
        """maybe_peers() should return the peers directive in Swarm mode."""
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                    HaproxyInstance("corex", "https://corex:5555/v3"),
                    HaproxyInstance("corex2", "https://corex:5555/v3"),
                ]):
                    result = ha_service.maybe_peers(None)
                    assert result == " peers corex-peers"


class TestSwarmIsHaEnabled:
    def test_is_ha_enabled_works_in_swarm(self):
        """is_ha_enabled() should work regardless of Swarm mode."""
        with patch.object(ha_service.settings, 'HA_ENABLED', True):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                assert ha_service.is_ha_enabled(None) is True

    def test_is_ha_disabled_works_in_swarm(self):
        """is_ha_enabled() should return False when HA is off in Swarm mode."""
        with patch.object(ha_service.settings, 'HA_ENABLED', False):
            with patch.object(ha_service.settings, 'SWARM_MODE', True):
                assert ha_service.is_ha_enabled(None) is False
