"""Tests for the HA (High Availability) service.

Covers:
- HAPROXY_INSTANCES parsing and serialization
- Peers section generation (empty when HA off, populated when HA on)
- maybe_peers() returns empty string when HA off
- Keepalived config generation (empty when HA off)
- is_ha_enabled() respects DB setting and env fallback
- push_config_to_all_instances pushes to all configured instances
"""
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from app.services import ha as ha_service
from app.services.ha import HaproxyInstance, _parse_instances, _instances_to_str


# ---------------------------------------------------------------------------
# Instance parsing
# ---------------------------------------------------------------------------

class TestInstanceParsing:
    def test_parse_empty(self):
        assert _parse_instances("") == []

    def test_parse_single(self):
        result = _parse_instances("corex=https://haproxy:5555/v3")
        assert len(result) == 1
        assert result[0].name == "corex"
        assert result[0].url == "https://haproxy:5555/v3"

    def test_parse_multiple(self):
        result = _parse_instances("corex=https://haproxy:5555/v3;corex2=https://haproxy2:5555/v3")
        assert len(result) == 2
        assert result[0].name == "corex"
        assert result[1].name == "corex2"

    def test_parse_multiple_comma_backward_compat(self):
        result = _parse_instances("corex=https://haproxy:5555/v3,corex2=https://haproxy2:5555/v3")
        assert len(result) == 2
        assert result[0].name == "corex"
        assert result[1].name == "corex2"

    def test_parse_with_credentials(self):
        result = _parse_instances("corex=https://haproxy:5555/v3,admin,secret")
        assert len(result) == 1
        assert result[0].user == "admin"
        assert result[0].password == "secret"

    def test_parse_multiple_with_credentials(self):
        result = _parse_instances("corex=https://haproxy:5555/v3;corex2=https://haproxy2:5555/v3,admin,secret")
        assert len(result) == 2
        assert result[0].name == "corex"
        assert result[1].name == "corex2"
        assert result[1].user == "admin"
        assert result[1].password == "secret"

    def test_parse_malformed_skipped(self):
        result = _parse_instances("corex=https://haproxy:5555/v3;badentry;nourl")
        assert len(result) == 1
        assert result[0].name == "corex"

    def test_serialize_roundtrip(self):
        instances = [
            HaproxyInstance("corex", "https://haproxy:5555/v3"),
            HaproxyInstance("corex2", "https://haproxy2:5555/v3", "admin", "pass"),
        ]
        s = _instances_to_str(instances)
        parsed = _parse_instances(s)
        assert len(parsed) == 2
        assert parsed[0].name == "corex"
        assert parsed[1].name == "corex2"
        assert parsed[1].user == "admin"
        assert parsed[1].password == "pass"


# ---------------------------------------------------------------------------
# Peers section generation
# ---------------------------------------------------------------------------

class TestPeersSection:
    def test_empty_when_ha_disabled(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=False):
            assert ha_service.generate_peers_section(None) == ""

    def test_empty_when_single_instance(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                HaproxyInstance("corex", "https://haproxy:5555/v3"),
            ]):
                assert ha_service.generate_peers_section(None) == ""

    def test_populated_when_ha_enabled_multiple(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                HaproxyInstance("corex", "https://haproxy:5555/v3"),
                HaproxyInstance("corex2", "https://haproxy2:5555/v3"),
            ]):
                with patch.object(ha_service.settings, 'HAPROXY_PEER_PORT', 10000):
                    result = ha_service.generate_peers_section(None)
                    assert "peers corex-peers" in result
                    assert "peer corex haproxy:10000" in result
                    assert "peer corex2 haproxy2:10000" in result


class TestMaybePeers:
    def test_empty_when_ha_disabled(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=False):
            assert ha_service.maybe_peers(None) == ""

    def test_empty_when_single_instance(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                HaproxyInstance("corex", "https://haproxy:5555/v3"),
            ]):
                assert ha_service.maybe_peers(None) == ""

    def test_peers_directive_when_ha_enabled(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service, 'get_haproxy_instances', return_value=[
                HaproxyInstance("corex", "https://haproxy:5555/v3"),
                HaproxyInstance("corex2", "https://haproxy2:5555/v3"),
            ]):
                result = ha_service.maybe_peers(None)
                assert result == " peers corex-peers"


# ---------------------------------------------------------------------------
# Keepalived config generation
# ---------------------------------------------------------------------------

class TestKeepalivedConfig:
    def test_empty_when_ha_disabled(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=False):
            assert ha_service.generate_keepalived_config(None) == ""

    def test_empty_when_no_vip(self):
        with patch.object(ha_service, 'is_ha_enabled', return_value=True):
            with patch.object(ha_service, '_get_keepalived_setting', return_value=""):
                assert ha_service.generate_keepalived_config(None) == ""

    def test_generates_valid_config(self):
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
            with patch.object(ha_service, '_get_keepalived_setting', side_effect=lambda db, k, d: settings_map.get(k, d)):
                config = ha_service.generate_keepalived_config(None)
                assert "vrrp_instance VI_1" in config
                assert "10.0.0.100" in config
                assert "virtual_router_id 51" in config
                assert "priority 100" in config
                assert "auth_pass secret" in config
                assert "10.0.0.2" in config
                assert "preempt" in config


# ---------------------------------------------------------------------------
# is_ha_enabled
# ---------------------------------------------------------------------------

class TestIsHaEnabled:
    def test_false_when_no_db_and_env_false(self):
        with patch.object(ha_service.settings, 'HA_ENABLED', False):
            assert ha_service.is_ha_enabled(None) is False

    def test_true_when_env_true(self):
        with patch.object(ha_service.settings, 'HA_ENABLED', True):
            assert ha_service.is_ha_enabled(None) is True

    def test_true_when_db_setting_true(self):
        mock_db = MagicMock()
        with patch.object(ha_service, 'get_setting', return_value='true'):
            assert ha_service.is_ha_enabled(mock_db) is True

    def test_false_when_db_setting_false(self):
        mock_db = MagicMock()
        with patch.object(ha_service, 'get_setting', return_value='false'):
            with patch.object(ha_service.settings, 'HA_ENABLED', True):
                assert ha_service.is_ha_enabled(mock_db) is False


# ---------------------------------------------------------------------------
# Push config to all instances
# ---------------------------------------------------------------------------

class TestPushConfigToAll:
    def test_pushes_to_all_instances(self):
        instances = [
            HaproxyInstance("corex", "https://haproxy:5555/v3"),
            HaproxyInstance("corex2", "https://haproxy2:5555/v3"),
        ]
        with patch.object(ha_service, 'get_haproxy_instances', return_value=instances):
            with patch.object(ha_service.dataplane, 'push_config', side_effect=[
                {"status": "ok", "message": "pushed"},
                {"status": "ok", "message": "pushed"},
            ]) as mock_push:
                results = ha_service.push_config_to_all_instances(None, "config text")
                assert len(results) == 2
                assert results["corex"]["status"] == "ok"
                assert results["corex2"]["status"] == "ok"
                assert mock_push.call_count == 2

    def test_handles_push_failure(self):
        instances = [HaproxyInstance("corex", "https://haproxy:5555/v3")]
        with patch.object(ha_service, 'get_haproxy_instances', return_value=instances):
            with patch.object(ha_service.dataplane, 'push_config', return_value={"status": "error", "message": "connection refused"}):
                results = ha_service.push_config_to_all_instances(None, "config text")
                assert results["corex"]["status"] == "error"
                assert "connection refused" in results["corex"]["message"]

    def test_handles_exception(self):
        instances = [HaproxyInstance("corex", "https://haproxy:5555/v3")]
        with patch.object(ha_service, 'get_haproxy_instances', return_value=instances):
            with patch.object(ha_service.dataplane, 'push_config', side_effect=Exception("network error")):
                results = ha_service.push_config_to_all_instances(None, "config text")
                assert results["corex"]["status"] == "error"
                assert "network error" in results["corex"]["message"]
