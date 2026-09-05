"""Tests for the beacon_trust_persist service (table export parsing, Valkey
round-trip, re-seed command generation).
"""
from unittest.mock import patch, MagicMock

from app.services import beacon_trust_persist


class TestParseShowTable:
    def test_parse_single_entry(self):
        output = (
            "# table: beacon_trust_table, type: ip, size:102400, used:1\n"
            "0x7f1234: key=192.168.1.5 use=0 exp=45000 shard=0 gpt0=0\n"
        )
        ips = beacon_trust_persist._parse_show_table(output)
        assert ips == ["192.168.1.5"]

    def test_parse_multiple_entries(self):
        output = (
            "# table: beacon_trust_table, type: ip, size:102400, used:2\n"
            "0x7f1234: key=192.168.1.5 use=0 exp=45000 shard=0 gpt0=0\n"
            "0x7f5678: key=10.0.0.1 use=0 exp=30000 shard=0 gpt0=0\n"
        )
        ips = beacon_trust_persist._parse_show_table(output)
        assert set(ips) == {"192.168.1.5", "10.0.0.1"}

    def test_parse_any_key_present(self):
        """Any key in the table is trusted — we don't check gpt0 anymore."""
        output = (
            "# table: beacon_trust_table, type: ip, size:102400, used:1\n"
            "0x7f1234: key=192.168.1.5 use=0 exp=45000 shard=0 gpt0=0\n"
        )
        ips = beacon_trust_persist._parse_show_table(output)
        assert ips == ["192.168.1.5"]

    def test_parse_empty_output(self):
        ips = beacon_trust_persist._parse_show_table("")
        assert ips == []

    def test_parse_error_output(self):
        ips = beacon_trust_persist._parse_show_table("error: table not found")
        assert ips == []

    def test_parse_ipv6(self):
        output = (
            "# table: beacon_trust_table, type: ip, size:102400, used:1\n"
            "0x7f1234: key=::ffff:192.168.1.5 use=0 exp=45000 shard=0 gpt0=0\n"
        )
        ips = beacon_trust_persist._parse_show_table(output)
        assert ips == ["::ffff:192.168.1.5"]


class TestExportTrustTable:
    @patch("app.services.stats._send_command")
    @patch("app.services.beacon_trust_persist.valkey_client")
    def test_export_stores_ips(self, mock_valkey, mock_send):
        mock_send.return_value = (
            "# table: beacon_trust_table, type: ip, size:102400, used:2\n"
            "0x7f1: key=1.2.3.4 use=0 exp=45000 shard=0 gpt0=0\n"
            "0x7f2: key=5.6.7.8 use=0 exp=30000 shard=0 gpt0=0\n"
        )
        mock_valkey.cache_set = MagicMock(return_value=True)
        ips = beacon_trust_persist.export_trust_table()
        assert set(ips) == {"1.2.3.4", "5.6.7.8"}
        mock_valkey.cache_set.assert_called_once()
        args = mock_valkey.cache_set.call_args
        assert args[0][0] == "beacon_trust:ips"

    @patch("app.services.stats._send_command")
    @patch("app.services.beacon_trust_persist.valkey_client")
    def test_export_empty_table(self, mock_valkey, mock_send):
        mock_send.return_value = "# table: beacon_trust_table, type: ip, size:102400, used:0\n"
        mock_valkey.cache_set = MagicMock(return_value=True)
        ips = beacon_trust_persist.export_trust_table()
        assert ips == []
        mock_valkey.cache_set.assert_not_called()

    @patch("app.services.stats._send_command")
    @patch("app.services.beacon_trust_persist.valkey_client")
    def test_export_socket_error(self, mock_valkey, mock_send):
        mock_send.return_value = "error: socket not found"
        mock_valkey.cache_set = MagicMock(return_value=True)
        ips = beacon_trust_persist.export_trust_table()
        assert ips == []
        mock_valkey.cache_set.assert_not_called()


class TestSeedBeaconTrustTable:
    @patch("app.services.stats._send_command_batch")
    @patch("app.services.beacon_trust_persist.valkey_client")
    def test_seed_sends_commands(self, mock_valkey, mock_batch):
        mock_valkey.cache_get = MagicMock(return_value=["1.2.3.4", "5.6.7.8"])
        mock_batch.return_value = ""
        count = beacon_trust_persist.seed_beacon_trust_table()
        assert count == 2
        mock_batch.assert_called_once()
        commands = mock_batch.call_args[0][0]
        assert len(commands) == 2
        assert "set table beacon_trust_table key 1.2.3.4 data.http_req_cnt 1" in commands
        assert "set table beacon_trust_table key 5.6.7.8 data.http_req_cnt 1" in commands

    @patch("app.services.beacon_trust_persist.valkey_client")
    def test_seed_no_ips_in_valkey(self, mock_valkey):
        mock_valkey.cache_get = MagicMock(return_value=None)
        count = beacon_trust_persist.seed_beacon_trust_table()
        assert count == 0

    @patch("app.services.stats._send_command_batch")
    @patch("app.services.beacon_trust_persist.valkey_client")
    def test_seed_socket_error(self, mock_valkey, mock_batch):
        mock_valkey.cache_get = MagicMock(return_value=["1.2.3.4"])
        mock_batch.return_value = "error: socket not found"
        count = beacon_trust_persist.seed_beacon_trust_table()
        assert count == 0
