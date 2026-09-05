"""Tests for the stick_tables service (parsers, pagination, cache, clear)."""
from unittest.mock import patch, MagicMock

from app.services import stick_tables


# ---------------------------------------------------------------------------
# parse_show_tables
# ---------------------------------------------------------------------------

class TestParseShowTables:
    def test_parse_single_table(self):
        raw = "# table: beacon_trust_table, type: ip, size:1048576, used:12\n"
        result = stick_tables.parse_show_tables(raw)
        assert result == [
            {"name": "beacon_trust_table", "type": "ip", "size": 1048576, "used": 12}
        ]

    def test_parse_multiple_tables_sorted_by_name(self):
        raw = (
            "# table: zeta_table, type: string, size:10240, used:3\n"
            "# table: alpha_table, type: ip, size:1048576, used:100\n"
        )
        result = stick_tables.parse_show_tables(raw)
        assert [t["name"] for t in result] == ["alpha_table", "zeta_table"]
        assert result[0]["type"] == "ip"
        assert result[1]["type"] == "string"

    def test_parse_empty(self):
        assert stick_tables.parse_show_tables("") == []

    def test_parse_error_output(self):
        assert stick_tables.parse_show_tables("error: no tables") == []

    def test_ignores_non_header_lines(self):
        raw = (
            "some random line\n"
            "# table: t1, type: ip, size:100, used:1\n"
            "another line\n"
        )
        result = stick_tables.parse_show_tables(raw)
        assert len(result) == 1
        assert result[0]["name"] == "t1"

    def test_parse_real_haproxy_output(self):
        """Regression test: real HAProxy output has a comma between size and used
        (``size:10240, used:0``), not just whitespace (``size:10240 used:0``).
        The regex must handle both formats.
        """
        raw = (
            "# table: mcp_gateway, type: string, size:10240, used:0\n"
            "# table: beacon_trust_table, type: ip, size:102400, used:1\n"
            "# table: cxid_table, type: string, size:102400, used:18\n"
            "# table: resp_code_table_default_shared, type: ip, size:1048576, used:0\n"
            "# table: resp_code_table_force_tls, type: ip, size:1048576, used:0\n"
            "# table: block_table_default_shared, type: ip, size:1048576, used:3\n"
            "# table: block_table_force_tls, type: ip, size:1048576, used:1\n"
            "# table: default_shared, type: ip, size:1048576, used:2\n"
            "# table: force_tls, type: ip, size:1048576, used:0\n"
        )
        result = stick_tables.parse_show_tables(raw)
        assert len(result) == 9
        assert result[0]["name"] == "beacon_trust_table"
        assert result[0]["type"] == "ip"
        assert result[0]["size"] == 102400
        assert result[0]["used"] == 1
        assert result[1]["name"] == "block_table_default_shared"
        assert result[1]["used"] == 3


# ---------------------------------------------------------------------------
# parse_show_table (entries)
# ---------------------------------------------------------------------------

class TestParseShowTable:
    def test_parse_single_entry(self):
        raw = (
            "# table: t1, type: ip, size:100, used:1\n"
            "0x7f1234: key=192.168.1.5 use=0 exp=45000 shard=0 gpt0=0\n"
        )
        entries = stick_tables.parse_show_table(raw)
        assert len(entries) == 1
        e = entries[0]
        assert e["key"] == "192.168.1.5"
        assert e["use"] == 0
        assert e["exp"] == 45000
        assert e["stores"]["shard"] == "0"
        assert e["stores"]["gpt0"] == "0"

    def test_parse_multiple_entries(self):
        raw = (
            "# table: t1, type: ip, size:100, used:2\n"
            "0x7f1: key=1.2.3.4 use=0 exp=45000 gpc0=5\n"
            "0x7f2: key=5.6.7.8 use=1 exp=30000 gpc0=10\n"
        )
        entries = stick_tables.parse_show_table(raw)
        assert len(entries) == 2
        assert entries[0]["key"] == "1.2.3.4"
        assert entries[1]["stores"]["gpc0"] == "10"

    def test_parse_rate_store_with_window(self):
        """Store names like `gpc0_rate(60s)` should be preserved verbatim."""
        raw = (
            "# table: t1, type: ip, size:100, used:1\n"
            "0x7f1: key=1.2.3.4 use=0 exp=45000 gpc0_rate(60s)=42\n"
        )
        entries = stick_tables.parse_show_table(raw)
        assert entries[0]["stores"]["gpc0_rate(60s)"] == "42"

    def test_parse_ipv6_key(self):
        raw = (
            "# table: t1, type: ip, size:100, used:1\n"
            "0x7f1: key=::ffff:192.168.1.5 use=0 exp=45000 gpt0=1\n"
        )
        entries = stick_tables.parse_show_table(raw)
        assert entries[0]["key"] == "::ffff:192.168.1.5"

    def test_parse_real_haproxy_output(self):
        """Regression test using real HAProxy output from cxid_table.

        Entry lines have the format:
            0x<hex>: key=<uuid> use=<n> exp=<n> shard=<n> http_req_cnt=<n>
        """
        raw = (
            "# table: cxid_table, type: string, size:102400, used:18\n"
            "0x741694b6e308: key=90ee401a-20b0-470f-a447-c995ec1cf87b use=0 exp=438947 shard=0 http_req_cnt=1\n"
            "0x741694dc9708: key=da64b7b9-50ab-4f49-9ad7-72f960887023 use=0 exp=438856 shard=0 http_req_cnt=1\n"
            "0x7416b71a6708: key=590c362b-bd64-4ac7-bb59-6e1f08105320 use=0 exp=210139 shard=0 http_req_cnt=1\n"
        )
        entries = stick_tables.parse_show_table(raw)
        assert len(entries) == 3
        assert entries[0]["key"] == "90ee401a-20b0-470f-a447-c995ec1cf87b"
        assert entries[0]["use"] == 0
        assert entries[0]["exp"] == 438947
        assert entries[0]["stores"]["shard"] == "0"
        assert entries[0]["stores"]["http_req_cnt"] == "1"
        assert entries[1]["key"] == "da64b7b9-50ab-4f49-9ad7-72f960887023"
        assert entries[2]["stores"]["http_req_cnt"] == "1"

    def test_parse_empty_table(self):
        raw = "# table: t1, type: ip, size:100, used:0\n"
        assert stick_tables.parse_show_table(raw) == []

    def test_parse_error_output(self):
        assert stick_tables.parse_show_table("error: table not found") == []

    def test_parse_skips_non_entry_lines(self):
        raw = (
            "# table: t1, type: ip, size:100, used:1\n"
            "table: t1\n"
            "0x7f1: key=1.2.3.4 use=0 exp=45000 gpc0=1\n"
        )
        entries = stick_tables.parse_show_table(raw)
        assert len(entries) == 1
        assert entries[0]["key"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# get_table (pagination + search + cache)
# ---------------------------------------------------------------------------

class TestGetTable:
    @patch("app.services.stick_tables._send_table_command")
    @patch("app.services.stick_tables._get_cached", return_value=None)
    @patch("app.services.stick_tables._set_cached")
    def test_pagination(self, mock_set, mock_get, mock_send):
        # 5 entries
        lines = ["# table: t1, type: ip, size:100, used:5\n"]
        for i in range(5):
            lines.append(f"0x{i}: key=10.0.0.{i} use=0 exp=45000 gpc0={i}\n")
        mock_send.return_value = "".join(lines)

        result = stick_tables.get_table("t1", limit=2, offset=0)
        assert result["total"] == 5
        assert result["offset"] == 0
        assert result["limit"] == 2
        assert len(result["entries"]) == 2
        assert result["entries"][0]["key"] == "10.0.0.0"
        assert result["entries"][1]["key"] == "10.0.0.1"

        # Second page
        result2 = stick_tables.get_table("t1", limit=2, offset=2)
        assert result2["entries"][0]["key"] == "10.0.0.2"
        assert result2["entries"][1]["key"] == "10.0.0.3"

    @patch("app.services.stick_tables._send_table_command")
    @patch("app.services.stick_tables._get_cached", return_value=None)
    @patch("app.services.stick_tables._set_cached")
    def test_search_filters_by_key_substring(self, mock_set, mock_get, mock_send):
        lines = ["# table: t1, type: ip, size:100, used:3\n"]
        lines.append("0x1: key=10.0.0.1 use=0 exp=45000 gpc0=1\n")
        lines.append("0x2: key=10.0.0.2 use=0 exp=45000 gpc0=2\n")
        lines.append("0x3: key=192.168.1.1 use=0 exp=45000 gpc0=3\n")
        mock_send.return_value = "".join(lines)

        result = stick_tables.get_table("t1", limit=10, offset=0, search="10.0.0")
        assert result["total"] == 2
        keys = [e["key"] for e in result["entries"]]
        assert "10.0.0.1" in keys
        assert "10.0.0.2" in keys
        assert "192.168.1.1" not in keys

    @patch("app.services.stick_tables._send_table_command")
    @patch("app.services.stick_tables._get_cached", return_value=None)
    @patch("app.services.stick_tables._set_cached")
    def test_search_is_case_insensitive(self, mock_set, mock_get, mock_send):
        lines = ["# table: t1, type: string, size:100, used:2\n"]
        lines.append("0x1: key=AbCdef use=0 exp=45000 gpc0=1\n")
        lines.append("0x2: key=xyz use=0 exp=45000 gpc0=2\n")
        mock_send.return_value = "".join(lines)

        result = stick_tables.get_table("t1", limit=10, offset=0, search="ABC")
        assert result["total"] == 1
        assert result["entries"][0]["key"] == "AbCdef"

    @patch("app.services.stick_tables._send_table_command")
    @patch("app.services.stick_tables._get_cached", return_value=None)
    @patch("app.services.stick_tables._set_cached")
    def test_limit_capped_to_max(self, mock_set, mock_get, mock_send):
        lines = ["# table: t1, type: ip, size:100, used:1\n"]
        lines.append("0x1: key=10.0.0.1 use=0 exp=45000 gpc0=1\n")
        mock_send.return_value = "".join(lines)

        # Request limit=99999 — should be capped to STICK_TABLE_MAX_PAGE_SIZE
        result = stick_tables.get_table("t1", limit=99999, offset=0)
        assert result["limit"] <= 500

    @patch("app.services.stick_tables._send_table_command")
    @patch("app.services.stick_tables._get_cached", return_value=None)
    @patch("app.services.stick_tables._set_cached")
    def test_socket_error_returns_empty(self, mock_set, mock_get, mock_send):
        mock_send.return_value = "error: socket not found"
        result = stick_tables.get_table("t1", limit=10, offset=0)
        assert result["entries"] == []
        assert result["total"] == 0

    @patch("app.services.stick_tables._send_table_command")
    @patch("app.services.stick_tables._set_cached")
    def test_uses_cache_when_available(self, mock_set, mock_send):
        """When Valkey has a cached blob, the socket is NOT hit."""
        cached = {
            "type": "ip",
            "size": 100,
            "used": 2,
            "entries": [
                {"key": "1.1.1.1", "use": 0, "exp": 100, "stores": {"gpc0": "1"}},
                {"key": "2.2.2.2", "use": 0, "exp": 100, "stores": {"gpc0": "2"}},
            ],
        }
        with patch("app.services.stick_tables._get_cached", return_value=cached):
            result = stick_tables.get_table("t1", limit=10, offset=0)
        mock_send.assert_not_called()
        assert result["type"] == "ip"
        assert result["used"] == 2
        assert result["total"] == 2
        assert len(result["entries"]) == 2


# ---------------------------------------------------------------------------
# clear_entry / clear_table
# ---------------------------------------------------------------------------

class TestClear:
    @patch("app.services.stick_tables._send_table_command", return_value="")
    @patch("app.services.stick_tables._invalidate_cache")
    def test_clear_entry_success(self, mock_inval, mock_send):
        result = stick_tables.clear_entry("t1", "1.2.3.4")
        assert result["ok"] is True
        assert result["cleared"] == 1
        mock_send.assert_called_once_with("clear table t1 key 1.2.3.4")
        mock_inval.assert_called_once_with("t1")

    @patch("app.services.stick_tables._send_table_command", return_value="error: nope")
    @patch("app.services.stick_tables._invalidate_cache")
    def test_clear_entry_socket_error(self, mock_inval, mock_send):
        result = stick_tables.clear_entry("t1", "1.2.3.4")
        assert result["ok"] is False
        assert result["cleared"] == 0
        mock_inval.assert_not_called()

    @patch("app.services.stick_tables._send_table_command", return_value="")
    @patch("app.services.stick_tables._invalidate_cache")
    def test_clear_table_success(self, mock_inval, mock_send):
        result = stick_tables.clear_table("t1")
        assert result["ok"] is True
        mock_send.assert_called_once_with("clear table t1")
        mock_inval.assert_called_once_with("t1")

    @patch("app.services.stick_tables._send_table_command", return_value="error: nope")
    @patch("app.services.stick_tables._invalidate_cache")
    def test_clear_table_socket_error(self, mock_inval, mock_send):
        result = stick_tables.clear_table("t1")
        assert result["ok"] is False
        mock_inval.assert_not_called()


# ---------------------------------------------------------------------------
# list_tables
# ---------------------------------------------------------------------------

class TestListTables:
    @patch("app.services.stick_tables._send_table_command")
    def test_list_tables(self, mock_send):
        mock_send.return_value = (
            "# table: b_table, type: ip, size:1000, used:5\n"
            "# table: a_table, type: string, size:10000, used:50\n"
        )
        result = stick_tables.list_tables()
        assert [t["name"] for t in result] == ["a_table", "b_table"]
        assert result[0]["type"] == "string"
        assert result[1]["used"] == 5
        mock_send.assert_called_once_with("show table")

    @patch("app.services.stick_tables._send_table_command", return_value="error: nope")
    def test_list_tables_socket_error(self, mock_send):
        assert stick_tables.list_tables() == []

    @patch("app.services.stick_tables._send_table_command", return_value="")
    def test_list_tables_empty(self, mock_send):
        assert stick_tables.list_tables() == []
