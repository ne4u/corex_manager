"""Unit tests for security_lists validation, feed parsing, and list-file writing."""
import os

import pytest

from app.services import security_lists
from app.services.security_lists import (
    COUNTRY_NAMES,
    get_country_options,
    parse_feed_text,
    safe_filename,
    validate_asn_value,
    validate_country_code,
    validate_ja4_value,
    validate_network_value,
    validate_pattern_value,
    write_security_list_files,
)


# --- Network value validation ----------------------------------------------

def test_validate_network_value_single_ip():
    assert validate_network_value("10.0.0.1") == "10.0.0.1"


def test_validate_network_value_ipv6():
    assert validate_network_value("::1") == "::1"


def test_validate_network_value_cidr():
    assert validate_network_value("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_network_value_cidr_non_strict_normalizes():
    # 10.0.0.5/24 has host bits set; strict=False normalizes to the network.
    assert validate_network_value("10.0.0.5/24") == "10.0.0.0/24"


def test_validate_network_value_invalid():
    with pytest.raises(ValueError):
        validate_network_value("not-an-ip")
    with pytest.raises(ValueError):
        validate_network_value("10.0.0.0/33")
    with pytest.raises(ValueError):
        validate_network_value("")


# --- ASN value validation ---------------------------------------------------

def test_validate_asn_value_plain():
    assert validate_asn_value("12345") == "AS12345"


def test_validate_asn_value_with_prefix():
    assert validate_asn_value("AS12345") == "AS12345"
    assert validate_asn_value("as12345") == "AS12345"


def test_validate_asn_value_max():
    assert validate_asn_value("4294967295") == "AS4294967295"


def test_validate_asn_value_out_of_range():
    with pytest.raises(ValueError):
        validate_asn_value("4294967296")
    with pytest.raises(ValueError):
        validate_asn_value("0")


def test_validate_asn_value_invalid():
    with pytest.raises(ValueError):
        validate_asn_value("ASabc")
    with pytest.raises(ValueError):
        validate_asn_value("")


# --- Country code validation ------------------------------------------------

def test_validate_country_code_uppercases():
    assert validate_country_code("us") == "US"


def test_validate_country_code_valid():
    assert validate_country_code("US") == "US"
    assert validate_country_code("GB") == "GB"


def test_validate_country_code_invalid_format():
    with pytest.raises(ValueError):
        validate_country_code("USA")
    with pytest.raises(ValueError):
        validate_country_code("1A")
    with pytest.raises(ValueError):
        validate_country_code("")


def test_validate_country_code_unknown_iso():
    # 'ZZ' is not an officially assigned ISO 3166-1 alpha-2 code.
    with pytest.raises(ValueError):
        validate_country_code("ZZ")


def test_get_country_options_fallback(monkeypatch):
    """When the MaxMind DB is absent, get_country_options uses the static ISO fallback."""
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "GEOIP_DB_PATH", "/nonexistent/GeoLite2-Country.mmdb")
    security_lists._country_cache = None
    security_lists._country_cache_db_mtime = None

    options = get_country_options()
    assert len(options) == len(COUNTRY_NAMES)
    # Sorted by name (case-insensitive), then code.
    names = [o["name"].lower() for o in options]
    assert names == sorted(names)
    us = next(o for o in options if o["code"] == "US")
    assert us["name"] == COUNTRY_NAMES["US"]


def test_get_country_options_from_maxmind(monkeypatch, tmp_path):
    from unittest.mock import patch
    from app.core.config import get_settings

    db = tmp_path / "GeoLite2-Country.mmdb"
    db.write_text("")
    settings = get_settings()
    monkeypatch.setattr(settings, "GEOIP_DB_PATH", str(db))
    security_lists._country_cache = None
    security_lists._country_cache_db_mtime = None

    class FakeRecord:
        class country:
            iso_code = "US"
            name = "United States"

    class FakeReader:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def networks(self):
            return [("1.2.3.0/24", FakeRecord()), ("5.6.7.0/24", FakeRecord())]

    with patch("geoip2.database.Reader", return_value=FakeReader()):
        options = get_country_options()

    assert options == [{"code": "US", "name": "United States"}]


# --- JA4 fingerprint validation ---------------------------------------------

def test_validate_ja4_value_valid_tcp():
    fp = "t13d1516h2_8daaf6152771_b186095e22b6"
    assert validate_ja4_value(fp) == fp


def test_validate_ja4_value_valid_quic():
    fp = "q13d0312h3_55b375c5d22e_06cda9e17597"
    assert validate_ja4_value(fp) == fp


def test_validate_ja4_value_valid_dtls():
    fp = "d12i000000_000000000000_000000000000"
    assert validate_ja4_value(fp) == fp


def test_validate_ja4_value_uppercases_to_lower():
    fp = "T13D1516H2_8DAAF6152771_B186095E22B6"
    assert validate_ja4_value(fp) == "t13d1516h2_8daaf6152771_b186095e22b6"


def test_validate_ja4_value_strips_whitespace():
    fp = "  t13d1516h2_8daaf6152771_b186095e22b6  "
    assert validate_ja4_value(fp) == "t13d1516h2_8daaf6152771_b186095e22b6"


def test_validate_ja4_value_no_alpn():
    fp = "t13d151600_8daaf6152771_b186095e22b6"
    assert validate_ja4_value(fp) == fp


def test_validate_ja4_value_invalid_proto():
    with pytest.raises(ValueError):
        validate_ja4_value("x13d1516h2_8daaf6152771_b186095e22b6")


def test_validate_ja4_value_invalid_sni():
    with pytest.raises(ValueError):
        validate_ja4_value("t13x1516h2_8daaf6152771_b186095e22b6")


def test_validate_ja4_value_missing_section():
    with pytest.raises(ValueError):
        validate_ja4_value("t13d1516h2_8daaf6152771")


def test_validate_ja4_value_short_hash():
    with pytest.raises(ValueError):
        validate_ja4_value("t13d1516h2_8daaf615277_b186095e22b6")


def test_validate_ja4_value_non_hex_hash():
    with pytest.raises(ValueError):
        validate_ja4_value("t13d1516h2_8daaf615277g_b186095e22b6")


def test_validate_ja4_value_empty():
    with pytest.raises(ValueError):
        validate_ja4_value("")


def test_validate_ja4_value_wrong_delimiter():
    with pytest.raises(ValueError):
        validate_ja4_value("t13d1516h2-8daaf6152771-b186095e22b6")


# --- Pattern (regex) validation ---------------------------------------------

def test_validate_pattern_value_valid():
    assert validate_pattern_value("Ahref/1.*") == "Ahref/1.*"
    assert validate_pattern_value("Googlebot/version.9.*6") == "Googlebot/version.9.*6"
    assert validate_pattern_value("^exactstring$") == "^exactstring$"


def test_validate_pattern_value_strips_whitespace():
    assert validate_pattern_value("  Ahref/1.*  ") == "Ahref/1.*"


def test_validate_pattern_value_empty():
    with pytest.raises(ValueError):
        validate_pattern_value("")
    with pytest.raises(ValueError):
        validate_pattern_value("   ")


def test_validate_pattern_value_invalid_regex():
    with pytest.raises(ValueError):
        validate_pattern_value("[unclosed")
    with pytest.raises(ValueError):
        validate_pattern_value("*invalid")


def test_validate_pattern_value_rejects_newlines():
    with pytest.raises(ValueError):
        validate_pattern_value("valid\nsecond")
    with pytest.raises(ValueError):
        validate_pattern_value("valid\rsecond")


# --- Feed parser ------------------------------------------------------------

def test_parse_feed_text_plain_lines():
    text = "10.0.0.1\n10.0.0.2\n10.0.0.0/24\n"
    assert parse_feed_text(text) == [
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("10.0.0.0/24", None),
    ]


def test_parse_feed_text_ignores_comments_and_blanks():
    text = "# comment\n10.0.0.1\n\n  # indented comment\n10.0.0.2\n"
    assert parse_feed_text(text) == [("10.0.0.1", None), ("10.0.0.2", None)]


def test_parse_feed_text_comma_delimited():
    text = "10.0.0.1,10.0.0.2,10.0.0.3\n"
    assert parse_feed_text(text) == [
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("10.0.0.3", None),
    ]


def test_parse_feed_text_semicolon_delimited():
    text = "10.0.0.1;10.0.0.2\n"
    assert parse_feed_text(text) == [("10.0.0.1", None), ("10.0.0.2", None)]


def test_parse_feed_text_pipe_delimited():
    text = "10.0.0.1|10.0.0.2\n"
    assert parse_feed_text(text) == [("10.0.0.1", None), ("10.0.0.2", None)]


def test_parse_feed_text_tab_delimited():
    text = "10.0.0.1\t10.0.0.2\n"
    assert parse_feed_text(text) == [("10.0.0.1", None), ("10.0.0.2", None)]


def test_parse_feed_text_whitespace_separated():
    text = "10.0.0.1   10.0.0.2    10.0.0.3\n"
    assert parse_feed_text(text) == [
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("10.0.0.3", None),
    ]


def test_parse_feed_text_mixed_delimiters_and_comments():
    text = "# feed\n10.0.0.1, 10.0.0.2 | 10.0.0.3\n# done\n10.0.0.0/24\n"
    assert parse_feed_text(text) == [
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("10.0.0.3", None),
        ("10.0.0.0/24", None),
    ]


def test_parse_feed_text_empty():
    assert parse_feed_text("") == []
    assert parse_feed_text(None) == []  # type: ignore[arg-type]


def test_parse_feed_text_csv_with_notes():
    text = "value,note\n10.0.0.1,scanner\n10.0.0.0/24,bad network\n"
    assert parse_feed_text(text, list_type="network") == [
        ("10.0.0.1", "scanner"),
        ("10.0.0.0/24", "bad network"),
    ]


def test_parse_feed_text_csv_with_quoted_note():
    text = 'value,note\n10.0.0.1,"scanner, evil"\n'
    assert parse_feed_text(text, list_type="network") == [
        ("10.0.0.1", "scanner, evil"),
    ]


def test_parse_feed_text_csv_without_header():
    text = "10.0.0.1,scanner\n10.0.0.2\n"
    assert parse_feed_text(text, list_type="network") == [
        ("10.0.0.1", "scanner"),
        ("10.0.0.2", None),
    ]


def test_parse_feed_text_csv_multi_value_still_works():
    text = "10.0.0.1,10.0.0.2,10.0.0.3\n"
    assert parse_feed_text(text, list_type="network") == [
        ("10.0.0.1", None),
        ("10.0.0.2", None),
        ("10.0.0.3", None),
    ]


def test_parse_feed_text_csv_asn_prepends_as_prefix():
    text = "asn,note\n12345,evil\nAS67890,also evil\n"
    assert parse_feed_text(text, list_type="asn") == [
        ("12345", "evil"),
        ("AS67890", "also evil"),
    ]


def test_parse_feed_text_csv_ja4_with_notes():
    text = "ja4,note\nt13d1516h2_8daaf6152771_b186095e22b6,suspicious\n"
    assert parse_feed_text(text, list_type="ja4") == [
        ("t13d1516h2_8daaf6152771_b186095e22b6", "suspicious"),
    ]


# --- Filename safety --------------------------------------------------------

def test_safe_filename_basic():
    assert safe_filename("my-list") == "my-list"


def test_safe_filename_strips_path_chars():
    assert safe_filename("../etc/passwd") == "etc_passwd"


def test_safe_filename_empty():
    assert safe_filename("") == "unnamed"


# --- List file writer -------------------------------------------------------

def test_write_security_list_files(db, tmp_path, monkeypatch):
    from app.core.config import get_settings
    from app.models.models import NetworkList, NetworkListEntry, AsnList, AsnListEntry, GeoList, GeoListEntry, Ja4List, Ja4ListEntry, PatternList, PatternListEntry

    settings = get_settings()
    monkeypatch.setattr(settings, "SECURITY_LISTS_DIR", str(tmp_path))

    nl = NetworkList(name="net1", description="d")
    db.add(nl)
    db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.0/24"))

    al = AsnList(name="asn1")
    db.add(al)
    db.flush()
    db.add(AsnListEntry(list_id=al.id, value="AS12345"))

    gl = GeoList(name="geo1")
    db.add(gl)
    db.flush()
    db.add(GeoListEntry(list_id=gl.id, value="US"))

    jl = Ja4List(name="ja4_1")
    db.add(jl)
    db.flush()
    db.add(Ja4ListEntry(list_id=jl.id, value="t13d1516h2_8daaf6152771_b186095e22b6"))

    pl = PatternList(name="pat1", description="bad bots")
    db.add(pl)
    db.flush()
    db.add(PatternListEntry(list_id=pl.id, value="Ahref/1.*"))
    db.add(PatternListEntry(list_id=pl.id, value="Googlebot/version.9.*6"))

    db.commit()

    summary = write_security_list_files(db)
    assert len(summary["network"]) == 1
    assert len(summary["asn"]) == 1
    assert len(summary["geo"]) == 1
    assert len(summary["ja4"]) == 1
    assert len(summary["pattern"]) == 1

    net_path = os.path.join(str(tmp_path), "network", "net1.lst")
    with open(net_path) as f:
        assert f.read() == "10.0.0.1\n10.0.0.0/24\n"

    asn_path = os.path.join(str(tmp_path), "asn", "asn1.lst")
    with open(asn_path) as f:
        assert f.read() == "AS12345\n"

    geo_path = os.path.join(str(tmp_path), "geo", "geo1.lst")
    with open(geo_path) as f:
        assert f.read() == "US\n"

    ja4_path = os.path.join(str(tmp_path), "ja4", "ja4_1.lst")
    with open(ja4_path) as f:
        assert f.read() == "t13d1516h2_8daaf6152771_b186095e22b6\n"

    pat_path = os.path.join(str(tmp_path), "pattern", "pat1.lst")
    with open(pat_path) as f:
        assert f.read() == "Ahref/1.*\nGooglebot/version.9.*6\n"


def test_generate_security_list_file_contents(db):
    """generate_security_list_file_contents returns in-memory contents without writing disk."""
    from app.models.models import NetworkList, NetworkListEntry

    nl = NetworkList(name="net1", description="d")
    db.add(nl)
    db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.0/24"))
    db.commit()

    contents = security_lists.generate_security_list_file_contents(db)
    assert "network/net1.lst" in contents
    assert contents["network/net1.lst"] == "10.0.0.1\n10.0.0.0/24\n"


def test_write_security_list_files_writes_applied_and_cleans_stale(db, tmp_path, monkeypatch):
    """write_security_list_files writes .applied snapshots and removes stale files for deleted lists."""
    from app.core.config import get_settings
    from app.models.models import NetworkList, NetworkListEntry

    settings = get_settings()
    monkeypatch.setattr(settings, "SECURITY_LISTS_DIR", str(tmp_path))

    nl = NetworkList(name="net1", description="d")
    db.add(nl)
    db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
    db.commit()

    security_lists.write_security_list_files(db)
    live = os.path.join(str(tmp_path), "network", "net1.lst")
    applied = f"{live}.applied"
    assert os.path.exists(live)
    assert os.path.exists(applied)

    # Delete the list and re-write — stale files should be cleaned up.
    # The cascade="all, delete-orphan" on NetworkList.entries handles child
    # deletion automatically, so we only delete the parent here.
    db.delete(nl)
    db.commit()
    security_lists.write_security_list_files(db)
    assert not os.path.exists(live)
    assert not os.path.exists(applied)


def _baseline_all_configs(db, tmp_path, monkeypatch):
    """Write .applied baselines for haproxy.cfg + risk_rules_data.lua +
    resp-transform files so the only thing that can move get_config_status
    is a security-list edit."""
    from app.core.config import get_settings
    from app.services import haproxy
    s = get_settings()
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    monkeypatch.setattr(s, "SECURITY_LISTS_DIR", str(lists_dir))
    monkeypatch.setattr(s, "HAPROXY_CONFIG_PATH", str(tmp_path / "haproxy.cfg"))
    monkeypatch.setattr(s, "CORAZA_SPOA_ENABLED", False)
    # Isolate resp-transform dir so generated query_detokenize.json has a
    # matching .applied baseline (otherwise it always shows as unapplied).
    rt_dir = tmp_path / "resp-transform"
    rt_dir.mkdir()
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(rt_dir))

    cfg_path = str(tmp_path / "haproxy.cfg")
    baseline = haproxy.generate_config(db)
    with open(cfg_path, "w") as f:
        f.write(baseline)
    with open(f"{cfg_path}.applied", "w") as f:
        f.write(baseline)

    # Risk rules data file baseline (if risk scoring is importable).
    try:
        from app.services.risk_scoring import generate_risk_rules_data, _risk_rules_data_path
        rrd_path = _risk_rules_data_path()
        rrd = generate_risk_rules_data(db)
        os.makedirs(os.path.dirname(rrd_path), exist_ok=True)
        with open(rrd_path, "w") as f:
            f.write(rrd)
        with open(f"{rrd_path}.applied", "w") as f:
            f.write(rrd)
    except Exception:
        pass

    # Response transform file baselines (if resp transform is importable).
    try:
        from app.services.resp_transform import generate_resp_transform_file_contents
        rt_gen = generate_resp_transform_file_contents(db)
        for fname, content in rt_gen.items():
            fpath = str(rt_dir / fname)
            with open(fpath, "w") as f:
                f.write(content)
            with open(f"{fpath}.applied", "w") as f:
                f.write(content)
    except Exception:
        pass


def test_config_status_detects_security_list_edit(db, tmp_path, monkeypatch):
    """Editing a security list entry should make get_config_status report unapplied changes."""
    from app.models.models import NetworkList, NetworkListEntry
    from app.services.config import get_config_status
    from app.services.security_lists import write_security_list_files

    _baseline_all_configs(db, tmp_path, monkeypatch)

    nl = NetworkList(name="blocklist", description="d")
    db.add(nl)
    db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
    db.commit()

    # Apply: writes .lst + .applied → status should be False.
    write_security_list_files(db)
    assert get_config_status(db) is False

    # Edit: add an entry → status should become True (banner appears).
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.2"))
    db.commit()
    assert get_config_status(db) is True

    # Re-apply → status back to False.
    write_security_list_files(db)
    assert get_config_status(db) is False


def test_security_list_files_unapplied(db, tmp_path, monkeypatch):
    """security_list_files_unapplied distinguishes list-only diffs from other pending changes."""
    from app.models.models import NetworkList, NetworkListEntry
    from app.services.config import security_list_files_unapplied
    from app.services.security_lists import write_security_list_files

    _baseline_all_configs(db, tmp_path, monkeypatch)

    nl = NetworkList(name="blocklist", description="d")
    db.add(nl)
    db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
    db.commit()
    write_security_list_files(db)

    # No changes → (False, False)
    assert security_list_files_unapplied(db) == (False, False)

    # List edit only → (True, False)
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.2"))
    db.commit()
    assert security_list_files_unapplied(db) == (True, False)
