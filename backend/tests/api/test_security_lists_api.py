"""Integration tests for the /security-lists endpoints."""
from unittest.mock import patch

import pytest
import requests


# --- Network lists ----------------------------------------------------------

def test_create_and_list_network_list(client, db):
    res = client.post("/api/v1/security-lists/network", json={"name": "net1", "description": "desc"})
    assert res.status_code == 200
    assert res.json()["name"] == "net1"
    assert res.json()["entry_count"] == 0

    res = client.get("/api/v1/security-lists/network")
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["name"] == "net1"


def test_update_network_list(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    res = client.put(f"/api/v1/security-lists/network/{lid}", json={"description": "updated"})
    assert res.status_code == 200
    assert res.json()["description"] == "updated"


def test_delete_network_list(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    res = client.delete(f"/api/v1/security-lists/network/{lid}")
    assert res.status_code == 200
    assert client.get("/api/v1/security-lists/network").json() == []


def test_network_entry_validation_ip(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1"})
    assert res.status_code == 200
    assert res.json()["value"] == "10.0.0.1"


def test_network_entry_validation_cidr(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.0/24"})
    assert res.status_code == 200
    assert res.json()["value"] == "10.0.0.0/24"


def test_network_entry_invalid_rejected(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "not-an-ip"})
    assert res.status_code == 400


def test_network_entry_with_note(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1", "note": "bad actor"})
    assert res.status_code == 200
    assert res.json()["note"] == "bad actor"


def test_list_network_entries(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1"})
    client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.2"})
    res = client.get(f"/api/v1/security-lists/network/{lid}/entries")
    assert res.status_code == 200
    assert len(res.json()) == 2


def test_update_network_entry(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    er = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1"})
    eid = er.json()["id"]
    res = client.put(f"/api/v1/security-lists/network/{lid}/entries/{eid}", json={"note": "updated note"})
    assert res.status_code == 200
    assert res.json()["note"] == "updated note"


def test_delete_network_entry(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    er = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1"})
    eid = er.json()["id"]
    res = client.delete(f"/api/v1/security-lists/network/{lid}/entries/{eid}")
    assert res.status_code == 200
    assert client.get(f"/api/v1/security-lists/network/{lid}/entries").json() == []


# --- ASN lists --------------------------------------------------------------

def test_asn_entry_normalizes(client, db):
    r = client.post("/api/v1/security-lists/asn", json={"name": "asn1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/asn/{lid}/entries", json={"value": "12345"})
    assert res.status_code == 200
    assert res.json()["value"] == "AS12345"


def test_asn_entry_with_prefix(client, db):
    r = client.post("/api/v1/security-lists/asn", json={"name": "asn1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/asn/{lid}/entries", json={"value": "AS64500"})
    assert res.status_code == 200
    assert res.json()["value"] == "AS64500"


def test_asn_entry_invalid(client, db):
    r = client.post("/api/v1/security-lists/asn", json={"name": "asn1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/asn/{lid}/entries", json={"value": "not-an-asn"})
    assert res.status_code == 400


# --- GeoIP lists ------------------------------------------------------------

def test_geo_entry_uppercases(client, db):
    r = client.post("/api/v1/security-lists/geo", json={"name": "geo1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/geo/{lid}/entries", json={"value": "us"})
    assert res.status_code == 200
    assert res.json()["value"] == "US"


def test_geo_entry_invalid_format(client, db):
    r = client.post("/api/v1/security-lists/geo", json={"name": "geo1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/geo/{lid}/entries", json={"value": "USA"})
    assert res.status_code == 400


def test_geo_entry_unknown_iso(client, db):
    r = client.post("/api/v1/security-lists/geo", json={"name": "geo1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/geo/{lid}/entries", json={"value": "ZZ"})
    assert res.status_code == 400


def test_list_geo_countries_fallback(client, db, monkeypatch):
    from app.core.config import get_settings
    from app.services import security_lists

    settings = get_settings()
    monkeypatch.setattr(settings, "GEOIP_DB_PATH", "/nonexistent/GeoLite2-Country.mmdb")
    security_lists._country_cache = None
    security_lists._country_cache_db_mtime = None

    res = client.get("/api/v1/security-lists/geo/countries")
    assert res.status_code == 200
    data = res.json()
    assert len(data) > 200
    codes = {c["code"] for c in data}
    assert "US" in codes
    assert "GB" in codes
    # Sorted by name.
    names = [c["name"].lower() for c in data]
    assert names == sorted(names)


# --- JA4 lists --------------------------------------------------------------

VALID_JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"


def test_create_and_list_ja4_list(client, db):
    res = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1", "description": "desc"})
    assert res.status_code == 200
    assert res.json()["name"] == "ja4_1"
    assert res.json()["entry_count"] == 0

    res = client.get("/api/v1/security-lists/ja4")
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["name"] == "ja4_1"


def test_update_ja4_list(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.put(f"/api/v1/security-lists/ja4/{lid}", json={"description": "updated"})
    assert res.status_code == 200
    assert res.json()["description"] == "updated"


def test_delete_ja4_list(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.delete(f"/api/v1/security-lists/ja4/{lid}")
    assert res.status_code == 200
    assert client.get("/api/v1/security-lists/ja4").json() == []


def test_ja4_entry_valid(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": VALID_JA4})
    assert res.status_code == 200
    assert res.json()["value"] == VALID_JA4


def test_ja4_entry_uppercase_normalizes(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": "T13D1516H2_8DAAF6152771_B186095E22B6"})
    assert res.status_code == 200
    assert res.json()["value"] == VALID_JA4


def test_ja4_entry_invalid_format(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": "not-a-ja4-fingerprint"})
    assert res.status_code == 400


def test_ja4_entry_invalid_proto(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": "x13d1516h2_8daaf6152771_b186095e22b6"})
    assert res.status_code == 400


def test_ja4_entry_missing_section(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": "t13d1516h2_8daaf6152771"})
    assert res.status_code == 400


def test_ja4_entry_with_note(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": VALID_JA4, "note": "bot client"})
    assert res.status_code == 200
    assert res.json()["note"] == "bot client"


def test_list_ja4_entries(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": VALID_JA4})
    client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": "q13d0312h3_55b375c5d22e_06cda9e17597"})
    res = client.get(f"/api/v1/security-lists/ja4/{lid}/entries")
    assert res.status_code == 200
    assert len(res.json()) == 2


def test_update_ja4_entry(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    er = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": VALID_JA4})
    eid = er.json()["id"]
    res = client.put(f"/api/v1/security-lists/ja4/{lid}/entries/{eid}", json={"note": "updated"})
    assert res.status_code == 200
    assert res.json()["note"] == "updated"


def test_delete_ja4_entry(client, db):
    r = client.post("/api/v1/security-lists/ja4", json={"name": "ja4_1"})
    lid = r.json()["id"]
    er = client.post(f"/api/v1/security-lists/ja4/{lid}/entries", json={"value": VALID_JA4})
    eid = er.json()["id"]
    res = client.delete(f"/api/v1/security-lists/ja4/{lid}/entries/{eid}")
    assert res.status_code == 200
    assert client.get(f"/api/v1/security-lists/ja4/{lid}/entries").json() == []


# --- Dynamic feeds ----------------------------------------------------------

def test_create_feed_creates_target_list(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n10.0.0.2\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={
                "name": "feed1",
                "list_type": "network",
                "url": "http://example.com/feed.txt",
                "update_interval_hours": 12,
            },
        )
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "feed1"
    assert data["list_type"] == "network"
    assert data["target_list_id"] is not None
    assert data["last_entry_count"] == 2

    # The target list should exist and have 2 entries.
    lists = client.get("/api/v1/security-lists/network").json()
    assert any(l["name"] == "feed1" and l["entry_count"] == 2 for l in lists)


def test_create_feed_with_existing_target_list(client, db):
    lr = client.post("/api/v1/security-lists/network", json={"name": "existing"})
    lid = lr.json()["id"]
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.0/24\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={
                "name": "feed1",
                "list_type": "network",
                "url": "http://example.com/feed.txt",
                "target_list_id": lid,
            },
        )
    assert res.status_code == 200
    assert res.json()["target_list_id"] == lid
    assert res.json()["last_entry_count"] == 1


def test_create_feed_invalid_list_type(client, db):
    res = client.post(
        "/api/v1/security-lists/feeds",
        json={"name": "feed1", "list_type": "geo", "url": "http://x"},
    )
    assert res.status_code == 422  # schema validation


def test_create_feed_target_list_not_found(client, db):
    res = client.post(
        "/api/v1/security-lists/feeds",
        json={"name": "feed1", "list_type": "network", "url": "http://x", "target_list_id": 9999},
    )
    assert res.status_code == 404


def test_refresh_feed_now(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    fid = cr.json()["id"]

    with patch("app.services.security_list_feeds.requests.get") as mock_get2:
        mock_get2.return_value.status_code = 200
        mock_get2.return_value.text = "10.0.0.1\n10.0.0.2\n10.0.0.3\n"
        mock_get2.return_value.raise_for_status = lambda: None
        res = client.post(f"/api/v1/security-lists/feeds/{fid}/refresh")
    assert res.status_code == 200
    assert res.json()["entry_count"] == 3


def test_delete_feed_keeps_list_by_default(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    fid = cr.json()["id"]
    lid = cr.json()["target_list_id"]

    res = client.delete(f"/api/v1/security-lists/feeds/{fid}")
    assert res.status_code == 200
    # Feed gone.
    feeds = client.get("/api/v1/security-lists/feeds").json()
    assert feeds == []
    # List still present.
    lists = client.get("/api/v1/security-lists/network").json()
    assert any(l["id"] == lid for l in lists)


def test_delete_feed_with_delete_list(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    fid = cr.json()["id"]
    lid = cr.json()["target_list_id"]

    res = client.delete(f"/api/v1/security-lists/feeds/{fid}?delete_list=true")
    assert res.status_code == 200
    lists = client.get("/api/v1/security-lists/network").json()
    assert not any(l["id"] == lid for l in lists)


def test_delete_list_blocked_by_feed(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    lid = cr.json()["target_list_id"]
    res = client.delete(f"/api/v1/security-lists/network/{lid}")
    assert res.status_code == 409


def test_delete_list_force_with_feed(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    fid = cr.json()["id"]
    lid = cr.json()["target_list_id"]
    res = client.delete(f"/api/v1/security-lists/network/{lid}?force=true")
    assert res.status_code == 200
    feeds = client.get("/api/v1/security-lists/feeds").json()
    assert not any(f["id"] == fid for f in feeds)


def test_create_ja4_feed_creates_target_list(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "t13d1516h2_8daaf6152771_b186095e22b6\nq13d0312h3_55b375c5d22e_06cda9e17597\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={
                "name": "ja4_feed",
                "list_type": "ja4",
                "url": "http://example.com/ja4.txt",
                "update_interval_hours": 12,
            },
        )
    assert res.status_code == 200
    data = res.json()
    assert data["list_type"] == "ja4"
    assert data["target_list_id"] is not None
    assert data["last_entry_count"] == 2

    lists = client.get("/api/v1/security-lists/ja4").json()
    assert any(l["name"] == "ja4_feed" and l["entry_count"] == 2 for l in lists)


def test_create_ja4_feed_with_existing_target_list(client, db):
    lr = client.post("/api/v1/security-lists/ja4", json={"name": "existing"})
    lid = lr.json()["id"]
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "t13d1516h2_8daaf6152771_b186095e22b6\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "ja4_feed", "list_type": "ja4", "url": "http://x", "target_list_id": lid},
        )
    assert res.status_code == 200
    assert res.json()["target_list_id"] == lid
    assert res.json()["last_entry_count"] == 1


def test_ja4_feed_skips_invalid_entries(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "t13d1516h2_8daaf6152771_b186095e22b6\nnot-a-ja4\nx13d1516h2_8daaf6152771_b186095e22b6\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "ja4_feed", "list_type": "ja4", "url": "http://x"},
        )
    assert res.status_code == 200
    assert res.json()["last_entry_count"] == 1  # only the valid one


def test_create_network_feed_csv_with_notes(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "ip,note\n10.0.0.1,scanner\n10.0.0.2,bad actor\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "csv_feed", "list_type": "network", "url": "http://x"},
        )
    assert res.status_code == 200
    assert res.json()["last_entry_count"] == 2
    lid = res.json()["target_list_id"]
    entries = client.get(f"/api/v1/security-lists/network/{lid}/entries").json()
    assert {e["value"] for e in entries} == {"10.0.0.1", "10.0.0.2"}
    assert {e["note"] for e in entries} == {"scanner", "bad actor"}


def test_create_asn_feed_csv_prepends_as(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "asn,note\n12345,evil\nAS67890,also evil\n"
        mock_get.return_value.raise_for_status = lambda: None
        res = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "asn_csv_feed", "list_type": "asn", "url": "http://x"},
        )
    assert res.status_code == 200
    assert res.json()["last_entry_count"] == 2
    lid = res.json()["target_list_id"]
    entries = client.get(f"/api/v1/security-lists/asn/{lid}/entries").json()
    assert {e["value"] for e in entries} == {"AS12345", "AS67890"}
    assert all(e["note"] == "evil" or e["note"] == "also evil" for e in entries)


def test_old_acl_routes_removed(client, db):
    assert client.get("/api/v1/network-acls").status_code == 404
    assert client.get("/api/v1/geo-acls").status_code == 404
    assert client.get("/api/v1/asn-acls").status_code == 404


# --- updated_at bumping on entry changes ------------------------------------

def test_entry_create_bumps_list_updated_at(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    original_updated = r.json()["updated_at"]

    import time
    time.sleep(0.01)
    client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1"})

    lists = client.get("/api/v1/security-lists/network").json()
    lst = next(l for l in lists if l["id"] == lid)
    assert lst["updated_at"] > original_updated


def test_entry_delete_bumps_list_updated_at(client, db):
    r = client.post("/api/v1/security-lists/network", json={"name": "net1"})
    lid = r.json()["id"]
    er = client.post(f"/api/v1/security-lists/network/{lid}/entries", json={"value": "10.0.0.1"})
    eid = er.json()["id"]

    lists = client.get("/api/v1/security-lists/network").json()
    original_updated = next(l for l in lists if l["id"] == lid)["updated_at"]

    import time
    time.sleep(0.01)
    client.delete(f"/api/v1/security-lists/network/{lid}/entries/{eid}")

    lists = client.get("/api/v1/security-lists/network").json()
    lst = next(l for l in lists if l["id"] == lid)
    assert lst["updated_at"] > original_updated


def test_feed_refresh_bumps_list_updated_at(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    lid = cr.json()["target_list_id"]

    lists = client.get("/api/v1/security-lists/network").json()
    original_updated = next(l for l in lists if l["id"] == lid)["updated_at"]

    import time
    time.sleep(0.01)
    with patch("app.services.security_list_feeds.requests.get") as mock_get2:
        mock_get2.return_value.status_code = 200
        mock_get2.return_value.text = "10.0.0.2\n"
        mock_get2.return_value.raise_for_status = lambda: None
        client.post(f"/api/v1/security-lists/feeds/{cr.json()['id']}/refresh")

    lists = client.get("/api/v1/security-lists/network").json()
    lst = next(l for l in lists if l["id"] == lid)
    assert lst["updated_at"] > original_updated


def test_feed_refresh_failure_does_not_update_last_updated_at(client, db):
    with patch("app.services.security_list_feeds.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "10.0.0.1\n"
        mock_get.return_value.raise_for_status = lambda: None
        cr = client.post(
            "/api/v1/security-lists/feeds",
            json={"name": "feed1", "list_type": "network", "url": "http://x"},
        )
    fid = cr.json()["id"]
    original_last_updated = cr.json()["last_updated_at"]
    assert original_last_updated is not None

    import time
    time.sleep(0.01)
    with patch("app.services.security_list_feeds.requests.get") as mock_get2:
        mock_get2.side_effect = requests.RequestException("network error")
        res = client.post(f"/api/v1/security-lists/feeds/{fid}/refresh")

    # The feed's last_updated_at should NOT change on failure.
    feeds = client.get("/api/v1/security-lists/feeds").json()
    feed = next(f for f in feeds if f["id"] == fid)
    assert feed["last_updated_at"] == original_last_updated
    assert feed["last_error"] is not None


# --- Pattern lists ----------------------------------------------------------

def test_create_and_list_pattern_list(client, db):
    res = client.post("/api/v1/security-lists/pattern", json={"name": "pat1", "description": "bad bots"})
    assert res.status_code == 200
    assert res.json()["name"] == "pat1"
    assert res.json()["entry_count"] == 0

    res = client.get("/api/v1/security-lists/pattern")
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["name"] == "pat1"


def test_update_pattern_list(client, db):
    r = client.post("/api/v1/security-lists/pattern", json={"name": "pat1"})
    lid = r.json()["id"]
    res = client.put(f"/api/v1/security-lists/pattern/{lid}", json={"description": "updated"})
    assert res.status_code == 200
    assert res.json()["description"] == "updated"


def test_delete_pattern_list(client, db):
    r = client.post("/api/v1/security-lists/pattern", json={"name": "pat1"})
    lid = r.json()["id"]
    res = client.delete(f"/api/v1/security-lists/pattern/{lid}")
    assert res.status_code == 200
    assert client.get("/api/v1/security-lists/pattern").json() == []


def test_pattern_entry_validation_valid_regex(client, db):
    r = client.post("/api/v1/security-lists/pattern", json={"name": "pat1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/pattern/{lid}/entries", json={"value": "Ahref/1.*"})
    assert res.status_code == 200
    assert res.json()["value"] == "Ahref/1.*"


def test_pattern_entry_validation_invalid_regex(client, db):
    r = client.post("/api/v1/security-lists/pattern", json={"name": "pat1"})
    lid = r.json()["id"]
    res = client.post(f"/api/v1/security-lists/pattern/{lid}/entries", json={"value": "[unclosed"})
    assert res.status_code == 400


def test_pattern_entry_crud(client, db):
    r = client.post("/api/v1/security-lists/pattern", json={"name": "pat1"})
    lid = r.json()["id"]
    # Create
    r = client.post(f"/api/v1/security-lists/pattern/{lid}/entries", json={"value": "Ahref/1.*", "note": "crawler"})
    assert r.status_code == 200
    eid = r.json()["id"]
    # List
    res = client.get(f"/api/v1/security-lists/pattern/{lid}/entries")
    assert res.status_code == 200
    assert len(res.json()) == 1
    # Update
    res = client.put(f"/api/v1/security-lists/pattern/{lid}/entries/{eid}", json={"value": "Googlebot/.*"})
    assert res.status_code == 200
    assert res.json()["value"] == "Googlebot/.*"
    # Delete
    res = client.delete(f"/api/v1/security-lists/pattern/{lid}/entries/{eid}")
    assert res.status_code == 200
    assert client.get(f"/api/v1/security-lists/pattern/{lid}/entries").json() == []


# --- "In use" delete protection -------------------------------------------

def test_delete_network_list_referenced_by_rule_returns_409(client, db):
    """A network list referenced by a security rule cannot be deleted."""
    from app.models.models import NetworkList
    nl = NetworkList(name="referenced_net")
    db.add(nl)
    db.commit()
    db.refresh(nl)

    # Create a security rule that references the list
    r = client.post("/api/v1/security-rules", json={
        "name": "Block via list",
        "expression": "ip.src in $network:referenced_net",
        "action": "block",
    })
    assert r.status_code == 200

    # Deleting the list should 409
    res = client.delete(f"/api/v1/security-lists/network/{nl.id}")
    assert res.status_code == 409
    assert "in use" in res.json()["detail"].lower()
    assert "Block via list" in res.json()["detail"]

    # force=true should NOT override the rule reference (hard block)
    res = client.delete(f"/api/v1/security-lists/network/{nl.id}?force=true")
    assert res.status_code == 409


def test_delete_network_list_referenced_by_setting_returns_409(client, db):
    """A network list referenced by the trusted-source setting cannot be deleted."""
    from app.models.models import NetworkList
    nl = NetworkList(name="trusted_cdn")
    db.add(nl)
    db.commit()
    db.refresh(nl)

    # Set the trusted-source setting
    r = client.put("/api/v1/settings/restore_client_ip_trusted_network_list",
                   json={"value": "trusted_cdn"})
    assert r.status_code == 200

    # Deleting the list should 409
    res = client.delete(f"/api/v1/security-lists/network/{nl.id}")
    assert res.status_code == 409
    assert "in use" in res.json()["detail"].lower()
    assert "Restore Client IP" in res.json()["detail"]

    # force=true should NOT override the setting reference (hard block)
    res = client.delete(f"/api/v1/security-lists/network/{nl.id}?force=true")
    assert res.status_code == 409


def test_delete_network_list_with_feed_force_bypasses(client, db):
    """A network list with only a feed reference can be force-deleted (existing behavior)."""
    from app.models.models import NetworkList, DynamicFeed
    nl = NetworkList(name="feed_owned")
    db.add(nl)
    db.commit()
    db.refresh(nl)

    feed = DynamicFeed(name="feed1", list_type="network", target_list_id=nl.id,
                       url="http://example.com/list.txt", update_interval_hours=24)
    db.add(feed)
    db.commit()

    # Without force → 409 (feed message)
    res = client.delete(f"/api/v1/security-lists/network/{nl.id}")
    assert res.status_code == 409
    assert "dynamic feed" in res.json()["detail"].lower()

    # With force → 200 (cascades to feed)
    res = client.delete(f"/api/v1/security-lists/network/{nl.id}?force=true")
    assert res.status_code == 200


def test_delete_unreferenced_network_list_succeeds(client, db):
    """An unreferenced network list deletes normally (no regression)."""
    from app.models.models import NetworkList
    nl = NetworkList(name="free_net")
    db.add(nl)
    db.commit()
    db.refresh(nl)

    res = client.delete(f"/api/v1/security-lists/network/{nl.id}")
    assert res.status_code == 200


def test_delete_geo_list_referenced_by_rule_returns_409(client, db):
    """A geo list referenced by a security rule cannot be deleted (new check)."""
    from app.models.models import GeoList
    gl = GeoList(name="blocked_countries")
    db.add(gl)
    db.commit()
    db.refresh(gl)

    r = client.post("/api/v1/security-rules", json={
        "name": "Block countries",
        "expression": "ip.geoip.country in $geo:blocked_countries",
        "action": "block",
    })
    assert r.status_code == 200

    res = client.delete(f"/api/v1/security-lists/geo/{gl.id}")
    assert res.status_code == 409
    assert "in use" in res.json()["detail"].lower()


def test_delete_pattern_list_referenced_by_rule_returns_409(client, db):
    """A pattern list referenced by a security rule cannot be deleted (new check)."""
    from app.models.models import PatternList
    pl = PatternList(name="bad_bots")
    db.add(pl)
    db.commit()
    db.refresh(pl)

    r = client.post("/api/v1/security-rules", json={
        "name": "Block bots",
        "expression": "http.request.user_agent in $pattern:bad_bots",
        "action": "block",
    })
    assert r.status_code == 200

    res = client.delete(f"/api/v1/security-lists/pattern/{pl.id}")
    assert res.status_code == 409
    assert "in use" in res.json()["detail"].lower()
