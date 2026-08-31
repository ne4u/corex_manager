"""Tests for the restore_client_ip_trusted_network_list setting validation."""
from app.models.models import NetworkList


def test_set_trusted_network_list_existing(client, db):
    """PUT setting to an existing NetworkList name returns 200."""
    nl = NetworkList(name="cdn_edges")
    db.add(nl)
    db.commit()

    r = client.put("/api/v1/settings/restore_client_ip_trusted_network_list", json={"value": "cdn_edges"})
    assert r.status_code == 200
    assert r.json()["value"] == "cdn_edges"


def test_set_trusted_network_list_multiple_existing(client, db):
    """PUT setting with multiple comma-separated existing names returns 200."""
    db.add(NetworkList(name="cloudflare"))
    db.add(NetworkList(name="fastly"))
    db.commit()

    r = client.put("/api/v1/settings/restore_client_ip_trusted_network_list", json={"value": "cloudflare,fastly"})
    assert r.status_code == 200
    assert r.json()["value"] == "cloudflare,fastly"


def test_set_trusted_network_list_one_nonexistent_returns_400(client, db):
    """PUT setting where one of multiple names doesn't exist returns 400."""
    db.add(NetworkList(name="cloudflare"))
    db.commit()

    r = client.put("/api/v1/settings/restore_client_ip_trusted_network_list", json={"value": "cloudflare,no_such_list"})
    assert r.status_code == 400
    assert "no_such_list" in r.json()["detail"]


def test_set_trusted_network_list_nonexistent_returns_400(client, db):
    """PUT setting to a non-existent NetworkList name returns 400."""
    r = client.put("/api/v1/settings/restore_client_ip_trusted_network_list", json={"value": "no_such_list"})
    assert r.status_code == 400
    assert "not found" in r.json()["detail"].lower()


def test_set_trusted_network_list_empty_clears(client, db):
    """PUT setting with empty string clears it (200)."""
    # First set it
    nl = NetworkList(name="cdn_edges")
    db.add(nl)
    db.commit()
    client.put("/api/v1/settings/restore_client_ip_trusted_network_list", json={"value": "cdn_edges"})

    # Then clear it
    r = client.put("/api/v1/settings/restore_client_ip_trusted_network_list", json={"value": ""})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Password policy setting validation
# ---------------------------------------------------------------------------

def test_set_password_min_length_valid(client, db):
    r = client.put("/api/v1/settings/password_min_length", json={"value": "12"})
    assert r.status_code == 200
    assert r.json()["value"] == "12"


def test_set_password_min_length_too_low(client, db):
    r = client.put("/api/v1/settings/password_min_length", json={"value": "7"})
    assert r.status_code == 400
    assert "between 8 and 128" in r.json()["detail"]


def test_set_password_min_length_too_high(client, db):
    r = client.put("/api/v1/settings/password_min_length", json={"value": "129"})
    assert r.status_code == 400


def test_set_password_min_length_non_integer(client, db):
    r = client.put("/api/v1/settings/password_min_length", json={"value": "abc"})
    assert r.status_code == 400


def test_set_password_require_uppercase_true(client, db):
    r = client.put("/api/v1/settings/password_require_uppercase", json={"value": "true"})
    assert r.status_code == 200
    assert r.json()["value"] == "true"


def test_set_password_require_uppercase_false(client, db):
    r = client.put("/api/v1/settings/password_require_uppercase", json={"value": "false"})
    assert r.status_code == 200


def test_set_password_require_digit_invalid(client, db):
    r = client.put("/api/v1/settings/password_require_digit", json={"value": "maybe"})
    assert r.status_code == 400
    assert "boolean" in r.json()["detail"]


def test_set_password_require_symbol_invalid(client, db):
    r = client.put("/api/v1/settings/password_require_symbol", json={"value": "yesno"})
    assert r.status_code == 400


def test_set_password_rotation_months_valid(client, db):
    r = client.put("/api/v1/settings/password_rotation_months", json={"value": "3"})
    assert r.status_code == 200
    assert r.json()["value"] == "3"


def test_set_password_rotation_months_disabled(client, db):
    r = client.put("/api/v1/settings/password_rotation_months", json={"value": "0"})
    assert r.status_code == 200


def test_set_password_rotation_months_too_high(client, db):
    r = client.put("/api/v1/settings/password_rotation_months", json={"value": "25"})
    assert r.status_code == 400


def test_set_password_rotation_months_negative(client, db):
    r = client.put("/api/v1/settings/password_rotation_months", json={"value": "-1"})
    assert r.status_code == 400


def test_set_password_rotation_months_non_integer(client, db):
    r = client.put("/api/v1/settings/password_rotation_months", json={"value": "abc"})
    assert r.status_code == 400
