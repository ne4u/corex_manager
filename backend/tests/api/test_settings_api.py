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
