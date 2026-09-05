"""API tests for the /haproxy/tables endpoints (System → Tables tab)."""
from unittest.mock import patch


def test_list_tables(client):
    with patch("app.api.v1.system.stick_tables.list_tables") as mock_list:
        mock_list.return_value = [
            {"name": "beacon_trust_table", "type": "ip", "size": 1048576, "used": 12},
            {"name": "cxid_table", "type": "string", "size": 100000, "used": 3},
        ]
        res = client.get("/api/v1/haproxy/tables")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    assert data[0]["name"] == "beacon_trust_table"
    assert data[1]["type"] == "string"


def test_get_table_paginated(client):
    payload = {
        "name": "t1",
        "type": "ip",
        "size": 100,
        "used": 5,
        "total": 5,
        "offset": 0,
        "limit": 2,
        "entries": [
            {"key": "10.0.0.1", "use": 0, "exp": 45000, "stores": {"gpc0": "1"}},
            {"key": "10.0.0.2", "use": 0, "exp": 45000, "stores": {"gpc0": "2"}},
        ],
    }
    with patch("app.api.v1.system.stick_tables.get_table", return_value=payload):
        res = client.get("/api/v1/haproxy/tables/t1?limit=2&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "t1"
    assert data["total"] == 5
    assert len(data["entries"]) == 2
    assert data["entries"][0]["key"] == "10.0.0.1"
    assert data["entries"][0]["stores"]["gpc0"] == "1"


def test_get_table_with_search(client):
    payload = {
        "name": "t1", "type": "ip", "size": 100, "used": 3,
        "total": 2, "offset": 0, "limit": 100,
        "entries": [
            {"key": "10.0.0.1", "use": 0, "exp": 100, "stores": {}},
            {"key": "10.0.0.2", "use": 0, "exp": 100, "stores": {}},
        ],
    }
    with patch("app.api.v1.system.stick_tables.get_table", return_value=payload) as mock_get:
        res = client.get("/api/v1/haproxy/tables/t1?search=10.0.0")
    assert res.status_code == 200
    mock_get.assert_called_once_with("t1", limit=100, offset=0, search="10.0.0")


def test_get_table_rejects_invalid_limit(client):
    # limit=0 should be rejected by the ge=1 validator
    res = client.get("/api/v1/haproxy/tables/t1?limit=0")
    assert res.status_code == 422


def test_get_table_rejects_limit_over_max(client):
    # limit > 500 should be rejected by the le=500 validator
    res = client.get("/api/v1/haproxy/tables/t1?limit=501")
    assert res.status_code == 422


def test_clear_table(client):
    with patch("app.api.v1.system.stick_tables.clear_table", return_value={"ok": True, "cleared": -1}):
        res = client.delete("/api/v1/haproxy/tables/t1")
    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_clear_entry(client):
    with patch("app.api.v1.system.stick_tables.clear_entry", return_value={"ok": True, "cleared": 1}):
        res = client.delete("/api/v1/haproxy/tables/t1/entries/1.2.3.4")
    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_clear_entry_ipv6_key(client):
    """IPv6 keys contain `:` and should be accepted as a path param."""
    with patch("app.api.v1.system.stick_tables.clear_entry", return_value={"ok": True, "cleared": 1}) as mock_clear:
        res = client.delete("/api/v1/haproxy/tables/t1/entries/::ffff:192.168.1.5")
    assert res.status_code == 200
    mock_clear.assert_called_once_with("t1", "::ffff:192.168.1.5")


def test_clear_requires_admin(client):
    """A non-admin user should be forbidden from clearing tables.

    The `client` fixture overrides get_current_user with an admin user, so to
    test the admin guard we override require_admin's underlying get_current_user
    with a viewer and check that the dependency rejects.
    """
    from app.api.deps import get_current_user, require_admin
    from app.models.models import User
    from app.main import app

    viewer = User(username="viewer", role="viewer", is_admin=False, hashed_password="x")
    # require_admin calls get_current_user internally; override it to return a viewer
    app.dependency_overrides[get_current_user] = lambda: viewer
    try:
        res = client.delete("/api/v1/haproxy/tables/t1")
        assert res.status_code == 403
    finally:
        # Restore the admin override that the `client` fixture set
        app.dependency_overrides[get_current_user] = lambda: User(
            username="test-admin", role="admin", is_admin=True, hashed_password="x"
        )
