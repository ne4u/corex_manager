"""API tests for the /valkey/* endpoints (System → Valkey tab)."""
from unittest.mock import patch


def test_valkey_info(client):
    with patch("app.api.v1.system.valkey_inspect.server_info") as mock_info:
        mock_info.return_value = {
            "available": True,
            "version": "7.2.5",
            "uptime_seconds": 3665,
            "connected_clients": 5,
            "used_memory_human": "1.00M",
            "used_memory_peak_human": "2.00M",
            "total_keys": 42,
            "db_count": 1,
            "role": "master",
            "error": None,
        }
        res = client.get("/api/v1/valkey/info")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["version"] == "7.2.5"
    assert data["total_keys"] == 42


def test_valkey_info_unavailable(client):
    with patch("app.api.v1.system.valkey_inspect.server_info") as mock_info:
        mock_info.return_value = {"available": False, "error": "valkey not reachable"}
        res = client.get("/api/v1/valkey/info")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is False
    assert data["error"] == "valkey not reachable"


def test_valkey_namespaces(client):
    with patch("app.api.v1.system.valkey_inspect.list_namespaces") as mock_list:
        mock_list.return_value = [
            {"prefix": "cache", "count": 3, "sample_keys": ["cache:a", "cache:b"]},
            {"prefix": "stick_table", "count": 1, "sample_keys": ["stick_table:t1"]},
        ]
        res = client.get("/api/v1/valkey/namespaces")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    assert data[0]["prefix"] == "cache"
    assert data[0]["count"] == 3


def test_valkey_namespace_paginated(client):
    payload = {
        "prefix": "cache",
        "total": 5,
        "offset": 0,
        "limit": 2,
        "keys": [
            {"key": "cache:a", "type": "string", "ttl": -1, "size": 100, "preview": "v1"},
            {"key": "cache:b", "type": "string", "ttl": 60, "size": 50, "preview": "v2"},
        ],
    }
    with patch("app.api.v1.system.valkey_inspect.get_namespace", return_value=payload):
        res = client.get("/api/v1/valkey/namespaces/cache?limit=2&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 5
    assert len(data["keys"]) == 2
    assert data["keys"][0]["key"] == "cache:a"
    assert data["keys"][0]["type"] == "string"
    assert data["keys"][1]["ttl"] == 60


def test_valkey_namespace_with_search(client):
    payload = {"prefix": "cache", "total": 1, "offset": 0, "limit": 100, "keys": []}
    with patch("app.api.v1.system.valkey_inspect.get_namespace", return_value=payload) as mock_get:
        res = client.get("/api/v1/valkey/namespaces/cache?search=foo")
    assert res.status_code == 200
    mock_get.assert_called_once_with("cache", limit=100, offset=0, search="foo")


def test_valkey_namespace_rejects_invalid_limit(client):
    res = client.get("/api/v1/valkey/namespaces/cache?limit=0")
    assert res.status_code == 422


def test_valkey_namespace_rejects_limit_over_max(client):
    res = client.get("/api/v1/valkey/namespaces/cache?limit=501")
    assert res.status_code == 422


def test_valkey_namespace_no_namespace_sentinel(client):
    """The __none__ sentinel prefix should be passed through to the service."""
    payload = {"prefix": "__none__", "total": 0, "offset": 0, "limit": 100, "keys": []}
    with patch("app.api.v1.system.valkey_inspect.get_namespace", return_value=payload) as mock_get:
        res = client.get("/api/v1/valkey/namespaces/__none__")
    assert res.status_code == 200
    mock_get.assert_called_once_with("__none__", limit=100, offset=0, search=None)


def test_valkey_delete_key(client):
    with patch("app.api.v1.system.valkey_inspect.delete_key", return_value={"ok": True, "deleted": 1}):
        res = client.delete("/api/v1/valkey/keys/cache:foo")
    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert res.json()["deleted"] == 1


def test_valkey_delete_key_with_slash(client):
    """Keys containing `/` should be accepted via the {key:path} converter."""
    with patch("app.api.v1.system.valkey_inspect.delete_key", return_value={"ok": True, "deleted": 1}) as mock_del:
        # encodeURIComponent encodes `/` as %2F; FastAPI's {key:path} decodes it.
        res = client.delete("/api/v1/valkey/keys/cache:foo%2Fbar")
    assert res.status_code == 200
    mock_del.assert_called_once_with("cache:foo/bar")


def test_valkey_delete_key_ipv6_style(client):
    """Keys with `:` (e.g. IPv6-ish) should be accepted."""
    with patch("app.api.v1.system.valkey_inspect.delete_key", return_value={"ok": True, "deleted": 1}) as mock_del:
        res = client.delete("/api/v1/valkey/keys/revoked:token:abc:def")
    assert res.status_code == 200
    mock_del.assert_called_once_with("revoked:token:abc:def")


def test_valkey_delete_refuses_own_cache_key(client):
    with patch("app.api.v1.system.valkey_inspect.delete_key", return_value={"ok": False, "deleted": 0}):
        res = client.delete("/api/v1/valkey/keys/valkey_inspect:ns:cache")
    assert res.status_code == 200
    assert res.json()["ok"] is False


def test_valkey_delete_requires_admin(client):
    """A non-admin user should be forbidden from deleting keys."""
    from app.api.deps import get_current_user
    from app.models.models import User
    from app.main import app

    viewer = User(username="viewer", role="viewer", is_admin=False, hashed_password="x")
    app.dependency_overrides[get_current_user] = lambda: viewer
    try:
        res = client.delete("/api/v1/valkey/keys/cache:foo")
        assert res.status_code == 403
    finally:
        app.dependency_overrides[get_current_user] = lambda: User(
            username="test-admin", role="admin", is_admin=True, hashed_password="x"
        )
