"""Tests for backend API persistence of restore_client_ip fields."""
from tests.factories import make_backend, make_server


def test_create_backend_with_restore_client_ip(client, db):
    """POST /backends with restore_client_ip=true persists the field."""
    r = client.post("/api/v1/backends", json={
        "name": "cdn_pool",
        "protocol": "http",
        "algorithm": "roundrobin",
        "restore_client_ip": True,
        "client_ip_header": "CF-Connecting-IP",
        "servers": [{"name": "srv1", "address": "10.0.0.1", "port": 80}],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["restore_client_ip"] is True
    assert data["client_ip_header"] == "CF-Connecting-IP"


def test_create_backend_defaults_restore_client_ip(client, db):
    """POST /backends without restore_client_ip defaults to False + X-Forwarded-For."""
    r = client.post("/api/v1/backends", json={
        "name": "origin_pool",
        "protocol": "http",
        "algorithm": "roundrobin",
        "servers": [{"name": "srv1", "address": "10.0.0.1", "port": 80}],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["restore_client_ip"] is False
    assert data["client_ip_header"] == "X-Forwarded-For"


def test_update_backend_restore_client_ip(client, db):
    """PUT /backends/{id} updates restore_client_ip and client_ip_header."""
    backend = make_backend(db, name="pool")
    make_server(db, backend.id)

    r = client.put(f"/api/v1/backends/{backend.id}", json={
        "restore_client_ip": True,
        "client_ip_header": "True-Client-IP",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["restore_client_ip"] is True
    assert data["client_ip_header"] == "True-Client-IP"


def test_create_backend_rejects_invalid_header_name(client, db):
    """POST /backends with invalid header name (semicolons) returns 422."""
    r = client.post("/api/v1/backends", json={
        "name": "bad_pool",
        "protocol": "http",
        "algorithm": "roundrobin",
        "restore_client_ip": True,
        "client_ip_header": "X-Forwarded-For; rm -rf /",
        "servers": [{"name": "srv1", "address": "10.0.0.1", "port": 80}],
    })
    assert r.status_code == 422
