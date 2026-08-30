"""Tests for the API Armor → req_fp dependency gating.

API Armor's body parser reads 9 req_fp subfields at runtime (req_fp_ctype,
req_fp_method, req_fp_path, req_fp_full, etc.). Without req_fp enabled,
those subfields are never set, breaking API Armor's content-type detection
and profiling telemetry.

Three layers of enforcement:
1. Settings update validation: reject api_armor_enabled=true if req_fp off;
   reject req_fp_enabled=false if api_armor on.
2. Config-gen defensive guard: force req_fp on if api_armor is on.
3. Frontend UX hints (tested via UI, not here).
"""
from app.services import haproxy
from app.services.settings import set_setting
from tests.factories import make_backend, make_listener, make_server


# ---- Layer 1: API settings endpoint rejects api_armor_enabled=true if req_fp off ----

def test_enable_api_armor_requires_req_fp(db, client):
    """PUT /api-armor/settings with api_armor_enabled=true → 400 if req_fp is off."""
    set_setting(db, "req_fp_enabled", "false")
    set_setting(db, "api_armor_enabled", "false")
    db.commit()
    resp = client.put("/api/v1/api-armor/settings", json={
        "api_armor_enabled": True,
        "api_armor_max_body_bytes": 1048576,
        "api_armor_module_enabled": True,
        "api_armor_schema_learning_enabled": False,
        "api_armor_profiling_learning_enabled": False,
        "api_armor_profile_retention_days": 30,
    })
    assert resp.status_code == 400
    assert "request fingerprinting" in resp.json()["detail"].lower()


def test_enable_api_armor_succeeds_when_req_fp_on(db, client):
    """PUT /api-armor/settings with api_armor_enabled=true → 200 if req_fp is on."""
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "api_armor_enabled", "false")
    db.commit()
    resp = client.put("/api/v1/api-armor/settings", json={
        "api_armor_enabled": True,
        "api_armor_max_body_bytes": 1048576,
        "api_armor_module_enabled": True,
        "api_armor_schema_learning_enabled": False,
        "api_armor_profiling_learning_enabled": False,
        "api_armor_profile_retention_days": 30,
    })
    assert resp.status_code == 200
    assert resp.json()["api_armor_enabled"] is True


# ---- Layer 1: Generic settings endpoint rejects req_fp_enabled=false if api_armor on ----

def test_disable_req_fp_blocked_when_api_armor_on(db, client):
    """PUT /settings/req_fp_enabled value=false → 400 if api_armor is enabled."""
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    resp = client.put("/api/v1/settings/req_fp_enabled", json={"value": "false"})
    assert resp.status_code == 400
    assert "api armor" in resp.json()["detail"].lower()


def test_disable_req_fp_succeeds_when_api_armor_off(db, client):
    """PUT /settings/req_fp_enabled value=false → 200 if api_armor is off."""
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "api_armor_enabled", "false")
    db.commit()
    resp = client.put("/api/v1/settings/req_fp_enabled", json={"value": "false"})
    assert resp.status_code == 200


# ---- Layer 2: Config-gen defensive guard ----

def test_config_gen_forces_req_fp_when_api_armor_on(db):
    """If api_armor_enabled=true and req_fp_enabled=false in DB (bypassing API),
    generate_config forces req_fp on and emits lua.req_fp_capture."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "api_armor_enabled", "true")
    set_setting(db, "req_fp_enabled", "false")
    db.commit()
    cfg = haproxy.generate_config(db)
    # req_fp actions are emitted despite req_fp_enabled=false in DB
    # because the defensive guard forces it on when api_armor is on
    assert "http-request lua.req_fp_capture" in cfg
    assert "http-response lua.req_fp" in cfg


def test_config_gen_no_force_when_api_armor_off(db):
    """If api_armor_enabled=false and req_fp_enabled=false, req_fp stays off."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "api_armor_enabled", "false")
    set_setting(db, "req_fp_enabled", "false")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "lua.req_fp_capture" not in cfg
    assert "lua.req_fp" not in cfg
