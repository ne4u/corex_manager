"""Tests for API Armor conditional body buffering and module loading in haproxy config generation.

API Armor is gated by the `api_armor_enabled` DB setting (with env fallback).
When enabled, listeners with the `api_armor` option get conditional body
buffering (wait-for-body for JSON/form/graphql content types) and the
lua.api_body_parse action. The Rust module is loaded via the combined
modules.lua loader.
"""
from app.services import haproxy
from app.services.settings import set_setting
from tests.factories import make_backend, make_listener, make_server


def test_no_api_armor_by_default(db):
    """API Armor disabled by default → no body buffering or parse actions."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    cfg = haproxy.generate_config(db)
    assert "is_api_armor" not in cfg
    assert "lua.api_body_parse" not in cfg
    assert "wait-for-body time 10s if is_api_armor" not in cfg


def test_api_armor_enabled_but_listener_not_opted_in(db):
    """API Armor enabled globally but listener has no api_armor option → no buffering."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "is_api_armor" not in cfg


def test_api_armor_enabled_and_listener_opted_in(db):
    """API Armor enabled + listener has api_armor option → body buffering emitted."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "acl is_api_armor" in cfg
    assert "wait-for-body time 10s if is_api_armor" in cfg
    assert "set-var(txn.api_body) req.body if is_api_armor" in cfg
    assert "lua.api_body_parse if is_api_armor" in cfg


def test_api_armor_max_body_deny_line(db):
    """Max body size deny line uses the configured api_armor_max_body_bytes setting."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "api_armor_enabled", "true")
    set_setting(db, "api_armor_max_body_bytes", "524288")  # 512KB
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "deny_status 413 if is_api_armor { req.body_len gt 524288 }" in cfg


def test_api_armor_module_loaded_in_global_section(db):
    """Global section includes api_armor in the combined modules.lua loader when enabled."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    # The combined loader is written to modules.lua and loaded via lua-load-per-thread
    assert "lua-load-per-thread" in cfg
    # Verify the loader file contains the api_armor module require
    import os
    from app.core.config import get_settings
    settings = get_settings()
    loader_path = os.path.join(
        os.path.dirname(os.path.abspath(settings.HAPROXY_CONFIG_PATH)),
        "modules.lua",
    )
    if os.path.exists(loader_path):
        with open(loader_path) as f:
            loader_content = f.read()
        assert "haproxy_api_armor_module" in loader_content


def test_api_armor_content_type_acl(db):
    """The is_api_armor ACL matches JSON, GraphQL, and form content types."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "application/json" in cfg
    assert "application/graphql" in cfg
    assert "application/x-www-form-urlencoded" in cfg


def test_api_armor_disabled_does_not_load_module(db):
    """API Armor disabled → no api_armor module in the combined loader."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "api_armor_enabled", "false")
    db.commit()
    # Remove stale modules.lua from previous tests so we get a clean check
    import os
    from app.core.config import get_settings
    settings = get_settings()
    loader_path = os.path.join(
        os.path.dirname(os.path.abspath(settings.HAPROXY_CONFIG_PATH)),
        "modules.lua",
    )
    if os.path.exists(loader_path):
        os.remove(loader_path)
    cfg = haproxy.generate_config(db)
    if os.path.exists(loader_path):
        with open(loader_path) as f:
            loader_content = f.read()
        assert "haproxy_api_armor_module" not in loader_content
