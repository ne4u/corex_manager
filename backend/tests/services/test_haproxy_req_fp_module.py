"""Tests for the haproxy-req-fp Rust Lua module wiring in config generation.

The req_fp module is a Rust cdylib loaded via the combined modules.lua loader
(single lua-load-per-thread) when req_fp_enabled is true and the module is
available. The per-frontend http-request lua.req_fp_capture action is emitted
only when both conditions are met. The response-phase fingerprint is assembled
by native HAProxy http-response set-var-fmt directives (no Lua action).

The old standalone `lua-load /etc/haproxy/req_fp.lua` line is removed — req_fp
is now Rust-only (Docker-only), matching the compression/resp_transform/
api-armor modules.
"""
from app.services import haproxy
from app.services.settings import set_setting
from tests.factories import make_backend, make_listener, make_server


def test_req_fp_disabled_no_module_loading(db):
    """req_fp disabled → no combined loader for req_fp, no per-frontend actions."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "false")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "lua.req_fp_capture" not in cfg
    assert "lua.req_fp" not in cfg
    # The standalone lua-load req_fp.lua line is gone
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_req_fp_enabled_emits_combined_loader_and_actions(db):
    """req_fp enabled → combined loader contains req_fp module, per-frontend actions emitted."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    # Combined loader is emitted (lua-prepend-path + lua-load-per-thread)
    assert "lua-prepend-path /etc/haproxy/?.so cpath" in cfg
    assert "lua-load-per-thread" in cfg
    # The combined loader script includes the req_fp module require
    # (read the generated modules.lua to verify)
    import os
    from app.core.config import get_settings
    settings = get_settings()
    loader_path = os.path.join(
        os.path.dirname(os.path.abspath(settings.HAPROXY_CONFIG_PATH)),
        "modules.lua",
    )
    with open(loader_path) as f:
        loader_content = f.read()
    assert '"haproxy_req_fp_module"' in loader_content
    assert "req_fp.register" in loader_content
    # Per-frontend actions are emitted
    assert "http-request lua.req_fp_capture" in cfg
    assert "http-response lua.req_fp_response" in cfg


def test_req_fp_standalone_lua_load_removed(db):
    """The old standalone lua-load /etc/haproxy/req_fp.lua line is never emitted."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_req_fp_module_disabled_no_actions(db, monkeypatch):
    """REQ_FP_MODULE_ENABLED=false → no per-frontend actions even if req_fp_enabled=true."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "REQ_FP_MODULE_ENABLED", False)

    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    # Actions not emitted because module is unavailable
    assert "lua.req_fp_capture" not in cfg
    assert "lua.req_fp_response" not in cfg


def test_req_fp_log_format_var_still_present(db):
    """var(txn.req_fp) in log-format is always safe-empty when req_fp is off."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "false")
    db.commit()
    cfg = haproxy.generate_config(db)
    # The log-format still references var(txn.req_fp) — it returns empty
    # when the req_fp_capture action isn't emitted.
    assert "var(txn.req_fp)" in cfg
