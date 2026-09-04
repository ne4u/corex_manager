"""Tests for req_fp_parse_body — independent body buffering for request fingerprinting.

When req_fp_enabled and req_fp_parse_body are both on (and API Armor is not
handling the listener), the generated HAProxy config emits:
  - an is_req_fp_body ACL matching form/JSON content types
  - an is_req_fp_body_oversize ACL gating on req_fp_max_body_bytes
  - wait-for-body + set-var(txn.req_fp_body) BEFORE lua.req_fp_capture,
    scoped to !is_req_fp_body_oversize so oversized bodies skip buffering
    (req_fp.lua falls back to query-only; body params become nil)
  - when req_fp_enforce_max_body is on, an additional 413 deny for
    oversized bodies

When API Armor is enabled on the listener, it handles body buffering via
txn.api_body and the req_fp_parse_body path is skipped (no double buffering).
"""
from app.services import haproxy
from app.services.settings import set_setting
from tests.factories import make_backend, make_listener, make_server


def test_req_fp_parse_body_disabled_by_default(db):
    """req_fp_parse_body off → no is_req_fp_body ACL or body buffering."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "is_req_fp_body" not in cfg
    assert "txn.req_fp_body" not in cfg


def test_req_fp_parse_body_enabled_emits_buffering(db):
    """req_fp + req_fp_parse_body on → body buffering emitted before capture."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "acl is_req_fp_body" in cfg
    assert "acl is_req_fp_body_oversize" in cfg
    assert "wait-for-body time 10s if is_req_fp_body !is_req_fp_body_oversize" in cfg
    assert "set-var(txn.req_fp_body) req.body if is_req_fp_body !is_req_fp_body_oversize" in cfg
    # The set-var must appear BEFORE lua.req_fp_capture in the config
    set_var_idx = cfg.index("set-var(txn.req_fp_body) req.body if is_req_fp_body !is_req_fp_body_oversize")
    capture_idx = cfg.index("lua.req_fp_capture")
    assert set_var_idx < capture_idx, "req_fp_body set-var must precede lua.req_fp_capture"


def test_req_fp_parse_body_released_after_capture(db):
    """The buffered body var is unset right after lua.req_fp_capture consumes it."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    unset_line = "http-request unset-var(txn.req_fp_body) if is_req_fp_body"
    assert unset_line in cfg
    assert cfg.index("lua.req_fp_capture") < cfg.index(unset_line)


def test_req_fp_parse_body_content_type_acl(db):
    """The is_req_fp_body ACL matches JSON and form content types (not GraphQL)."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "application/json" in cfg
    assert "application/x-www-form-urlencoded" in cfg
    # GraphQL is NOT included in req_fp_parse_body (only API Armor handles it)
    # Find the is_req_fp_body ACL line specifically
    for line in cfg.splitlines():
        if "is_req_fp_body" in line and "acl" in line:
            assert "application/graphql" not in line
            break


def test_req_fp_parse_body_max_body_oversize_acl(db):
    """Oversize ACL uses the configured req_fp_max_body_bytes setting.

    Default (req_fp_enforce_max_body off): oversized bodies skip buffering,
    no 413 deny is emitted.
    """
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    set_setting(db, "req_fp_max_body_bytes", "524288")  # 512KB
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "acl is_req_fp_body_oversize req.body_len gt 524288" in cfg
    # Oversized bodies skip buffering instead of being rejected with 413
    assert "deny_status 413 if is_req_fp_body" not in cfg
    # wait-for-body / set-var are scoped to !is_req_fp_body_oversize
    assert "wait-for-body time 10s if is_req_fp_body !is_req_fp_body_oversize" in cfg
    assert "set-var(txn.req_fp_body) req.body if is_req_fp_body !is_req_fp_body_oversize" in cfg


def test_req_fp_parse_body_enforce_max_body_emits_413(db):
    """req_fp_enforce_max_body on → oversized bodies rejected with 413."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    set_setting(db, "req_fp_max_body_bytes", "524288")  # 512KB
    set_setting(db, "req_fp_enforce_max_body", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "acl is_req_fp_body_oversize req.body_len gt 524288" in cfg
    assert "deny_status 413 if is_req_fp_body is_req_fp_body_oversize" in cfg
    # Non-oversized bodies still get buffered
    assert "wait-for-body time 10s if is_req_fp_body !is_req_fp_body_oversize" in cfg
    assert "set-var(txn.req_fp_body) req.body if is_req_fp_body !is_req_fp_body_oversize" in cfg


def test_req_fp_parse_body_enforce_max_body_default_off(db):
    """req_fp_enforce_max_body defaults to off (no 413 deny)."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "deny_status 413 if is_req_fp_body" not in cfg


def test_req_fp_parse_body_skipped_when_api_armor_on_listener(db):
    """API Armor on listener → req_fp_parse_body skipped (no double buffering)."""
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "req_fp_parse_body", "true")
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    # API Armor handles body buffering, so req_fp_parse_body path is skipped
    assert "is_req_fp_body" not in cfg
    assert "txn.req_fp_body" not in cfg
    # But API Armor's body buffering is present
    assert "set-var(txn.api_body) req.body if is_api_armor" in cfg


def test_req_fp_parse_body_skipped_when_req_fp_disabled(db):
    """req_fp disabled → req_fp_parse_body has no effect."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in")
    set_setting(db, "req_fp_enabled", "false")
    set_setting(db, "req_fp_parse_body", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    assert "is_req_fp_body" not in cfg
    assert "txn.req_fp_body" not in cfg
    assert "lua.req_fp_capture" not in cfg


def test_api_armor_set_var_precedes_req_fp_capture(db):
    """API Armor's set-var(txn.api_body) must run before lua.req_fp_capture.

    This is a regression test for the ordering fix: previously the API Armor
    block (including set-var(txn.api_body)) was emitted AFTER req_fp_capture,
    so req_fp.lua could never see txn.api_body during the capture phase.
    """
    backend = make_backend(db)
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="http_in")
    listener.options = {"api_armor": True}
    db.commit()
    set_setting(db, "req_fp_enabled", "true")
    set_setting(db, "api_armor_enabled", "true")
    db.commit()
    cfg = haproxy.generate_config(db)
    set_var_idx = cfg.index("set-var(txn.api_body) req.body if is_api_armor")
    capture_idx = cfg.index("lua.req_fp_capture")
    assert set_var_idx < capture_idx, "api_body set-var must precede lua.req_fp_capture"
    # But lua.api_body_parse must still run AFTER req_fp_capture
    parse_idx = cfg.index("lua.api_body_parse if is_api_armor")
    assert parse_idx > capture_idx, "lua.api_body_parse must follow lua.req_fp_capture"
