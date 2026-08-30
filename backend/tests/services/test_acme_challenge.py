"""Tests for ACME HTTP-01 challenge HAProxy config generation."""
from app.services import haproxy
from tests.factories import make_backend, make_listener, make_server


def test_acme_frontend_uses_exact_token_regex(db):
    """The ACME ACL should only match exact token paths, not path_beg."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    # Exact token regex, not path_beg
    assert "acl is_acme_challenge path -m reg '^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$'" in cfg
    assert "path_beg /.well-known/acme-challenge/" not in cfg


def test_acme_frontend_no_allow_bypass(db):
    """The old http-request allow bypass should be gone."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "http-request allow if is_acme_challenge" not in cfg


def test_acme_frontend_sets_webroot_var(db):
    """The webroot path should be set in a txn variable for the Lua script."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "http-request set-var(txn.acme_file) path,field(3,/) if is_acme_challenge" in cfg
    assert "http-request set-var(txn.acme_webroot)" in cfg
    assert "acme-webroot" in cfg


def test_acme_frontend_lua_content_serve(db):
    """Challenge files should be served via Lua fetch with -m found guard."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "http-request set-var(txn.acme_content) lua.acme_challenge_file if is_acme_challenge" in cfg
    assert 'http-request return status 200 content-type "application/octet-stream" lf-string "%[var(txn.acme_content)]"' in cfg
    assert "var(txn.acme_content) -m found" in cfg


def test_acme_use_backend_fallback_guarded(db):
    """The use_backend fallback should only fire when webroot file is missing."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "use_backend acme_challenge_backend if is_acme_challenge" in cfg
    assert "!{ var(txn.acme_content) -m found }" in cfg


def test_acme_backend_has_deny_guard(db):
    """The ACME backend should deny non-token paths (defense in depth)."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "backend acme_challenge_backend" in cfg
    assert "http-request deny status 403 unless { path -m reg '^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$' }" in cfg


def test_acme_lua_script_loaded(db):
    """The acme.lua script should be loaded in the global section."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "lua-load /etc/haproxy/acme.lua" in cfg


def test_acme_not_emitted_for_tcp_listener(db):
    """ACME use_backend should not be emitted for TCP-mode listeners."""
    backend = make_backend(db, mode="tcp")
    listener = make_listener(db, backend=backend, protocol="tcp", mode="tcp")
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    # The ACL is still emitted (harmless), but use_backend is not for TCP
    assert "use_backend acme_challenge_backend" not in cfg
