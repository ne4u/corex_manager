from app.services import haproxy
from tests.factories import make_backend, make_listener, make_rewrite, make_server


def test_rewrite_without_host_emits_no_host_acl(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rewrite(db, name="rw_plain", listener_ids=[listener.id], host_match=None)
    cfg = haproxy.generate_config(db)
    assert "acl rewrite_path_rw_plain path_reg ^/" in cfg
    assert "http-request set-path /prefix%[path] if rewrite_path_rw_plain" in cfg
    assert "rewrite_host_rw_plain" not in cfg


def test_rewrite_with_host_emits_host_acl_and_combined_condition(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rewrite(db, name="rw_host", listener_ids=[listener.id], host_match="test.bob.com")
    cfg = haproxy.generate_config(db)
    assert "acl rewrite_path_rw_host path_reg ^/" in cfg
    assert "acl rewrite_host_rw_host hdr(host) -i test.bob.com" in cfg
    assert (
        "http-request set-path /prefix%[path] if rewrite_path_rw_host rewrite_host_rw_host"
        in cfg
    )


def test_rewrite_both_type_emits_acls_once(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rewrite(
        db,
        name="rw_both",
        listener_ids=[listener.id],
        host_match="test.bob.com",
        type="both",
    )
    cfg = haproxy.generate_config(db)
    # path_reg and host ACLs must appear exactly once each (not duplicated by the query block)
    assert cfg.count("acl rewrite_path_rw_both path_reg ^/") == 1
    assert cfg.count("acl rewrite_host_rw_both hdr(host) -i test.bob.com") == 1
    assert (
        "http-request set-path /prefix%[path] if rewrite_path_rw_both rewrite_host_rw_both"
        in cfg
    )
    assert "http-request set-query" in cfg


def test_rewrite_query_only_with_host_emits_acls_in_query_block(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rewrite(
        db,
        name="rw_q",
        listener_ids=[listener.id],
        host_match="test.bob.com",
        type="query",
    )
    cfg = haproxy.generate_config(db)
    assert "acl rewrite_path_rw_q path_reg ^/" in cfg
    assert "acl rewrite_host_rw_q hdr(host) -i test.bob.com" in cfg
    assert "http-request set-query" in cfg
    assert "rewrite_host_rw_q" in cfg
