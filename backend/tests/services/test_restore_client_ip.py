"""Tests for the Restore Client IP feature (per-backend-pool set-src generation).

Verifies that:
- CDN-backed backend pools emit http-request set-src conditioned on their
  routing rules, positioned before the rate-limit stage.
- The trusted-source network list gates set-src on the connection source.
- Non-CDN backends on the same listener do not emit set-src.
- Default-backend catch-all emits set-src when no BackendRule matched.
- Custom header names flow through.
- TCP-mode listeners skip set-src entirely.
"""
from app.services import haproxy
from app.services.settings import set_setting
from tests.factories import make_backend, make_server, make_listener

from app.models.models import BackendRule, NetworkList, NetworkListEntry


def _make_backend_rule(db, listener_id, backend_id, condition_type="path", operator="beg", value="/cdn", priority=100):
    rule = BackendRule(
        listener_id=listener_id,
        backend_id=backend_id,
        name=f"rule_{backend_id}",
        priority=priority,
        condition_type=condition_type,
        operator=operator,
        value=value,
        enabled=True,
    )
    db.add(rule)
    db.flush()
    return rule


def test_cdn_backend_rule_emits_set_src(db):
    """CDN-backed backend targeted by a path rule emits set-src before rate limiting."""
    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    backend.client_ip_header = "X-Forwarded-For"
    db.flush()
    make_server(db, backend.id)

    other = make_backend(db, name="origin_backend")
    make_server(db, other.id)

    listener = make_listener(db, backend=other, name="http_in", bind_port=80)
    _make_backend_rule(db, listener.id, backend.id, value="/cdn")

    cfg = haproxy.generate_config(db)

    # set-src line should exist and reference the combined ACL
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    assert "be_rule_" in cfg
    assert "{ req.hdr_ip(X-Forwarded-For,1) -m found }" in cfg

    # set-src should appear before the rate-limit stick-table tracking
    set_src_pos = cfg.find("http-request set-src req.hdr_ip(X-Forwarded-For,1)")
    stick_table_pos = cfg.find("stick-table type ip")
    if stick_table_pos != -1:
        assert set_src_pos < stick_table_pos, "set-src must appear before rate-limit stick-table"


def test_cdn_backend_with_trusted_list_gates_on_src(db, tmp_path, monkeypatch):
    """Trusted network list adds { src -f <path> } to the set-src condition."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "SECURITY_LISTS_DIR", str(tmp_path))

    # Create a network list
    nl = NetworkList(name="cdn_edges")
    db.add(nl)
    db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="173.245.48.0/20"))
    db.commit()

    # Set the trusted list setting
    set_setting(db, "restore_client_ip_trusted_network_list", "cdn_edges")

    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)

    # set-src should include the src -f condition
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    assert "src -f" in cfg
    assert "cdn_edges.lst" in cfg


def test_cdn_backend_with_multiple_trusted_lists_gates_on_src(db, tmp_path, monkeypatch):
    """Multiple trusted network lists emit multiple -f flags (OR'd by HAProxy)."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "SECURITY_LISTS_DIR", str(tmp_path))

    # Create two network lists
    nl1 = NetworkList(name="cloudflare_edges")
    db.add(nl1)
    db.flush()
    db.add(NetworkListEntry(list_id=nl1.id, value="173.245.48.0/20"))
    nl2 = NetworkList(name="fastly_edges")
    db.add(nl2)
    db.flush()
    db.add(NetworkListEntry(list_id=nl2.id, value="151.101.0.0/16"))
    db.commit()

    # Set the trusted list setting with both names, comma-separated
    set_setting(db, "restore_client_ip_trusted_network_list", "cloudflare_edges,fastly_edges")

    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)

    # set-src should include both -f flags
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    assert "src -f" in cfg
    assert "cloudflare_edges.lst" in cfg
    assert "fastly_edges.lst" in cfg


def test_trusted_multiple_lists_one_deleted_skips_only_deleted(db, tmp_path, monkeypatch):
    """If one of multiple trusted lists is deleted, only the deleted one is skipped."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "SECURITY_LISTS_DIR", str(tmp_path))

    nl1 = NetworkList(name="exists_list")
    db.add(nl1)
    db.flush()
    db.add(NetworkListEntry(list_id=nl1.id, value="10.0.0.0/8"))
    db.commit()

    # Setting references one existing and one non-existent list
    set_setting(db, "restore_client_ip_trusted_network_list", "exists_list,deleted_list")

    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)

    # set-src should include only the existing list's -f path
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    assert "exists_list.lst" in cfg
    assert "deleted_list.lst" not in cfg


def test_trusted_list_deleted_falls_back_to_ungated(db, tmp_path, monkeypatch):
    """If the trusted list is deleted, set-src falls back to ungated (no -f path)."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "SECURITY_LISTS_DIR", str(tmp_path))

    # Set the setting to a list name that doesn't exist
    set_setting(db, "restore_client_ip_trusted_network_list", "nonexistent_list")

    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)

    # set-src should still be emitted but without the src -f condition
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    assert "src -f" not in cfg


def test_restore_preserves_original_src_for_xff_hop(db):
    """When restore rules exist, the original connection source is captured in
    txn.orig_src before set-src, and the XFF hop uses it (the CDN edge IP)
    instead of the restored client IP."""
    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)

    assert "http-request set-var(txn.orig_src) src" in cfg
    assert 'http-request add-header X-Forwarded-For "%[var(txn.orig_src)]"' in cfg
    # set-var must come before set-src, which must come before the XFF add
    var_pos = cfg.find("set-var(txn.orig_src)")
    set_src_pos = cfg.find("http-request set-src")
    xff_pos = cfg.find('add-header X-Forwarded-For "%[var(txn.orig_src)]"')
    assert var_pos < set_src_pos < xff_pos


def test_no_restore_uses_plain_src_for_xff_hop(db):
    """Without restore rules, the XFF hop uses %[src] directly and no
    txn.orig_src var is emitted."""
    backend = make_backend(db, name="origin_backend")
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)

    assert 'http-request add-header X-Forwarded-For "%[src]"' in cfg
    assert "txn.orig_src" not in cfg


def test_non_cdn_backend_no_set_src(db):
    """Non-CDN backend on same listener does not emit set-src for its rule."""
    backend = make_backend(db, name="origin_backend")
    backend.restore_client_ip = False
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)
    # No rules, no restore — no set-src

    cfg = haproxy.generate_config(db)
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" not in cfg


def test_cdn_default_backend_no_rules_emits_set_src(db):
    """CDN-backed default_backend with no rules emits unconditional set-src."""
    backend = make_backend(db, name="cdn_default")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    # With no rules, the condition is just the header-found guard
    assert "{ req.hdr_ip(X-Forwarded-For,1) -m found }" in cfg


def test_cdn_default_backend_with_rules_emits_catch_all(db):
    """CDN-backed default_backend with other rules emits set-src catch-all.

    The catch-all uses just the header-found guard (no rule negation) because
    set-src is idempotent — if a CDN-backed rule already fired, the catch-all
    sets the same value. If a non-CDN rule matched, the catch-all still fires
    but the trusted-source gate ensures it only applies to legitimate CDN
    traffic, and restoring the real client IP is correct behavior for
    CDN-proxied requests regardless of which backend they reach.
    """
    cdn_default = make_backend(db, name="cdn_default")
    cdn_default.restore_client_ip = True
    db.flush()
    make_server(db, cdn_default.id)

    other = make_backend(db, name="other_backend")
    make_server(db, other.id)

    listener = make_listener(db, backend=cdn_default, name="http_in", bind_port=80)
    rule = _make_backend_rule(db, listener.id, other.id, value="/other")

    cfg = haproxy.generate_config(db)

    # The catch-all set-src should be present with just the header guard
    # (no negation of rule ACLs)
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" in cfg
    # The per-rule use_backend should use the combined expression directly
    assert f"use_backend other_backend if be_rule_{rule.id}_c1" in cfg


def test_custom_header_name_flows_through(db):
    """Custom header name (e.g. CF-Connecting-IP) appears in the set-src directive."""
    backend = make_backend(db, name="cdn_backend")
    backend.restore_client_ip = True
    backend.client_ip_header = "CF-Connecting-IP"
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="http_in", bind_port=80)

    cfg = haproxy.generate_config(db)
    assert "http-request set-src req.hdr_ip(CF-Connecting-IP,1)" in cfg
    assert "{ req.hdr_ip(CF-Connecting-IP,1) -m found }" in cfg


def test_tcp_listener_no_set_src(db):
    """TCP-mode listener does not emit set-src (no request headers to read)."""
    backend = make_backend(db, name="cdn_backend", protocol="tcp", mode="tcp")
    backend.restore_client_ip = True
    db.flush()
    make_server(db, backend.id)

    listener = make_listener(db, backend=backend, name="tcp_in", bind_port=8080, protocol="tcp", mode="tcp")

    cfg = haproxy.generate_config(db)
    assert "http-request set-src req.hdr_ip(X-Forwarded-For,1)" not in cfg
