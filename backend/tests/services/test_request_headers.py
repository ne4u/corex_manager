"""Tests for backend-scoped request header HAProxy config generation.

Verifies that HAProxy sample-fetch expressions (%[src], %[hdr(...)], etc.) and
ACL-style conditions pass through sanitization unchanged so users can configure
directives like:

    http-request add-header X-Forwarded-For %[src] if !{ hdr_val(X-Forwarded-For) -m found }
    http-request set-header X-Forwarded-For %[hdr(X-Forwarded-For)] ,%[src] if { hdr_val(X-Forwarded-For) -m found }
"""
from app.services import haproxy
from tests.factories import make_backend, make_request_header, make_server


def test_request_header_sample_fetch_in_value(db):
    """%[src] in the value field survives sanitization and is emitted in the backend section."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_request_header(
        db,
        name="xff-add",
        backend_id=backend.id,
        header="X-Forwarded-For",
        value="%[src]",
        action="add",
        condition="!{ hdr_val(X-Forwarded-For) -m found }",
    )
    cfg = haproxy.generate_config(db)
    assert 'http-request add-header X-Forwarded-For "%[src]" if !{ hdr_val(X-Forwarded-For) -m found }' in cfg


def test_request_header_concatenated_samples_in_value(db):
    """Comma-separated sample expressions like %[hdr(...)] ,%[src] are preserved."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_request_header(
        db,
        name="xff-set",
        backend_id=backend.id,
        header="X-Forwarded-For",
        value="%[hdr(X-Forwarded-For)] ,%[src]",
        action="override",
        condition="{ hdr_val(X-Forwarded-For) -m found }",
    )
    cfg = haproxy.generate_config(db)
    assert 'http-request set-header X-Forwarded-For "%[hdr(X-Forwarded-For)] ,%[src]" if { hdr_val(X-Forwarded-For) -m found }' in cfg


def test_request_header_del_action(db):
    """del action emits del-header without a value."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_request_header(
        db,
        name="rm-header",
        backend_id=backend.id,
        header="X-Internal-Debug",
        value="ignored",
        action="del",
    )
    cfg = haproxy.generate_config(db)
    assert "http-request del-header X-Internal-Debug" in cfg


def test_request_header_scoped_to_specific_backend(db):
    """A request header bound to one backend does not appear in another backend's section."""
    b1 = make_backend(db, name="web1")
    b2 = make_backend(db, name="web2")
    make_server(db, b1.id)
    make_server(db, b2.id)
    make_request_header(
        db,
        name="b1-only",
        backend_id=b1.id,
        header="X-Backend",
        value="%[src]",
        action="add",
    )
    cfg = haproxy.generate_config(db)
    assert 'http-request add-header X-Backend "%[src]"' in cfg
    # The header should appear in backend web1's section but not web2's
    b1_section = cfg.split("backend web1")[1].split("backend ")[0] if "backend web1" in cfg else ""
    b2_section = cfg.split("backend web2")[1].split("backend ")[0] if "backend web2" in cfg else ""
    assert "X-Backend" in b1_section
    assert "X-Backend" not in b2_section


def test_request_header_global_applies_to_all_backends(db):
    """A request header with no backend binding applies to all HTTP backends."""
    b1 = make_backend(db, name="web1")
    b2 = make_backend(db, name="web2")
    make_server(db, b1.id)
    make_server(db, b2.id)
    make_request_header(
        db,
        name="global-rh",
        backend_id=None,
        backend_ids=[],
        header="X-Global",
        value="%[src]",
        action="add",
    )
    cfg = haproxy.generate_config(db)
    assert cfg.count('http-request add-header X-Global "%[src]"') == 2


def test_request_header_not_duplicated_in_frontend(db):
    """Request headers are emitted only in backend sections, never in the
    frontend — emitting in both caused 'add' headers to be applied twice
    (duplicated value at the upstream server)."""
    from tests.factories import make_listener

    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http_in", bind_port=80)
    make_request_header(
        db,
        name="true-ip",
        backend_id=None,
        backend_ids=[],
        header="X-True-Ip",
        value="%[src]",
        action="add",
    )
    cfg = haproxy.generate_config(db)
    # Exactly once: in the single backend section, not in the frontend
    assert cfg.count('http-request add-header X-True-Ip "%[src]"') == 1
    frontend_section = cfg.split("frontend http_in")[1].split("backend ")[0]
    assert "X-True-Ip" not in frontend_section


def test_request_header_skipped_for_tcp_backend(db):
    """Request headers are not emitted for TCP-mode backends."""
    backend = make_backend(db, name="tcp_be", protocol="tcp", mode="tcp")
    make_server(db, backend.id)
    make_request_header(
        db,
        name="tcp-rh",
        backend_id=backend.id,
        header="X-TCP",
        value="%[src]",
        action="add",
    )
    cfg = haproxy.generate_config(db)
    assert "X-TCP" not in cfg


def test_request_header_condition_with_leading_if(db):
    """A condition that starts with 'if' should not produce a double 'if'."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_request_header(
        db,
        name="xff-add",
        backend_id=backend.id,
        header="X-Forwarded-For",
        value="%[src]",
        action="add",
        condition="if !{ hdr_val(X-Forwarded-For) -m found }",
    )
    cfg = haproxy.generate_config(db)
    assert 'http-request add-header X-Forwarded-For "%[src]" if !{ hdr_val(X-Forwarded-For) -m found }' in cfg
    # Must not contain double "if if"
    assert "if if" not in cfg
