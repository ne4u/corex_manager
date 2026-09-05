"""Tests for Server-Timing metrics in HAProxy config generation.

When server_timing_metrics_enabled is True, HAProxy adds connect/response/total
timing metrics (dur in ms) to the Server-Timing response header on all responses.

When Page Protect beacon trust is also enabled, the cxid and timing metrics are
combined in a single Server-Timing header on HTML responses, and timing-only
on non-HTML responses.
"""
from app.services.haproxy import generate_frontend
from tests.factories import make_backend, make_listener, make_server


def test_server_timing_metrics_emitted_on_all_responses(db):
    """Server-Timing with timing metrics is emitted on all responses (no condition)."""
    backend = make_backend(db, name="web")
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_server(db, backend.id)

    cfg = generate_frontend(listener, db, server_timing_metrics_enabled=True)

    # The timing-only line should have no condition (all responses)
    assert 'http-response set-header Server-Timing "total;dur=%Tt, connect;dur=%Tc, response;dur=%Tr"' in cfg, \
        "Server-Timing metrics not emitted on all responses"
    # Should NOT have the cxid-only line
    assert "cxid;desc" not in cfg, "cxid emitted when beacon_trust is not enabled"


def test_server_timing_metrics_not_emitted_when_disabled(db):
    """Server-Timing metrics are NOT emitted when the setting is off."""
    backend = make_backend(db, name="web")
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_server(db, backend.id)

    cfg = generate_frontend(listener, db, server_timing_metrics_enabled=False)

    assert "total;dur=%Tt" not in cfg, "Server-Timing metrics emitted when disabled"


def test_server_timing_combined_with_beacon_trust_on_html(db):
    """When both beacon_trust and timing metrics are enabled, HTML gets combined header."""
    backend = make_backend(db, name="web")
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_server(db, backend.id)

    cfg = generate_frontend(
        listener, db,
        server_timing_metrics_enabled=True,
        page_protect_enabled=True,
        page_protect_beacon={"enabled": False, "trust_enabled": True},
    )

    # HTML: combined cxid + timing
    assert 'cxid;desc=\\"%[var(txn.cxid)]\\", total;dur=%Tt, connect;dur=%Tc, response;dur=%Tr' in cfg, \
        "Combined cxid+timing not emitted on HTML responses"
    # Non-HTML: timing-only
    assert 'http-response set-header Server-Timing "total;dur=%Tt, connect;dur=%Tc, response;dur=%Tr" if !is_html_response' in cfg, \
        "Timing-only not emitted on non-HTML responses"


def test_server_timing_beacon_trust_only_no_timing(db):
    """When only beacon_trust is enabled (no timing), cxid-only on HTML (existing behavior)."""
    backend = make_backend(db, name="web")
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_server(db, backend.id)

    cfg = generate_frontend(
        listener, db,
        server_timing_metrics_enabled=False,
        page_protect_enabled=True,
        page_protect_beacon={"enabled": False, "trust_enabled": True},
    )

    # cxid-only on HTML (existing behavior, no timing metrics)
    assert 'http-response set-header Server-Timing "cxid;desc=\\"%[var(txn.cxid)]\\"" if is_html_response' in cfg, \
        "cxid-only Server-Timing not emitted on HTML"
    assert "total;dur=%Tt" not in cfg, "Timing metrics emitted when only beacon_trust is on"


def test_server_timing_metrics_via_generate_config(db):
    """generate_config reads the DB setting and passes it to generate_frontend."""
    from app.services import haproxy
    from app.services.settings import set_setting
    backend = make_backend(db, name="web")
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_server(db, backend.id)

    set_setting(db, "server_timing_metrics_enabled", "true")
    cfg = haproxy.generate_config(db)

    assert "total;dur=%Tt" in cfg, "Server-Timing metrics not emitted via generate_config"


def test_server_timing_metrics_disabled_by_default(db):
    """Server-Timing metrics are off by default (no DB setting)."""
    from app.services import haproxy
    backend = make_backend(db, name="web")
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_server(db, backend.id)

    cfg = haproxy.generate_config(db)

    assert "total;dur=%Tt" not in cfg, "Server-Timing metrics emitted by default"
