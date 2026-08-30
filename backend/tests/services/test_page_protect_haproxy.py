"""Tests for Page Protect HAProxy config generation."""
from app.services.haproxy import generate_config, generate_frontend, generate_backend, _default_json_log_format
from app.services.page_protect import is_page_protect_enabled
from app.services.settings import set_setting
from tests.factories import make_backend, make_listener, make_page_protect_policy


def test_log_format_includes_csp_report_field():
    fmt = _default_json_log_format(ja4_enabled=False, page_protect_enabled=True)
    assert "csp_report" in fmt
    assert "txn.csp_report" in fmt
    # The json converter escapes the CSP report body (which is itself JSON) but
    # does NOT wrap it in quotes. We wrap it ourselves so the log line is valid
    # JSON. When empty, the output is "csp_report":"-" (valid JSON string).
    assert '"csp_report":"%[var(txn.csp_report),json]"' in fmt


def test_log_format_excludes_csp_report_when_disabled():
    fmt = _default_json_log_format(ja4_enabled=False, page_protect_enabled=False)
    assert "csp_report" not in fmt


def test_frontend_emits_csp_report_capture(db):
    listener = make_listener(db, name="http_in", bind_port=80)
    db.commit()
    config = generate_frontend(listener, db, page_protect_enabled=True, page_protect_report_path="/_csp-report")
    assert "is_csp_report" in config
    assert "wait-for-body" in config
    assert "txn.csp_report" in config
    assert "return status 204" in config


def test_frontend_no_csp_rules_when_disabled(db):
    listener = make_listener(db, name="http_in", bind_port=80)
    db.commit()
    config = generate_frontend(listener, db, page_protect_enabled=False)
    assert "is_csp_report" not in config
    assert "txn.csp_report" not in config


def test_backend_emits_csp_header_monitor(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             directives={"script-src": ["'self'", "https://cdn.example.com"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    assert "Content-Security-Policy-Report-Only" in config
    assert "script-src" in config
    assert "'self'" in config
    assert "https://cdn.example.com" in config


def test_backend_emits_csp_report_uri(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             report_path="/_csp-report",
                             directives={"default-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    assert "report-uri /_csp-report" in config


def test_backend_csp_header_value_is_not_double_quoted(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             directives={"default-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    # The config line should use a single HAProxy double-quoted token and the
    # browser must not receive a value starting with a double quote.
    assert '    http-response set-header Content-Security-Policy-Report-Only "default-src' in config
    assert '"default-src' not in config.split("\n")[0]
    # Make sure the value is not wrapped in outer single quotes that would keep
    # the literal double quotes in the header value sent to the browser.
    assert "'\"default-src" not in config


def test_backend_emits_csp_header_enforce(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="enforce",
                             directives={"default-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    assert "Content-Security-Policy" in config
    assert "Content-Security-Policy-Report-Only" not in config


def test_backend_csp_header_sampling(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             sample_rate_percent=50, directives={"script-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    assert "rand(100)" in config
    assert "lt 50" in config


def test_backend_csp_header_full_sample_no_rand(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             sample_rate_percent=100, directives={"script-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    assert "rand(100)" not in config


def test_backend_csp_header_per_backend_scoping(db):
    backend1 = make_backend(db, name="be1")
    backend2 = make_backend(db, name="be2")
    make_page_protect_policy(db, name="p1", backend_ids=[backend1.id], mode="monitor",
                             directives={"script-src": ["'self'"]})
    db.commit()
    config1 = generate_backend(backend1, db, page_protect_enabled=True)
    config2 = generate_backend(backend2, db, page_protect_enabled=True)
    assert "Content-Security-Policy-Report-Only" in config1
    assert "Content-Security-Policy-Report-Only" not in config2


def test_backend_csp_header_all_backends_when_empty(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[], mode="monitor",
                             directives={"script-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=True)
    assert "Content-Security-Policy-Report-Only" in config


def test_backend_no_csp_when_disabled(db):
    backend = make_backend(db, name="be1")
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             directives={"script-src": ["'self'"]})
    db.commit()
    config = generate_backend(backend, db, page_protect_enabled=False)
    assert "Content-Security-Policy" not in config


def test_generate_config_with_page_protect_enabled(db):
    listener = make_listener(db, name="http_in", bind_port=80)
    backend = make_backend(db, name="be1")
    listener.default_backend_id = backend.id
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             directives={"script-src": ["'self'"]})
    set_setting(db, "page_protect_monitoring_enabled", "true")
    db.commit()
    config = generate_config(db)
    assert "is_csp_report" in config
    assert "Content-Security-Policy-Report-Only" in config
    assert "csp_report" in config  # log-format field


def test_generate_config_without_page_protect(db):
    listener = make_listener(db, name="http_in", bind_port=80)
    backend = make_backend(db, name="be1")
    listener.default_backend_id = backend.id
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             directives={"script-src": ["'self'"]})
    set_setting(db, "page_protect_monitoring_enabled", "false")
    db.commit()
    config = generate_config(db)
    assert "is_csp_report" not in config
    assert "Content-Security-Policy-Report-Only" not in config


def test_is_page_protect_enabled_default(db):
    assert is_page_protect_enabled(db) is False


def test_is_page_protect_enabled_true(db):
    set_setting(db, "page_protect_monitoring_enabled", "true")
    db.commit()
    assert is_page_protect_enabled(db) is True


def test_generate_config_sets_log_len_for_csp_reports(db):
    """CSP report bodies can exceed the default 1024-byte HAProxy log line."""
    listener = make_listener(db, name="http_in", bind_port=80)
    backend = make_backend(db, name="be1")
    listener.default_backend_id = backend.id
    make_page_protect_policy(db, name="p1", backend_ids=[backend.id], mode="monitor",
                             directives={"script-src": ["'self'"]})
    set_setting(db, "page_protect_monitoring_enabled", "true")
    db.commit()
    config = generate_config(db)
    assert "log stdout len 65535 format raw daemon" in config


def test_generate_frontend_inherits_log_len_for_csp_reports(db):
    """Per-listener log targets must also use the raised len limit."""
    from app.models.logging import LogDestination

    listener = make_listener(db, name="http_in", bind_port=80)
    db.add(LogDestination(name="stdout-test", target="stdout", facility="local0", enabled=True))
    db.add(LogDestination(name="syslog-test", target="127.0.0.1:514", facility="local0", level="info", enabled=True))
    db.commit()
    config = generate_frontend(listener, db)
    assert "log stdout len 65535 format raw local0" in config
    assert "log 127.0.0.1:514 len 65535 local0 info" in config
