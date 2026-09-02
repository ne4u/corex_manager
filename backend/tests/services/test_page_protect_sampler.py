"""Tests for the Page Protect sampler (CSP report collection from HAProxy logs)."""
import json
from unittest.mock import patch, MagicMock

import pytest

from app.services.page_protect_sampler import _parse_log_line, sample_csp_reports
from app.models.models import CspReport, PageProtectScript


@pytest.fixture
def mock_docker(monkeypatch):
    """Mock the runtime backend so haproxy_logs returns test data.

    Returns (mock_runtime, mock_client) where mock_runtime.haproxy_logs
    can be configured with the desired log output.
    """
    from app.services.runtime import get_runtime

    # Clear the lru_cache so get_runtime() picks up our mock
    get_runtime.cache_clear()

    mock_runtime = MagicMock()
    mock_runtime.is_available.return_value = True
    mock_runtime.haproxy_logs.return_value = ""

    # Patch get_runtime in both the sampler module and the runtime package
    import app.services.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "get_runtime", lambda: mock_runtime)
    monkeypatch.setattr("app.services.page_protect_sampler.get_runtime", lambda: mock_runtime)

    # Return a mock_container-like object for backward compat with test code
    # that sets mock_container.logs.return_value
    mock_container = MagicMock()
    mock_client = MagicMock()
    # Wire mock_container.logs to mock_runtime.haproxy_logs
    mock_runtime.haproxy_logs.side_effect = lambda **kwargs: mock_container.logs.return_value
    return mock_container, mock_client


def test_parse_log_line_with_csp_report():
    log_entry = {
        "ts": "2026-01-01T00:00:00Z",
        "client": "1.2.3.4",
        "frontend": "http_in",
        "backend": "be1",
        "csp_report": json.dumps({
            "csp-report": {
                "document-uri": "https://example.com/page",
                "violated-directive": "script-src",
                "blocked-uri": "https://evil.example.com/script.js",
            }
        }),
    }
    line = f"2026-01-01T00:00:00.000000000Z {json.dumps(log_entry)}"
    result = _parse_log_line(line)
    assert result is not None
    assert result["csp_report"] is not None
    assert result["parsed"]["client"] == "1.2.3.4"


def test_parse_log_line_without_csp_report():
    log_entry = {
        "ts": "2026-01-01T00:00:00Z",
        "client": "1.2.3.4",
        "frontend": "http_in",
        "backend": "be1",
    }
    line = f"2026-01-01T00:00:00.000000000Z {json.dumps(log_entry)}"
    result = _parse_log_line(line)
    assert result is None


def test_parse_log_line_non_json():
    result = _parse_log_line("2026-01-01T00:00:00Z not json at all")
    assert result is None


def test_parse_log_line_empty():
    result = _parse_log_line("")
    assert result is None


def test_sample_csp_reports_stores_reports(db, monkeypatch, mock_docker):
    """End-to-end: mock Docker SDK, verify reports are stored in DB."""
    mock_container, mock_client = mock_docker
    log_entry = {
        "client": "1.2.3.4",
        "frontend": "http_in",
        "backend": "be1",
        "csp_report": json.dumps({
            "csp-report": {
                "document-uri": "https://example.com/page",
                "violated-directive": "script-src",
                "blocked-uri": "https://evil.example.com/script.js",
            }
        }),
    }
    raw_logs = f"2026-01-01T00:00:00.000000000Z {json.dumps(log_entry)}\n"
    mock_container.logs.return_value = raw_logs.encode("utf-8")

    # Use the test DB session
    monkeypatch.setattr("app.services.page_protect_sampler.SessionLocal", lambda: db)
    # Disable offset persistence
    monkeypatch.setattr("app.services.page_protect_sampler._write_offset", lambda ts: None)
    monkeypatch.setattr("app.services.page_protect_sampler._read_offset", lambda: None)

    stored = sample_csp_reports()
    assert stored == 1

    reports = db.query(CspReport).all()
    assert len(reports) == 1
    assert reports[0].client_ip == "1.2.3.4"
    assert reports[0].backend_name == "be1"
    assert reports[0].violated_directive == "script-src"
    assert reports[0].blocked_uri == "https://evil.example.com/script.js"


def test_sample_csp_reports_upserts_scripts(db, monkeypatch, mock_docker):
    """Verify script inventory is updated from CSP reports."""
    mock_container, mock_client = mock_docker
    log_entry = {
        "client": "1.2.3.4",
        "frontend": "http_in",
        "backend": "be1",
        "csp_report": json.dumps({
            "csp-report": {
                "violated-directive": "script-src",
                "blocked-uri": "https://cdn.example.com/lib.js",
            }
        }),
    }
    raw_logs = f"2026-01-01T00:00:00.000000000Z {json.dumps(log_entry)}\n"
    mock_container.logs.return_value = raw_logs.encode("utf-8")

    monkeypatch.setattr("app.services.page_protect_sampler.SessionLocal", lambda: db)
    monkeypatch.setattr("app.services.page_protect_sampler._write_offset", lambda ts: None)
    monkeypatch.setattr("app.services.page_protect_sampler._read_offset", lambda: None)

    sample_csp_reports()

    scripts = db.query(PageProtectScript).all()
    assert len(scripts) == 1
    assert scripts[0].url == "https://cdn.example.com/lib.js"
    assert scripts[0].resource_type == "script"
    assert scripts[0].domain == "cdn.example.com"
    assert scripts[0].occurrence_count == 1


def test_parse_log_line_rejects_unescaped_csp_report():
    """A log line whose csp_report value contains literal quotes (the old
    format before the json converter) is not valid JSON and must be rejected.
    """
    raw_body = '{"csp-report":{"blocked-uri":"https://evil.com/x.js"}}'
    broken = (
        '{"ts":"2026-01-01T00:00:00Z","client":"1.2.3.4",'
        f'"csp_report":"{raw_body}"'
        '}'
    )
    result = _parse_log_line(broken)
    assert result is None


def test_sample_csp_reports_no_docker_sdk(db, monkeypatch):
    """When the runtime backend is not available, should return 0 gracefully."""
    from app.services.runtime import get_runtime

    get_runtime.cache_clear()
    mock_runtime = MagicMock()
    mock_runtime.is_available.return_value = False
    import app.services.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "get_runtime", lambda: mock_runtime)
    monkeypatch.setattr("app.services.page_protect_sampler.get_runtime", lambda: mock_runtime)

    result = sample_csp_reports()
    assert result == 0
