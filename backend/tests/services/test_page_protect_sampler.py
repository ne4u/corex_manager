"""Tests for the Page Protect sampler (CSP report collection from HAProxy logs)."""
import json
import sys
from unittest.mock import patch, MagicMock

import pytest

from app.services.page_protect_sampler import _parse_log_line, sample_csp_reports
from app.models.models import CspReport, PageProtectScript


@pytest.fixture
def mock_docker(monkeypatch):
    """Inject a mock docker module into sys.modules so `import docker` succeeds."""
    mock_container = MagicMock()
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container
    mock_docker_mod = MagicMock()
    mock_docker_mod.from_env.return_value = mock_client

    monkeypatch.setitem(sys.modules, "docker", mock_docker_mod)
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
    """When Docker SDK is not available, should return 0 gracefully."""
    # Remove docker from sys.modules so the import fails
    monkeypatch.delitem(sys.modules, "docker", raising=False)
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "docker":
            raise ImportError("No module named 'docker'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    result = sample_csp_reports()
    assert result == 0
