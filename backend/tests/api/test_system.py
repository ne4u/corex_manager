from unittest.mock import MagicMock


def _mock_runtime(monkeypatch, logs_return_value):
    """Patch get_runtime() to return a fake runtime with the given logs.

    The log viewer endpoint calls runtime.is_available() and
    runtime.haproxy_logs(tail=..., timestamps=True). This helper creates a
    fake runtime that returns True for is_available and returns the provided
    logs_return_value from haproxy_logs.
    """
    from app.api.v1 import system as system_module
    from app.services.runtime import get_runtime

    # Clear the lru_cache so get_runtime() picks up our mock
    get_runtime.cache_clear()

    fake_runtime = MagicMock()
    fake_runtime.is_available.return_value = True
    fake_runtime.haproxy_logs.return_value = logs_return_value
    fake_runtime.describe.return_value = {"available": True, "error": None, "type": "docker"}

    monkeypatch.setattr(system_module, "get_runtime", lambda: fake_runtime)
    # Also patch the source so any other module that imports get_runtime gets the mock
    import app.services.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "get_runtime", lambda: fake_runtime)

    return fake_runtime


def test_logs_recent_parses_json_log_lines(client, monkeypatch):
    """Regression test for /api/v1/logs/recent JSON parsing path.

    The endpoint used to raise NameError on `json.loads` because the
    `json` module was not imported in the router module.
    """
    from app.core.config import get_settings
    from app.api.v1 import system as system_module

    settings = get_settings()
    monkeypatch.setattr(settings, "HAPROXY_LOG_VIEWER_ENABLED", True)
    monkeypatch.setattr(system_module, "settings", settings)

    _mock_runtime(monkeypatch, (
        b'2023-10-01T12:00:00.000000000Z {"foo":"bar"}\n'
        b'2023-10-01T12:00:00.000000000Z not json\n'
    ))

    res = client.get("/api/v1/logs/recent?limit=100")
    assert res.status_code == 200
    data = res.json()
    assert "error" not in data
    assert len(data["lines"]) == 1
    assert data["lines"][0]["parsed"] == {"foo": "bar"}
    assert data["lines"][0]["docker_ts"].endswith("Z")
    # Non-JSON lines are counted and reported back to the caller.
    assert data["skipped_non_json"] == 1
    assert data["skipped_control"] == 0


def test_logs_recent_strips_control_chars_before_json(client, monkeypatch):
    """Regression test: HAProxy can emit NUL/control bytes before the JSON
    payload (observed on rate-limited 429 responses). str.strip() does not
    remove these, so json.loads() failed and the line was silently dropped.
    The endpoint should strip leading control chars and parse the JSON.
    """
    from app.core.config import get_settings
    from app.api.v1 import system as system_module

    settings = get_settings()
    monkeypatch.setattr(settings, "HAPROXY_LOG_VIEWER_ENABLED", True)
    monkeypatch.setattr(system_module, "settings", settings)

    # NUL byte + a couple of other control chars prefix the JSON payload,
    # mirroring real-world HAProxy output on rate-limited requests.
    _mock_runtime(monkeypatch, (
        b'2023-10-01T12:00:00.000000000Z \x00\x01\x02{"ts":"x","status":"429"}\n'
        b'2023-10-01T12:00:01.000000000Z {"ts":"y","status":"200"}\n'
        b'2023-10-01T12:00:02.000000000Z ALERT: some haproxy system message\n'
    ))

    res = client.get("/api/v1/logs/recent?limit=100")
    assert res.status_code == 200
    data = res.json()
    assert "error" not in data
    # Both JSON lines should parse, including the control-char-prefixed one.
    # The backend returns lines in input order (the frontend reverses them).
    assert len(data["lines"]) == 2
    assert data["lines"][0]["parsed"] == {"ts": "x", "status": "429"}
    assert data["lines"][1]["parsed"] == {"ts": "y", "status": "200"}
    # The ALERT line is non-JSON and should be counted as skipped.
    assert data["skipped_non_json"] == 1
    # One line had control chars stripped.
    assert data["skipped_control"] == 1


def test_logs_recent_returns_newest_lines_when_over_limit(client, monkeypatch):
    """Regression test: when the fetched window has more parsed JSON lines than
    `limit`, the endpoint must return the NEWEST `limit` lines, not the oldest.

    Previously the loop iterated oldest→newest and broke at `limit`, returning
    the oldest slice of the fetched window. During a request flood (e.g. a
    burst of WAF 403 denials) this made fresh logs invisible — the viewer only
    ever showed stale entries and never reached the recent flood logs at the
    tail of the Docker log buffer.
    """
    from app.core.config import get_settings
    from app.api.v1 import system as system_module

    settings = get_settings()
    monkeypatch.setattr(settings, "HAPROXY_LOG_VIEWER_ENABLED", True)
    monkeypatch.setattr(system_module, "settings", settings)

    # 5 JSON log lines, oldest→newest as Docker returns them.
    _mock_runtime(monkeypatch, (
        b'2023-10-01T12:00:00.000000000Z {"ts":"L1","status":"200"}\n'
        b'2023-10-01T12:00:01.000000000Z {"ts":"L2","status":"200"}\n'
        b'2023-10-01T12:00:02.000000000Z {"ts":"L3","status":"403"}\n'
        b'2023-10-01T12:00:03.000000000Z {"ts":"L4","status":"403"}\n'
        b'2023-10-01T12:00:04.000000000Z {"ts":"L5","status":"403"}\n'
    ))

    # limit=2 — only the 2 newest parsed lines should come back.
    res = client.get("/api/v1/logs/recent?limit=2")
    assert res.status_code == 200
    data = res.json()
    assert "error" not in data
    assert len(data["lines"]) == 2
    # Backend returns oldest→newest of the selected slice; the frontend
    # reverses for newest-first display. The slice must be the NEWEST 2
    # (L4, L5), not the oldest 2 (L1, L2).
    assert data["lines"][0]["parsed"] == {"ts": "L4", "status": "403"}
    assert data["lines"][1]["parsed"] == {"ts": "L5", "status": "403"}


def test_get_maxmind_license_key(client):
    """Regression test for /settings/maxmind/license-key NameError.

    The endpoint referenced the `Setting` model without importing it.
    """
    res = client.get("/api/v1/settings/maxmind/license-key")
    assert res.status_code == 200
    data = res.json()
    assert data["key"] == "maxmind_license_key"
    assert "value" in data
