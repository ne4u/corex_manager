"""Tests for the Page Protect hasher (code change detection)."""
from unittest.mock import patch, MagicMock
import hashlib

from app.services.page_protect_hasher import hash_script, check_script, check_all_scripts, reset_script_hash
from app.models.models import PageProtectScript


def _mock_response(content=b"console.log(1);", status_code=200, content_type="text/javascript"):
    """Build a mock httpx.Response.

    raise_for_status() raises ValueError for non-2xx status codes, mirroring
    httpx's real behavior so the hasher's error handling is exercised.
    """
    r = MagicMock()
    r.content = content
    r.headers = {"content-type": content_type} if content_type else {}
    r.status_code = status_code
    if status_code >= 400:
        r.raise_for_status.side_effect = ValueError(f"HTTP {status_code}")
    else:
        r.raise_for_status = MagicMock()
    return r


def _mock_httpx_client(responses=None, side_effect=None):
    """Build a mock httpx.Client usable as a context manager.

    hash_script uses ``with httpx.Client(...) as client: client.request(method, url)``,
    so tests must mock ``httpx.Client`` (not ``httpx.get``) and return a
    mock that supports both ``__enter__`` and ``.request``.

    Pass ``responses`` for success cases (a single response or a list for
    sequential calls — used by auto-probe tests where GET returns 405 then
    POST returns 200). Pass ``side_effect`` for error cases.
    """
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    if side_effect is not None:
        mock_client.request.side_effect = side_effect
    elif isinstance(responses, list):
        mock_client.request.side_effect = responses
    else:
        mock_client.request.return_value = responses
    return mock_client


def test_hash_script_success():
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    mock_response = _mock_response(b"console.log(1);")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    assert result.content == "console.log(1);"
    assert result.content_type == "text/javascript"


def test_hash_script_non_http_url():
    script = MagicMock()
    script.url = "data:text/javascript,alert(1)"
    result = hash_script(script)
    assert result is None


def test_hash_script_fetch_error():
    script = MagicMock()
    script.url = "https://nonexistent.example.com/script.js"
    with patch("httpx.Client", return_value=_mock_httpx_client(side_effect=Exception("connection refused"))):
        result = hash_script(script)
    assert result is None


def test_check_script_fetch_failure_sets_hash_checked_at(db):
    """On fetch failure, hash_checked_at is still updated so the UI can
    distinguish 'checked but failed' from 'never checked'."""
    script = PageProtectScript(
        url="https://cdn.example.com/lib.js",
        resource_type="script",
        domain="cdn.example.com",
    )
    db.add(script)
    db.flush()
    assert script.hash_checked_at is None
    with patch("httpx.Client", return_value=_mock_httpx_client(side_effect=Exception("connection refused"))):
        result = check_script(db, script)
    assert result is None
    assert script.last_hash is None
    assert script.last_hash_at is None
    assert script.hash_checked_at is not None


def test_check_script_success_then_failure_shows_error(db):
    """After a successful check, a failed check should leave last_hash_at
    older than hash_checked_at so the UI can detect the error."""
    script = PageProtectScript(url="https://cdn.example.com/lib.js", resource_type="script", domain="cdn.example.com")
    db.add(script)
    db.flush()

    # First check: success
    mock_response = MagicMock()
    mock_response.content = b"console.log(1);"
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        result = check_script(db, script)
    assert result is not None
    assert script.last_hash is not None
    assert script.last_hash_at is not None
    assert script.hash_checked_at == script.last_hash_at

    # Second check: failure
    import time
    time.sleep(0.01)  # ensure hash_checked_at is strictly newer
    with patch("httpx.Client", return_value=_mock_httpx_client(side_effect=Exception("connection refused"))):
        result = check_script(db, script)
    assert result is None
    # last_hash and last_hash_at retain the old successful values...
    assert script.last_hash is not None
    assert script.last_hash_at is not None
    # ...but hash_checked_at is now newer, indicating the last check failed
    assert script.hash_checked_at > script.last_hash_at


def test_check_script_first_hash(db):
    script = PageProtectScript(url="https://cdn.example.com/lib.js", resource_type="script", domain="cdn.example.com")
    db.add(script)
    db.flush()
    mock_response = MagicMock()
    mock_response.content = b"console.log(1);"
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        result = check_script(db, script)
    assert result is not None
    assert script.first_hash == result
    assert script.last_hash == result
    assert script.first_hash_at is not None
    assert script.hash_checked_at is not None
    assert script.hash_changed is False


def test_check_script_change_detected(db):
    script = PageProtectScript(
        url="https://cdn.example.com/lib.js",
        resource_type="script",
        domain="cdn.example.com",
        first_hash="abc123",
        last_hash="abc123",
        hash_changed=False,
    )
    db.add(script)
    db.flush()
    mock_response = MagicMock()
    mock_response.content = b"console.log('changed');"
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        result = check_script(db, script)
    new_hash = hashlib.sha256(b"console.log('changed');").hexdigest()
    assert result == new_hash
    assert script.last_hash == new_hash
    assert script.hash_changed is True


def test_check_script_no_change(db):
    content = b"console.log(1);"
    h = hashlib.sha256(content).hexdigest()
    script = PageProtectScript(
        url="https://cdn.example.com/lib.js",
        resource_type="script",
        domain="cdn.example.com",
        first_hash=h,
        last_hash=h,
        hash_changed=False,
    )
    db.add(script)
    db.flush()
    mock_response = MagicMock()
    mock_response.content = content
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        result = check_script(db, script)
    assert result == h
    assert script.hash_changed is False
    assert script.hash_checked_at is not None


def test_check_script_ignored_is_skipped(db):
    """Ignored scripts are not fetched and do not update hash fields."""
    from tests.factories import make_page_protect_script
    script = make_page_protect_script(db, url="https://cdn.example.com/ignored.js", ignored=True)
    db.commit()
    with patch("httpx.Client") as mock_client_cls:
        result = check_script(db, script)
    assert result is None
    assert script.hash_checked_at is None
    mock_client_cls.assert_not_called()


def test_check_all_scripts_force(db, monkeypatch):
    from tests.factories import make_page_protect_script
    s1 = make_page_protect_script(db, url="https://cdn1.example.com/a.js")
    s2 = make_page_protect_script(db, url="https://cdn2.example.com/b.js")
    s3 = make_page_protect_script(db, url="https://cdn3.example.com/c.js", ignored=True)
    db.commit()

    # Mock settings to enable change detection
    from app.services.page_protect import get_page_protect_settings
    monkeypatch.setattr(
        "app.services.page_protect_hasher.get_page_protect_settings",
        lambda db: {"change_detection_enabled": True, "change_detection_interval_hours": 24}
    )

    mock_response = MagicMock()
    mock_response.content = b"console.log(1);"
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        checked = check_all_scripts(db, force=True)
    assert checked == 2
    assert s1.last_hash is not None
    assert s2.last_hash is not None
    assert s3.last_hash is None


def test_check_all_scripts_commits_on_all_failures(db, monkeypatch):
    """Even when every fetch fails, hash_checked_at updates are committed
    so the UI can show 'Error' instead of 'Unchecked'."""
    from tests.factories import make_page_protect_script
    s1 = make_page_protect_script(db, url="https://cdn1.example.com/a.js")
    db.commit()

    monkeypatch.setattr(
        "app.services.page_protect_hasher.get_page_protect_settings",
        lambda db: {
            "change_detection_enabled": True,
            "change_detection_interval_hours": 24,
        },
    )

    with patch("httpx.Client", return_value=_mock_httpx_client(side_effect=Exception("connection refused"))):
        checked = check_all_scripts(db, force=True)
    assert checked == 0
    db.refresh(s1)
    assert s1.last_hash is None
    assert s1.hash_checked_at is not None


def test_reset_script_hash_clears_fields(db):
    """reset_script_hash clears all hash fields so the next check is a fresh baseline."""
    from tests.factories import make_page_protect_script
    s = make_page_protect_script(
        db,
        url="https://cdn.example.com/lib.js",
        last_hash="abc123",
        hash_changed=True,
    )
    s.first_hash = "abc123"
    s.first_hash_at = s.last_seen
    s.hash_checked_at = s.last_seen
    db.commit()

    reset_script_hash(db, s)
    db.commit()

    assert s.first_hash is None
    assert s.first_hash_at is None
    assert s.last_hash is None
    assert s.hash_checked_at is None
    assert s.hash_changed is False


def test_reset_then_check_establishes_new_baseline(db, monkeypatch):
    """After reset, the next check sets a fresh first_hash with hash_changed=False."""
    from tests.factories import make_page_protect_script
    s = make_page_protect_script(
        db,
        url="https://cdn.example.com/lib.js",
        last_hash="oldhash",
        hash_changed=True,
    )
    s.first_hash = "oldhash"
    db.commit()

    # Reset
    reset_script_hash(db, s)
    db.commit()
    assert s.first_hash is None
    assert s.hash_changed is False

    # Now check — should establish a new baseline
    monkeypatch.setattr(
        "app.services.page_protect_hasher.get_page_protect_settings",
        lambda db: {"change_detection_enabled": True, "change_detection_interval_hours": 24},
    )
    mock_response = MagicMock()
    mock_response.content = b"console.log('new version');"
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=mock_response)):
        result = check_script(db, s)
    db.commit()

    assert result is not None
    assert s.first_hash == result
    assert s.last_hash == result
    assert s.hash_changed is False
    assert s.first_hash_at is not None


# ----- fetch_method / auto-probe tests -----


def test_hash_script_explicit_get():
    """When fetch_method='GET', the hasher uses GET and does not probe."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "GET"
    script.last_fetch_method = None
    resp = _mock_response(b"console.log(1);")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)) as mock_client_cls:
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    # Verify GET was used (not POST)
    mock_client_cls.return_value.request.assert_called_with("GET", script.url)


def test_hash_script_explicit_post():
    """When fetch_method='POST', the hasher uses POST directly."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "POST"
    script.last_fetch_method = None
    resp = _mock_response(b"console.log(1);")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)) as mock_client_cls:
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    mock_client_cls.return_value.request.assert_called_with("POST", script.url)


def test_hash_script_auto_uses_last_fetch_method():
    """When fetch_method='auto' and last_fetch_method is set, use it directly (no probe)."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "auto"
    script.last_fetch_method = "POST"
    resp = _mock_response(b"console.log(1);")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)) as mock_client_cls:
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    # Should use POST (from last_fetch_method) without probing
    mock_client_cls.return_value.request.assert_called_once_with("POST", script.url)


def test_hash_script_auto_probes_get_then_post_on_405():
    """When fetch_method='auto' and no last_fetch_method, GET returns 405,
    fall back to POST and persist last_fetch_method='POST'."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "auto"
    script.last_fetch_method = None
    # First response (GET) → 405, second (POST) → 200 with content
    resp_405 = _mock_response(b"", status_code=405)
    resp_200 = _mock_response(b"console.log(1);", status_code=200)
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=[resp_405, resp_200])):
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    assert script.last_fetch_method == "POST"


def test_hash_script_auto_probes_get_then_post_on_403():
    """Same as above but with 403 Forbidden."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "auto"
    script.last_fetch_method = None
    resp_403 = _mock_response(b"", status_code=403)
    resp_200 = _mock_response(b"console.log(1);", status_code=200)
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=[resp_403, resp_200])):
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    assert script.last_fetch_method == "POST"


def test_hash_script_auto_get_success_persists_get():
    """When fetch_method='auto' and GET succeeds, persist last_fetch_method='GET'."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "auto"
    script.last_fetch_method = None
    resp = _mock_response(b"console.log(1);", status_code=200)
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)):
        result = hash_script(script)
    assert result is not None
    assert result.hash == hashlib.sha256(b"console.log(1);").hexdigest()
    assert script.last_fetch_method == "GET"


def test_hash_script_auto_does_not_reprobe_when_last_fetch_method_set():
    """When fetch_method='auto' and last_fetch_method='GET', a 405 should NOT
    trigger a POST retry — the persisted method is used directly and
    raise_for_status() will raise."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "auto"
    script.last_fetch_method = "GET"
    resp_405 = _mock_response(b"", status_code=405)
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp_405)) as mock_client_cls:
        result = hash_script(script)
    # raise_for_status raises on 405 → hash_script returns None
    assert result is None
    # Only one request (no POST retry)
    assert mock_client_cls.return_value.request.call_count == 1


def test_hash_script_auto_both_methods_fail():
    """When fetch_method='auto', GET returns 405, POST also raises → None."""
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    script.fetch_method = "auto"
    script.last_fetch_method = None
    resp_405 = _mock_response(b"", status_code=405)
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=[resp_405, Exception("post also failed")])):
        result = hash_script(script)
    assert result is None
    # last_fetch_method should NOT be persisted since POST also failed
    assert script.last_fetch_method is None


# ----- content persistence tests -----


def test_check_script_stores_content_on_first_check(db):
    """A first successful check persists the decoded body."""
    script = PageProtectScript(
        url="https://cdn.example.com/lib.js",
        resource_type="script",
        domain="cdn.example.com",
    )
    db.add(script)
    db.flush()
    resp = _mock_response(b"console.log('hello');")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)):
        result = check_script(db, script)
    assert result is not None
    assert script.content == "console.log('hello');"


def test_check_script_updates_content_when_hash_changes(db):
    """When the hash changes, the stored content is replaced."""
    script = PageProtectScript(
        url="https://cdn.example.com/lib.js",
        resource_type="script",
        domain="cdn.example.com",
        first_hash="abc123",
        last_hash="abc123",
        hash_changed=False,
        content="old content",
    )
    db.add(script)
    db.flush()
    resp = _mock_response(b"console.log('changed');")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)):
        result = check_script(db, script)
    assert result is not None
    assert script.hash_changed is True
    assert script.content == "console.log('changed');"


def test_check_script_keeps_content_when_unchanged(db):
    """When the hash is unchanged, existing content is preserved."""
    content = b"console.log(1);"
    h = hashlib.sha256(content).hexdigest()
    script = PageProtectScript(
        url="https://cdn.example.com/lib.js",
        resource_type="script",
        domain="cdn.example.com",
        first_hash=h,
        last_hash=h,
        hash_changed=False,
        content="console.log(1);",
    )
    db.add(script)
    db.flush()
    resp = _mock_response(content)
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)):
        result = check_script(db, script)
    assert result == h
    assert script.hash_changed is False
    assert script.content == "console.log(1);"


def test_hash_script_skips_binary_content():
    """Binary content types (e.g., images) are hashed but not stored as text."""
    script = MagicMock()
    script.url = "https://cdn.example.com/logo.png"
    script.resource_type = "img"
    script.fetch_method = "GET"
    script.last_fetch_method = None
    resp = _mock_response(b"\x89PNG\r\n\x1a\n", status_code=200, content_type="image/png")
    with patch("httpx.Client", return_value=_mock_httpx_client(responses=resp)):
        result = hash_script(script)
    assert result is not None
    assert result.hash is not None
    assert result.content is None
