"""Tests for the Page Protect hasher (code change detection)."""
from unittest.mock import patch, MagicMock
import hashlib

from app.services.page_protect_hasher import hash_script, check_script, check_all_scripts, reset_script_hash
from app.models.models import PageProtectScript


def test_hash_script_success():
    script = MagicMock()
    script.url = "https://cdn.example.com/lib.js"
    mock_response = MagicMock()
    mock_response.content = b"console.log(1);"
    mock_response.raise_for_status = MagicMock()
    with patch("httpx.get", return_value=mock_response):
        result = hash_script(script)
    assert result == hashlib.sha256(b"console.log(1);").hexdigest()


def test_hash_script_non_http_url():
    script = MagicMock()
    script.url = "data:text/javascript,alert(1)"
    result = hash_script(script)
    assert result is None


def test_hash_script_fetch_error():
    script = MagicMock()
    script.url = "https://nonexistent.example.com/script.js"
    with patch("httpx.get", side_effect=Exception("connection refused")):
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
    with patch("httpx.get", side_effect=Exception("connection refused")):
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
    with patch("httpx.get", return_value=mock_response):
        result = check_script(db, script)
    assert result is not None
    assert script.last_hash is not None
    assert script.last_hash_at is not None
    assert script.hash_checked_at == script.last_hash_at

    # Second check: failure
    import time
    time.sleep(0.01)  # ensure hash_checked_at is strictly newer
    with patch("httpx.get", side_effect=Exception("connection refused")):
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
    with patch("httpx.get", return_value=mock_response):
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
    with patch("httpx.get", return_value=mock_response):
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
    with patch("httpx.get", return_value=mock_response):
        result = check_script(db, script)
    assert result == h
    assert script.hash_changed is False
    assert script.hash_checked_at is not None


def test_check_all_scripts_force(db, monkeypatch):
    from tests.factories import make_page_protect_script
    s1 = make_page_protect_script(db, url="https://cdn1.example.com/a.js")
    s2 = make_page_protect_script(db, url="https://cdn2.example.com/b.js")
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
    with patch("httpx.get", return_value=mock_response):
        checked = check_all_scripts(db, force=True)
    assert checked == 2
    assert s1.last_hash is not None
    assert s2.last_hash is not None


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

    with patch("httpx.get", side_effect=Exception("connection refused")):
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
    with patch("httpx.get", return_value=mock_response):
        result = check_script(db, s)
    db.commit()

    assert result is not None
    assert s.first_hash == result
    assert s.last_hash == result
    assert s.hash_changed is False
    assert s.first_hash_at is not None
