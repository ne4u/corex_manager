"""Tests for the remote rule set downloader."""
import hashlib
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from tests.factories import make_backend, make_listener, make_waf_rule
from app.services import rule_set_downloader
from app.services.rule_set_downloader import RuleSetUpdater, download_rule_set


def test_download_rule_set_success(db, tmp_path, monkeypatch):
    """Successful download writes the file and updates the rule."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
    )

    mock_resp = MagicMock()
    mock_resp.text = "SecRule REQUEST_URI \"@rx .\" \"id:1,phase:1,deny\""
    mock_resp.raise_for_status = MagicMock()

    with patch("app.services.rule_set_downloader.requests.get", return_value=mock_resp):
        ok = download_rule_set(db, rule)

    assert ok is True
    assert rule.rule_set_last_error is None
    assert rule.rule_set_last_updated_at is not None
    path = rule_set_downloader._rule_file_path(rule.name)
    assert os.path.exists(path)
    with open(path) as f:
        assert "SecRule REQUEST_URI" in f.read()


def test_download_rule_set_sha256_mismatch(db, tmp_path, monkeypatch):
    """SHA256 mismatch sets error and does not write the file."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    content = "SecRule REQUEST_URI \"@rx .\" \"id:1,phase:1,deny\""
    expected_hash = hashlib.sha256(content.encode()).hexdigest()
    rule = make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
        rule_set_sha256="wrong_hash",
    )

    mock_resp = MagicMock()
    mock_resp.text = content
    mock_resp.raise_for_status = MagicMock()

    with patch("app.services.rule_set_downloader.requests.get", return_value=mock_resp):
        ok = download_rule_set(db, rule)

    assert ok is False
    assert "SHA256 mismatch" in (rule.rule_set_last_error or "")
    path = rule_set_downloader._rule_file_path(rule.name)
    assert not os.path.exists(path)


def test_download_rule_set_sha256_match(db, tmp_path, monkeypatch):
    """SHA256 match writes the file."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    content = "SecRule REQUEST_URI \"@rx .\" \"id:1,phase:1,deny\""
    expected_hash = hashlib.sha256(content.encode()).hexdigest()
    rule = make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
        rule_set_sha256=expected_hash,
    )

    mock_resp = MagicMock()
    mock_resp.text = content
    mock_resp.raise_for_status = MagicMock()

    with patch("app.services.rule_set_downloader.requests.get", return_value=mock_resp):
        ok = download_rule_set(db, rule)

    assert ok is True
    assert rule.rule_set_last_error is None


def test_download_rule_set_network_error(db, tmp_path, monkeypatch):
    """Network error sets error and does not write the file."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
    )

    import requests as req
    with patch("app.services.rule_set_downloader.requests.get", side_effect=req.RequestException("timeout")):
        ok = download_rule_set(db, rule)

    assert ok is False
    assert "timeout" in (rule.rule_set_last_error or "")


def test_download_rule_set_no_url(db, tmp_path, monkeypatch):
    """No URL configured returns False with error."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url=None,
    )

    ok = download_rule_set(db, rule)
    assert ok is False
    assert "No URL" in (rule.rule_set_last_error or "")


def test_rule_set_updater_tick_downloads_missing_file(db, tmp_path, monkeypatch):
    """Updater downloads files that don't exist yet."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(
        db, name="auto-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
        rule_set_auto_update=False,
    )
    db.commit()  # Ensure data is visible to other sessions

    mock_resp = MagicMock()
    mock_resp.text = "SecRule REQUEST_URI \"@rx .\" \"id:1,phase:1,deny\""
    mock_resp.raise_for_status = MagicMock()

    updater = RuleSetUpdater()
    with patch("app.services.rule_set_downloader.requests.get", return_value=mock_resp):
        with patch("app.services.coraza_config.write_coraza_spoa_config"):
            with patch("app.services.rule_set_downloader.SessionLocal") as mock_session:
                mock_session.return_value.__enter__.return_value = db
                updater._tick()

    path = rule_set_downloader._rule_file_path(rule.name)
    assert os.path.exists(path)


def test_rule_set_updater_skips_non_remote_rules(db, tmp_path, monkeypatch):
    """Updater only processes rules with rule_set == 'remote'."""
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="crs-waf", listener_id=listener.id, rule_set="crs")

    mock_get = MagicMock()
    updater = RuleSetUpdater()
    with patch("app.services.rule_set_downloader.requests.get", mock_get):
        updater._tick()

    mock_get.assert_not_called()
