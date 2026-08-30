"""Tests for the CRS downloader service."""
import io
import json
import os
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from app.services import crs_downloader
from app.services.crs_downloader import (
    download_crs,
    list_crs_snapshots,
    rollback_crs,
    delete_crs_snapshot,
    get_crs_status,
    _prune_crs_snapshots,
    _next_snapshot_id,
)
from app.services.settings import get_setting, set_setting


def _make_crs_zip(version: str = "4.0.0") -> bytes:
    """Build a minimal CRS ZIP in memory for testing."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        top = f"coreruleset-{version}-minimal"
        zf.writestr(f"{top}/crs-setup.conf.example", "# CRS setup\nSecDefaultAction \"phase:1,pass,nolog\"\n")
        zf.writestr(f"{top}/rules/REQUEST-901-INITIALIZATION.conf", "# Init rules\nSecRule &TX:paranoia_level \"@eq 0\" \"id:901001,phase:1,pass,nolog\"\n")
        zf.writestr(f"{top}/rules/REQUEST-949-BLOCKING-EVALUATION.conf", "# Blocking\nSecRule TX:anomaly_score @gt 5 \"id:949110,phase:1,deny\"\n")
    return buf.getvalue()


def _mock_github_response(tag: str = "v4.0.0", zip_bytes: bytes = b""):
    """Build a mock GitHub API response dict."""
    return {
        "tag_name": tag,
        "assets": [
            {
                "name": f"coreruleset-{tag.lstrip('v')}-minimal.zip",
                "browser_download_url": f"https://example.com/crs/{tag}/minimal.zip",
            }
        ],
    }


def test_download_crs_success(db, tmp_path, monkeypatch):
    """Successful download extracts files, saves snapshot, sets active version."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    zip_bytes = _make_crs_zip("4.0.0")

    api_resp = MagicMock()
    api_resp.status_code = 200
    api_resp.json.return_value = _mock_github_response("v4.0.0")
    api_resp.raise_for_status = MagicMock()

    zip_resp = MagicMock()
    zip_resp.content = zip_bytes
    zip_resp.raise_for_status = MagicMock()

    with patch("app.services.crs_downloader.requests.get", side_effect=[api_resp, zip_resp]):
        with patch("app.services.coraza_config.write_coraza_spoa_config") as mock_write:
            result = download_crs(db, created_by="tester")

    assert result["ok"] is True
    assert result["version"] == "v4.0.0"
    assert result["file_hash"] is not None
    assert result["error"] is None

    # Files extracted
    crs_dir = os.path.join(str(tmp_path), "4.0.0")
    assert os.path.exists(os.path.join(crs_dir, "crs-setup.conf.example"))
    assert os.path.exists(os.path.join(crs_dir, "rules", "REQUEST-901-INITIALIZATION.conf"))

    # Active version set
    assert get_setting(db, "crs_active_version") == "4.0.0"

    # Snapshot saved
    snapshots = list_crs_snapshots(db)
    assert len(snapshots) == 1
    assert snapshots[0]["version"] == "v4.0.0"
    assert snapshots[0]["dir_version"] == "4.0.0"
    assert snapshots[0]["created_by"] == "tester"

    # Coraza config regenerated
    mock_write.assert_called_once_with(db)


def test_download_crs_pinned_version(db, tmp_path, monkeypatch):
    """Pinned version fetches the specific release tag."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_pinned_version", "4.1.0")
    zip_bytes = _make_crs_zip("4.1.0")

    api_resp = MagicMock()
    api_resp.status_code = 200
    api_resp.json.return_value = _mock_github_response("v4.1.0")
    api_resp.raise_for_status = MagicMock()

    zip_resp = MagicMock()
    zip_resp.content = zip_bytes
    zip_resp.raise_for_status = MagicMock()

    with patch("app.services.crs_downloader.requests.get", side_effect=[api_resp, zip_resp]):
        with patch("app.services.coraza_config.write_coraza_spoa_config"):
            result = download_crs(db)

    assert result["ok"] is True
    assert result["version"] == "v4.1.0"
    crs_dir = os.path.join(str(tmp_path), "4.1.0")
    assert os.path.exists(crs_dir)


def test_download_crs_github_api_rate_limit(db, tmp_path, monkeypatch):
    """GitHub API 403 returns an error result."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))

    api_resp = MagicMock()
    api_resp.status_code = 403
    api_resp.json.return_value = {}
    api_resp.raise_for_status = MagicMock()

    with patch("app.services.crs_downloader.requests.get", return_value=api_resp):
        result = download_crs(db)

    assert result["ok"] is False
    assert "rate limit" in result["error"].lower()


def test_download_crs_network_error(db, tmp_path, monkeypatch):
    """Network error during ZIP download returns error result."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    import requests

    api_resp = MagicMock()
    api_resp.status_code = 200
    api_resp.json.return_value = _mock_github_response("v4.0.0")
    api_resp.raise_for_status = MagicMock()

    with patch("app.services.crs_downloader.requests.get", side_effect=[api_resp, requests.RequestException("timeout")]):
        result = download_crs(db)

    assert result["ok"] is False
    assert "timeout" in result["error"]


def test_list_crs_snapshots_sorted_newest_first(db, monkeypatch):
    """Snapshots are sorted by created_at descending."""
    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v3.3.0", "dir_version": "3.3.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_snapshot_2", json.dumps({"id": 2, "version": "v4.0.0", "dir_version": "4.0.0", "file_hash": "bbb", "file_path": "/y", "created_at": "2024-06-01T00:00:00", "created_by": "b"}))

    snapshots = list_crs_snapshots(db)
    assert len(snapshots) == 2
    assert snapshots[0]["id"] == 2  # newer first
    assert snapshots[1]["id"] == 1


def test_rollback_crs_switches_active_version(db, tmp_path, monkeypatch):
    """Rollback switches the active version to the snapshot's version."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))

    # Create two version directories
    for v in ["3.3.0", "4.0.0"]:
        d = os.path.join(str(tmp_path), v)
        os.makedirs(d)
        with open(os.path.join(d, "crs-setup.conf.example"), "w") as f:
            f.write("# setup\n")

    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v3.3.0", "dir_version": "3.3.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_snapshot_2", json.dumps({"id": 2, "version": "v4.0.0", "dir_version": "4.0.0", "file_hash": "bbb", "file_path": "/y", "created_at": "2024-06-01T00:00:00", "created_by": "b"}))
    set_setting(db, "crs_active_version", "4.0.0")

    with patch("app.services.coraza_config.write_coraza_spoa_config"):
        result = rollback_crs(db, 1)

    assert result["ok"] is True
    assert result["version"] == "3.3.0"
    assert get_setting(db, "crs_active_version") == "3.3.0"


def test_rollback_crs_missing_files(db, tmp_path, monkeypatch):
    """Rollback fails if the version directory doesn't exist."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v3.3.0", "dir_version": "3.3.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))

    result = rollback_crs(db, 1)
    assert result["ok"] is False
    assert "not found on disk" in result["error"]


def test_rollback_crs_snapshot_not_found(db):
    """Rollback with invalid snapshot ID returns error."""
    result = rollback_crs(db, 999)
    assert result["ok"] is False
    assert "not found" in result["error"].lower()


def test_delete_crs_snapshot_removes_record(db, tmp_path, monkeypatch):
    """Delete removes the snapshot record and files if not referenced."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    d = os.path.join(str(tmp_path), "3.3.0")
    os.makedirs(d)
    with open(os.path.join(d, "crs-setup.conf.example"), "w") as f:
        f.write("# setup\n")

    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v3.3.0", "dir_version": "3.3.0", "file_hash": "aaa", "file_path": d, "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_active_version", "4.0.0")

    result = delete_crs_snapshot(db, 1)
    assert result["ok"] is True
    assert not os.path.exists(d)
    snapshots = list_crs_snapshots(db)
    assert len(snapshots) == 0


def test_delete_crs_snapshot_prevents_deleting_active(db, tmp_path, monkeypatch):
    """Cannot delete the active version's snapshot."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v4.0.0", "dir_version": "4.0.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_active_version", "4.0.0")

    result = delete_crs_snapshot(db, 1)
    assert result["ok"] is False
    assert "active" in result["error"].lower()


def test_prune_crs_snapshots_respects_max(db, monkeypatch):
    """Pruning removes oldest snapshots beyond the max."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_SNAPSHOT_MAX", 2)
    for i in range(1, 5):
        set_setting(db, f"crs_snapshot_{i}", json.dumps({
            "id": i, "version": f"v{i}.0.0", "dir_version": f"{i}.0.0",
            "file_hash": "x", "file_path": "/x",
            "created_at": f"2024-0{i}-01T00:00:00", "created_by": "a",
        }))

    removed = _prune_crs_snapshots(db)
    assert removed == 2
    remaining = list_crs_snapshots(db)
    assert len(remaining) == 2
    # Keep the 2 newest (id=4 and id=3)
    ids = {s["id"] for s in remaining}
    assert ids == {3, 4}


def test_get_crs_status_embedded_mode(db):
    """Status returns embedded mode when no active version is set."""
    status = get_crs_status(db)
    assert status["mode"] == "embedded"
    assert status["active_version"] is None
    assert status["files_present"] is False


def test_get_crs_status_filesystem_mode(db, tmp_path, monkeypatch):
    """Status returns filesystem mode when active version exists on disk."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    d = os.path.join(str(tmp_path), "4.0.0")
    os.makedirs(d)
    set_setting(db, "crs_active_version", "4.0.0")

    status = get_crs_status(db)
    assert status["mode"] == "filesystem"
    assert status["active_version"] == "4.0.0"
    assert status["files_present"] is True
    assert status["path"] == "/app/data/crs/4.0.0"


def test_get_crs_status_filesystem_mode_files_missing(db, tmp_path, monkeypatch):
    """Status returns filesystem mode but files_present=False if dir is gone."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_active_version", "4.0.0")

    status = get_crs_status(db)
    assert status["mode"] == "filesystem"
    assert status["active_version"] == "4.0.0"
    assert status["files_present"] is False
    assert status["path"] is None


def test_next_snapshot_id_increments(db):
    """Next snapshot ID is max existing + 1."""
    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1}))
    set_setting(db, "crs_snapshot_3", json.dumps({"id": 3}))
    assert _next_snapshot_id(db) == 4


def test_download_crs_replaces_existing_directory(db, tmp_path, monkeypatch):
    """Re-downloading the same version replaces the existing directory."""
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    d = os.path.join(str(tmp_path), "4.0.0")
    os.makedirs(os.path.join(d, "old-stuff"))
    with open(os.path.join(d, "old-stuff", "old.txt"), "w") as f:
        f.write("old")

    zip_bytes = _make_crs_zip("4.0.0")
    api_resp = MagicMock()
    api_resp.status_code = 200
    api_resp.json.return_value = _mock_github_response("v4.0.0")
    api_resp.raise_for_status = MagicMock()
    zip_resp = MagicMock()
    zip_resp.content = zip_bytes
    zip_resp.raise_for_status = MagicMock()

    with patch("app.services.crs_downloader.requests.get", side_effect=[api_resp, zip_resp]):
        with patch("app.services.coraza_config.write_coraza_spoa_config"):
            result = download_crs(db)

    assert result["ok"] is True
    # Old file should be gone (directory was replaced)
    assert not os.path.exists(os.path.join(d, "old-stuff"))
    # New CRS files should be present
    assert os.path.exists(os.path.join(d, "rules", "REQUEST-901-INITIALIZATION.conf"))
