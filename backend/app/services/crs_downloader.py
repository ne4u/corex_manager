"""CRS downloader service.

Downloads the official OWASP CRS minimal ZIP from GitHub releases, extracts it
to a per-version directory on the shared volume, and manages CRS snapshots for
rollback. Snapshots are stored in the settings table as JSON values.
"""
import hashlib
import io
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import Setting
from .settings import get_setting, set_setting

logger = logging.getLogger(__name__)
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _crs_dir(version: str) -> str:
    """Filesystem path for a CRS version's extracted files."""
    return os.path.join(os.path.abspath(settings.CRS_DIR), version)


def _coraza_crs_path(version: str) -> str:
    """Path as seen from inside the coraza-spoa container."""
    return f"/app/data/crs/{version}"


def get_active_crs_version(db: Session) -> Optional[str]:
    """Return the currently active CRS version, or None if using embedded."""
    val = get_setting(db, "crs_active_version")
    return val if val else None


def get_pinned_crs_version(db: Session) -> Optional[str]:
    """Return the user-pinned CRS version, or None for 'latest'."""
    val = get_setting(db, "crs_pinned_version")
    return val if val else None


def _find_minimal_zip_url(release_data: dict) -> Optional[str]:
    """Find the minimal ZIP download URL from a GitHub release's assets."""
    for asset in release_data.get("assets", []):
        name = asset.get("name", "")
        if "minimal" in name and name.endswith(".zip"):
            return asset.get("browser_download_url")
    return None


def _resolve_version(db: Session) -> tuple:
    """Resolve which version to download. Returns (version_tag, zip_url).

    If pinned version is set, fetch that specific release.
    Otherwise, fetch the latest release.
    """
    pinned = get_pinned_crs_version(db)
    if pinned:
        tag = pinned if pinned.startswith("v") else f"v{pinned}"
        url = f"https://api.github.com/repos/coreruleset/coreruleset/releases/tags/{tag}"
        resp = requests.get(url, timeout=15, headers={"Accept": "application/vnd.github+json"})
        if resp.status_code == 403:
            raise RuntimeError("GitHub API rate limit exceeded")
        resp.raise_for_status()
        data = resp.json()
        zip_url = _find_minimal_zip_url(data)
        if not zip_url:
            raise ValueError(f"No minimal ZIP found for CRS release {tag}")
        return tag, zip_url
    else:
        resp = requests.get(
            settings.CRS_GITHUB_API,
            timeout=15,
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp.status_code == 403:
            raise RuntimeError("GitHub API rate limit exceeded")
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "latest")
        zip_url = _find_minimal_zip_url(data)
        if not zip_url:
            raise ValueError("No minimal ZIP found for latest CRS release")
        return tag, zip_url


def _extract_zip(zip_bytes: bytes, dest_dir: str) -> str:
    """Extract a CRS ZIP to dest_dir, flattening the top-level directory.

    The ZIP contains a top-level directory (e.g. 'coreruleset-4.0.0-minimal/').
    We extract and then move contents up one level so rules/ is directly under dest_dir.
    """
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(dest_dir)

    entries = os.listdir(dest_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest_dir, entries[0])):
        top_dir = os.path.join(dest_dir, entries[0])
        for item in os.listdir(top_dir):
            os.rename(os.path.join(top_dir, item), os.path.join(dest_dir, item))
        os.rmdir(top_dir)

    return dest_dir


def download_crs(db: Session, created_by: Optional[str] = None) -> Dict[str, Any]:
    """Download and extract the CRS rules. Returns a result dict.

    Steps:
    1. Resolve the version (pinned or latest)
    2. Download the minimal ZIP
    3. Compute SHA256 of the ZIP
    4. Extract to data/crs/{version}/
    5. Save a CRS snapshot to the settings table
    6. Set the active version to the new version
    7. Regenerate the Coraza config

    Returns: {ok, version, file_hash, error?}
    """
    try:
        version, zip_url = _resolve_version(db)
    except Exception as exc:
        return {"ok": False, "version": None, "file_hash": None, "error": str(exc)}

    dir_version = version.lstrip("v")

    try:
        resp = requests.get(zip_url, timeout=120)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, "version": version, "file_hash": None, "error": str(exc)}

    zip_bytes = resp.content
    file_hash = hashlib.sha256(zip_bytes).hexdigest()

    dest = _crs_dir(dir_version)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)

    try:
        _extract_zip(zip_bytes, dest)
    except Exception as exc:
        return {"ok": False, "version": version, "file_hash": file_hash, "error": f"Extraction failed: {exc}"}

    snapshot_id = _next_snapshot_id(db)
    snapshot_data = {
        "id": snapshot_id,
        "version": version,
        "dir_version": dir_version,
        "file_hash": file_hash,
        "file_path": dest,
        "created_at": _utcnow().replace(tzinfo=None).isoformat(),
        "created_by": created_by,
    }
    set_setting(db, f"crs_snapshot_{snapshot_id}", json.dumps(snapshot_data))

    set_setting(db, "crs_active_version", dir_version)

    _prune_crs_snapshots(db)

    from . import coraza_config
    coraza_config.write_coraza_spoa_config(db)

    return {"ok": True, "version": version, "file_hash": file_hash, "error": None}


def list_crs_snapshots(db: Session) -> List[Dict[str, Any]]:
    """List all CRS snapshots from the settings table, newest first."""
    rows = db.query(Setting).filter(Setting.key.like("crs_snapshot_%")).all()
    snapshots = []
    for row in rows:
        try:
            data = json.loads(row.value)
            snapshots.append(data)
        except (json.JSONDecodeError, TypeError):
            continue
    snapshots.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return snapshots


def rollback_crs(db: Session, snapshot_id: int, created_by: Optional[str] = None) -> Dict[str, Any]:
    """Rollback to a previous CRS version by switching the active version.

    Returns: {ok, version, error?}
    """
    row = db.query(Setting).filter(Setting.key == f"crs_snapshot_{snapshot_id}").first()
    if not row:
        return {"ok": False, "version": None, "error": "Snapshot not found"}

    try:
        data = json.loads(row.value)
    except (json.JSONDecodeError, TypeError):
        return {"ok": False, "version": None, "error": "Invalid snapshot data"}

    dir_version = data.get("dir_version")
    if not dir_version:
        return {"ok": False, "version": None, "error": "Snapshot missing version"}

    dest = _crs_dir(dir_version)
    if not os.path.exists(dest):
        return {"ok": False, "version": dir_version, "error": f"CRS version {dir_version} not found on disk"}

    set_setting(db, "crs_active_version", dir_version)

    from . import coraza_config
    coraza_config.write_coraza_spoa_config(db)

    return {"ok": True, "version": dir_version, "error": None}


def delete_crs_snapshot(db: Session, snapshot_id: int) -> Dict[str, Any]:
    """Delete a CRS snapshot record and its files if not active and not referenced."""
    row = db.query(Setting).filter(Setting.key == f"crs_snapshot_{snapshot_id}").first()
    if not row:
        return {"ok": False, "error": "Snapshot not found"}

    try:
        data = json.loads(row.value)
    except (json.JSONDecodeError, TypeError):
        data = {}

    dir_version = data.get("dir_version")
    active = get_active_crs_version(db)

    if dir_version and active and dir_version == active:
        return {"ok": False, "error": "Cannot delete the active CRS version snapshot"}

    if dir_version:
        other_refs = [
            s for s in list_crs_snapshots(db)
            if s.get("dir_version") == dir_version and s.get("id") != snapshot_id
        ]
        if not other_refs:
            dest = _crs_dir(dir_version)
            if os.path.exists(dest):
                shutil.rmtree(dest)

    db.delete(row)
    db.commit()
    return {"ok": True, "error": None}


def _next_snapshot_id(db: Session) -> int:
    """Get the next snapshot ID by examining existing snapshot keys."""
    rows = db.query(Setting).filter(Setting.key.like("crs_snapshot_%")).all()
    max_id = 0
    for row in rows:
        try:
            data = json.loads(row.value)
            sid = int(data.get("id", 0))
            if sid > max_id:
                max_id = sid
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return max_id + 1


def _prune_crs_snapshots(db: Session) -> int:
    """Delete oldest CRS snapshots beyond the max. Returns count removed."""
    max_keep = settings.CRS_SNAPSHOT_MAX
    if max_keep <= 0:
        return 0
    snapshots = list_crs_snapshots(db)
    if len(snapshots) <= max_keep:
        return 0
    to_remove = snapshots[max_keep:]
    count = 0
    for snap in to_remove:
        sid = snap.get("id")
        if sid is not None:
            row = db.query(Setting).filter(Setting.key == f"crs_snapshot_{sid}").first()
            if row:
                db.delete(row)
                count += 1
    db.commit()
    return count


def get_crs_status(db: Session) -> Dict[str, Any]:
    """Return current CRS status for the UI."""
    active = get_active_crs_version(db)
    pinned = get_pinned_crs_version(db)

    if active:
        dest = _crs_dir(active)
        files_exist = os.path.exists(dest)
        return {
            "mode": "filesystem",
            "active_version": active,
            "pinned_version": pinned,
            "files_present": files_exist,
            "path": _coraza_crs_path(active) if files_exist else None,
        }
    else:
        return {
            "mode": "embedded",
            "active_version": None,
            "pinned_version": pinned,
            "files_present": False,
            "path": None,
        }
