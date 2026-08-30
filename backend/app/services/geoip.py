"""MaxMind GeoLite2 database download and extraction."""
import os
import re
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
import geoip2.database
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import Setting
from .scheduler import PeriodicTask
from .settings import get_maxmind_license_key

settings = get_settings()

EDITIONS = [
    {"edition_id": "GeoLite2-ASN", "path": settings.ASN_DB_PATH},
    {"edition_id": "GeoLite2-Country", "path": settings.GEOIP_DB_PATH},
    {"edition_id": "GeoLite2-City", "path": settings.GEOIP_CITY_DB_PATH},
]


class GeoIpDownloader(PeriodicTask):
    """Background thread that downloads MaxMind GeoLite2 DBs at a fixed interval.

    Restart-safe: skips the immediate download on startup when the databases
    were recently fetched (within ``interval_hours``) and the .mmdb files
    exist. Stamps ``geoip_download_last_run_at`` only on a fully successful
    download so a partial failure retries on the next interval.
    """

    def __init__(self, interval_hours: float = 24.0):
        super().__init__(
            name="geoip_download",
            interval_seconds=interval_hours * 3600,
            files_required=[settings.GEOIP_DB_PATH, settings.ASN_DB_PATH, settings.GEOIP_CITY_DB_PATH],
        )
        self.last_status: Dict[str, Any] = {}

    def _tick(self) -> bool:
        try:
            with SessionLocal() as db:
                result = download_maxmind_dbs(db)
                result["maps"] = write_haproxy_maps()
                # When the Rust Lua module is enabled, it hot-reloads the MMDB
                # files in-place on its own reload_interval cycle — no full
                # HAProxy process reload needed. Only reload when the module is
                # disabled (falls back to native geoip2 / map_ip files which
                # require a process reload to pick up new DBs/map files).
                if not getattr(settings, "GEOIP_LUA_MODULE_ENABLED", True):
                    if any(m.get("ok") for m in result["maps"].values()):
                        from . import haproxy as haproxy_service
                        haproxy_service.reload_haproxy()
                self.last_status = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "ok": True,
                    "result": result,
                }
                return bool(result.get("ok", False))
        except Exception as exc:
            self.last_status = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "ok": False,
                "error": str(exc),
            }
            return False


def _mmdb_filename(edition_id: str) -> str:
    return f"{edition_id}.mmdb"


def _find_mmdb_member(tar: tarfile.TarFile, edition_id: str) -> Optional[tarfile.TarInfo]:
    pattern = re.compile(rf"{re.escape(edition_id)}.*\.mmdb$")
    for member in tar.getmembers():
        if pattern.search(member.name):
            return member
    return None


def _download_url(edition_id: str, license_key: str) -> str:
    return (
        "https://download.maxmind.com/app/geoip_download"
        f"?edition_id={edition_id}&suffix=tar.gz&license_key={license_key}"
    )


def _download_one(edition_id: str, dest_path: str, license_key: str) -> Dict[str, Any]:
    if not license_key:
        return {"edition_id": edition_id, "ok": False, "error": "Missing MaxMind license key"}

    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)

    url = _download_url(edition_id, license_key)
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"edition_id": edition_id, "ok": False, "error": str(exc)}

    temp_archive = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
    try:
        with open(temp_archive.name, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        with tarfile.open(temp_archive.name, "r:gz") as tar:
            member = _find_mmdb_member(tar, edition_id)
            if not member:
                return {
                    "edition_id": edition_id,
                    "ok": False,
                    "error": f"No {edition_id}.mmdb file found in archive",
                }
            extracted = tar.extractfile(member)
            if not extracted:
                return {
                    "edition_id": edition_id,
                    "ok": False,
                    "error": f"Could not read {member.name} from archive",
                }

            temp_mmdb = f"{dest_path}.tmp"
            with open(temp_mmdb, "wb") as out:
                shutil.copyfileobj(extracted, out)
            shutil.move(temp_mmdb, dest_path)

        return {"edition_id": edition_id, "ok": True, "path": dest_path}
    finally:
        try:
            os.unlink(temp_archive.name)
        except OSError:
            pass


# HAProxy map_ip fallback files. Derived from settings so they resolve
# correctly in both dev (project-relative) and container (/app/data) contexts.
# Populated by write_haproxy_maps() below and seeded empty by haproxy/entrypoint.sh.
COUNTRY_MAP_PATH = os.path.abspath(settings.GEOIP_COUNTRY_MAP_PATH)
ASN_MAP_PATH = os.path.abspath(settings.GEOIP_ASN_MAP_PATH)


def _write_network_map(db_path: str, map_path: str, value_fn) -> Dict[str, Any]:
    """Read a MaxMind mmdb and write a HAProxy map_ip text file."""
    if not db_path or not os.path.exists(db_path):
        return {"ok": False, "error": f"Database not found: {db_path}"}
    try:
        with geoip2.database.Reader(db_path) as reader:
            with open(map_path, "w") as f:
                for network, record in reader.networks():
                    value = value_fn(record)
                    if value:
                        f.write(f"{network} {value}\n")
        return {"ok": True, "path": map_path}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def write_haproxy_maps() -> Dict[str, Any]:
    """Generate HAProxy map_ip files from downloaded MaxMind mmdb databases."""
    result: Dict[str, Any] = {}
    result["country"] = _write_network_map(
        os.path.abspath(settings.GEOIP_DB_PATH),
        COUNTRY_MAP_PATH,
        lambda r: r.country.iso_code.upper() if r and r.country and r.country.iso_code else None,
    )
    result["asn"] = _write_network_map(
        os.path.abspath(settings.ASN_DB_PATH),
        ASN_MAP_PATH,
        lambda r: f"AS{r.autonomous_system_number}" if r and r.autonomous_system_number else None,
    )
    return result


def download_maxmind_dbs(db: Session) -> Dict[str, Any]:
    """Download all configured MaxMind editions and return per-file results."""
    license_key = get_maxmind_license_key(db)
    results = []
    all_ok = True
    for edition in EDITIONS:
        res = _download_one(edition["edition_id"], edition["path"], license_key or "")
        results.append(res)
        if not res.get("ok"):
            all_ok = False
    return {"ok": all_ok, "results": results}
