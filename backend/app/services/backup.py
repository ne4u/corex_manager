"""Full-system export/restore for coreX Manager.

Bundles the running configuration (all DB tables, cert files, generated HAProxy/Coraza
configs, security list files, CRS/custom WAF rule sets, GeoIP databases, and config
snapshot history) into a downloadable ZIP archive with optional AES (Fernet) password
protection. Restore accepts an uploaded archive and replaces the running configuration.
"""
import io
import json
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import Base, SessionLocal
from ..services.haproxy import (
    _jsonable,
    _parse_value,
    _serialize_row,
    write_config,
    reload_haproxy,
)

settings = get_settings()

# Tables always excluded from export (runtime-only, regenerated on startup).
# Note: users/audit_events/metrics are conditionally included based on export flags.
_ALWAYS_EXCLUDED = set()

# Secret fields to redact when include_secrets=False.
SECRET_FIELDS: Dict[str, List[str]] = {
    "users": ["hashed_password", "totp_secret"],
    "certificates": ["dns_credentials"],
    "waf_siem_integrations": ["auth_header"],
}

# Setting keys that are secret — filtered out when include_secrets=False.
SECRET_SETTING_KEYS = {"maxmind_license_key"}

# Tables only included when include_metrics=True.
METRICS_TABLES = {"metric_snapshots", "waf_metrics", "audit_events", "waf_rule_versions", "tasks", "csp_reports", "page_protect_scripts", "cache_metric_snapshots"}

# Tables only included when include_secrets=True.
SECRET_TABLES = {"users"}

# Encryption magic header: 7-byte magic + 16-byte salt + ciphertext.
_ENC_MAGIC = b"HPMENC1"
_PBKDF2_SALT_LEN = 16
_PBKDF2_ITERATIONS = 480_000

# Archive manifest version.
ARCHIVE_VERSION = 1


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _serialize_db(db: Session, include_secrets: bool, include_metrics: bool) -> Dict[str, List[Dict[str, Any]]]:
    """Serialize all DB tables into a dict of {table_name: [row_dicts]}.

    Conditionally includes users (secrets) and metrics tables.
    Redacts secret fields when include_secrets=False.

    Uses yield_per to stream large tables without loading all rows into memory
    at once, reducing the time the SQLite read transaction is held open.
    """
    snapshot: Dict[str, List[Dict[str, Any]]] = {}
    for table in Base.metadata.tables.values():
        name = table.name
        if name in SECRET_TABLES and not include_secrets:
            continue
        if name in METRICS_TABLES and not include_metrics:
            continue
        rows = []
        for row in db.execute(table.select().execution_options(yield_per=500)).mappings():
            rows.append(_serialize_row(row, table))
        if not include_secrets and name in SECRET_FIELDS:
            for r in rows:
                for col in SECRET_FIELDS[name]:
                    if col in r:
                        r[col] = None
        # Filter secret setting keys from the settings table.
        if not include_secrets and name == "settings":
            rows = [r for r in rows if r.get("key") not in SECRET_SETTING_KEYS]
        snapshot[name] = rows
    return snapshot


def _stream_db_json_to_zip(
    zf: zipfile.ZipFile,
    db: Session,
    include_secrets: bool,
    include_metrics: bool,
) -> None:
    """Stream all DB tables as JSON directly into the zip entry ``db.json``.

    This avoids building the entire db_snapshot dict and JSON string in memory,
    which is critical when metrics tables contain hundreds of MB of data.

    Writes compact JSON (no indent) to minimize size and serialization time.
    """
    tables = list(Base.metadata.tables.values())
    with zf.open("db.json", "w") as f:
        f.write(b"{")
        first_table = True
        for table in tables:
            name = table.name
            if name in SECRET_TABLES and not include_secrets:
                continue
            if name in METRICS_TABLES and not include_metrics:
                continue
            if not first_table:
                f.write(b",")
            first_table = False
            f.write(json.dumps(name).encode("utf-8"))
            f.write(b":")
            f.write(b"[")
            first_row = True
            for row in db.execute(table.select().execution_options(yield_per=500)).mappings():
                row_dict = _serialize_row(row, table)
                # Redact secret fields
                if not include_secrets and name in SECRET_FIELDS:
                    for col in SECRET_FIELDS[name]:
                        if col in row_dict:
                            row_dict[col] = None
                # Filter secret setting keys
                if not include_secrets and name == "settings":
                    if row_dict.get("key") in SECRET_SETTING_KEYS:
                        continue
                if not first_row:
                    f.write(b",")
                first_row = False
                f.write(json.dumps(row_dict, default=str).encode("utf-8"))
            f.write(b"]")
        f.write(b"}")


def _restore_db_from_snapshot(db: Session, snapshot: Dict[str, List[Dict[str, Any]]]) -> int:
    """Restore DB tables from an in-memory snapshot dict.

    Deletes all tables present in the snapshot (in reverse dependency order) and
    inserts rows in dependency order. Returns the number of tables restored.
    """
    sorted_tables = list(Base.metadata.sorted_tables)
    # Delete in reverse dependency order — only tables present in the snapshot.
    for table in reversed(sorted_tables):
        if table.name not in snapshot:
            continue
        db.execute(table.delete())

    # Insert in dependency order.
    count = 0
    for table in sorted_tables:
        if table.name not in snapshot:
            continue
        rows = snapshot[table.name]
        if not rows:
            count += 1
            continue
        cleaned_rows = []
        for row in rows:
            cleaned = {col.name: _parse_value(row.get(col.name), col) for col in table.columns if col.name in row}
            cleaned_rows.append(cleaned)
        if cleaned_rows:
            db.execute(table.insert(), cleaned_rows)
        count += 1

    db.commit()
    _restore_sqlite_sequences(db, snapshot)
    return count


def _restore_sqlite_sequences(db: Session, snapshot: Dict[str, List[Dict[str, Any]]]) -> None:
    """Fix sqlite_sequence table after restore so autoincrement continues correctly."""
    if not settings.DATABASE_URL.startswith("sqlite"):
        return
    res = db.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"))
    if not res.fetchone():
        return
    for table in Base.metadata.sorted_tables:
        if table.name not in snapshot:
            continue
        rows = snapshot[table.name]
        ids = [r.get("id") for r in rows if r.get("id") is not None]
        if not ids:
            continue
        db.execute(
            text("INSERT OR REPLACE INTO sqlite_sequence(name, seq) VALUES (:name, :seq)"),
            {"name": table.name, "seq": max(ids)},
        )
    db.commit()


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

# File extensions that are already compressed — using ZIP_DEFLATED on these
# wastes CPU for no size benefit. Use ZIP_STORED instead.
_STORED_EXTENSIONS = {".mmdb", ".gz", ".zip", ".png", ".jpg", ".jpeg", ".woff2"}


def _zip_compress_type(file_path: str) -> int:
    """Return ZIP_STORED for already-compressed files, ZIP_DEFLATED otherwise."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in _STORED_EXTENSIONS:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def _add_dir_to_zip(zf: zipfile.ZipFile, dir_path: str, arcname: str) -> int:
    """Recursively add a directory to the zip. Returns number of files added."""
    if not os.path.isdir(dir_path):
        return 0
    count = 0
    for root, _dirs, files in os.walk(dir_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, dir_path)
            zf.write(fpath, os.path.join(arcname, rel), compress_type=_zip_compress_type(fpath))
            count += 1
    return count


def _add_file_to_zip(zf: zipfile.ZipFile, file_path: str, arcname: str) -> bool:
    """Add a single file to the zip if it exists. Returns True if added."""
    if os.path.isfile(file_path):
        zf.write(file_path, arcname, compress_type=_zip_compress_type(file_path))
        return True
    return False


def _collect_files(db: Session, include_secrets: bool, include_metrics: bool) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """Return (files, dirs) to include in the archive as (source_path, arcname) pairs."""
    files: List[Tuple[str, str]] = []
    dirs: List[Tuple[str, str]] = []

    # HAProxy + Coraza config files.
    files.append((settings.HAPROXY_CONFIG_PATH, "config/haproxy.cfg"))
    files.append((f"{settings.HAPROXY_CONFIG_PATH}.applied", "config/haproxy.cfg.applied"))
    files.append((settings.CORAZA_SPOE_CONFIG_PATH, "config/coraza.cfg"))
    files.append((settings.CORAZA_SPOA_CONFIG_PATH, "config/coraza-spoa.yaml"))

    # Cert files.
    dirs.append((settings.CERT_DIR, "certs"))

    # Security list files.
    dirs.append((settings.SECURITY_LISTS_DIR, "data/lists"))

    # CRS and custom WAF rules.
    dirs.append((settings.CRS_DIR, "data/crs"))
    dirs.append((settings.CUSTOM_RULES_DIR, "data/custom-rules"))

    # Config snapshot history.
    from ..services.haproxy import _snapshots_dir
    dirs.append((_snapshots_dir(), "data/snapshots"))

    # GeoIP databases.
    geoip_files = [
        (settings.GEOIP_DB_PATH, "data/geoip/GeoLite2-Country.mmdb"),
        (settings.GEOIP_CITY_DB_PATH, "data/geoip/GeoLite2-City.mmdb"),
        (settings.ASN_DB_PATH, "data/geoip/GeoLite2-ASN.mmdb"),
    ]
    files.extend(geoip_files)

    return files, dirs


# ---------------------------------------------------------------------------
# File extraction (restore)
# ---------------------------------------------------------------------------

def _extract_dir_from_zip(zf: zipfile.ZipFile, arc_prefix: str, dest_dir: str) -> int:
    """Extract all files under arc_prefix from the zip into dest_dir. Returns count."""
    if not arc_prefix.endswith("/"):
        arc_prefix += "/"
    count = 0
    # Clear existing destination directory.
    if os.path.isdir(dest_dir):
        shutil.rmtree(dest_dir, ignore_errors=True)
    os.makedirs(dest_dir, exist_ok=True)
    for info in zf.infolist():
        if info.is_dir():
            continue
        if info.filename.startswith(arc_prefix):
            rel = info.filename[len(arc_prefix):]
            if not rel:
                continue
            dest = os.path.join(dest_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst)
            count += 1
    return count


def _extract_file_from_zip(zf: zipfile.ZipFile, arcname: str, dest_path: str) -> bool:
    """Extract a single file from the zip to dest_path. Returns True if extracted."""
    if arcname not in zf.namelist():
        return False
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with zf.open(arcname) as src, open(dest_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return True


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def _derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password + salt using PBKDF2."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def _encrypt_archive(plaintext: bytes, password: str) -> bytes:
    """Encrypt archive bytes with a password. Returns magic + salt + ciphertext."""
    import os as _os
    from cryptography.fernet import Fernet

    salt = _os.urandom(_PBKDF2_SALT_LEN)
    key = _derive_fernet_key(password, salt)
    cipher = Fernet(key)
    ciphertext = cipher.encrypt(plaintext)
    return _ENC_MAGIC + salt + ciphertext


def _decrypt_archive(data: bytes, password: Optional[str]) -> bytes:
    """Decrypt archive bytes. Raises ValueError if encrypted without password or wrong password."""
    if not data.startswith(_ENC_MAGIC):
        # Not encrypted — return as-is.
        return data
    if not password:
        raise ValueError("Archive is password-protected. Please provide the password.")
    from cryptography.fernet import Fernet, InvalidToken

    salt = data[len(_ENC_MAGIC):len(_ENC_MAGIC) + _PBKDF2_SALT_LEN]
    ciphertext = data[len(_ENC_MAGIC) + _PBKDF2_SALT_LEN:]
    key = _derive_fernet_key(password, salt)
    cipher = Fernet(key)
    try:
        return cipher.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError("Invalid password or corrupted archive.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_export(
    db: Session,
    include_secrets: bool = True,
    include_metrics: bool = False,
    password: Optional[str] = None,
) -> Tuple[str, bool]:
    """Build a full-system export archive and return (temp_file_path, encrypted).

    The archive is a ZIP written to a temporary file (to avoid holding 200+ MB
    in memory). If a password is provided, the ZIP is Fernet-encrypted.

    The caller is responsible for deleting the temp file when done.

    Uses a separate short-lived session for the DB read so the caller's session
    is not held open (which would block other writers on SQLite).

    db.json is streamed directly into the zip (table by table, row by row)
    instead of building one giant JSON string in memory. This is critical
    when metrics tables contain hundreds of MB of data.
    """
    manifest = {
        "version": ARCHIVE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "include_secrets": include_secrets,
        "include_metrics": include_metrics,
        "encrypted": password is not None,
    }

    # Build ZIP to a temp file (not in memory — archives with GeoIP DBs + metrics can be 500+ MB).
    fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="hpm_export_")
    os.close(fd)  # We'll let zipfile open it

    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

            # Stream DB tables directly into db.json — no giant in-memory dict/string.
            export_db = SessionLocal()
            try:
                _stream_db_json_to_zip(zf, export_db, include_secrets, include_metrics)
            finally:
                export_db.close()

            files, dirs = _collect_files(db, include_secrets, include_metrics)
            for src, arc in files:
                _add_file_to_zip(zf, src, arc)
            for src_dir, arc_dir in dirs:
                _add_dir_to_zip(zf, src_dir, arc_dir)

        if password:
            # Read the zip, encrypt it, write back to the temp file.
            with open(tmp_path, "rb") as f:
                zip_bytes = f.read()
            encrypted = _encrypt_archive(zip_bytes, password)
            with open(tmp_path, "wb") as f:
                f.write(encrypted)
            return tmp_path, True

        return tmp_path, False
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def restore_export(
    db: Session,
    archive_bytes: bytes,
    password: Optional[str] = None,
    apply_config: bool = True,
) -> Dict[str, Any]:
    """Restore the system from an export archive.

    Replaces all DB tables and files present in the archive, then optionally
    applies the config and reloads HAProxy. Returns a summary dict.
    """
    # Decrypt if needed.
    zip_bytes = _decrypt_archive(archive_bytes, password)

    # Open as ZIP.
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile:
        raise ValueError("Invalid archive: not a valid ZIP file.")

    # Read manifest + db.json.
    try:
        manifest = json.loads(zf.read("manifest.json"))
    except KeyError:
        raise ValueError("Invalid archive: manifest.json not found.")
    try:
        db_snapshot = json.loads(zf.read("db.json"))
    except KeyError:
        raise ValueError("Invalid archive: db.json not found.")

    # Restore DB.
    tables_restored = _restore_db_from_snapshot(db, db_snapshot)

    # Restore files.
    files_restored = 0

    # Config files.
    config_files = [
        ("config/haproxy.cfg", settings.HAPROXY_CONFIG_PATH),
        ("config/haproxy.cfg.applied", f"{settings.HAPROXY_CONFIG_PATH}.applied"),
        ("config/coraza.cfg", settings.CORAZA_SPOE_CONFIG_PATH),
        ("config/coraza-spoa.yaml", settings.CORAZA_SPOA_CONFIG_PATH),
    ]
    for arcname, dest in config_files:
        if _extract_file_from_zip(zf, arcname, dest):
            files_restored += 1

    # Directories.
    from ..services.haproxy import _snapshots_dir
    dir_mappings = [
        ("certs", settings.CERT_DIR),
        ("data/lists", settings.SECURITY_LISTS_DIR),
        ("data/crs", settings.CRS_DIR),
        ("data/custom-rules", settings.CUSTOM_RULES_DIR),
        ("data/snapshots", _snapshots_dir()),
    ]
    for arc_prefix, dest_dir in dir_mappings:
        files_restored += _extract_dir_from_zip(zf, arc_prefix, dest_dir)

    # GeoIP databases.
    geoip_files = [
        ("data/geoip/GeoLite2-Country.mmdb", settings.GEOIP_DB_PATH),
        ("data/geoip/GeoLite2-City.mmdb", settings.GEOIP_CITY_DB_PATH),
        ("data/geoip/GeoLite2-ASN.mmdb", settings.ASN_DB_PATH),
    ]
    for arcname, dest in geoip_files:
        if _extract_file_from_zip(zf, arcname, dest):
            files_restored += 1

    zf.close()

    # Auto-apply config + reload HAProxy.
    config_applied = False
    reload_result: Optional[Dict[str, Any]] = None
    if apply_config:
        try:
            write_config(db, created_by="system-restore")
            reload_result = reload_haproxy()
            config_applied = True
        except Exception as exc:
            reload_result = {"error": str(exc)}

    return {
        "status": "ok",
        "tables_restored": tables_restored,
        "files_restored": files_restored,
        "config_applied": config_applied,
        "reload_result": reload_result,
        "manifest": manifest,
    }
