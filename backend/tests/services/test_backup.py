"""Tests for the full-system export/restore backup service."""
import io
import json
import os
import zipfile

import pytest

from app.services.backup import (
    create_export,
    restore_export,
    _serialize_db,
    _decrypt_archive,
    _ENC_MAGIC,
    SECRET_FIELDS,
    SECRET_SETTING_KEYS,
)
from app.models.models import Backend, Certificate, Setting, User, WafSiemIntegration
from tests.factories import make_backend, make_server


def _export_to_bytes(db, **kwargs):
    """Helper: call create_export and read the temp file into bytes, cleaning up."""
    tmp_path, encrypted = create_export(db, **kwargs)
    try:
        with open(tmp_path, "rb") as f:
            return f.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_serialize_db_includes_config_tables(db):
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=False)
    assert "backends" in snapshot
    assert "servers" in snapshot
    assert any(r["name"] == "web" for r in snapshot["backends"])


def test_serialize_db_excludes_users_without_secrets(db):
    db.add(User(username="admin", hashed_password="x", role="admin", is_admin=True))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=False, include_metrics=False)
    assert "users" not in snapshot


def test_serialize_db_includes_users_with_secrets(db):
    db.add(User(username="admin", hashed_password="secret_hash", role="admin", is_admin=True))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=False)
    assert "users" in snapshot
    assert any(r["username"] == "admin" for r in snapshot["users"])


def test_serialize_db_redacts_secret_fields(db):
    db.add(Certificate(
        name="test-cert",
        domain="example.com",
        provider="custom",
        dns_provider="cloudflare",
        dns_credentials={"CF_API_TOKEN": "super-secret-token"},
    ))
    db.commit()
    # Without secrets — dns_credentials should be redacted to None.
    snapshot = _serialize_db(db, include_secrets=False, include_metrics=False)
    cert_rows = snapshot.get("certificates", [])
    assert len(cert_rows) == 1
    assert cert_rows[0]["dns_credentials"] is None


def test_serialize_db_preserves_secret_fields_with_secrets(db):
    db.add(Certificate(
        name="test-cert",
        domain="example.com",
        provider="custom",
        dns_provider="cloudflare",
        dns_credentials={"CF_API_TOKEN": "super-secret-token"},
    ))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=False)
    cert_rows = snapshot.get("certificates", [])
    assert len(cert_rows) == 1
    assert cert_rows[0]["dns_credentials"] == {"CF_API_TOKEN": "super-secret-token"}


def test_serialize_db_filters_secret_settings(db):
    db.add(Setting(key="maxmind_license_key", value="ABC123_secret"))
    db.add(Setting(key="max_snapshots", value="10"))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=False, include_metrics=False)
    setting_keys = {r["key"] for r in snapshot.get("settings", [])}
    assert "maxmind_license_key" not in setting_keys
    assert "max_snapshots" in setting_keys


def test_serialize_db_includes_secret_settings_with_secrets(db):
    db.add(Setting(key="maxmind_license_key", value="ABC123_secret"))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=False)
    setting_keys = {r["key"] for r in snapshot.get("settings", [])}
    assert "maxmind_license_key" in setting_keys


def test_serialize_db_excludes_metrics_by_default(db):
    from app.models.models import MetricSnapshot, WafMetric, AuditEvent
    db.add(MetricSnapshot(process_info={}, stats=[]))
    db.add(WafMetric(action="deny"))
    db.add(AuditEvent(action="test", method="POST", path="/api/v1/test"))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=False)
    assert "metric_snapshots" not in snapshot
    assert "waf_metrics" not in snapshot
    assert "audit_events" not in snapshot


def test_serialize_db_includes_metrics_when_requested(db):
    from app.models.models import MetricSnapshot, WafMetric
    db.add(MetricSnapshot(process_info={}, stats=[]))
    db.add(WafMetric(action="deny"))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=True)
    assert "metric_snapshots" in snapshot
    assert "waf_metrics" in snapshot


# ---------------------------------------------------------------------------
# Export / Restore roundtrip
# ---------------------------------------------------------------------------

def test_export_returns_valid_zip(db):
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False)
    assert isinstance(archive, bytes)
    zf = zipfile.ZipFile(io.BytesIO(archive), "r")
    assert "manifest.json" in zf.namelist()
    assert "db.json" in zf.namelist()
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["version"] == 1
    assert manifest["include_secrets"] is True
    assert manifest["include_metrics"] is False
    assert manifest["encrypted"] is False


def test_export_roundtrip_restores_db(db):
    backend = make_backend(db, name="web")
    make_server(db, backend.id, name="s1", address="10.0.0.1")
    db.add(Setting(key="max_snapshots", value="15"))
    db.commit()

    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False)

    # Mutate the DB so we can verify restore overwrites.
    db.query(Backend).delete()
    db.query(Setting).filter(Setting.key == "max_snapshots").delete()
    db.commit()
    assert db.query(Backend).count() == 0

    # Restore (without applying config — no HAProxy in test env).
    result = restore_export(db, archive, apply_config=False)
    assert result["status"] == "ok"
    assert result["tables_restored"] > 0

    # Verify data was restored.
    restored_backend = db.query(Backend).filter(Backend.name == "web").first()
    assert restored_backend is not None
    restored_setting = db.query(Setting).filter(Setting.key == "max_snapshots").first()
    assert restored_setting is not None
    assert restored_setting.value == "15"


def test_export_without_secrets_excludes_users(db):
    db.add(User(username="admin", hashed_password="x", role="admin", is_admin=True))
    db.commit()
    archive = _export_to_bytes(db, include_secrets=False, include_metrics=False)
    zf = zipfile.ZipFile(io.BytesIO(archive), "r")
    db_snapshot = json.loads(zf.read("db.json"))
    assert "users" not in db_snapshot


def test_export_with_secrets_includes_users(db):
    db.add(User(username="admin", hashed_password="x", role="admin", is_admin=True))
    db.commit()
    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False)
    zf = zipfile.ZipFile(io.BytesIO(archive), "r")
    db_snapshot = json.loads(zf.read("db.json"))
    assert "users" in db_snapshot


# ---------------------------------------------------------------------------
# Password encryption
# ---------------------------------------------------------------------------

def test_password_encryption_roundtrip(db):
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    db.commit()

    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False, password="my-secret-pass")
    # Should start with the encryption magic header.
    assert archive[:len(_ENC_MAGIC)] == _ENC_MAGIC

    # Restore with correct password.
    result = restore_export(db, archive, password="my-secret-pass", apply_config=False)
    assert result["status"] == "ok"
    assert db.query(Backend).filter(Backend.name == "web").first() is not None


def test_password_encryption_wrong_password_fails(db):
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    db.commit()

    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False, password="correct-pass")
    with pytest.raises(ValueError, match="Invalid password"):
        restore_export(db, archive, password="wrong-pass", apply_config=False)


def test_encrypted_archive_without_password_fails(db):
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    db.commit()

    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False, password="correct-pass")
    with pytest.raises(ValueError, match="password-protected"):
        restore_export(db, archive, password=None, apply_config=False)


def test_unencrypted_archive_with_password_ignored(db):
    """Providing a password for an unencrypted archive should not error."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    db.commit()

    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False, password=None)
    # Should NOT start with magic header.
    assert archive[:len(_ENC_MAGIC)] != _ENC_MAGIC
    result = restore_export(db, archive, password="unused-password", apply_config=False)
    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# Restore replaces config
# ---------------------------------------------------------------------------

def test_restore_replaces_config(db):
    backend1 = make_backend(db, name="web1")
    make_server(db, backend1.id, name="s1", address="10.0.0.1")
    db.commit()

    archive = _export_to_bytes(db, include_secrets=True, include_metrics=False)

    # Add a second backend after export.
    backend2 = make_backend(db, name="web2")
    make_server(db, backend2.id, name="s2", address="10.0.0.2")
    db.commit()
    assert db.query(Backend).count() == 2

    # Restore — web2 should be gone, only web1 should remain.
    result = restore_export(db, archive, apply_config=False)
    assert result["status"] == "ok"
    assert db.query(Backend).count() == 1
    assert db.query(Backend).filter(Backend.name == "web1").first() is not None
    assert db.query(Backend).filter(Backend.name == "web2").first() is None


# ---------------------------------------------------------------------------
# SIEM auth_header redaction
# ---------------------------------------------------------------------------

def test_siem_auth_header_redacted_without_secrets(db):
    db.add(WafSiemIntegration(name="siem1", target="http://siem", auth_header="Bearer secret-token"))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=False, include_metrics=False)
    siem_rows = snapshot.get("waf_siem_integrations", [])
    assert len(siem_rows) == 1
    assert siem_rows[0]["auth_header"] is None


def test_siem_auth_header_preserved_with_secrets(db):
    db.add(WafSiemIntegration(name="siem1", target="http://siem", auth_header="Bearer secret-token"))
    db.commit()
    snapshot = _serialize_db(db, include_secrets=True, include_metrics=False)
    siem_rows = snapshot.get("waf_siem_integrations", [])
    assert len(siem_rows) == 1
    assert siem_rows[0]["auth_header"] == "Bearer secret-token"
