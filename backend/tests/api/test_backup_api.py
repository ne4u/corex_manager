"""Integration tests for the /system/export and /system/restore endpoints."""
import io
import json
import zipfile

import pytest

from app.models.models import Backend, Setting


def test_export_endpoint_returns_zip(client, db):
    # Create some config to export.
    client.post("/api/v1/backends", json={"name": "export-test", "protocol": "http"})
    res = client.get("/api/v1/system/export")
    assert res.status_code == 200
    assert "application/zip" in res.headers.get("content-type", "")
    assert "attachment" in res.headers.get("content-disposition", "")
    # Verify it's a valid ZIP with manifest + db.json.
    zf = zipfile.ZipFile(io.BytesIO(res.content), "r")
    assert "manifest.json" in zf.namelist()
    assert "db.json" in zf.namelist()
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["include_secrets"] is True
    assert manifest["include_metrics"] is False
    assert manifest["encrypted"] is False


def test_export_endpoint_with_password_returns_encrypted(client, db):
    client.post("/api/v1/backends", json={"name": "enc-test", "protocol": "http"})
    res = client.get("/api/v1/system/export?password=test-pass")
    assert res.status_code == 200
    assert "application/octet-stream" in res.headers.get("content-type", "")
    assert "attachment" in res.headers.get("content-disposition", "")
    # Should start with the encryption magic header.
    assert res.content[:7] == b"HPMENC1"


def test_export_endpoint_excludes_secrets(client, db):
    from app.models.models import User
    db.add(User(username="admin", hashed_password="x", role="admin", is_admin=True))
    db.commit()
    res = client.get("/api/v1/system/export?include_secrets=false")
    assert res.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(res.content), "r")
    db_snapshot = json.loads(zf.read("db.json"))
    assert "users" not in db_snapshot


def test_export_endpoint_includes_metrics(client, db):
    from app.models.models import MetricSnapshot
    db.add(MetricSnapshot(process_info={}, stats=[]))
    db.commit()
    res = client.get("/api/v1/system/export?include_metrics=true")
    assert res.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(res.content), "r")
    db_snapshot = json.loads(zf.read("db.json"))
    assert "metric_snapshots" in db_snapshot


def test_restore_endpoint_restores_config(client, db):
    # Create config, export it.
    client.post("/api/v1/backends", json={"name": "restore-test", "protocol": "http"})
    export_res = client.get("/api/v1/system/export")
    assert export_res.status_code == 200
    archive_bytes = export_res.content

    # Delete the backend.
    backend = db.query(Backend).filter(Backend.name == "restore-test").first()
    db.delete(backend)
    db.commit()
    assert db.query(Backend).filter(Backend.name == "restore-test").first() is None

    # Restore via the API (multipart upload). Use apply_config=False by
    # patching restore_export to skip HAProxy reload (not available in test env).
    import app.services.backup as backup_mod
    original_restore = backup_mod.restore_export

    def _test_restore(db, archive_bytes, password=None, apply_config=True):
        return original_restore(db, archive_bytes, password=password, apply_config=False)

    backup_mod.restore_export = _test_restore
    try:
        res = client.post(
            "/api/v1/system/restore",
            files={"file": ("export.zip", archive_bytes, "application/zip")},
        )
    finally:
        backup_mod.restore_export = original_restore

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["tables_restored"] > 0
    # Verify the backend was restored.
    assert db.query(Backend).filter(Backend.name == "restore-test").first() is not None


def test_restore_endpoint_wrong_password_returns_400(client, db):
    client.post("/api/v1/backends", json={"name": "wrong-pass-test", "protocol": "http"})
    export_res = client.get("/api/v1/system/export?password=correct-pass")
    assert export_res.status_code == 200
    archive_bytes = export_res.content

    res = client.post(
        "/api/v1/system/restore",
        files={"file": ("export.zip", archive_bytes, "application/octet-stream")},
        data={"password": "wrong-pass"},
    )
    assert res.status_code == 400
    assert "Invalid password" in res.json()["detail"]


def test_restore_endpoint_encrypted_without_password_returns_400(client, db):
    client.post("/api/v1/backends", json={"name": "enc-no-pass-test", "protocol": "http"})
    export_res = client.get("/api/v1/system/export?password=correct-pass")
    assert export_res.status_code == 200
    archive_bytes = export_res.content

    res = client.post(
        "/api/v1/system/restore",
        files={"file": ("export.zip", archive_bytes, "application/octet-stream")},
    )
    assert res.status_code == 400
    assert "password-protected" in res.json()["detail"]


def test_restore_endpoint_correct_password_succeeds(client, db):
    client.post("/api/v1/backends", json={"name": "correct-pass-test", "protocol": "http"})
    export_res = client.get("/api/v1/system/export?password=correct-pass")
    assert export_res.status_code == 200
    archive_bytes = export_res.content

    # Delete the backend.
    backend = db.query(Backend).filter(Backend.name == "correct-pass-test").first()
    db.delete(backend)
    db.commit()

    # Patch to skip HAProxy reload.
    import app.services.backup as backup_mod
    original_restore = backup_mod.restore_export

    def _test_restore(db, archive_bytes, password=None, apply_config=True):
        return original_restore(db, archive_bytes, password=password, apply_config=False)

    backup_mod.restore_export = _test_restore
    try:
        res = client.post(
            "/api/v1/system/restore",
            files={"file": ("export.zip", archive_bytes, "application/octet-stream")},
            data={"password": "correct-pass"},
        )
    finally:
        backup_mod.restore_export = original_restore

    assert res.status_code == 200
    assert db.query(Backend).filter(Backend.name == "correct-pass-test").first() is not None
