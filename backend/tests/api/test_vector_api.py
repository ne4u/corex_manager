"""Tests for the /vector/* API endpoints."""
from unittest.mock import MagicMock, patch

import pytest

from app.core.config import get_settings
from app.models.logging import VectorSink
from app.services import vector_pipeline as vp


@pytest.fixture(autouse=True)
def _vector_tmp(tmp_path, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "VECTOR_CONFIG_PATH", str(tmp_path / "vector" / "vector.toml"))
    monkeypatch.setattr(s, "VECTOR_CONTAINER_CONFIG_PATH", "/app/data/vector/vector.toml")
    yield


S3_PAYLOAD = {
    "name": "s3", "type": "aws_s3", "source": "corex",
    "options": {"bucket": "logs", "region": "us-east-1",
                "access_key_id": "AKIA", "secret_access_key": "sekret"},
    "enabled": True,
}


def test_pipeline_endpoint(client):
    res = client.get("/api/v1/vector/pipeline")
    assert res.status_code == 200
    data = res.json()
    assert data["sources"] == {"corex": False, "waf": False, "mcp": False}
    assert data["sinks"] == []
    assert "runtime" in data


def test_sources_derived_from_sinks(client):
    """Sources are auto-enabled when a sink references them (no separate toggle)."""
    res = client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    assert res.status_code == 200
    res = client.get("/api/v1/vector/pipeline")
    assert res.json()["sources"]["corex"] is True
    assert res.json()["sources"]["waf"] is False


def test_create_sink_masks_secrets(client):
    res = client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    assert res.status_code == 200
    data = res.json()
    assert data["options"]["secret_access_key"] == "********"
    assert data["options"]["access_key_id"] == "********"
    assert data["options"]["bucket"] == "logs"


def test_create_sink_duplicate_name(client):
    client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    res = client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    assert res.status_code == 409


def test_create_sink_invalid_type(client):
    res = client.post("/api/v1/vector/sinks",
                      json={**S3_PAYLOAD, "type": "bogus"})
    assert res.status_code == 422


def test_create_sink_missing_required_option(client):
    res = client.post("/api/v1/vector/sinks",
                      json={**S3_PAYLOAD, "options": {"region": "us-east-1"}})
    assert res.status_code == 422


def test_create_sink_invalid_source(client):
    res = client.post("/api/v1/vector/sinks",
                      json={**S3_PAYLOAD, "source": "bogus"})
    assert res.status_code == 422


def test_update_sink_keeps_masked_secret(client, db):
    res = client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    sid = res.json()["id"]

    # Submit the masked secret back — stored ciphertext must be preserved
    res = client.put(f"/api/v1/vector/sinks/{sid}",
                     json={**S3_PAYLOAD, "name": "s3-renamed",
                           "options": {"bucket": "logs2", "region": "us-west-2",
                                       "secret_access_key": "********"}})
    assert res.status_code == 200

    row = db.get(VectorSink, sid)
    dec, _ = vp.decrypt_sink_options("aws_s3", row.options)
    assert dec["secret_access_key"] == "sekret"
    assert dec["bucket"] == "logs2"


def test_update_sink_replaces_secret(client, db):
    res = client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    sid = res.json()["id"]
    res = client.put(f"/api/v1/vector/sinks/{sid}",
                     json={**S3_PAYLOAD,
                           "options": {**S3_PAYLOAD["options"],
                                       "secret_access_key": "new-secret"}})
    assert res.status_code == 200
    row = db.get(VectorSink, sid)
    dec, _ = vp.decrypt_sink_options("aws_s3", row.options)
    assert dec["secret_access_key"] == "new-secret"


def test_delete_sink(client):
    res = client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    sid = res.json()["id"]
    assert client.delete(f"/api/v1/vector/sinks/{sid}").status_code == 200
    assert client.delete(f"/api/v1/vector/sinks/{sid}").status_code == 404


def test_preview_redacts_secrets(client):
    client.post("/api/v1/vector/sinks", json=S3_PAYLOAD)
    res = client.get("/api/v1/vector/preview")
    assert res.status_code == 200
    cfg = res.json()["config"]
    assert "[sinks.s3_corex]" in cfg
    assert "sekret" not in cfg
    assert "AKIA" not in cfg


def _fake_runtime(ok=True, output="vector: configuration valid"):
    rt = MagicMock()
    rt.vector_exec.return_value = (ok, output)
    return rt


def test_sink_check_validate_ok(client):
    with patch("app.services.runtime.get_runtime", return_value=_fake_runtime()):
        res = client.post("/api/v1/vector/sinks/test", json={
            "name": "t", "type": "splunk_hec_logs", "source": "corex",
            "options": {"endpoint": "https://splunk:8088", "token": "tok"},
        })
    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_sink_check_failure_output(client):
    rt = _fake_runtime(ok=False, output="healthcheck failed: connection refused")
    with patch("app.services.runtime.get_runtime", return_value=rt):
        res = client.post("/api/v1/vector/sinks/test", json={
            "name": "t", "type": "splunk_hec_logs", "source": "corex",
            "options": {"endpoint": "https://splunk:8088", "token": "tok"},
        })
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is False
    assert "connection refused" in body["output"]


def test_sink_check_unavailable_runtime(client):
    rt = _fake_runtime(ok=False, output="vector container not available")
    with patch("app.services.runtime.get_runtime", return_value=rt):
        res = client.post("/api/v1/vector/sinks/test", json={
            "name": "t", "type": "http", "source": "corex",
            "options": {"uri": "https://x"},
        })
    assert res.status_code == 503


def test_sink_check_redacts_secret_from_output(client):
    rt = _fake_runtime(ok=False, output="auth failed for token my-hec-secret")
    with patch("app.services.runtime.get_runtime", return_value=rt):
        res = client.post("/api/v1/vector/sinks/test", json={
            "name": "t", "type": "splunk_hec_logs", "source": "corex",
            "options": {"endpoint": "https://splunk:8088", "token": "my-hec-secret"},
        })
    assert res.status_code == 200
    assert "my-hec-secret" not in res.json()["output"]


def test_sink_check_send_test_event(client):
    # send_test_event now uses the same `vector validate` path (the vector
    # image entrypoint prevents running `sh -c 'timeout ...'`). The flag
    # still controls whether the staging config includes a demo_logs source.
    rt = _fake_runtime(ok=True, output="vector: configuration valid")
    with patch("app.services.runtime.get_runtime", return_value=rt):
        res = client.post("/api/v1/vector/sinks/test", json={
            "name": "t", "type": "http", "source": "corex",
            "options": {"uri": "https://x"}, "send_test_event": True,
        })
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert "configuration valid" in body["output"]


def test_validate_endpoint(client):
    with patch("app.services.runtime.get_runtime", return_value=_fake_runtime()):
        res = client.post("/api/v1/vector/validate")
    assert res.status_code == 200
    assert res.json()["valid"] is True


def test_restart_endpoint(client):
    rt = MagicMock()
    rt.restart_vector.return_value = True
    with patch("app.services.runtime.get_runtime", return_value=rt):
        res = client.post("/api/v1/vector/restart")
    assert res.status_code == 200

    rt.restart_vector.return_value = False
    with patch("app.services.runtime.get_runtime", return_value=rt):
        res = client.post("/api/v1/vector/restart")
    assert res.status_code == 503
