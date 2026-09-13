"""Tests for the Vector log-pipeline service (vector_pipeline.py)."""
import os

import pytest

from app.core.config import get_settings
from app.models.logging import VectorSink
from app.services import vector_pipeline as vp


@pytest.fixture(autouse=True)
def _vector_tmp(tmp_path, monkeypatch):
    """Point VECTOR_CONFIG_PATH at a temp dir for file-lifecycle tests."""
    s = get_settings()
    monkeypatch.setattr(s, "VECTOR_CONFIG_PATH", str(tmp_path / "vector" / "vector.toml"))
    yield


def _make_sink(db, name="s3", type="aws_s3", source="corex", options=None, enabled=True):
    sink = VectorSink(
        name=name, type=type, source=source,
        options=vp.encrypt_sink_options(type, options or {}), enabled=enabled)
    db.add(sink)
    db.commit()
    return sink


# ── Sources (derived from enabled sinks) ────────────────────────────────────

def test_sources_default_off(db):
    assert vp.get_vector_sources(db) == {"corex": False, "waf": False, "mcp": False}


def test_sources_derived_from_enabled_sinks(db):
    _make_sink(db, name="s3corex", source="corex",
               options={"bucket": "b", "region": "r"})
    _make_sink(db, name="s3waf", source="waf",
               options={"bucket": "b", "region": "r"})
    assert vp.get_vector_sources(db) == {"corex": True, "waf": True, "mcp": False}


def test_sources_disabled_sink_does_not_activate(db):
    _make_sink(db, name="off", source="corex", enabled=False,
               options={"bucket": "b", "region": "r"})
    assert vp.get_vector_sources(db) == {"corex": False, "waf": False, "mcp": False}


def test_corex_source_enabled(db):
    assert vp.corex_source_enabled(db) is False
    _make_sink(db, options={"bucket": "b", "region": "r"})
    assert vp.corex_source_enabled(db) is True


def test_vector_pipeline_active(db):
    assert vp.vector_pipeline_active(db) is False
    _make_sink(db, options={"bucket": "b", "region": "r"})
    assert vp.vector_pipeline_active(db) is True
    # A disabled sink row also marks the pipeline active
    _make_sink(db, name="off", enabled=False,
               options={"bucket": "b", "region": "r"})
    assert vp.vector_pipeline_active(db) is True


# ── Secret encryption / masking ──────────────────────────────────────────────

def test_encrypt_decrypt_round_trip(db):
    opts = {"bucket": "b", "secret_access_key": "supersecret"}
    enc = vp.encrypt_sink_options("aws_s3", opts)
    assert enc["secret_access_key"].startswith("enc:")
    assert enc["bucket"] == "b"  # non-secret untouched

    dec, plaintexts = vp.decrypt_sink_options("aws_s3", enc)
    assert dec["secret_access_key"] == "supersecret"
    assert "supersecret" in plaintexts


def test_mask_sink_options(db):
    enc = vp.encrypt_sink_options("datadog_logs", {"api_key": "dd-key-123"})
    masked = vp.mask_sink_options("datadog_logs", enc)
    assert masked["api_key"] == "********"


def test_encrypt_skips_mask_and_enc(db):
    enc = vp.encrypt_sink_options("splunk_hec_logs", {"token": "tok1"})
    # Re-encrypting an already-encrypted value must not double-wrap
    enc2 = vp.encrypt_sink_options("splunk_hec_logs", enc)
    assert enc2["token"] == enc["token"]
    # The mask sentinel is never encrypted
    m = vp.encrypt_sink_options("splunk_hec_logs", {"token": "********"})
    assert m["token"] == "********"


def test_redact_text(db):
    assert vp.redact_text("key = 'abc123'", ["abc123"]) == "key = '********'"


def test_redact_vector_text_masks_known_secret_keys():
    text = 'default_api_key = "secret-val"\nbucket = "b"\ntoken = "tok"'
    out = vp.redact_vector_text(text)
    assert "secret-val" not in out
    assert 'token = "tok"' not in out
    assert 'bucket = "b"' in out


# ── TOML generation ─────────────────────────────────────────────────────────

def test_empty_pipeline_emits_noop(db):
    toml_text, secrets = vp.generate_vector_toml(db)
    assert "[sinks.blackhole]" in toml_text
    assert secrets == []


def test_corex_source_and_transforms(db):
    _make_sink(db, options={"bucket": "logs", "region": "us-east-1"})
    toml_text, _ = vp.generate_vector_toml(db)
    assert '[sources.corex_syslog]' in toml_text
    assert 'mode = "tcp"' in toml_text
    assert 'address = "0.0.0.0:601"' in toml_text
    assert '[transforms.haproxy_parse_json]' in toml_text
    assert '[transforms.decode_ja4]' in toml_text
    assert '[transforms.decode_req_fp]' in toml_text
    assert '[transforms.haproxy_finalize]' in toml_text
    # VRL content is preserved
    assert "parse_json(.message)" in toml_text
    assert '.corex_source = "corex"' in toml_text
    # Internal HAProxy log fallback parsing (SSL handshake errors, etc.)
    assert "haproxy_internal" in toml_text
    assert "parse_regex(raw" in toml_text


def test_waf_and_mcp_sources(db):
    _make_sink(db, name="s3waf", source="waf",
               options={"bucket": "logs", "region": "us-east-1"})
    _make_sink(db, name="s3mcp", source="mcp",
               options={"bucket": "logs", "region": "us-east-1"})
    toml_text, _ = vp.generate_vector_toml(db)
    assert '[sources.waf_file]' in toml_text
    assert 'coraza-spoa.log' in toml_text
    assert '[sources.mcp_file]' in toml_text
    assert 'events.ndjson' in toml_text
    assert '[transforms.waf_parse_json]' in toml_text
    assert '[transforms.mcp_parse_json]' in toml_text
    assert '.corex_source = "waf"' in toml_text
    assert '.corex_source = "mcp"' in toml_text


def test_multiple_sinks_same_source(db):
    """Two sinks with the same source each get their own sink block."""
    _make_sink(db, name="s3", source="corex",
               options={"bucket": "logs", "region": "us-east-1"})
    _make_sink(db, name="dd", type="datadog_logs", source="corex",
               options={"api_key": "ddkey"})
    toml_text, _ = vp.generate_vector_toml(db)
    assert "[sinks.s3_corex]" in toml_text
    assert "[sinks.dd_corex]" in toml_text
    assert 'inputs = ["haproxy_finalize"]' in toml_text


def test_disabled_sink_excluded(db):
    _make_sink(db, name="off", enabled=False,
               options={"bucket": "logs", "region": "us-east-1"})
    toml_text, _ = vp.generate_vector_toml(db)
    assert "off" not in toml_text


def test_secrets_inlined_and_reported(db):
    _make_sink(db, options={
        "bucket": "logs", "region": "us-east-1",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI",
    })
    toml_text, secrets = vp.generate_vector_toml(db)
    assert 'access_key_id = "AKIAIOSFODNN7EXAMPLE"' in toml_text
    assert 'secret_access_key = "wJalrXUtnFEMI"' in toml_text
    assert "wJalrXUtnFEMI" in secrets
    # Redacted variant must not contain plaintext
    redacted = vp.generate_vector_toml_redacted(db)
    assert "wJalrXUtnFEMI" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted


def test_all_sink_types_render(db):
    fixtures = {
        "azure_logs_ingestion": {
            "endpoint": "https://dce.ingest.monitor.azure.com",
            "dcr_immutable_id": "dcr-123", "stream_name": "Custom-x",
            "tenant_id": "t", "client_id": "c", "client_secret": "cs",
        },
        "datadog_logs": {"api_key": "ddkey"},
        "elasticsearch": {"endpoints": ["https://es:9200"],
                          "auth_strategy": "basic", "user": "u", "password": "p"},
        "http": {"uri": "https://logs.example.com/in", "auth_strategy": "bearer",
                 "token": "tok", "headers": {"X-A": "b"}},
        "new_relic": {"account_id": "12345", "license_key": "nrlic"},
        "splunk_hec_logs": {"endpoint": "https://splunk:8088", "token": "hec"},
    }
    for i, (stype, opts) in enumerate(fixtures.items()):
        _make_sink(db, name=f"s{i}", type=stype, options=opts)
    toml_text, _ = vp.generate_vector_toml(db)
    for i, stype in enumerate(fixtures):
        assert f"[sinks.s{i}_corex]" in toml_text
        assert f'type = "{stype}"' in toml_text
    assert 'strategy = "basic"' in toml_text
    assert 'strategy = "bearer"' in toml_text
    assert 'api = "logs"' in toml_text          # new_relic
    assert 'bulk.index = "corex-log-%Y.%m.%d"' in toml_text  # es default index
    assert 'endpoint_target = "event"' in toml_text
    assert '"X-A" = "b"' in toml_text           # http headers table


def test_elasticsearch_per_source_index(db):
    _make_sink(db, name="es_corex", type="elasticsearch", source="corex",
               options={"endpoints": "https://es:9200",
                        "index_corex": "custom-corex-%F"})
    _make_sink(db, name="es_waf", type="elasticsearch", source="waf",
               options={"endpoints": "https://es:9200"})
    toml_text, _ = vp.generate_vector_toml(db)
    assert 'bulk.index = "custom-corex-%F"' in toml_text
    assert 'bulk.index = "waf-logs-%Y.%m.%d"' in toml_text


# ── Staging config (check sink) ─────────────────────────────────────────────

def test_staging_uses_demo_source_when_no_sinks(db):
    toml_text, secrets = vp.generate_staging_sink_toml(
        db, "splunk_hec_logs", "corex",
        {"endpoint": "https://splunk:8088", "token": "hec-tok"}, False)
    assert '[sources.test_events]' in toml_text
    assert 'type = "demo_logs"' in toml_text
    assert 'inputs = ["test_events"]' in toml_text
    assert "[sinks.check_corex]" in toml_text
    assert 'default_token = "hec-tok"' in toml_text
    assert "hec-tok" in secrets


def test_staging_uses_enabled_transform(db):
    _make_sink(db, options={"bucket": "b", "region": "r"})
    toml_text, _ = vp.generate_staging_sink_toml(
        db, "aws_s3", "corex", {"bucket": "b", "region": "r"}, False)
    assert '[sources.corex_syslog]' in toml_text
    assert 'inputs = ["haproxy_finalize"]' in toml_text
    assert "demo_logs" not in toml_text


def test_staging_send_test_event_uses_demo_even_with_sinks(db):
    _make_sink(db, options={"bucket": "b", "region": "r"})
    toml_text, _ = vp.generate_staging_sink_toml(
        db, "http", "corex", {"uri": "https://x"}, True)
    assert "demo_logs" in toml_text
    assert 'inputs = ["test_events"]' in toml_text


# ── File lifecycle ──────────────────────────────────────────────────────────

def test_write_vector_config(db):
    s = get_settings()
    assert vp.write_vector_config(db, restart=False) is True
    assert os.path.exists(s.VECTOR_CONFIG_PATH)
    assert os.path.exists(f"{s.VECTOR_CONFIG_PATH}.applied")
    # Second write with identical content is a no-op
    assert vp.write_vector_config(db, restart=False) is False


def test_write_only_if_missing(db):
    s = get_settings()
    vp.write_vector_config(db, restart=False)
    # Modify on-disk file, then only_if_missing must not touch it
    with open(s.VECTOR_CONFIG_PATH, "w") as f:
        f.write("custom")
    assert vp.write_vector_config(db, restart=False, only_if_missing=True) is False
    with open(s.VECTOR_CONFIG_PATH) as f:
        assert f.read() == "custom"
