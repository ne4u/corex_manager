"""Tests for the in-process /config/status cache and its invalidation hooks."""

import threading
import time

import pytest
from app.services import config as config_service


@pytest.fixture(autouse=True)
def _reset_status_cache(monkeypatch):
    # conftest disables the cache session-wide (TTL=0) so direct-DB tests keep
    # pre-cache semantics; these tests opt back in to exercise the cache.
    monkeypatch.setattr(config_service, "_CONFIG_STATUS_TTL", 5.0)
    config_service.invalidate_config_status()
    yield
    config_service.invalidate_config_status()


def _fake_status(value):
    """Return a _config_status_data replacement that counts invocations."""
    calls = []

    def _impl(_db):
        calls.append(1)
        return value, {}, {}

    return _impl, calls


def test_get_config_status_caches_result(db, monkeypatch):
    impl, calls = _fake_status(True)
    monkeypatch.setattr(config_service, "_config_status_data", impl)

    assert config_service.get_config_status(db) is True
    assert config_service.get_config_status(db) is True
    assert len(calls) == 1


def test_get_config_status_ttl_expiry(db, monkeypatch):
    impl, calls = _fake_status(False)
    monkeypatch.setattr(config_service, "_config_status_data", impl)

    assert config_service.get_config_status(db) is False
    assert len(calls) == 1

    # Simulate a cache entry older than the TTL — next call must regenerate.
    config_service._config_status_cache = (time.monotonic() - 999, False)
    assert config_service.get_config_status(db) is False
    assert len(calls) == 2


def test_invalidate_config_status_forces_regeneration(db, monkeypatch):
    impl, calls = _fake_status(True)
    monkeypatch.setattr(config_service, "_config_status_data", impl)

    config_service.get_config_status(db)
    config_service.invalidate_config_status()
    config_service.get_config_status(db)
    assert len(calls) == 2


def test_get_config_status_single_flight(db, monkeypatch):
    """Concurrent status polls share one regeneration (lock held during compute)."""
    calls = []

    def _slow(_db):
        calls.append(1)
        time.sleep(0.1)
        return True, {}, {}

    monkeypatch.setattr(config_service, "_config_status_data", _slow)

    results = []
    threads = [threading.Thread(target=lambda: results.append(config_service.get_config_status(db))) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == [True] * 4
    assert len(calls) == 1


def test_invalidate_does_not_block_during_regen(db, monkeypatch):
    """invalidate_config_status must return immediately while a regeneration
    holds the lock (it is called from async middleware — blocking would stall
    the event loop)."""
    started = threading.Event()
    release = threading.Event()

    def _slow(_db):
        started.set()
        release.wait(timeout=5)
        return True, {}, {}

    monkeypatch.setattr(config_service, "_config_status_data", _slow)
    t = threading.Thread(target=lambda: config_service.get_config_status(db))
    t.start()
    try:
        assert started.wait(timeout=5)
        t0 = time.monotonic()
        config_service.invalidate_config_status()
        assert time.monotonic() - t0 < 1
    finally:
        release.set()
        t.join(timeout=5)


def test_invalidation_during_regen_is_not_cached(db, monkeypatch):
    """A mutation landing mid-regeneration must not let the (possibly stale)
    result get cached — the next call regenerates."""

    def _impl(_db):
        config_service.invalidate_config_status()
        return True, {}, {}

    monkeypatch.setattr(config_service, "_config_status_data", _impl)
    assert config_service.get_config_status(db) is True
    assert config_service._config_status_cache is None


def _baseline_configs(db, tmp_path, monkeypatch):
    """Redirect generated-config paths to tmp_path and write .applied
    snapshots so get_config_status starts False."""
    import os

    from app.core.config import get_settings
    from app.services import haproxy

    s = get_settings()
    (tmp_path / "lists").mkdir()
    (tmp_path / "resp-transform").mkdir()
    monkeypatch.setattr(s, "SECURITY_LISTS_DIR", str(tmp_path / "lists"))
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(tmp_path / "resp-transform"))
    monkeypatch.setattr(s, "HAPROXY_CONFIG_PATH", str(tmp_path / "haproxy.cfg"))
    monkeypatch.setattr(s, "CORAZA_SPOA_ENABLED", False)
    monkeypatch.setattr(s, "MCP_GATEWAY_ENABLED", False)

    cfg_path = str(tmp_path / "haproxy.cfg")
    baseline = haproxy.generate_config(db)
    with open(cfg_path, "w") as f:
        f.write(baseline)
    with open(f"{cfg_path}.applied", "w") as f:
        f.write(baseline)

    try:
        from app.services.risk_scoring import _risk_rules_data_path, generate_risk_rules_data

        rrd_path = _risk_rules_data_path()
        rrd = generate_risk_rules_data(db)
        os.makedirs(os.path.dirname(rrd_path), exist_ok=True)
        with open(rrd_path, "w") as f:
            f.write(rrd)
        with open(f"{rrd_path}.applied", "w") as f:
            f.write(rrd)
    except Exception:
        pass

    # Response transform file baselines (query_detokenize.json is always
    # generated — without a matching .applied file it shows as unapplied).
    try:
        from app.services.resp_transform import generate_resp_transform_file_contents

        rt_dir = tmp_path / "resp-transform"
        for fname, content in generate_resp_transform_file_contents(db).items():
            fpath = rt_dir / fname
            with open(fpath, "w") as f:
                f.write(content)
            with open(f"{fpath}.applied", "w") as f:
                f.write(content)
    except Exception:
        pass


def test_reorder_detected_end_to_end(db, client, tmp_path, monkeypatch):
    """User-reported regression: reordering security rules via the API must
    flip /config/status to unapplied even though the status bool is cached.

    Exercises the real path: GET /config/status primes the cache (False),
    PUT /security-rules/reorder triggers middleware invalidation, and the
    next GET must regenerate and report True."""
    from tests.factories import make_backend, make_listener, make_security_rule

    be = make_backend(db, name="be1")
    listener = make_listener(db, backend=be, name="http_in")
    r1 = make_security_rule(db, name="r1", priority=0, listener_ids=[listener.id])
    r2 = make_security_rule(db, name="r2", priority=1, listener_ids=[listener.id])
    db.commit()

    _baseline_configs(db, tmp_path, monkeypatch)

    # Prime the cache through the real endpoint.
    resp = client.get("/api/v1/config/status")
    assert resp.status_code == 200
    assert resp.json()["unapplied"] is False
    assert config_service._config_status_cache is not None

    # Reorder via the real endpoint — middleware must invalidate the cache.
    resp = client.put("/api/v1/security-rules/reorder", json={"ordered_ids": [r2.id, r1.id]})
    assert resp.status_code == 200
    assert config_service._config_status_cache is None

    # Next poll regenerates and detects the diff.
    resp = client.get("/api/v1/config/status")
    assert resp.json()["unapplied"] is True


def test_middleware_invalidates_on_config_change(db, client, monkeypatch):
    impl, calls = _fake_status(True)
    monkeypatch.setattr(config_service, "_config_status_data", impl)

    # Prime the cache.
    assert config_service.get_config_status(db) is True
    assert len(calls) == 1

    # A mutating config-affecting path invalidates the cache even when the
    # request fails validation (invalidation is unconditional).
    client.post("/api/v1/backends", json={})
    assert config_service._config_status_cache is None

    # Re-prime, then hit a denylisted non-config path — cache must survive.
    config_service.get_config_status(db)
    assert len(calls) == 2
    client.post("/api/v1/vector/validate", json={})
    assert config_service._config_status_cache is not None
