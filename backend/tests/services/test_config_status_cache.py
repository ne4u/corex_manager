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
