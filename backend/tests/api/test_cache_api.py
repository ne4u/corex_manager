"""Tests for cache API endpoints (CRUD + clear + metrics)."""
from datetime import datetime, timedelta, timezone

from tests.factories import (
    make_backend,
    make_server,
    make_cache_config,
    make_cache_metric_snapshot,
)


def test_list_empty(client):
    """Listing cache configs when none exist returns an empty list."""
    r = client.get("/api/v1/cache/configs")
    assert r.status_code == 200
    assert r.json() == []


def test_create_cache_config(client, db):
    """Creating a cache config returns 201 and the config."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    r = client.post("/api/v1/cache/configs", json={
        "backend_id": backend.id,
        "haproxy_enabled": True,
        "haproxy_total_max_size": 200,
        "haproxy_max_age": 600,
    })
    assert r.status_code == 201
    data = r.json()
    assert data["backend_id"] == backend.id
    assert data["backend_name"] == "web"
    assert data["haproxy_enabled"] is True
    assert data["haproxy_total_max_size"] == 200


def test_create_duplicate_returns_409(client, db):
    """Creating a second cache config for the same backend returns 409."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    r = client.post("/api/v1/cache/configs", json={
        "backend_id": backend.id,
        "haproxy_enabled": True,
    })
    assert r.status_code == 409


def test_create_for_tcp_backend_returns_400(client, db):
    """Creating a cache config for a TCP backend returns 400."""
    backend = make_backend(db, protocol="tcp", mode="tcp")
    make_server(db, backend.id)
    r = client.post("/api/v1/cache/configs", json={
        "backend_id": backend.id,
        "haproxy_enabled": True,
    })
    assert r.status_code == 400
    assert "TCP" in r.json()["detail"]


def test_create_disk_cache_without_global_toggle_returns_400(client, db):
    """Creating a disk cache config when the global toggle is off returns 400."""
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "false")
    backend = make_backend(db)
    make_server(db, backend.id)
    r = client.post("/api/v1/cache/configs", json={
        "backend_id": backend.id,
        "disk_cache_enabled": True,
    })
    assert r.status_code == 400
    assert "Disk cache" in r.json()["detail"]


def test_get_cache_config(client, db):
    """Getting a cache config by backend_id returns the config."""
    backend = make_backend(db, name="api")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True, haproxy_max_age=120)
    r = client.get(f"/api/v1/cache/configs/{backend.id}")
    assert r.status_code == 200
    data = r.json()
    assert data["backend_name"] == "api"
    assert data["haproxy_max_age"] == 120


def test_get_nonexistent_returns_404(client, db):
    """Getting a cache config for a backend without one returns 404."""
    backend = make_backend(db)
    r = client.get(f"/api/v1/cache/configs/{backend.id}")
    assert r.status_code == 404


def test_update_cache_config(client, db):
    """Updating a cache config changes the specified fields."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=False, haproxy_max_age=300)
    r = client.put(f"/api/v1/cache/configs/{backend.id}", json={
        "haproxy_enabled": True,
        "haproxy_max_age": 600,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["haproxy_enabled"] is True
    assert data["haproxy_max_age"] == 600


def test_delete_cache_config(client, db):
    """Deleting a cache config removes it."""
    backend = make_backend(db)
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    r = client.delete(f"/api/v1/cache/configs/{backend.id}")
    assert r.status_code == 200
    # Verify it's gone
    r2 = client.get(f"/api/v1/cache/configs/{backend.id}")
    assert r2.status_code == 404


def test_cache_status(client, db):
    """The status endpoint returns the global disk cache toggle state."""
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "false")
    r = client.get("/api/v1/cache/status")
    assert r.status_code == 200
    assert r.json()["disk_cache_globally_enabled"] is False


def test_cache_status_enabled(client, db):
    """The status endpoint returns True when the global toggle is on."""
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "true")
    r = client.get("/api/v1/cache/status")
    assert r.status_code == 200
    assert r.json()["disk_cache_globally_enabled"] is True


def test_clear_backend_cache(client, db, monkeypatch):
    """Clearing a backend cache returns a response (even if no HAProxy running)."""
    # Mock reload_haproxy so the test doesn't try to reach a real HAProxy
    monkeypatch.setattr("app.services.haproxy.reload_haproxy", lambda: {"status": "ok", "message": "HAProxy reloaded"})
    backend = make_backend(db)
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    r = client.post(f"/api/v1/cache/{backend.id}/clear")
    assert r.status_code == 200
    data = r.json()
    assert "message" in data
    assert "memory_cleared" in data
    assert "disk_cleared" in data


def test_clear_backend_cache_uses_haproxy_section_name(db, monkeypatch):
    """clear_backend_cache must pass the HAProxy section name (the value stored
    in X-Cache-Backend) to purge_backend, not the raw backend name. This matters
    when the backend name contains characters that _safe_name and _safe_vcl_name
    handle differently, or when uniqueness suffixes were appended."""
    from app.services import cache as cache_service
    from app.models.models import Listener

    # Create a backend with a name that contains a dot (valid in _safe_name,
    # but stripped by _safe_vcl_name — the old bug)
    backend = make_backend(db, name="api.example.com")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Need a listener so _get_section_names has a frontend
    from tests.factories import make_listener
    make_listener(db, backend=backend)
    db.commit()

    captured = []

    def fake_purge_backend(x_cache_backend_value):
        captured.append(x_cache_backend_value)
        return True

    monkeypatch.setattr(cache_service.varnish, "purge_backend", fake_purge_backend)
    result = cache_service.clear_backend_cache(db, backend.id)
    assert result["disk_cleared"] is True
    # The captured value should be the HAProxy section name, which preserves
    # dots (via _safe_name). The old bug would have passed "api_example_com"
    # (via _safe_vcl_name) which wouldn't match the stored X-Cache-Backend.
    assert len(captured) == 1
    assert captured[0] == "api.example.com"


def test_clear_backend_cache_memory_reloads_haproxy(db, monkeypatch):
    """clear_backend_cache must reload HAProxy to clear the memory cache —
    HAProxy has no `clear cache` admin socket command, and the cache lives in
    process RAM so a reload spawns a new worker with an empty cache."""
    from app.services import cache as cache_service

    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    # Need a listener so _get_section_names has a frontend
    from tests.factories import make_listener
    make_listener(db, backend=backend)
    db.commit()

    reload_called = []

    def fake_reload_haproxy():
        reload_called.append(True)
        return {"status": "ok", "message": "HAProxy reloaded"}

    # Patch reload_haproxy in the haproxy module since cache.py imports it lazily
    monkeypatch.setattr("app.services.haproxy.reload_haproxy", fake_reload_haproxy)
    result = cache_service.clear_backend_cache(db, backend.id)
    assert result["memory_cleared"] is True
    assert len(reload_called) == 1
    assert "reloaded" in result["message"].lower()


def test_clear_backend_cache_memory_reload_failure(db, monkeypatch):
    """When the HAProxy reload fails, memory_cleared must be False and the
    error message must be surfaced."""
    from app.services import cache as cache_service

    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    from tests.factories import make_listener
    make_listener(db, backend=backend)
    db.commit()

    monkeypatch.setattr("app.services.haproxy.reload_haproxy", lambda: {"status": "error", "message": "config invalid"})
    result = cache_service.clear_backend_cache(db, backend.id)
    assert result["memory_cleared"] is False
    assert "config invalid" in result["message"]


def test_clear_backend_cache_only_disk_no_reload(db, monkeypatch):
    """When only disk cache is enabled (no memory cache), clear_backend_cache
    must NOT reload HAProxy — the Varnish BAN is sufficient."""
    from app.services import cache as cache_service

    backend = make_backend(db, name="disk_only")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=False, disk_cache_enabled=True)
    from tests.factories import make_listener
    make_listener(db, backend=backend)
    db.commit()

    reload_called = []
    monkeypatch.setattr("app.services.haproxy.reload_haproxy", lambda: reload_called.append(True) or {"status": "ok", "message": ""})
    monkeypatch.setattr(cache_service.varnish, "purge_backend", lambda name: True)
    result = cache_service.clear_backend_cache(db, backend.id)
    assert result["disk_cleared"] is True
    assert result["memory_cleared"] is False
    assert len(reload_called) == 0, "HAProxy should not be reloaded when only disk cache is enabled"


def test_clear_all_caches(client, db, monkeypatch):
    """Clearing all caches returns a summary response."""
    monkeypatch.setattr("app.services.haproxy.reload_haproxy", lambda: {"status": "ok", "message": "HAProxy reloaded"})
    backend = make_backend(db)
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    r = client.post("/api/v1/cache/clear-all")
    assert r.status_code == 200
    data = r.json()
    assert "message" in data


def test_cache_metrics_empty(client, db):
    """The metrics endpoint returns empty snapshots when no data exists."""
    r = client.get("/api/v1/cache/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "snapshots" in data
    assert "summary" in data
    assert data["snapshots"] == []


def test_cache_metrics_haproxy_deltas(client, db):
    """HAProxy cache counters are cumulative; the API must return per-interval deltas, not sums of cumulative values."""
    backend = make_backend(db, name="delta_be")
    make_cache_config(db, backend.id, haproxy_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Three samples with cumulative counters: hits 10→25→40, misses 5→8→12
    # Expected deltas: hits 15,15  misses 3,4
    for i, (hit, miss) in enumerate([(10, 5), (25, 8), (40, 12)]):
        make_cache_metric_snapshot(
            db,
            backend_id=backend.id,
            created_at=now - timedelta(minutes=10 - i * 5),
            haproxy_stats={"cache_hit": hit, "cache_miss": miss},
        )
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    data = r.json()
    snaps = data["snapshots"]
    assert len(snaps) >= 1
    # Total deltas over the window: hits 15+15=30, misses 3+4=7
    assert data["summary"]["total_haproxy_hits"] == 30
    assert data["summary"]["total_haproxy_miss"] == 7
    # Hit rate = 30 / 37
    assert abs(data["summary"]["haproxy_hit_rate"] - round(30 / 37 * 100, 2)) < 0.01
    # No snapshot should contain the raw cumulative value (40 or 12)
    for s in snaps:
        assert s["haproxy_cache_hit"] <= 30
        assert s["haproxy_cache_miss"] <= 7


def test_cache_metrics_disk_dedup_across_backends(client, db):
    """Disk cache counters are global (same value stored on every backend row); deltas must not be multiplied by backend count."""
    be1 = make_backend(db, name="disk_be1")
    be2 = make_backend(db, name="disk_be2")
    make_cache_config(db, be1.id, disk_cache_enabled=True)
    make_cache_config(db, be2.id, disk_cache_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Two sample times, each stored on BOTH backend rows (same disk stats).
    # Cumulative: hit 100→150, miss 20→30
    # Expected delta: hit 50, miss 10  (NOT 100, 20 which is what you'd get
    # if you summed across both backends).
    for t_min, (hit, miss, obj) in [(-10, (100, 20, 5)), (-5, (150, 30, 8))]:
        ts = now + timedelta(minutes=t_min)
        for bid in (be1.id, be2.id):
            make_cache_metric_snapshot(
                db,
                backend_id=bid,
                created_at=ts,
                disk_cache_stats={"MAIN.cache_hit": hit, "MAIN.cache_miss": miss, "MAIN.n_object": obj},
            )
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["total_disk_hits"] == 50
    assert data["summary"]["total_disk_miss"] == 10
    # n_object is a gauge — should report the latest value (8), not a sum
    for s in data["snapshots"]:
        assert s["disk_cache_objects"] <= 8


def test_cache_metrics_disk_grace_hitpass_hitmiss(client, db):
    """Disk hit rate must include cache_hit_grace as hits and cache_hitpass/
    cache_hitmiss as misses — Varnish caches pass/miss *decisions*, so those
    lookups are neither true hits nor absent from the denominator."""
    backend = make_backend(db, name="disk_grace_be")
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Two samples (cumulative counters):
    #   Sample 1: hit=100, miss=20, grace=10, hitpass=5, hitmiss=5
    #   Sample 2: hit=150, miss=30, grace=25, hitpass=15, hitmiss=10
    # Expected deltas:
    #   hit_delta   = (150-100) + (25-10)  = 50 + 15 = 65
    #   miss_delta  = (30-20) + (15-5) + (10-5) = 10 + 10 + 5 = 25
    #   hit_rate    = 65 / (65 + 25) = 65 / 90 = 72.22%
    for t_min, stats in [
        (-10, dict(hit=100, miss=20, grace=10, hitpass=5, hitmiss=5)),
        (-5, dict(hit=150, miss=30, grace=25, hitpass=15, hitmiss=10)),
    ]:
        ts = now + timedelta(minutes=t_min)
        make_cache_metric_snapshot(
            db,
            backend_id=backend.id,
            created_at=ts,
            disk_cache_stats={
                "MAIN.cache_hit": stats["hit"],
                "MAIN.cache_miss": stats["miss"],
                "MAIN.cache_hit_grace": stats["grace"],
                "MAIN.cache_hitpass": stats["hitpass"],
                "MAIN.cache_hitmiss": stats["hitmiss"],
                "MAIN.n_object": 5,
            },
        )
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["total_disk_hits"] == 65
    assert data["summary"]["total_disk_miss"] == 25
    assert abs(data["summary"]["disk_hit_rate"] - round(65 / 90 * 100, 2)) < 0.01


def test_cache_metrics_disk_health_check_no_phantom_saved(client, db):
    """Health-check synth responses (s_resp_bodybytes incrementing with no
    cache hit/miss events) must not be counted as disk_cache_bytes_saved.

    HAProxy sends regular health checks to the Varnish disk_cache server.
    Varnish answers with synth(200, "OK") from vcl_recv, which increments
    s_resp_bodybytes without incrementing b_resp_bodybytes or any cache
    hit/miss counter. Without the guard, this produces a constant phantom
    bytes-saved value even with zero real traffic.
    """
    backend = make_backend(db, name="health_be")
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Two samples: s_resp_bodybytes increments (health check synth bodies)
    # but cache_hit/miss/etc stay at 0 — no real traffic.
    for t_min, s_body in [(-10, 0), (-5, 14069)]:
        ts = now + timedelta(minutes=t_min)
        make_cache_metric_snapshot(
            db,
            backend_id=backend.id,
            created_at=ts,
            disk_cache_stats={
                "MAIN.cache_hit": 0,
                "MAIN.cache_miss": 0,
                "MAIN.cache_hit_grace": 0,
                "MAIN.cache_hitpass": 0,
                "MAIN.cache_hitmiss": 0,
                "MAIN.n_object": 0,
                "MAIN.s_resp_bodybytes": s_body,
                "MAIN.b_resp_bodybytes": 0,
            },
        )
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    data = r.json()
    # No cache events → no phantom bytes saved
    assert data["summary"]["total_disk_cache_bytes_saved"] == 0
    for s in data["snapshots"]:
        assert s["disk_cache_bytes_saved"] == 0


def test_cache_metrics_disk_bytes_saved_with_real_traffic(client, db):
    """When there ARE cache events, disk_cache_bytes_saved should still be
    computed from s_resp_bodybytes - b_resp_bodybytes."""
    backend = make_backend(db, name="real_traffic_be")
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Two samples with real cache hits:
    #   s_resp_bodybytes: 0 → 50000 (bytes sent to clients)
    #   b_resp_bodybytes: 0 → 10000 (bytes fetched from backend)
    #   cache_hit:        0 → 40
    #   cache_miss:       0 → 10
    # Expected disk_cache_bytes_saved = 50000 - 10000 = 40000
    for t_min, (s_body, b_body, hit, miss) in [(-10, (0, 0, 0, 0)), (-5, (50000, 10000, 40, 10))]:
        ts = now + timedelta(minutes=t_min)
        make_cache_metric_snapshot(
            db,
            backend_id=backend.id,
            created_at=ts,
            disk_cache_stats={
                "MAIN.cache_hit": hit,
                "MAIN.cache_miss": miss,
                "MAIN.cache_hit_grace": 0,
                "MAIN.cache_hitpass": 0,
                "MAIN.cache_hitmiss": 0,
                "MAIN.n_object": 5,
                "MAIN.s_resp_bodybytes": s_body,
                "MAIN.b_resp_bodybytes": b_body,
            },
        )
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["total_disk_cache_bytes_saved"] == 40000


def test_cache_metrics_counter_reset(client, db):
    """A counter reset (process restart) should produce a delta equal to the new reading, not a large negative."""
    backend = make_backend(db, name="reset_be")
    make_cache_config(db, backend.id, haproxy_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Cumulative hits: 100 → 5 (reset) → 15
    # Expected deltas: 5 (reset → current), 10
    make_cache_metric_snapshot(db, backend.id, now - timedelta(minutes=10), haproxy_stats={"cache_hit": 100, "cache_miss": 50})
    make_cache_metric_snapshot(db, backend.id, now - timedelta(minutes=5), haproxy_stats={"cache_hit": 5, "cache_miss": 2})
    make_cache_metric_snapshot(db, backend.id, now, haproxy_stats={"cache_hit": 15, "cache_miss": 6})
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    data = r.json()
    # 5 + 10 = 15 hits; 2 + 4 = 6 misses
    assert data["summary"]["total_haproxy_hits"] == 15
    assert data["summary"]["total_haproxy_miss"] == 6


def test_cache_metrics_per_bucket_hit_rate(client, db):
    """Each snapshot bucket includes a per-bucket hit_rate field."""
    backend = make_backend(db, name="rate_be")
    make_cache_config(db, backend.id, haproxy_enabled=True)
    db.commit()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Bucket 1: 80 hits, 20 misses (80%); Bucket 2: 40 hits, 60 misses (40%)
    make_cache_metric_snapshot(db, backend.id, now - timedelta(minutes=10), haproxy_stats={"cache_hit": 0, "cache_miss": 0})
    make_cache_metric_snapshot(db, backend.id, now - timedelta(minutes=9), haproxy_stats={"cache_hit": 80, "cache_miss": 20})
    make_cache_metric_snapshot(db, backend.id, now - timedelta(minutes=5), haproxy_stats={"cache_hit": 80, "cache_miss": 20})
    make_cache_metric_snapshot(db, backend.id, now - timedelta(minutes=4), haproxy_stats={"cache_hit": 120, "cache_miss": 80})
    db.commit()

    r = client.get("/api/v1/cache/metrics?step=300")
    assert r.status_code == 200
    snaps = r.json()["snapshots"]
    assert len(snaps) == 2
    # Sort by timestamp to identify buckets
    snaps.sort(key=lambda s: s["timestamp"])
    assert abs(snaps[0]["haproxy_hit_rate"] - 80.0) < 0.01
    assert abs(snaps[1]["haproxy_hit_rate"] - 40.0) < 0.01


# Cacheability rules
# ---------------------------------------------------------------------------

def _config_for(client, db, name="rules_be"):
    backend = make_backend(db, name=name)
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    db.commit()
    return backend


def test_list_rules_empty(client, db):
    backend = _config_for(client, db)
    r = client.get(f"/api/v1/cache/configs/{backend.id}/rules")
    assert r.status_code == 200
    assert r.json() == []


def test_list_rules_without_config_returns_404(client, db):
    backend = make_backend(db, name="no_cfg")
    db.commit()
    r = client.get(f"/api/v1/cache/configs/{backend.id}/rules")
    assert r.status_code == 404


def test_create_rule_normalizes_pattern(client, db):
    """Patterns are stored canonically so '/downloads/*' and '*.png' work as typed."""
    backend = _config_for(client, db, name="norm_be")
    r = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                    json={"match_type": "path", "pattern": "/downloads/*", "action": "cache", "tier": "memory"})
    assert r.status_code == 201
    assert r.json()["pattern"] == "/downloads/"

    r = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                    json={"match_type": "extension", "pattern": "*.PNG", "action": "cache", "tier": "memory"})
    assert r.status_code == 201
    assert r.json()["pattern"] == "png"


def test_create_rule_rejects_invalid_pattern(client, db):
    backend = _config_for(client, db, name="bad_be")
    r = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                    json={"match_type": "path", "pattern": "downloads/", "action": "cache", "tier": "memory"})
    assert r.status_code == 422


def test_create_rule_rejects_invalid_action(client, db):
    backend = _config_for(client, db, name="badact_be")
    r = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                    json={"match_type": "extension", "pattern": "png", "action": "explode", "tier": "memory"})
    assert r.status_code == 422


def test_create_rule_appends_to_end(client, db):
    backend = _config_for(client, db, name="append_be")
    for ext in ("png", "jpg", "gif"):
        client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                    json={"match_type": "extension", "pattern": ext, "tier": "memory"})
    rules = client.get(f"/api/v1/cache/configs/{backend.id}/rules").json()
    assert [x["pattern"] for x in rules] == ["png", "jpg", "gif"]


def test_update_rule_partial_renormalizes(client, db):
    """Changing only the pattern still normalizes against the stored match_type."""
    backend = _config_for(client, db, name="upd_be")
    created = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                          json={"match_type": "extension", "pattern": "png", "tier": "memory"}).json()
    r = client.put(f"/api/v1/cache/configs/{backend.id}/rules/{created['id']}",
                   json={"pattern": "*.WEBP"})
    assert r.status_code == 200
    assert r.json()["pattern"] == "webp"


def test_update_rule_invalid_pattern_returns_400(client, db):
    backend = _config_for(client, db, name="updbad_be")
    created = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                          json={"match_type": "path", "pattern": "/a/", "tier": "memory"}).json()
    r = client.put(f"/api/v1/cache/configs/{backend.id}/rules/{created['id']}",
                   json={"pattern": "relative/"})
    assert r.status_code == 400


def test_delete_rule(client, db):
    backend = _config_for(client, db, name="del_be")
    created = client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                          json={"match_type": "extension", "pattern": "png", "tier": "memory"}).json()
    assert client.delete(f"/api/v1/cache/configs/{backend.id}/rules/{created['id']}").status_code == 200
    assert client.get(f"/api/v1/cache/configs/{backend.id}/rules").json() == []


def test_reorder_rules(client, db):
    backend = _config_for(client, db, name="reorder_be")
    ids = [client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                       json={"match_type": "extension", "pattern": e, "tier": "memory"}).json()["id"]
           for e in ("png", "jpg", "gif")]
    r = client.post(f"/api/v1/cache/configs/{backend.id}/rules/reorder",
                    json={"rule_ids": list(reversed(ids))})
    assert r.status_code == 200
    assert [x["pattern"] for x in r.json()] == ["gif", "jpg", "png"]


def test_reorder_rejects_incomplete_list(client, db):
    backend = _config_for(client, db, name="badorder_be")
    ids = [client.post(f"/api/v1/cache/configs/{backend.id}/rules",
                       json={"match_type": "extension", "pattern": e, "tier": "memory"}).json()["id"]
           for e in ("png", "jpg")]
    r = client.post(f"/api/v1/cache/configs/{backend.id}/rules/reorder",
                    json={"rule_ids": ids[:1]})
    assert r.status_code == 400


def test_rules_are_scoped_to_their_backend(client, db):
    """A rule id from another backend must not be reachable."""
    a = _config_for(client, db, name="scope_a")
    b = _config_for(client, db, name="scope_b")
    rule = client.post(f"/api/v1/cache/configs/{a.id}/rules",
                       json={"match_type": "extension", "pattern": "png", "tier": "memory"}).json()
    assert client.put(f"/api/v1/cache/configs/{b.id}/rules/{rule['id']}",
                      json={"enabled": False}).status_code == 404
    assert client.delete(f"/api/v1/cache/configs/{b.id}/rules/{rule['id']}").status_code == 404
