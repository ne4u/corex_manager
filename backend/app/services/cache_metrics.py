"""Cache metrics sampler — periodically captures cache stats for time-series charts.

Samples HAProxy memory cache stats (from `show stat`) and disk cache stats
(from `varnishstat -j`) every CACHE_METRICS_SAMPLE_INTERVAL_SECONDS, stores
them in CacheMetricSnapshot rows, and prunes old data.
"""
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import Backend, CacheConfig, CacheMetricSnapshot
from . import stats, varnish
from .settings import get_setting

logger = logging.getLogger(__name__)
settings = get_settings()


def _disk_cache_globally_enabled(db: Session) -> bool:
    """Check if the global disk_cache_enabled setting is on."""
    return get_setting(db, "disk_cache_enabled", str(settings.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")


def _extract_haproxy_cache_stats(backend_name: str, all_stats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract cache-related counters from HAProxy `show stat` for a backend.

    HAProxy's `show stat` CSV exposes `cache_lookups` and `cache_hits` for
    HTTP proxies with the cache filter active. Misses are derived as the
    difference. The cache filter counters only appear on the BACKEND row.

    Also extracts native compression counters (`comp_in`, `comp_out`) which
    track bytes fed into and produced by HAProxy's built-in gzip/deflate
    compression filter. These do NOT track brotli/zstd (Lua filter) — those
    are handled separately via the Rust module's AtomicU64 counter.

    Memory cache bandwidth saved is estimated as:
        cache_hits × avg_object_size
    where avg_object_size = bout / total_responses for the backend. This is
    an approximation since HAProxy doesn't expose per-cache-hit bytes.
    """
    result: Dict[str, Any] = {}
    for row in all_stats:
        if not isinstance(row, dict):
            continue
        pxname = row.get("pxname", "")
        svname = row.get("svname", "")
        if pxname == backend_name and svname == "BACKEND":
            try:
                lookups = int(row.get("cache_lookups", 0) or 0)
                hits = int(row.get("cache_hits", 0) or 0)
                result["cache_hit"] = hits
                result["cache_miss"] = lookups - hits

                # Native compression (gzip/deflate) byte counters.
                comp_in = int(row.get("comp_in", 0) or 0)
                comp_out = int(row.get("comp_out", 0) or 0)
                result["comp_in"] = comp_in
                result["comp_out"] = comp_out

                # Memory cache bandwidth-saved estimate:
                # cache_hits × avg_object_size, where avg_object_size is
                # derived from the backend's cumulative bytes out / total
                # responses. This is an approximation — HAProxy doesn't
                # expose per-cache-hit bytes.
                bout = int(row.get("bout", 0) or 0)
                total_resp = sum(
                    int(row.get(f, 0) or 0)
                    for f in ("hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other")
                )
                if total_resp > 0 and hits > 0:
                    avg_obj_size = bout / total_resp
                    result["cache_bytes_saved_estimate"] = int(hits * avg_obj_size)
                else:
                    result["cache_bytes_saved_estimate"] = 0
            except (TypeError, ValueError):
                result = {}
            break
    return result


def sample_cache_metrics() -> None:
    """Capture a single cache metrics snapshot and store it."""
    db = None
    try:
        db = SessionLocal()

        disk_globally_enabled = _disk_cache_globally_enabled(db)

        # Get all HAProxy stats once (cached for 5s by the stats service)
        haproxy_all_stats: List[Dict[str, Any]] = []
        try:
            haproxy_all_stats = stats.get_backend_stats()
        except Exception as exc:
            logger.debug("Failed to fetch HAProxy stats for cache metrics: %s", exc)

        # Get disk cache stats once (if any backend uses disk cache)
        disk_stats: Dict[str, Any] = {}
        any_disk = db.query(CacheConfig).filter(CacheConfig.disk_cache_enabled == True).first()  # noqa: E712
        if any_disk and disk_globally_enabled:
            try:
                disk_stats = varnish.get_stats()
            except Exception as exc:
                logger.debug("Failed to fetch disk cache stats: %s", exc)

        # Get Lua module stats once (global counters from Rust modules).
        # These are only available when the respective modules are loaded
        # (compression or img_2_webp enabled in Global Options). The function
        # returns 0 for unavailable counters.
        lua_module_stats: Dict[str, Any] = {}
        try:
            lua_module_stats = stats.get_lua_module_stats()
        except Exception as exc:
            logger.debug("Failed to fetch Lua module stats: %s", exc)

        # Store per-backend snapshots. Use a single timestamp for all rows in
        # this sample cycle so that the global disk/Lua counters (which are
        # stored identically on every backend row) can be deduplicated by
        # epoch-second in get_cache_metrics. If each row got its own
        # datetime.now() and the loop crossed a second boundary, the dedup
        # would fail and global counters would be double-counted.
        sample_time = datetime.now(timezone.utc).replace(tzinfo=None)
        for cc in db.query(CacheConfig).all():
            backend = db.get(Backend, cc.backend_id)
            if not backend:
                continue

            haproxy_cache_stats: Dict[str, Any] = {}
            if cc.haproxy_enabled:
                haproxy_cache_stats = _extract_haproxy_cache_stats(backend.name, haproxy_all_stats)

            backend_disk_stats: Dict[str, Any] = {}
            if cc.disk_cache_enabled and disk_globally_enabled:
                backend_disk_stats = disk_stats

            # Only store if at least one cache is enabled
            if not cc.haproxy_enabled and not cc.disk_cache_enabled:
                continue

            snapshot = CacheMetricSnapshot(
                created_at=sample_time,
                backend_id=cc.backend_id,
                haproxy_stats=haproxy_cache_stats,
                disk_cache_stats=backend_disk_stats,
                lua_module_stats=lua_module_stats,
            )
            db.add(snapshot)

        db.commit()
        logger.debug("Cache metric snapshots stored")
    except Exception as exc:
        logger.exception("Failed to sample cache metrics: %s", exc)
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def prune_cache_metrics(db: Session) -> int:
    """Delete cache metric snapshots older than the retention window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.CACHE_METRICS_RETENTION_DAYS)).replace(tzinfo=None)
    result = db.query(CacheMetricSnapshot).filter(CacheMetricSnapshot.created_at < cutoff).delete()
    db.commit()
    return result


def _bucket(ts: datetime, step: int) -> datetime:
    """Floor a timestamp to the start of a step bucket."""
    epoch = ts.replace(tzinfo=timezone.utc).timestamp()
    return datetime.fromtimestamp((epoch // step) * step, tz=timezone.utc)


def _auto_step(start: datetime, end: datetime) -> int:
    """Pick a reasonable aggregation step based on the requested range."""
    duration = (end - start).total_seconds()
    if duration <= 300:
        return 5
    if duration <= 3600:
        return 30
    if duration <= 86400:
        return 300
    if duration <= 604800:
        return 3600
    return 86400


def _counter_delta(cur: int, prev: int) -> int:
    """Delta between two cumulative counter readings, handling resets.

    A negative delta means the counter reset (process restart, cache clear).
    Treat the current reading as a fresh counter starting from 0.
    """
    d = cur - prev
    return d if d >= 0 else cur


def get_cache_metrics(
    db: Session,
    from_ts: Optional[datetime] = None,
    to_ts: Optional[datetime] = None,
    step: Optional[int] = None,
    backend_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Query cache metrics, aggregated into time buckets.

    HAProxy ``cache_lookups``/``cache_hits`` and Varnish ``MAIN.cache_hit``/
    ``MAIN.cache_miss`` are **monotonically increasing cumulative counters**
    (since process start), not instantaneous gauges. This function derives
    per-interval **deltas** (i.e. hits/misses that occurred during each bucket)
    and sums those deltas into buckets. Summing cumulative values directly
    would multiply the reading by the number of samples in the bucket and
    produce a staircase that only ever rises.

    Varnish ``MAIN.*`` counters are **global** (not per-backend), but the
    sampler stores the same dict on every per-backend row. To avoid
    multiplying disk deltas by the backend count, the disk series is
    deduplicated by sample timestamp before deltas are computed.

    ``MAIN.n_object`` is a gauge (current object count), not a counter — the
    last value in each bucket is reported rather than a delta.

    Returns {"snapshots": [...], "summary": {...}}.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if to_ts is None:
        to_ts = now
    if from_ts is None:
        from_ts = to_ts - timedelta(hours=1)
    if step is None or step <= 0:
        step = _auto_step(from_ts, to_ts)

    # Normalize timestamps to UTC naive for SQLite comparison
    if from_ts.tzinfo:
        from_ts = from_ts.astimezone(timezone.utc).replace(tzinfo=None)
    if to_ts.tzinfo:
        to_ts = to_ts.astimezone(timezone.utc).replace(tzinfo=None)

    # Fetch one extra sample interval before the window so the first in-window
    # delta has a baseline. Without this, the first bucket would always be 0.
    sample_interval = settings.CACHE_METRICS_SAMPLE_INTERVAL_SECONDS
    fetch_from = from_ts - timedelta(seconds=sample_interval * 2)

    query = db.query(CacheMetricSnapshot).filter(
        CacheMetricSnapshot.created_at >= fetch_from,
        CacheMetricSnapshot.created_at <= to_ts,
    )
    if backend_id is not None:
        query = query.filter(CacheMetricSnapshot.backend_id == backend_id)

    snapshots = query.order_by(CacheMetricSnapshot.created_at).all()

    # --- HAProxy memory cache: per-backend cumulative counters ---
    # Group by backend, compute deltas between consecutive samples, then sum
    # deltas across backends into shared time buckets.
    by_backend: Dict[int, List[CacheMetricSnapshot]] = {}
    for snap in snapshots:
        by_backend.setdefault(snap.backend_id, []).append(snap)

    # bucket_time -> accumulators
    buckets: Dict[datetime, Dict[str, int]] = {}

    def _ensure_bucket(b: datetime) -> Dict[str, int]:
        return buckets.setdefault(b, {
            "haproxy_hit": 0, "haproxy_miss": 0,
            "disk_hit": 0, "disk_miss": 0, "disk_objects": 0,
            # Bandwidth-saved accumulators (bytes):
            "memory_cache_bytes_saved": 0,
            "native_compression_bytes_saved": 0,
            "disk_cache_bytes_saved": 0,
            "brotli_zstd_bytes_saved": 0,
            "webp_bytes_saved": 0,
        })

    for _bid, snaps in by_backend.items():
        prev_hit: Optional[int] = None
        prev_miss: Optional[int] = None
        prev_cache_bytes_saved: Optional[int] = None
        prev_comp_in: Optional[int] = None
        prev_comp_out: Optional[int] = None
        for snap in snaps:
            hs = snap.haproxy_stats or {}
            cur_hit = int(hs.get("cache_hit", 0) or 0)
            cur_miss = int(hs.get("cache_miss", 0) or 0)
            cur_cache_bytes_saved = int(hs.get("cache_bytes_saved_estimate", 0) or 0)
            cur_comp_in = int(hs.get("comp_in", 0) or 0)
            cur_comp_out = int(hs.get("comp_out", 0) or 0)
            if prev_hit is not None:
                d_hit = _counter_delta(cur_hit, prev_hit)
                d_miss = _counter_delta(cur_miss, prev_miss)
                # Bandwidth-saved deltas (cumulative counters → per-interval deltas)
                d_cache_bytes = _counter_delta(cur_cache_bytes_saved, prev_cache_bytes_saved)
                d_comp_in = _counter_delta(cur_comp_in, prev_comp_in)
                d_comp_out = _counter_delta(cur_comp_out, prev_comp_out)
                # Native compression bytes saved = bytes in - bytes out (gzip/deflate)
                d_native_comp_saved = max(0, d_comp_in - d_comp_out)
                # Only count deltas whose sample falls inside the requested window
                if snap.created_at >= from_ts:
                    b = _bucket(snap.created_at, step)
                    bucket = _ensure_bucket(b)
                    bucket["haproxy_hit"] += d_hit
                    bucket["haproxy_miss"] += d_miss
                    bucket["memory_cache_bytes_saved"] += d_cache_bytes
                    bucket["native_compression_bytes_saved"] += d_native_comp_saved
            prev_hit = cur_hit
            prev_miss = cur_miss
            prev_cache_bytes_saved = cur_cache_bytes_saved
            prev_comp_in = cur_comp_in
            prev_comp_out = cur_comp_out

    # --- Disk cache: GLOBAL cumulative counters (same value on every backend row) ---
    # Deduplicate by sample timestamp (rounded to second) to avoid multiplying
    # by the number of cached backends.
    disk_series: Dict[int, Dict[str, int]] = {}  # epoch_second -> counters
    for snap in snapshots:
        ds = snap.disk_cache_stats or {}
        if not ds:
            continue
        cur_hit = int(ds.get("MAIN.cache_hit", 0) or 0)
        cur_miss = int(ds.get("MAIN.cache_miss", 0) or 0)
        cur_hit_grace = int(ds.get("MAIN.cache_hit_grace", 0) or 0)
        cur_hitpass = int(ds.get("MAIN.cache_hitpass", 0) or 0)
        cur_hitmiss = int(ds.get("MAIN.cache_hitmiss", 0) or 0)
        cur_obj = int(ds.get("MAIN.n_object", 0) or 0)
        cur_s_body = int(ds.get("MAIN.s_resp_bodybytes", 0) or 0)
        cur_b_body = int(ds.get("MAIN.b_resp_bodybytes", 0) or 0)
        key = int(snap.created_at.replace(tzinfo=timezone.utc).timestamp())
        existing = disk_series.get(key)
        if existing is None:
            disk_series[key] = {
                "hit": cur_hit, "miss": cur_miss,
                "hit_grace": cur_hit_grace,
                "hitpass": cur_hitpass, "hitmiss": cur_hitmiss,
                "objects": cur_obj,
                "s_body": cur_s_body, "b_body": cur_b_body,
            }
        else:
            # All backends at the same sample time should have identical disk
            # stats; take max to be safe against partial/missing reads.
            existing["hit"] = max(existing["hit"], cur_hit)
            existing["miss"] = max(existing["miss"], cur_miss)
            existing["hit_grace"] = max(existing["hit_grace"], cur_hit_grace)
            existing["hitpass"] = max(existing["hitpass"], cur_hitpass)
            existing["hitmiss"] = max(existing["hitmiss"], cur_hitmiss)
            existing["objects"] = max(existing["objects"], cur_obj)
            existing["s_body"] = max(existing["s_body"], cur_s_body)
            existing["b_body"] = max(existing["b_body"], cur_b_body)

    prev_disk: Optional[Dict[str, int]] = None
    for key in sorted(disk_series.keys()):
        cur = disk_series[key]
        # Strip tzinfo for comparison with the naive from_ts/to_ts used above
        ts = datetime.fromtimestamp(key, tz=timezone.utc).replace(tzinfo=None)
        if ts >= from_ts:
            b = _bucket(ts, step)
            bucket = _ensure_bucket(b)
            if prev_disk is not None:
                # Grace hits served stale-from-cache — count as hits.
                d_hit = _counter_delta(cur["hit"], prev_disk["hit"])
                d_grace = _counter_delta(cur["hit_grace"], prev_disk["hit_grace"])
                bucket["disk_hit"] += d_hit + d_grace
                # Hit-for-pass and hit-for-miss are cached *decisions* to not
                # cache — the content was fetched from backend, so they count
                # as misses in the hit-rate denominator.
                d_miss = _counter_delta(cur["miss"], prev_disk["miss"])
                d_hitpass = _counter_delta(cur["hitpass"], prev_disk["hitpass"])
                d_hitmiss = _counter_delta(cur["hitmiss"], prev_disk["hitmiss"])
                bucket["disk_miss"] += d_miss + d_hitpass + d_hitmiss
                # Disk cache bytes saved = bytes sent to clients - bytes fetched
                # from backend. The difference is served from cache without a
                # backend fetch.
                #
                # Guard: only count when there are actual cache events (hits,
                # misses, grace, hitpass, or hitmiss). HAProxy sends regular
                # health checks to the Varnish disk_cache server, which Varnish
                # answers with synth(200, "OK") from vcl_recv — bypassing the
                # cache lookup entirely. These synth responses increment
                # s_resp_bodybytes (bytes sent to client) without incrementing
                # b_resp_bodybytes (no backend fetch), so without this guard
                # they'd be counted as "bytes saved from cache" and produce a
                # constant ~14KB per interval even with zero real traffic.
                d_cache_events = d_hit + d_grace + d_miss + d_hitpass + d_hitmiss
                if d_cache_events > 0:
                    d_s_body = _counter_delta(cur["s_body"], prev_disk["s_body"])
                    d_b_body = _counter_delta(cur["b_body"], prev_disk["b_body"])
                    bucket["disk_cache_bytes_saved"] += max(0, d_s_body - d_b_body)
            # n_object is a gauge — latest value in bucket wins
            bucket["disk_objects"] = max(bucket["disk_objects"], cur["objects"])
        prev_disk = cur

    # --- Lua module stats: GLOBAL cumulative counters (brotli/zstd + WebP) ---
    # Same deduplication pattern as disk cache — the sampler stores the same
    # global counters on every per-backend row.
    lua_series: Dict[int, Dict[str, int]] = {}  # epoch_second -> counters
    for snap in snapshots:
        ls = snap.lua_module_stats or {}
        if not ls:
            continue
        cur_br_zstd = int(ls.get("brotli_zstd_bytes_saved", 0) or 0)
        cur_webp = int(ls.get("webp_bytes_saved", 0) or 0)
        key = int(snap.created_at.replace(tzinfo=timezone.utc).timestamp())
        existing = lua_series.get(key)
        if existing is None:
            lua_series[key] = {"br_zstd": cur_br_zstd, "webp": cur_webp}
        else:
            existing["br_zstd"] = max(existing["br_zstd"], cur_br_zstd)
            existing["webp"] = max(existing["webp"], cur_webp)

    prev_lua: Optional[Dict[str, int]] = None
    for key in sorted(lua_series.keys()):
        cur = lua_series[key]
        ts = datetime.fromtimestamp(key, tz=timezone.utc).replace(tzinfo=None)
        if ts >= from_ts:
            b = _bucket(ts, step)
            bucket = _ensure_bucket(b)
            if prev_lua is not None:
                bucket["brotli_zstd_bytes_saved"] += _counter_delta(cur["br_zstd"], prev_lua["br_zstd"])
                bucket["webp_bytes_saved"] += _counter_delta(cur["webp"], prev_lua["webp"])
        prev_lua = cur

    # --- Build response ---
    result_snapshots: List[Dict[str, Any]] = []
    total_haproxy_hits = 0
    total_haproxy_miss = 0
    total_disk_hits = 0
    total_disk_miss = 0
    total_memory_cache_bytes_saved = 0
    total_native_compression_bytes_saved = 0
    total_disk_cache_bytes_saved = 0
    total_brotli_zstd_bytes_saved = 0
    total_webp_bytes_saved = 0

    for bucket_time in sorted(buckets.keys()):
        b = buckets[bucket_time]
        h_hit = b["haproxy_hit"]
        h_miss = b["haproxy_miss"]
        d_hit = b["disk_hit"]
        d_miss = b["disk_miss"]
        d_obj = b["disk_objects"]
        mem_bytes = b["memory_cache_bytes_saved"]
        native_comp_bytes = b["native_compression_bytes_saved"]
        disk_bytes = b["disk_cache_bytes_saved"]
        br_zstd_bytes = b["brotli_zstd_bytes_saved"]
        webp_bytes = b["webp_bytes_saved"]

        total_haproxy_hits += h_hit
        total_haproxy_miss += h_miss
        total_disk_hits += d_hit
        total_disk_miss += d_miss
        total_memory_cache_bytes_saved += mem_bytes
        total_native_compression_bytes_saved += native_comp_bytes
        total_disk_cache_bytes_saved += disk_bytes
        total_brotli_zstd_bytes_saved += br_zstd_bytes
        total_webp_bytes_saved += webp_bytes

        h_total = h_hit + h_miss
        d_total = d_hit + d_miss
        total_bandwidth_saved = (
            mem_bytes + native_comp_bytes + disk_bytes + br_zstd_bytes + webp_bytes
        )

        result_snapshots.append({
            "timestamp": bucket_time.isoformat(),
            "haproxy_cache_hit": h_hit,
            "haproxy_cache_miss": h_miss,
            "disk_cache_hit": d_hit,
            "disk_cache_miss": d_miss,
            "disk_cache_objects": d_obj,
            "haproxy_hit_rate": round(h_hit / h_total * 100, 2) if h_total > 0 else 0.0,
            "disk_hit_rate": round(d_hit / d_total * 100, 2) if d_total > 0 else 0.0,
            # Bandwidth-saved fields (bytes per interval):
            "memory_cache_bytes_saved": mem_bytes,
            "native_compression_bytes_saved": native_comp_bytes,
            "disk_cache_bytes_saved": disk_bytes,
            "brotli_zstd_bytes_saved": br_zstd_bytes,
            "webp_bytes_saved": webp_bytes,
            "total_bandwidth_saved": total_bandwidth_saved,
        })

    haproxy_total = total_haproxy_hits + total_haproxy_miss
    disk_total = total_disk_hits + total_disk_miss
    total_bandwidth = (
        total_memory_cache_bytes_saved + total_native_compression_bytes_saved
        + total_disk_cache_bytes_saved + total_brotli_zstd_bytes_saved
        + total_webp_bytes_saved
    )

    summary = {
        "haproxy_hit_rate": round(total_haproxy_hits / haproxy_total * 100, 2) if haproxy_total > 0 else 0.0,
        "disk_hit_rate": round(total_disk_hits / disk_total * 100, 2) if disk_total > 0 else 0.0,
        "total_haproxy_hits": total_haproxy_hits,
        "total_haproxy_miss": total_haproxy_miss,
        "total_disk_hits": total_disk_hits,
        "total_disk_miss": total_disk_miss,
        # Bandwidth-saved totals (bytes):
        "total_memory_cache_bytes_saved": total_memory_cache_bytes_saved,
        "total_native_compression_bytes_saved": total_native_compression_bytes_saved,
        "total_disk_cache_bytes_saved": total_disk_cache_bytes_saved,
        "total_brotli_zstd_bytes_saved": total_brotli_zstd_bytes_saved,
        "total_webp_bytes_saved": total_webp_bytes_saved,
        "total_bandwidth_saved": total_bandwidth,
    }

    return {"snapshots": result_snapshots, "summary": summary}


def _sampler_loop() -> None:
    while True:
        try:
            time.sleep(settings.CACHE_METRICS_SAMPLE_INTERVAL_SECONDS)
            sample_cache_metrics()
            try:
                db = SessionLocal()
                prune_cache_metrics(db)
                db.close()
            except Exception:
                pass
        except Exception as exc:
            logger.exception("Cache metrics sampler loop error: %s", exc)


def start_sampler() -> None:
    """Start a background thread that samples cache metrics."""
    sample_cache_metrics()
    thread = threading.Thread(target=_sampler_loop, daemon=True)
    thread.start()
