import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import MetricSnapshot
from . import stats

logger = logging.getLogger(__name__)
settings = get_settings()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bucket(ts: datetime, step: int) -> datetime:
    """Floor a timestamp to the start of a step bucket."""
    epoch = ts.replace(tzinfo=timezone.utc).timestamp()
    return datetime.fromtimestamp((epoch // step) * step, tz=timezone.utc)


def sample_metrics() -> None:
    """Capture a single HAProxy stats snapshot and store it."""
    db = None
    try:
        db = SessionLocal()
        info = stats.get_process_info()
        rows = stats.get_backend_stats()
        logger.debug("HAProxy socket returned info keys=%s, stat rows=%d",
                     list(info.keys()) if info else [], len(rows or []))
        snapshot = MetricSnapshot(
            captured_at=datetime.now(timezone.utc).replace(tzinfo=None),
            process_info=info,
            stats=rows,
        )
        db.add(snapshot)
        db.commit()
        logger.info("Metric snapshot stored at %s (rows=%d)", snapshot.captured_at, len(rows or []))
    except Exception as exc:
        logger.exception("Failed to sample metrics: %s", exc)
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def prune_metrics(db: Session) -> int:
    """Delete metric snapshots older than the retention window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.METRICS_RETENTION_DAYS)).replace(tzinfo=None)
    result = db.query(MetricSnapshot).filter(MetricSnapshot.captured_at < cutoff).delete()
    db.commit()
    return result


def _auto_step(start: datetime, end: datetime) -> int:
    """Pick a reasonable aggregation step based on the requested range."""
    duration = (end - start).total_seconds()
    if duration <= 300:  # <= 5 min
        return 5
    if duration <= 3600:  # <= 1 hour
        return 30
    if duration <= 86400:  # <= 1 day
        return 300  # 5 min
    if duration <= 604800:  # <= 7 days
        return 3600  # 1 hour
    return 86400


def _row_kind(row: Dict[str, Any]) -> Optional[str]:
    if not isinstance(row, dict):
        return None
    stype = row.get("type")
    if stype == "0":
        return "frontend"
    if stype == "1":
        return "backend"
    if stype == "2":
        return "server"
    if stype is None and "svname" in row and row.get("svname") in ("FRONTEND", "BACKEND"):
        return row.get("svname").lower()
    return None


def _proxy_name(row: Dict[str, Any]) -> str:
    return row.get("pxname") or "unknown"


def _server_name(row: Dict[str, Any]) -> str:
    return row.get("svname") or "unknown"


def _sum_field(rows: List[Dict[str, Any]], field: str) -> int:
    return sum(_int(r.get(field)) for r in rows)


def _sum_float_field(rows: List[Dict[str, Any]], field: str) -> float:
    return sum(_float(r.get(field)) for r in rows)


def _derive_proxy_metrics(rows: List[Dict[str, Any]], first_rows: Optional[List[Dict[str, Any]]], duration: float) -> Dict[str, Any]:
    """Derive per-proxy metrics from a snapshot and an optional earlier snapshot for deltas."""
    result = {
        "sessions": _sum_field(rows, "scur"),
        "sessions_pct": 0.0,
        "sessions_rate": _sum_float_field(rows, "rate"),
        "requests_rate": _sum_float_field(rows, "req_rate"),
        "bytes_in_rate": 0.0,
        "bytes_out_rate": 0.0,
        "denials": _sum_field(rows, "dreq") + _sum_field(rows, "dresp"),
        "denials_rate": 0.0,
        "hrsp_1xx": _sum_field(rows, "hrsp_1xx"),
        "hrsp_2xx": _sum_field(rows, "hrsp_2xx"),
        "hrsp_3xx": _sum_field(rows, "hrsp_3xx"),
        "hrsp_4xx": _sum_field(rows, "hrsp_4xx"),
        "hrsp_5xx": _sum_field(rows, "hrsp_5xx"),
        "hrsp_other": _sum_field(rows, "hrsp_other"),
        "total_responses": 0,
        "pct_1xx": 0.0,
        "pct_2xx": 0.0,
        "pct_3xx": 0.0,
        "pct_4xx": 0.0,
        "pct_5xx": 0.0,
        "pct_other": 0.0,
    }

    # Response-code delta values and byte rates for the bucket
    if first_rows and duration > 0:
        for field in ("hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other"):
            delta_name = field.replace("hrsp_", "")
            delta = _sum_field(rows, field) - _sum_field(first_rows, field)
            result[delta_name] = max(0, delta)

        for direction, rate_key in (("bin", "bytes_in_rate"), ("bout", "bytes_out_rate")):
            delta = _sum_field(rows, direction) - _sum_field(first_rows, direction)
            result[rate_key] = max(0, delta) / duration

        # Denials rate from cumulative dreq/dresp deltas (counters only go up
        # until HAProxy restarts, so the raw value is useless on a chart).
        denials_delta = (
            max(0, _sum_field(rows, "dreq") - _sum_field(first_rows, "dreq"))
            + max(0, _sum_field(rows, "dresp") - _sum_field(first_rows, "dresp"))
        )
        result["denials_rate"] = denials_delta / duration

        # RPS derived from cumulative response-counter deltas. Accurate for
        # backends (which lack req_rate) and additive for frontends.
        total_resp_delta = sum(result.get(c, 0) for c in ("1xx", "2xx", "3xx", "4xx", "5xx", "other"))
        result["responses_rate"] = max(0, total_resp_delta) / duration
    else:
        result["responses_rate"] = 0.0

    total_resp = sum(result.get(c, 0) for c in ("1xx", "2xx", "3xx", "4xx", "5xx", "other"))
    result["total_responses"] = total_resp
    if total_resp > 0:
        for code in ("1xx", "2xx", "3xx", "4xx", "5xx", "other"):
            result[f"pct_{code}"] = (result.get(code, 0) / total_resp) * 100

    result["sessions_pct"] = (result["sessions"] / max(1, settings.HAPROXY_MAXCONN)) * 100
    return result


def _derive_backend_metrics(rows: List[Dict[str, Any]], first_rows: Optional[List[Dict[str, Any]]], duration: float) -> Dict[str, Any]:
    result = _derive_proxy_metrics(rows, first_rows, duration)
    result.update({
        "queue": _sum_field(rows, "qcur"),
        "connection_errors": _sum_field(rows, "econ"),
        "retries_and_redispatches": _sum_field(rows, "wretr") + _sum_field(rows, "wredis"),
        "avg_response_time_ms": _sum_float_field(rows, "rtime"),
        "avg_connect_time_ms": _sum_float_field(rows, "ctime"),
        "avg_queue_time_ms": _sum_float_field(rows, "qtime"),
    })
    if first_rows and duration > 0:
        result["connection_errors_rate"] = max(0, _sum_field(rows, "econ") - _sum_field(first_rows, "econ")) / duration
        result["retries_and_redispatches_rate"] = (
            max(0, _sum_field(rows, "wretr") - _sum_field(first_rows, "wretr")) / duration
        ) + (
            max(0, _sum_field(rows, "wredis") - _sum_field(first_rows, "wredis")) / duration
        )
    else:
        result["connection_errors_rate"] = 0.0
        result["retries_and_redispatches_rate"] = 0.0
    return result


def _derive_server_status(row: Dict[str, Any], first_row: Optional[Dict[str, Any]] = None, duration: float = 0.0) -> Dict[str, Any]:
    result = {
        "status": row.get("status", "unknown"),
        "scur": _int(row.get("scur")),
        "rtime_ms": _float(row.get("rtime")),
        "ctime_ms": _float(row.get("ctime")),
        "qtime_ms": _float(row.get("qtime")),
        "qcur": _int(row.get("qcur")),
        "last_chk": row.get("last_chk", ""),
    }
    if first_row and duration > 0:
        resp_delta = sum(
            _int(row.get(f)) - _int(first_row.get(f))
            for f in ("hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other")
        )
        result["requests_rate"] = max(0, resp_delta) / duration
        result["bytes_in_rate"] = max(0, _int(row.get("bin")) - _int(first_row.get("bin"))) / duration
        result["bytes_out_rate"] = max(0, _int(row.get("bout")) - _int(first_row.get("bout"))) / duration
    else:
        result["requests_rate"] = 0.0
        result["bytes_in_rate"] = 0.0
        result["bytes_out_rate"] = 0.0
    return result


def _filter_rows(rows: List[Dict[str, Any]], kind: str) -> List[Dict[str, Any]]:
    return [r for r in rows if _row_kind(r) == kind]


def _aggregate(rows: List[Dict[str, Any]], first_rows: Optional[List[Dict[str, Any]]], duration: float) -> Dict[str, Any]:
    frontends = _filter_rows(rows, "frontend")
    backends = _filter_rows(rows, "backend")
    servers = [r for r in rows if _row_kind(r) == "server"]

    first_frontends = _filter_rows(first_rows or [], "frontend") if first_rows else None
    first_backends = _filter_rows(first_rows or [], "backend") if first_rows else None

    frontend_metrics = _derive_proxy_metrics(frontends, first_frontends, duration)
    backend_metrics = _derive_backend_metrics(backends, first_backends, duration)

    by_frontend: Dict[str, Any] = {}
    first_by_proxy: Dict[str, List[Dict[str, Any]]] = {}
    if first_rows:
        for r in first_rows:
            first_by_proxy.setdefault(_proxy_name(r), []).append(r)
    for row in frontends:
        name = _proxy_name(row)
        if name not in by_frontend:
            by_frontend[name] = _derive_proxy_metrics([row], first_by_proxy.get(name), duration)

    by_backend: Dict[str, Any] = {}
    for row in backends:
        name = _proxy_name(row)
        if name not in by_backend:
            by_backend[name] = _derive_backend_metrics([row], first_by_proxy.get(name), duration)

    by_server: Dict[str, Dict[str, Any]] = {}
    first_server: Dict[str, Dict[str, Any]] = {}
    if first_rows:
        for r in first_rows:
            if _row_kind(r) == "server":
                first_server[f"{_proxy_name(r)}|{_server_name(r)}"] = r
    for row in servers:
        backend = _proxy_name(row)
        server = _server_name(row)
        fr = first_server.get(f"{backend}|{server}")
        by_server.setdefault(backend, {})[server] = _derive_server_status(row, fr, duration)

    return {
        "frontend": frontend_metrics,
        "backend": backend_metrics,
        "frontends": by_frontend,
        "backends": by_backend,
        "servers": by_server,
    }


def get_metrics(db: Session, start: datetime, end: Optional[datetime] = None, step: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return aggregated metrics time-series for the requested range."""
    end = (end or datetime.now(timezone.utc)).replace(tzinfo=None)
    start = start.replace(tzinfo=None) if start else (end - timedelta(minutes=5))
    step = step or _auto_step(start, end)

    snapshots = (
        db.query(MetricSnapshot)
        .filter(MetricSnapshot.captured_at >= start, MetricSnapshot.captured_at <= end)
        .order_by(MetricSnapshot.captured_at)
        .all()
    )

    if not snapshots:
        logger.info("No metric snapshots found between %s and %s", start, end)
        return []

    buckets: Dict[datetime, List[MetricSnapshot]] = {}
    for snap in snapshots:
        ts = _bucket(snap.captured_at, step)
        buckets.setdefault(ts, []).append(snap)

    points: List[Dict[str, Any]] = []
    prev_snapshot: Optional[MetricSnapshot] = None
    for ts in sorted(buckets):
        bucket_snaps = buckets[ts]
        last = bucket_snaps[-1]
        first = bucket_snaps[0]
        duration = (last.captured_at - first.captured_at).total_seconds()
        first_rows = first.stats if first else None

        if duration <= 0:
            if prev_snapshot:
                duration = (last.captured_at - prev_snapshot.captured_at).total_seconds()
                first_rows = prev_snapshot.stats
            else:
                duration = settings.METRICS_SAMPLE_INTERVAL_SECONDS

        rows = last.stats or []
        agg = _aggregate(rows, first_rows, duration)

        info = last.process_info or {}
        agg["process"] = {
            "cpu_load": _float(stats._compute_cpu_load(info)),
            "memory_usage": _float(stats._compute_memory_usage_mb(info)),
            "current_connections": _int(info.get("CurrConns")),
            "max_connections": _int(info.get("Maxconn")),
            "total_requests": _int(info.get("CumReq")),
            "bytes_in": _int(info.get("CumInBytes")),
            "bytes_out": _int(info.get("TotalBytesOut")),
        }
        agg["time"] = ts.isoformat()
        points.append(agg)
        prev_snapshot = last

    return points


def _sampler_loop() -> None:
    while True:
        try:
            time.sleep(settings.METRICS_SAMPLE_INTERVAL_SECONDS)
            sample_metrics()
            try:
                db = SessionLocal()
                prune_metrics(db)
                db.close()
            except Exception:
                pass
        except Exception as exc:
            logger.exception("Metrics sampler loop error: %s", exc)


def start_sampler() -> None:
    """Start a background thread that samples HAProxy metrics."""
    # Capture one snapshot immediately so data is available right after startup
    sample_metrics()
    thread = threading.Thread(target=_sampler_loop, daemon=True)
    thread.start()
