"""MCP Gateway metrics sampler — tails events.ndjson, stores McpEvent rows, prunes old data.

Mirrors the WAF metrics sampler pattern: file offset tracking, periodic sampling,
time-bucketed aggregation with breakdown support.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..core.valkey_client import cache
from ..models.mcp import McpEvent

logger = logging.getLogger(__name__)

settings = get_settings()


def _offset_path() -> str:
    path = settings.MCP_EVENTS_LOG_PATH
    base = os.path.dirname(path) or "."
    return os.path.join(base, ".mcp_metrics_offset")


def _read_offset() -> int:
    try:
        with open(_offset_path(), "r") as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0


def _write_offset(offset: int) -> None:
    try:
        with open(_offset_path(), "w") as f:
            f.write(str(offset))
    except Exception:
        pass


def _parse_event_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single NDJSON event line."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        if not isinstance(data, dict):
            return None
        return data
    except json.JSONDecodeError:
        return None


def sample_mcp_metrics() -> None:
    """Read new lines from the events log and store them as McpEvent rows."""
    path = settings.MCP_EVENTS_LOG_PATH
    if not os.path.exists(path):
        return

    db = None
    try:
        last_offset = _read_offset()
        current_size = os.path.getsize(path)
        if current_size < last_offset:
            last_offset = 0

        db = SessionLocal()
        new_records = 0

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(last_offset)
            for line in f:
                parsed = _parse_event_line(line)
                if not parsed:
                    continue

                ts_str = parsed.get("ts")
                try:
                    captured_at = datetime.fromisoformat(ts_str).replace(tzinfo=None)
                except Exception:
                    captured_at = datetime.now(timezone.utc).replace(tzinfo=None)

                event = McpEvent(
                    captured_at=captured_at,
                    request_id=parsed.get("request_id"),
                    session_id=parsed.get("session_id"),
                    identity_id=parsed.get("identity_id"),
                    team_id=parsed.get("team_id"),
                    server_id=parsed.get("server_id"),
                    jsonrpc_method=parsed.get("method"),
                    tool=parsed.get("tool"),
                    resource_uri=parsed.get("resource_uri"),
                    prompt=parsed.get("prompt"),
                    action=parsed.get("action"),
                    status=parsed.get("status"),
                    latency_ms=parsed.get("latency_ms"),
                    error=parsed.get("error"),
                    bytes_in=parsed.get("bytes_in"),
                    bytes_out=parsed.get("bytes_out"),
                    dlp_hits=parsed.get("dlp_hits"),
                    guardrail_hits=parsed.get("guardrail_hits"),
                )
                db.add(event)
                new_records += 1
            db.commit()
            if new_records:
                logger.info("Stored %d MCP events from %s", new_records, path)
    except Exception as exc:
        logger.exception("Failed to sample MCP metrics: %s", exc)
    finally:
        _write_offset(current_size if "current_size" in locals() else 0)
        if db:
            try:
                db.close()
            except Exception:
                pass


def prune_mcp_metrics(db: Session) -> int:
    """Delete McpEvent rows older than retention period."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.MCP_METRICS_RETENTION_DAYS)).replace(tzinfo=None)
    result = db.query(McpEvent).filter(McpEvent.captured_at < cutoff).delete()
    db.commit()
    return result


def _mcp_sampler_loop() -> None:
    while True:
        try:
            time.sleep(settings.MCP_METRICS_SAMPLE_INTERVAL_SECONDS)
            sample_mcp_metrics()
            try:
                db = SessionLocal()
                prune_mcp_metrics(db)
                db.close()
            except Exception:
                pass
        except Exception as exc:
            logger.exception("MCP metrics sampler loop error: %s", exc)


def start_mcp_sampler() -> None:
    """Start the MCP metrics sampler background thread."""
    thread = threading.Thread(target=_mcp_sampler_loop, daemon=True)
    thread.start()


# ---------------------------------------------------------------------------
# Aggregation / API
# ---------------------------------------------------------------------------

def _bucket(ts: datetime, step: int) -> datetime:
    epoch = ts.replace(tzinfo=timezone.utc).timestamp()
    return datetime.fromtimestamp((epoch // step) * step, tz=timezone.utc)


def _auto_step(start: datetime, end: datetime) -> int:
    duration = (end - start).total_seconds()
    if duration <= 300:
        return 60
    if duration <= 3600:
        return 300
    if duration <= 86400:
        return 1800
    if duration <= 604800:
        return 21600
    return 86400


_BREAKDOWN_FIELDS = {
    "method": "jsonrpc_method",
    "tool": "tool",
    "identity": "identity_id",
    "server": "server_id",
    "action": "action",
    "status": "status",
}


@cache(ttl=10, key_prefix="mcp_metrics")
def get_mcp_metrics(
    db: Session,
    start: datetime,
    end: Optional[datetime] = None,
    step: Optional[int] = None,
    breakdown: str = "action",
) -> Dict[str, Any]:
    """Aggregate MCP events into time-bucketed series by breakdown field."""
    end = (end or datetime.now(timezone.utc)).replace(tzinfo=None)
    start = start.replace(tzinfo=None) if start else (end - timedelta(minutes=5))
    step = step or _auto_step(start, end)

    breakdown_col = _BREAKDOWN_FIELDS.get(breakdown, "action")

    rows = (
        db.query(McpEvent)
        .filter(
            McpEvent.captured_at >= start,
            McpEvent.captured_at <= end,
        )
        .order_by(McpEvent.captured_at)
        .limit(10000)
        .all()
    )

    if not rows:
        return {"time": [], "series": [], "breakdown": breakdown, "totals": {}, "latency": {}}

    # Build time buckets
    buckets: Dict[datetime, List[McpEvent]] = {}
    for row in rows:
        ts = _bucket(row.captured_at, step)
        buckets.setdefault(ts, []).append(row)

    # Determine breakdown keys and totals
    series_keys: set = set()
    totals: Dict[str, int] = {}
    for row in rows:
        val = str(getattr(row, breakdown_col) or "unknown")
        series_keys.add(val)
        totals[val] = totals.get(val, 0) + 1

    timestamps = sorted(buckets)
    series: List[Dict[str, Any]] = []
    for key in sorted(series_keys):
        data = []
        for ts in timestamps:
            count = sum(
                1
                for row in buckets[ts]
                if str(getattr(row, breakdown_col) or "unknown") == key
            )
            data.append({"time": ts.isoformat(), "count": count})
        series.append({"key": key, "data": data})

    # Latency stats per bucket
    latency_data: List[Dict[str, Any]] = []
    for ts in timestamps:
        latencies = [r.latency_ms for r in buckets[ts] if r.latency_ms is not None]
        if latencies:
            latencies.sort()
            p50 = latencies[len(latencies) // 2]
            p99 = latencies[min(int(len(latencies) * 0.99), len(latencies) - 1)]
            avg = sum(latencies) / len(latencies)
            latency_data.append({
                "time": ts.isoformat(),
                "p50": p50,
                "p99": p99,
                "avg": int(avg),
                "count": len(latencies),
            })
        else:
            latency_data.append({"time": ts.isoformat(), "p50": 0, "p99": 0, "avg": 0, "count": 0})

    return {
        "time": [t.isoformat() for t in timestamps],
        "series": series,
        "breakdown": breakdown,
        "totals": totals,
        "latency": latency_data,
    }
