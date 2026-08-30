import json
import logging
import os
import re
import threading
import time
import geoip2.database
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..core.valkey_client import cache
from ..models.models import WafMetric

logger = logging.getLogger(__name__)

settings = get_settings()

_ACTIONS = {
    "Access allowed": "allow",
    "Access denied": "deny",
    "Access dropped": "drop",
    "Access redirected": "redirect",
    "Warning": "pass",
}

_FIELD_RE = re.compile(r'\[(\w+) "([^"]*)"\]')
_ACTION_RE = re.compile(r'Coraza:\s*(Access allowed|Access denied|Access dropped|Access redirected|Warning)(?:\s+\(phase \d+\))?\.' )

# CRS anomaly-score messages include a varying total score. Collapse them into
# a single breakdown key so they group together when breaking down by message.
_ANOMALY_SCORE_RE = re.compile(r'^Inbound Anomaly Score Exceeded \(Total Score:?\s*[0-9]+\)$')


def _normalize_breakdown_value(breakdown: str, value: str) -> str:
    """Normalize a breakdown value for grouping.

    Currently collapses CRS "Inbound Anomaly Score Exceeded (Total Score N)"
    messages into a single "Inbound Anomaly Score Exceeded" key when breaking
    down by message.
    """
    if breakdown == "msg" and value and _ANOMALY_SCORE_RE.match(value):
        return "Inbound Anomaly Score Exceeded"
    return value


def _action_from_message(message: str) -> str:
    match = _ACTION_RE.search(message)
    if match:
        return _ACTIONS.get(match.group(1), "unknown")
    return "unknown"


def _parse_message(message: str) -> Dict[str, Any]:
    fields: Dict[str, str] = {}
    for key, value in _FIELD_RE.findall(message):
        if key in ("id", "severity", "msg", "uri", "client", "unique_id") and value:
            fields[key] = value

    if "client" not in fields:
        # Old-style log starts with [client "IP"]
        client_match = re.match(r'\[client "([^"]+)"\]', message)
        if client_match:
            fields["client"] = client_match.group(1)

    # If no [msg "..."] bracket was found, extract the free-text message:
    # the text between [client "..."] and the first [file "..."] (or end).
    if "msg" not in fields:
        msg_match = re.match(r'\[client "[^"]*"\]\s*(.+?)(?:\s*\[(?:file|line|id|severity|uri|unique_id)\s)|$', message)
        if msg_match:
            fields["msg"] = msg_match.group(1).strip()

    action = _action_from_message(message)
    return {
        "action": action,
        "rule_id": fields.get("id"),
        "severity": fields.get("severity"),
        "msg": fields.get("msg"),
        "client": fields.get("client"),
        "uri": fields.get("uri"),
        "unique_id": fields.get("unique_id"),
    }


def _stringify(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _action_from_match(match: Dict[str, Any]) -> Optional[str]:
    action = match.get("action")
    if isinstance(action, str) and action:
        return action
    if match.get("disruptive") is True:
        return "deny"
    if match.get("disruptive") is False:
        return "pass"
    msg = _stringify(match.get("msg") or match.get("message")) or ""
    if not msg:
        return None
    parsed_action = _action_from_message(msg)
    if parsed_action != "unknown":
        return parsed_action
    return None


def _extract_from_match(match: Dict[str, Any], time: Any = None, level: Any = None) -> Optional[Dict[str, Any]]:
    if not isinstance(match, dict):
        return None
    if not any(match.get(k) for k in ("action", "rule_id", "id", "msg", "message", "client", "uri", "unique_id", "file", "severity")):
        return None

    rule_id_raw = match.get("rule_id")
    if rule_id_raw is None:
        rule_id_raw = match.get("id")
    msg_raw = match.get("msg") or match.get("message")
    client_raw = match.get("client") or match.get("client_ip")
    uri_raw = match.get("uri") or match.get("path")

    return {
        "time": _stringify(time),
        "level": _stringify(level),
        "action": _action_from_match(match),
        "rule_id": _stringify(rule_id_raw),
        "severity": _stringify(match.get("severity")),
        "msg": _stringify(msg_raw),
        "client": _stringify(client_raw),
        "uri": _stringify(uri_raw),
        "unique_id": _stringify(match.get("unique_id")),
    }


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        if not isinstance(data, dict):
            return None

        time = data.get("time") if "time" in data else data.get("timestamp")
        level = data.get("level")

        # New coraza-spoa main emits a zerolog JSON line with a "match" object.
        match = data.get("match")
        if isinstance(match, dict):
            parsed = _extract_from_match(match, time=time, level=level)
            if parsed:
                return parsed

        # Already-structured JSON, including the raw errorLog object itself.
        if any(k in data for k in ("action", "rule_id", "id")):
            return _extract_from_match(data, time=time, level=level)

        # Some SPOA versions put the structured error object under "message"/"msg".
        for key in ("message", "msg"):
            raw_msg = data.get(key)
            if isinstance(raw_msg, dict):
                parsed = _extract_from_match(raw_msg, time=time, level=level)
                if parsed:
                    return parsed

        # Bracketed string message wrapped in a zerolog JSON log line.
        raw_msg = data.get("message")
        if raw_msg is None:
            raw_msg = data.get("msg")
        message = _stringify(raw_msg)
        if not message:
            return None
        parsed = _parse_message(message)
        if parsed:
            parsed["time"] = _stringify(time)
            parsed["level"] = _stringify(level)
            # If _parse_message found no WAF fields (action is "unknown" and
            # no rule_id/severity/msg/client/uri), this is a plain log line
            # (e.g. "Starting coraza-spoa"). Use the raw message and level.
            if parsed.get("action") == "unknown" and not any(
                parsed.get(k) for k in ("rule_id", "severity", "msg", "client", "uri")
            ):
                parsed["action"] = None
                parsed["msg"] = message
                if not parsed.get("severity"):
                    parsed["severity"] = _stringify(level)
        return parsed
    except json.JSONDecodeError:
        # Fall back to plain text parsing
        return _parse_message(line)
    except Exception:
        return None


def _geo_country(ip: Optional[str], reader: Optional[geoip2.database.Reader]) -> Optional[str]:
    if not ip or not reader:
        return "unknown"
    try:
        return reader.country(ip).country.iso_code or "unknown"
    except Exception:
        return "unknown"


def _offset_path() -> str:
    path = settings.CORAZA_SPOA_LOG_PATH
    base = os.path.dirname(path) or "."
    return os.path.join(base, ".waf_metrics_offset")


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


def sample_waf_metrics() -> None:
    if not settings.CORAZA_SPOA_ENABLED:
        return

    path = settings.CORAZA_SPOA_LOG_PATH
    if not os.path.exists(path):
        return

    db = None
    reader: Optional[geoip2.database.Reader] = None
    try:
        last_offset = _read_offset()
        current_size = os.path.getsize(path)
        if current_size < last_offset:
            # File was truncated/rotated
            last_offset = 0

        db = SessionLocal()
        new_records = 0
        geo_path = os.path.abspath(settings.GEOIP_DB_PATH)
        if os.path.exists(geo_path):
            try:
                reader = geoip2.database.Reader(geo_path)
            except Exception:
                pass

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(last_offset)
            for line in f:
                parsed = _parse_line(line)
                if not parsed:
                    continue
                # Skip log lines that don't represent an actual WAF decision.
                # These are typically health-checks, startup noise, or plain
                # audit messages that the parser could not classify.
                if not parsed.get("action") or parsed["action"] == "unknown":
                    continue
                parsed["country"] = _geo_country(parsed.get("client"), reader)
                metric = WafMetric(
                    captured_at=datetime.now(timezone.utc).replace(tzinfo=None),
                    action=parsed["action"],
                    rule_id=parsed.get("rule_id"),
                    severity=parsed.get("severity"),
                    msg=parsed.get("msg"),
                    client=parsed.get("client"),
                    country=parsed.get("country"),
                    uri=parsed.get("uri"),
                )
                db.add(metric)
                new_records += 1
            db.commit()
            logger.info("Stored %d WAF events from %s", new_records, path)
    except Exception as exc:
        logger.exception("Failed to sample WAF metrics: %s", exc)
    finally:
        if reader:
            try:
                reader.close()
            except Exception:
                pass
        _write_offset(current_size if 'current_size' in locals() else 0)
        if db:
            try:
                db.close()
            except Exception:
                pass


def prune_waf_metrics(db: Session) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.WAF_METRICS_RETENTION_DAYS)).replace(tzinfo=None)
    result = db.query(WafMetric).filter(WafMetric.captured_at < cutoff).delete()
    db.commit()
    return result


def _waf_sampler_loop() -> None:
    while True:
        try:
            time.sleep(settings.WAF_METRICS_SAMPLE_INTERVAL_SECONDS)
            sample_waf_metrics()
            try:
                db = SessionLocal()
                prune_waf_metrics(db)
                db.close()
            except Exception:
                pass
        except Exception as exc:
            logger.exception("WAF metrics sampler loop error: %s", exc)


def start_waf_sampler() -> None:
    thread = threading.Thread(target=_waf_sampler_loop, daemon=True)
    thread.start()


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


@cache(ttl=10, key_prefix="waf")
def get_waf_metrics(
    db: Session,
    start: datetime,
    end: Optional[datetime] = None,
    step: Optional[int] = None,
    breakdown: str = "action",
) -> Dict[str, Any]:
    end = (end or datetime.now(timezone.utc)).replace(tzinfo=None)
    start = start.replace(tzinfo=None) if start else (end - timedelta(minutes=5))
    step = step or _auto_step(start, end)

    rows = (
        db.query(WafMetric)
        .filter(
            WafMetric.captured_at >= start,
            WafMetric.captured_at <= end,
            WafMetric.action != "unknown",
        )
        .all()
    )

    if not rows:
        return {"time": [], "series": [], "breakdown": breakdown, "totals": {}}

    # Build time buckets and series by breakdown value
    buckets: Dict[datetime, List[WafMetric]] = {}
    for row in rows:
        ts = _bucket(row.captured_at, step)
        buckets.setdefault(ts, []).append(row)

    # Determine the set of breakdown keys and initialize series
    series_keys: set = set()
    for row in rows:
        value = _normalize_breakdown_value(breakdown, getattr(row, breakdown) or "unknown")
        series_keys.add(value)

    # Count totals per breakdown key
    totals: Dict[str, int] = {}
    for row in rows:
        value = _normalize_breakdown_value(breakdown, getattr(row, breakdown) or "unknown")
        totals[value] = totals.get(value, 0) + 1

    timestamps = sorted(buckets)
    series: List[Dict[str, Any]] = []
    for key in sorted(series_keys):
        data = []
        for ts in timestamps:
            count = sum(
                1
                for row in buckets[ts]
                if _normalize_breakdown_value(breakdown, getattr(row, breakdown) or "unknown") == key
            )
            data.append({"time": ts.isoformat(), "count": count})
        series.append({"key": key, "data": data})

    return {
        "time": [t.isoformat() for t in timestamps],
        "series": series,
        "breakdown": breakdown,
        "totals": totals,
    }

