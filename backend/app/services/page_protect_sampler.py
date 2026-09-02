"""Page Protect sampler — reads HAProxy logs via the runtime backend and stores CSP reports.

Background thread that polls HAProxy container logs every
PAGE_PROTECT_SAMPLER_INTERVAL_SECONDS, extracts lines with a non-empty
csp_report field, parses the CSP violation report, stores it in the database,
and upserts the script inventory.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from .page_protect import (
    get_page_protect_settings,
    parse_beacon_data,
    parse_csp_report,
    prune_csp_reports,
    prune_stale_scripts,
    store_beacon_resources,
    store_csp_report,
)
from .runtime import get_runtime

logger = logging.getLogger(__name__)

settings = get_settings()


def _offset_path() -> str:
    base = os.path.dirname(settings.HAPROXY_CONFIG_PATH) or "."
    return os.path.join(base, ".page_protect_sampler_offset")


def _read_offset() -> Optional[float]:
    """Read the last-seen Docker log timestamp (unix seconds) from disk."""
    try:
        with open(_offset_path(), "r") as f:
            val = f.read().strip()
            return float(val) if val else None
    except Exception:
        return None


def _write_offset(ts: Optional[float]) -> None:
    try:
        with open(_offset_path(), "w") as f:
            f.write(str(ts) if ts is not None else "")
    except Exception:
        pass


def _parse_log_line(line: str) -> Optional[dict]:
    """Parse a HAProxy JSON log line and return it if it has a csp_report or asset_beacon field."""
    line = line.strip()
    if not line:
        return None
    # Docker timestamps=True prepends an ISO timestamp followed by a space.
    docker_ts = None
    parts = line.split(" ", 1)
    if len(parts) == 2 and (parts[0].endswith("Z") or "T" in parts[0]):
        docker_ts, log_line = parts[0], parts[1]
    else:
        log_line = line
    try:
        parsed = json.loads(log_line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    csp_report = parsed.get("csp_report")
    # "-" is HAProxy's empty-value marker (emitted when the variable is unset,
    # now wrapped in quotes by the log format so it's valid JSON).
    # Treat it the same as missing/empty.
    if not csp_report or csp_report == "-":
        csp_report = None
    asset_beacon = parsed.get("asset_beacon")
    if not asset_beacon or asset_beacon == "-":
        asset_beacon = None
    if not csp_report and not asset_beacon:
        return None
    return {
        "docker_ts": docker_ts,
        "parsed": parsed,
        "csp_report": csp_report,
        "asset_beacon": asset_beacon,
    }


def _docker_ts_to_unix(ts_str: str) -> Optional[float]:
    """Convert a Docker ISO timestamp string to unix seconds."""
    try:
        # Docker uses ISO 8601 with nanosecond precision sometimes; trim to microseconds.
        ts_str = ts_str.rstrip("Z")
        if "." in ts_str:
            dt = datetime.fromisoformat(ts_str)
        else:
            dt = datetime.fromisoformat(ts_str)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def sample_csp_reports(force_recent: bool = False) -> int:
    """One sampling cycle: read new HAProxy logs, extract CSP reports, store them.

    Returns the number of reports stored.

    If ``force_recent`` is True, ignore the saved offset and grab the last 10
    minutes of logs. This is used by the manual "Sample Reports" button so the
    user can re-process logs that were previously skipped (e.g. due to a log
    format bug that has since been fixed).
    """
    runtime = get_runtime()
    if not runtime.is_available():
        logger.debug("Runtime backend not available; skipping CSP report sampling")
        return 0

    db: Optional[Session] = None
    try:
        if force_recent:
            # Manual trigger: grab last 10 minutes regardless of offset
            cutoff = int(time.time()) - 600
            raw = runtime.haproxy_logs(since=cutoff, timestamps=True)
        else:
            last_ts = _read_offset()
            # Fetch logs since the last timestamp (or last 5 minutes if first run).
            # The `since` parameter truncates to whole seconds, so we add 1
            # to skip past the last seen second entirely. This prevents
            # re-processing the same entry every cycle. Entries arriving in the
            # same second as the last processed one are rare with a 10s poll
            # interval and are recovered by the manual "Sample Reports" trigger.
            if last_ts is not None:
                raw = runtime.haproxy_logs(since=int(last_ts) + 1, timestamps=True)
            else:
                # First run: grab last 5 minutes
                cutoff = int(time.time()) - 300
                raw = runtime.haproxy_logs(since=cutoff, timestamps=True)

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        db = SessionLocal()
        pp_settings = get_page_protect_settings(db)
        retention_days = pp_settings.get("report_retention_days", 7)

        stored = 0
        max_ts: Optional[float] = None
        for line in raw.splitlines():
            entry = _parse_log_line(line)
            if not entry:
                continue

            # Track the latest Docker timestamp for the next poll
            if entry.get("docker_ts"):
                ts_unix = _docker_ts_to_unix(entry["docker_ts"])
                if ts_unix and (max_ts is None or ts_unix > max_ts):
                    max_ts = ts_unix

            parsed_log = entry["parsed"]
            client_ip = parsed_log.get("client")
            backend_name = parsed_log.get("backend")
            listener_name = parsed_log.get("frontend")

            # Process CSP report if present
            csp_body = entry.get("csp_report")
            if csp_body:
                # The csp_report field may be the raw JSON body or a string.
                # parse_csp_report expects a JSON string.
                if isinstance(csp_body, (dict, list)):
                    csp_body = json.dumps(csp_body)

                report = parse_csp_report(csp_body)
                if report:
                    store_csp_report(
                        db,
                        report,
                        client_ip=client_ip,
                        backend_name=backend_name,
                        listener_name=listener_name,
                    )
                    stored += 1

            # Process asset beacon if present
            beacon_body = entry.get("asset_beacon")
            if beacon_body:
                resources = parse_beacon_data(beacon_body)
                if resources:
                    beacon_stored = store_beacon_resources(db, resources)
                    if beacon_stored:
                        logger.info("Stored %d resources from beacon (page=%s)", beacon_stored, parsed_log.get("path", "?"))

        if stored:
            db.commit()
            logger.info("Stored %d CSP reports from HAProxy logs", stored)

        # Prune old reports
        try:
            pruned = prune_csp_reports(db, retention_days)
            if pruned:
                logger.debug("Pruned %d old CSP reports", pruned)
        except Exception:
            pass

        # Prune stale scripts (not seen in traffic or successfully hashed)
        try:
            stale_days = pp_settings.get("auto_prune_stale_days", 7)
            if stale_days and stale_days > 0:
                pruned_scripts = prune_stale_scripts(db, stale_days)
                if pruned_scripts:
                    logger.info("Pruned %d stale scripts (stale > %d days)", pruned_scripts, stale_days)
        except Exception:
            pass

        # Update the watermark
        if max_ts is not None:
            _write_offset(max_ts)

        return stored
    except Exception as exc:
        logger.exception("Failed to sample CSP reports: %s", exc)
        return 0
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def _sampler_loop() -> None:
    while True:
        try:
            time.sleep(settings.PAGE_PROTECT_SAMPLER_INTERVAL_SECONDS)
            sample_csp_reports()
        except Exception as exc:
            logger.exception("Page Protect sampler loop error: %s", exc)


def start_page_protect_sampler() -> None:
    thread = threading.Thread(target=_sampler_loop, daemon=True)
    thread.start()
