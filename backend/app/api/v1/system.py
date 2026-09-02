import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import geoip2
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy import func
from starlette.background import BackgroundTask
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_admin, rate_limit
from ...core.config import get_settings
from ...models.models import LogDestination, LoggedField, MetricSnapshot, Setting
from ...schemas.haproxy_options import HaproxyOption
from ...schemas.settings import AsnLookupResponse, GeoIpDownloadResponse, GeoIpStatusResponse, SettingCreate, SettingResponse
from ...schemas.stats import MetricsResponse, StatsResponse, WafMetricsResponse
from ...services.geoip import download_maxmind_dbs
from ...services.metrics import get_metrics
from ...services.settings import get_maxmind_license_key, get_setting, list_settings, set_setting
from ...services.stats import _send_command, get_stats
from ...services.waf_metrics import get_waf_metrics
from ...services.runtime import get_runtime

router = APIRouter()
settings = get_settings()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/system/health")
def system_health(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Return health status for key system components."""
    from ...core.valkey_client import is_available as valkey_available

    # HAProxy socket
    socket_path = settings.HAPROXY_SOCKET_PATH
    haproxy_socket = os.path.exists(socket_path)

    # Valkey/Redis
    valkey = valkey_available()

    # Runtime backend reachability (Docker SDK or Kubernetes API)
    runtime = get_runtime()
    rt_desc = runtime.describe()

    # GeoIP DB status
    geoip = {
        "country_db_exists": os.path.exists(settings.GEOIP_DB_PATH),
        "city_db_exists": os.path.exists(settings.GEOIP_CITY_DB_PATH) if hasattr(settings, "GEOIP_CITY_DB_PATH") else False,
        "asn_db_exists": os.path.exists(settings.ASN_DB_PATH) if hasattr(settings, "ASN_DB_PATH") else False,
    }

    # Coraza SPOA enabled
    coraza_enabled = bool(getattr(settings, "CORAZA_SPOA_ENABLED", False))

    return {
        "haproxy_socket": {"available": haproxy_socket, "path": socket_path},
        "valkey": {"available": valkey},
        "docker": {"available": rt_desc.get("available", False), "error": rt_desc.get("error")},
        "geoip": geoip,
        "coraza_spoa": {"enabled": coraza_enabled},
    }


@router.get("/stats", response_model=StatsResponse)
def stats(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return StatsResponse(**get_stats())


@router.get("/haproxy-stats/debug")
def metrics_debug(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    socket_path = settings.HAPROXY_SOCKET_PATH
    socket_exists = os.path.exists(socket_path)
    socket_test = ""
    if socket_exists:
        raw = _send_command("show info")
        socket_test = raw[:200] if raw else "(empty response)"

    total = db.query(func.count(MetricSnapshot.id)).scalar() or 0
    latest = db.query(func.max(MetricSnapshot.captured_at)).scalar()
    oldest = db.query(func.min(MetricSnapshot.captured_at)).scalar()
    server_now = datetime.now(timezone.utc).replace(tzinfo=None)

    return {
        "socket_path": socket_path,
        "socket_exists": socket_exists,
        "socket_test": socket_test,
        "snapshot_count": total,
        "latest_snapshot": str(latest) if latest else None,
        "oldest_snapshot": str(oldest) if oldest else None,
        "server_utc_now": str(server_now),
        "sample_interval_seconds": settings.METRICS_SAMPLE_INTERVAL_SECONDS,
    }


@router.get("/haproxy-stats", response_model=MetricsResponse)
def metrics(
    from_: Optional[datetime] = Query(None, alias="from"),
    to: Optional[datetime] = Query(None),
    step: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    end = to or datetime.now(timezone.utc)
    start = from_ or (end - timedelta(minutes=5))
    return MetricsResponse(data=get_metrics(db, start, end, step))


@router.get("/waf/haproxy-stats", response_model=WafMetricsResponse)
def waf_metrics(
    from_: Optional[datetime] = Query(None, alias="from"),
    to: Optional[datetime] = Query(None),
    step: Optional[int] = Query(None),
    breakdown: str = Query("action"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    end = to or datetime.now(timezone.utc)
    start = from_ or (end - timedelta(minutes=5))
    return WafMetricsResponse(**get_waf_metrics(db, start, end, step, breakdown))


# Log Viewer
@router.get("/logs/recent")
def get_recent_logs(limit: int = Query(100, le=1000), user=Depends(get_current_user), _=Depends(rate_limit)):
    """Fetch recent HAProxy logs from the haproxy container via Docker SDK.

    Returns a list of request log lines. Only lines that parse as JSON are
    included — this filters out HAProxy system messages (startup notices,
    reload warnings, SPOE agent output, SSL handshake errors, etc.) that
    are not request logs and would clutter the live log view.
    """
    if not getattr(settings, "HAPROXY_LOG_VIEWER_ENABLED", True):
        return {"lines": [], "error": "log viewer disabled"}

    runtime = get_runtime()
    if not runtime.is_available():
        return {"lines": [], "error": runtime.describe().get("error") or "runtime backend not available"}

    try:
        # Fetch more lines than requested so we still have `limit` after filtering
        # out non-JSON system messages.
        raw = runtime.haproxy_logs(tail=limit * 5, timestamps=True)
    except Exception as exc:
        return {"lines": [], "error": f"could not fetch logs: {exc}"}

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    lines_out = []
    skipped_non_json = 0
    skipped_control = 0
    # Iterate newest→oldest so the `break at limit` below keeps the MOST RECENT
    # parsed lines. Docker's `tail=N` returns oldest→newest; iterating in that
    # order and breaking at `limit` used to return the OLDEST `limit` lines of
    # the fetched window, discarding the newest ones entirely. During a request
    # flood (e.g. a burst of WAF 403s) this made fresh logs invisible — the
    # viewer only ever showed stale entries.
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if not line:
            continue
        # Docker timestamps=True prepends an ISO timestamp followed by a space.
        # Split it off so we have the actual log line.
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0].endswith("Z") or (len(parts) == 2 and "T" in parts[0]):
            docker_ts, log_line = parts[0], parts[1]
        else:
            docker_ts, log_line = None, line

        # HAProxy (and some SPOE/rate-limit paths) can emit non-printable
        # control characters (e.g. NUL bytes) before the JSON payload, which
        # str.strip() does not remove. Find the first '{' and drop anything
        # before it so json.loads() can parse the line.
        brace_idx = log_line.find("{")
        if brace_idx > 0:
            prefix = log_line[:brace_idx]
            # Only strip if the prefix is entirely control/non-printable chars
            # (avoid mangling lines where '{' appears mid-text after a real
            # non-JSON prefix like a syslog header).
            if all(ord(c) < 0x20 or ord(c) == 0x7F for c in prefix):
                log_line = log_line[brace_idx:]
                skipped_control += 1
        elif brace_idx == -1:
            # No JSON object on this line — skip it (system message, SPOE
            # output, SSL handshake error, etc.).
            skipped_non_json += 1
            continue

        # Only include lines that parse as JSON. The default log-format produces
        # JSON objects; HAProxy system messages (NOTICE/WARNING/ALERT), SPOE
        # agent output, and pre-handshake errors (SSL failures) are non-JSON
        # and are filtered out.
        try:
            parsed = json.loads(log_line)
        except (json.JSONDecodeError, ValueError):
            skipped_non_json += 1
            continue

        entry = {"raw": log_line}
        if docker_ts:
            entry["docker_ts"] = docker_ts
        entry["parsed"] = parsed
        lines_out.append(entry)

        # Stop once we have enough filtered lines
        if len(lines_out) >= limit:
            break

    # lines_out was collected newest→oldest; reverse to oldest→newest so the
    # frontend's `.reverse()` yields a newest-first display.
    lines_out.reverse()

    return {
        "lines": lines_out,
        "skipped_non_json": skipped_non_json,
        "skipped_control": skipped_control,
    }


@router.get("/logs/health")
def get_logs_health(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    """Return logging health/status: destinations, format, and Docker SDK reachability."""
    enabled_dests = db.query(LogDestination).filter(LogDestination.enabled == True).all()
    enabled_fields = db.query(LoggedField).filter(LoggedField.enabled == True).all()

    # Determine if the default stdout destination is active
    has_stdout = any(d.target in ("stdout", "stderr") for d in enabled_dests)
    default_stdout_active = len(enabled_dests) == 0 and getattr(settings, "HAPROXY_LOG_DEFAULT_STDOUT", True)

    # Check runtime backend reachability
    runtime = get_runtime()
    rt_desc = runtime.describe()
    docker_reachable = rt_desc.get("available", False)
    docker_error = rt_desc.get("error")

    # Determine current log-format mode
    log_format_mode = "json_default"
    if enabled_fields:
        log_format_mode = "custom"

    return {
        "enabled_destinations": len(enabled_dests),
        "has_stdout_target": has_stdout or default_stdout_active,
        "default_stdout_active": default_stdout_active,
        "custom_log_format": len(enabled_fields) > 0,
        "log_format_mode": log_format_mode,
        "docker_reachable": docker_reachable,
        "docker_error": docker_error,
        "destinations": [
            {"name": d.name, "target": d.target, "facility": d.facility, "level": d.level}
            for d in enabled_dests
        ],
    }


@router.get("/settings/maxmind/license-key", response_model=SettingResponse)
def get_maxmind_license_key_route(db: Session = Depends(get_db), user=Depends(require_admin), _=Depends(rate_limit)):
    value = get_maxmind_license_key(db)
    row = db.query(Setting).filter(Setting.key == "maxmind_license_key").first()
    if not row:
        row = Setting(key="maxmind_license_key", value=value)
    return row


@router.put("/settings/maxmind/license-key", response_model=SettingResponse)
def update_maxmind_license_key(s_in: SettingCreate, db: Session = Depends(get_db), user=Depends(require_admin), _=Depends(rate_limit)):
    return set_setting(db, "maxmind_license_key", s_in.value)


@router.post("/settings/geoip/download", response_model=GeoIpDownloadResponse)
def trigger_geoip_download(db: Session = Depends(get_db), user=Depends(require_admin), _=Depends(rate_limit)):
    return download_maxmind_dbs(db)


@router.get("/settings/geoip/status", response_model=GeoIpStatusResponse)
def get_geoip_status(db: Session = Depends(get_db), user=Depends(require_admin), _=Depends(rate_limit)):
    """Return the last successful MaxMind download timestamp and per-DB file info."""
    last_download = get_setting(db, "geoip_download_last_run_at")
    from datetime import datetime, timezone
    dbs = []
    for name, path in [
        ("Country", settings.GEOIP_DB_PATH),
        ("City", settings.GEOIP_CITY_DB_PATH),
        ("ASN", settings.ASN_DB_PATH),
    ]:
        info: Dict[str, Any] = {"name": name, "path": path, "exists": os.path.exists(path)}
        if info["exists"]:
            try:
                mtime = os.path.getmtime(path)
                info["modified"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                info["size_bytes"] = os.path.getsize(path)
            except OSError:
                pass
        dbs.append(info)
    return GeoIpStatusResponse(last_download=last_download, databases=dbs)


@router.get("/geoip/asn", response_model=AsnLookupResponse)
def lookup_asn(ip: str = Query(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"), user=Depends(require_admin), _=Depends(rate_limit)):
    """Look up ASN organization/network and city/country for a given IP using GeoLite2 databases."""
    import geoip2
    asn_path = settings.ASN_DB_PATH
    city_path = settings.GEOIP_CITY_DB_PATH
    result = AsnLookupResponse(ip=ip)

    # ASN lookup
    if asn_path and os.path.exists(asn_path):
        try:
            with geoip2.database.Reader(asn_path) as reader:
                r = reader.asn(ip)
                result.asn = r.autonomous_system_number
                result.organization = r.autonomous_system_organization
                result.network = str(r.network) if r.network else None
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass
        except Exception:
            pass

    # City + Country lookup
    if city_path and os.path.exists(city_path):
        try:
            with geoip2.database.Reader(city_path) as reader:
                r = reader.city(ip)
                result.city = r.city.name
                result.country = r.country.name
                result.country_code = r.country.iso_code
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass
        except Exception:
            pass
    elif os.path.exists(settings.GEOIP_DB_PATH):
        # Fall back to Country-only database if City DB is not available
        try:
            with geoip2.database.Reader(settings.GEOIP_DB_PATH) as reader:
                r = reader.country(ip)
                result.country = r.country.name
                result.country_code = r.country.iso_code
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass
        except Exception:
            pass

    return result


@router.get("/haproxy/global-options", response_model=List[HaproxyOption])
def get_haproxy_global_options(db: Session = Depends(get_db), user=Depends(require_admin), _=Depends(rate_limit)):
    raw = get_setting(db, "haproxy_global_options", "[]")
    try:
        opts = json.loads(raw) if isinstance(raw, str) and raw else []
    except (json.JSONDecodeError, TypeError):
        opts = []
    return [HaproxyOption(**o) for o in opts if isinstance(o, dict)]


@router.put("/haproxy/global-options", response_model=List[HaproxyOption])
def update_haproxy_global_options(opts: List[HaproxyOption], db: Session = Depends(get_db), user=Depends(require_admin), _=Depends(rate_limit)):
    set_setting(db, "haproxy_global_options", json.dumps([o.model_dump() for o in opts]))
    return opts


# System Export / Restore
@router.get("/system/export")
def system_export(
    include_secrets: bool = Query(True),
    include_metrics: bool = Query(False),
    password: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Export the full system configuration as a downloadable archive.

    Streams the archive so that data starts flowing immediately instead of
    building the entire ZIP in memory first (which caused proxy timeouts
    with large GeoIP databases).
    """
    from ...services.backup import create_export
    import os as _os

    tmp_path, encrypted = create_export(db, include_secrets=include_secrets, include_metrics=include_metrics, password=password)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"haproxy-manager-export-{timestamp}.zip"
    media_type = "application/octet-stream" if encrypted else "application/zip"

    def _cleanup(path: str) -> None:
        try:
            _os.unlink(path)
        except OSError:
            pass

    return FileResponse(
        tmp_path,
        media_type=media_type,
        filename=filename,
        background=BackgroundTask(_cleanup, tmp_path),
    )


@router.post("/system/restore")
async def system_restore(
    file: UploadFile = File(...),
    password: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Restore the full system configuration from an uploaded archive.

    Replaces all DB tables, cert files, config files, and data directories present
    in the archive, then applies the config and reloads HAProxy.
    """
    from ...services.backup import restore_export

    archive_bytes = await file.read()
    try:
        result = restore_export(db, archive_bytes, password=password, apply_config=True)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Restore failed: {exc}")


# ---------------------------------------------------------------------------
