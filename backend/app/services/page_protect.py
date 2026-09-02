"""Page Protect — Cloudflare Page Shield-style client-side security.

Core service: CSP header builder, CSP report parser, script inventory upsert,
settings helpers, and dashboard stats.
"""
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import CspReport, PageProtectPolicy, PageProtectScript, Setting
from .settings import get_setting, set_setting

logger = logging.getLogger(__name__)

settings = get_settings()

# Map CSP violated-directive → resource_type for the script inventory.
_DIRECTIVE_TO_RESOURCE_TYPE: Dict[str, str] = {
    "script-src": "script",
    "script-src-elem": "script",
    "script-src-attr": "script",
    "connect-src": "connect",
    "img-src": "img",
    "style-src": "style",
    "style-src-elem": "style",
    "style-src-attr": "style",
    "font-src": "font",
    "frame-src": "frame",
    "object-src": "object",
    "media-src": "other",
    "worker-src": "other",
    "manifest-src": "other",
    "child-src": "frame",
    "default-src": "other",
}

# Default settings values.
_DEFAULTS = {
    "monitoring_enabled": False,
    "change_detection_enabled": False,
    "change_detection_interval_hours": 24,
    "report_retention_days": 7,
    "report_path": settings.PAGE_PROTECT_DEFAULT_REPORT_PATH,
    "baseline_start": "",  # ISO timestamp or empty
    "baseline_end": "",    # ISO timestamp or empty
    "baseline_note": "",   # optional user label
    "beacon_injection_enabled": False,
    "beacon_path": "/_cx-assets",
    "beacon_script_path": "/_cx-assets.js",
    "beacon_content_types": "text/html",
    "beacon_path_patterns": "",
    "beacon_backend_ids": [],
    "auto_prune_stale_days": 7,
}

# Reverse map: resource_type → CSP directive for the recommender.
_RESOURCE_TYPE_TO_DIRECTIVE: Dict[str, str] = {
    "script": "script-src",
    "connect": "connect-src",
    "img": "img-src",
    "style": "style-src",
    "font": "font-src",
    "frame": "frame-src",
    "object": "object-src",
}

# Minimum distinct client IPs for an origin to be trusted in the recommender.
# Single-IP violations are likely attacker probes or browser extensions.
_MIN_DISTINCT_IPS = 2


def build_csp_header(directives: Dict[str, List[str]], report_uri: Optional[str] = None) -> str:
    """Convert a directive dict to a CSP header value string.

    Example: {"default-src": ["'self'"], "script-src": ["'self'", "https://cdn.example.com"]}
    → "default-src 'self'; script-src 'self' https://cdn.example.com"

    If report_uri is provided and the directives do not already contain
    "report-uri", it is appended as the report destination.
    """
    parts: List[str] = []
    for directive, sources in directives.items():
        if not sources:
            # Directive with no sources (e.g. upgrade-insecure-requests)
            parts.append(directive)
        else:
            parts.append(f"{directive} {' '.join(sources)}")
    if report_uri and "report-uri" not in directives:
        parts.append(f"report-uri {report_uri}")
    return "; ".join(parts)


def build_report_to_header(report_path: str, group_name: str = "csp-endpoint") -> str:
    """Build the Report-To header JSON value for the Reporting API.

    The endpoint group is relative to the site origin (report_path).
    """
    return json.dumps({
        "group": group_name,
        "max_age": 10886400,
        "endpoints": [{"url": report_path}],
    })


def is_page_protect_enabled(db: Session) -> bool:
    """Check the page_protect_monitoring_enabled setting."""
    val = get_setting(db, "page_protect_monitoring_enabled", str(_DEFAULTS["monitoring_enabled"]))
    return str(val).lower() in ("true", "1", "yes")


def is_page_protect_hashing_enabled(db: Session) -> bool:
    """Check the page_protect_change_detection_enabled setting."""
    val = get_setting(db, "page_protect_change_detection_enabled", str(_DEFAULTS["change_detection_enabled"]))
    return str(val).lower() in ("true", "1", "yes")


def get_page_protect_settings(db: Session) -> Dict[str, Any]:
    """Read all page_protect_* settings from the settings table."""
    result: Dict[str, Any] = {}
    for key, default in _DEFAULTS.items():
        val = get_setting(db, f"page_protect_{key}", str(default))
        if isinstance(default, bool):
            result[key] = str(val).lower() in ("true", "1", "yes")
        elif isinstance(default, int):
            try:
                result[key] = int(val)
            except (TypeError, ValueError):
                result[key] = default
        elif isinstance(default, list):
            try:
                parsed = json.loads(val) if val else []
                result[key] = parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, ValueError, TypeError):
                result[key] = []
        else:
            result[key] = val
    return result


def update_page_protect_settings(db: Session, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Write page_protect_* settings to the settings table."""
    for key, value in updates.items():
        if key not in _DEFAULTS:
            continue
        if isinstance(value, bool):
            stored = str(value).lower()
        elif isinstance(value, list):
            stored = json.dumps(value)
        else:
            stored = str(value)
        set_setting(db, f"page_protect_{key}", stored)
    return get_page_protect_settings(db)


def get_report_path(db: Session) -> str:
    """Return the configured CSP report path."""
    val = get_setting(db, "page_protect_report_path", _DEFAULTS["report_path"])
    return val or _DEFAULTS["report_path"]


def _extract_domain(url: str) -> Optional[str]:
    """Extract the domain (netloc) from a URL."""
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        if parsed.scheme == "data":
            return "data:"
        if url.startswith("'") or url in ("'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'"):
            return None
    except Exception:
        pass
    return None


def parse_csp_report(body: str) -> Optional[Dict[str, Any]]:
    """Parse a CSP report JSON body.

    Handles three formats:
    1. report-uri format: {"csp-report": {...}}
    2. Reporting API format: {"type": "csp-violation", "body": {...}}
    3. Reporting API batch: [{...}, {...}]

    Returns a dict with normalized fields, or None if unparseable.
    For batch reports, returns the first valid report.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None

    if isinstance(data, list):
        # Batch of reports — take the first valid one
        for item in data:
            parsed = _parse_single_report(item)
            if parsed:
                return parsed
        return None

    return _parse_single_report(data)


def _parse_single_report(data: Any) -> Optional[Dict[str, Any]]:
    """Parse a single report object (dict)."""
    if not isinstance(data, dict):
        return None

    # report-uri format: {"csp-report": {...}}
    if "csp-report" in data:
        r = data["csp-report"]
        if not isinstance(r, dict):
            return None
        return {
            "report_type": "csp",
            "document_uri": r.get("document-uri"),
            "referrer": r.get("referrer"),
            "violated_directive": r.get("violated-directive"),
            "effective_directive": r.get("effective-directive"),
            "original_policy": r.get("original-policy"),
            "blocked_uri": r.get("blocked-uri"),
            "source_file": r.get("source-file"),
            "line_number": r.get("line-number"),
            "column_number": r.get("column-number"),
            "status_code": r.get("status-code"),
            "script_sample": r.get("script-sample"),
        }

    # Reporting API format: {"type": "csp-violation", "body": {...}}
    if data.get("type") == "csp-violation" and "body" in data:
        r = data["body"]
        if not isinstance(r, dict):
            return None
        return {
            "report_type": "reporting-api",
            "document_uri": r.get("documentURL"),
            "referrer": r.get("referrer"),
            "violated_directive": r.get("effectiveDirective") or r.get("violatedDirective"),
            "effective_directive": r.get("effectiveDirective"),
            "original_policy": r.get("originalPolicy"),
            "blocked_uri": r.get("blockedURL"),
            "source_file": r.get("sourceFile"),
            "line_number": r.get("lineNumber"),
            "column_number": r.get("columnNumber"),
            "status_code": r.get("statusCode"),
            "script_sample": r.get("sample"),
        }

    # Bare report dict (some browsers send the report fields directly)
    if "violated-directive" in data or "blocked-uri" in data or "document-uri" in data:
        return {
            "report_type": "csp",
            "document_uri": data.get("document-uri"),
            "referrer": data.get("referrer"),
            "violated_directive": data.get("violated-directive"),
            "effective_directive": data.get("effective-directive"),
            "original_policy": data.get("original-policy"),
            "blocked_uri": data.get("blocked-uri"),
            "source_file": data.get("source-file"),
            "line_number": data.get("line-number"),
            "column_number": data.get("column-number"),
            "status_code": data.get("status-code"),
            "script_sample": data.get("script-sample"),
        }

    return None


def extract_script_info(report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract URL and resource_type from a parsed CSP report.

    Returns {"url": ..., "resource_type": ...} or None if no blocked URI.
    """
    blocked_uri = report.get("blocked_uri")
    if not blocked_uri:
        return None
    # Skip inline/eval keywords that aren't real URLs
    if blocked_uri in ("inline", "eval", "data", "blob", "wasm"):
        return None
    if blocked_uri.startswith("'") or blocked_uri in ("'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'"):
        return None

    violated = report.get("violated_directive") or ""
    # Strip the -elem/-attr suffix for resource type mapping
    base_directive = violated.split(" ")[0] if violated else ""
    resource_type = _DIRECTIVE_TO_RESOURCE_TYPE.get(base_directive, "other")

    domain = _extract_domain(blocked_uri)
    return {"url": blocked_uri, "resource_type": resource_type, "domain": domain}


def upsert_script_inventory(db: Session, url: str, resource_type: str, domain: Optional[str], source: str = "csp") -> PageProtectScript:
    """Upsert a PageProtectScript row (update last_seen, occurrence_count; insert if new)."""
    script = db.query(PageProtectScript).filter(PageProtectScript.url == url).first()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if script:
        script.last_seen = now
        script.occurrence_count = (script.occurrence_count or 0) + 1
        if domain and not script.domain:
            script.domain = domain
    else:
        script = PageProtectScript(
            url=url,
            resource_type=resource_type,
            domain=domain,
            first_seen=now,
            last_seen=now,
            occurrence_count=1,
            source=source,
        )
        db.add(script)
    db.flush()
    return script


def store_csp_report(
    db: Session,
    report: Dict[str, Any],
    client_ip: Optional[str] = None,
    backend_name: Optional[str] = None,
    listener_name: Optional[str] = None,
    policy_id: Optional[int] = None,
) -> CspReport:
    """Store a parsed CSP report in the database and upsert the script inventory."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    record = CspReport(
        policy_id=policy_id,
        captured_at=now,
        client_ip=client_ip,
        document_uri=report.get("document_uri"),
        referrer=report.get("referrer"),
        violated_directive=report.get("violated_directive"),
        effective_directive=report.get("effective_directive"),
        original_policy=report.get("original_policy"),
        blocked_uri=report.get("blocked_uri"),
        source_file=report.get("source_file"),
        line_number=report.get("line_number"),
        column_number=report.get("column_number"),
        status_code=report.get("status_code"),
        script_sample=report.get("script_sample"),
        backend_name=backend_name,
        listener_name=listener_name,
        report_type=report.get("report_type", "csp"),
    )
    db.add(record)

    # Upsert script inventory
    script_info = extract_script_info(report)
    if script_info:
        upsert_script_inventory(db, script_info["url"], script_info["resource_type"], script_info["domain"])

    db.flush()
    return record


def prune_csp_reports(db: Session, retention_days: int = 7) -> int:
    """Delete CSP reports older than retention_days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).replace(tzinfo=None)
    result = db.query(CspReport).filter(CspReport.captured_at < cutoff).delete()
    db.commit()
    return result


def prune_stale_scripts(db: Session, stale_days: int) -> int:
    """Delete scripts not seen in traffic or successfully hashed within stale_days.

    A row is pruned when ALL of:
    - ``last_seen`` is older than the cutoff (no CSP/beacon/manual detection recently)
    - ``last_hash_at`` is older than the cutoff OR NULL (hasher hasn't successfully
      fetched it recently)
    - ``hash_changed`` is False (preserve security alerts)

    Returns the number of rows deleted. ``stale_days <= 0`` disables pruning.
    """
    if stale_days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=stale_days)).replace(tzinfo=None)
    stale = db.query(PageProtectScript).filter(
        PageProtectScript.hash_changed == False,  # noqa: E712
        PageProtectScript.last_seen < cutoff,
        or_(
            PageProtectScript.last_hash_at == None,  # noqa: E711
            PageProtectScript.last_hash_at < cutoff,
        ),
    ).all()
    for s in stale:
        db.delete(s)
    if stale:
        db.commit()
    return len(stale)


def parse_beacon_data(body: Any) -> List[Dict[str, Any]]:
    """Parse a beacon POST body and return a list of resource dicts.

    The beacon JS sends JSON: ``{"page": "...", "resources": [...], "ts": ...}``
    Each resource has ``url``, ``resource_type``, ``domain``.
    """
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return []
    if isinstance(body, bytes):
        try:
            body = json.loads(body.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError):
            return []
    if not isinstance(body, dict):
        return []
    resources = body.get("resources") or []
    if not isinstance(resources, list):
        return []
    result = []
    for r in resources:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if not url or not isinstance(url, str):
            continue
        if not url.startswith(("http://", "https://")):
            continue
        result.append({
            "url": url,
            "resource_type": r.get("resource_type") or "other",
            "domain": r.get("domain"),
        })
    return result


def store_beacon_resources(db: Session, resources: List[Dict[str, Any]]) -> int:
    """Upsert beacon resources into the script inventory with source='beacon'."""
    count = 0
    for r in resources:
        upsert_script_inventory(db, r["url"], r["resource_type"], r.get("domain"), source="beacon")
        count += 1
    if count:
        db.commit()
    return count


def get_beacon_settings(db: Session) -> Dict[str, Any]:
    """Return beacon-specific settings from the Page Protect config."""
    pp = get_page_protect_settings(db)
    return {
        "enabled": pp.get("beacon_injection_enabled", False),
        "beacon_path": pp.get("beacon_path", "/_cx-assets"),
        "beacon_script_path": pp.get("beacon_script_path", "/_cx-assets.js"),
        "content_types": pp.get("beacon_content_types", "text/html"),
        "path_patterns": pp.get("beacon_path_patterns", ""),
        "backend_ids": pp.get("beacon_backend_ids", []),
    }


def build_beacon_rule(pp_settings: Dict[str, Any], beacon_script_url: str) -> Dict[str, Any]:
    """Build a resp_transform inject rule dict for the beacon script tag.

    This rule is merged into the per-backend resp-transform JSON config file
    alongside any user-defined transform rules.

    A cache-busting version hash is appended to the script URL so browsers
    fetch the new JS when its content changes (the file is served with a
    long max-age). HAProxy's ``path`` fetch strips the query string, so the
    ACL still matches the base path.
    """
    from .page_protect_beacon_js import BEACON_JS
    version = hashlib.sha256(BEACON_JS.encode()).hexdigest()[:8]
    separator = "&" if "?" in beacon_script_url else "?"
    versioned_url = f"{beacon_script_url}{separator}v={version}"
    content_types = [c.strip() for c in (pp_settings.get("beacon_content_types") or "text/html").split(",") if c.strip()]
    path_patterns = [p.strip() for p in (pp_settings.get("beacon_path_patterns") or "").split(",") if p.strip()]
    return {
        "id": 999999,  # sentinel ID to distinguish beacon rules from user rules
        "enabled": True,
        "priority": 0,  # inject before other transforms so the beacon is always added
        "transform_type": "inject",
        "content_types": content_types,
        "max_body_size": 1048576,
        "find_regex": "</head>|</body>",
        "inject_string": f'<script src="{versioned_url}"></script>',
        "inject_position": "before",
        "path_patterns": path_patterns,
    }


def get_stats(db: Session) -> Dict[str, Any]:
    """Aggregate dashboard stats."""
    total_scripts = db.query(func.count(PageProtectScript.id)).scalar() or 0
    total_reports = db.query(func.count(CspReport.id)).scalar() or 0
    changed_scripts = db.query(func.count(PageProtectScript.id)).filter(
        PageProtectScript.hash_changed == True  # noqa: E712
    ).scalar() or 0
    active_policies = db.query(func.count(PageProtectPolicy.id)).filter(
        PageProtectPolicy.enabled == True  # noqa: E712
    ).scalar() or 0

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_24h = now - timedelta(hours=24)
    reports_24h = db.query(func.count(CspReport.id)).filter(CspReport.captured_at >= cutoff_24h).scalar() or 0

    # Top violated directives (last 7 days)
    cutoff_7d = now - timedelta(days=7)
    top_directives = (
        db.query(CspReport.violated_directive, func.count(CspReport.id).label("count"))
        .filter(CspReport.captured_at >= cutoff_7d)
        .filter(CspReport.violated_directive.isnot(None))
        .group_by(CspReport.violated_directive)
        .order_by(func.count(CspReport.id).desc())
        .limit(10)
        .all()
    )
    top_violated_directives = [
        {"directive": d, "count": c} for d, c in top_directives if d
    ]

    # Top blocked URIs (last 7 days)
    top_uris = (
        db.query(CspReport.blocked_uri, func.count(CspReport.id).label("count"))
        .filter(CspReport.captured_at >= cutoff_7d)
        .filter(CspReport.blocked_uri.isnot(None))
        .group_by(CspReport.blocked_uri)
        .order_by(func.count(CspReport.id).desc())
        .limit(10)
        .all()
    )
    top_blocked_uris = [
        {"uri": u, "count": c} for u, c in top_uris if u
    ]

    return {
        "total_scripts": total_scripts,
        "total_reports": total_reports,
        "changed_scripts": changed_scripts,
        "active_policies": active_policies,
        "reports_24h": reports_24h,
        "top_violated_directives": top_violated_directives,
        "top_blocked_uris": top_blocked_uris,
    }


# ---------------------------------------------------------------------------
# Baselining window
# ---------------------------------------------------------------------------

def get_baseline(db: Session) -> Dict[str, Any]:
    """Return the current baseline window state."""
    start = get_setting(db, "page_protect_baseline_start", "")
    end = get_setting(db, "page_protect_baseline_end", "")
    note = get_setting(db, "page_protect_baseline_note", "")
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if not start:
        status = "idle"
    elif start and not end:
        status = "baselining"
    else:
        status = "complete"

    result: Dict[str, Any] = {"status": status, "note": note}

    if start:
        result["start"] = start
        try:
            start_dt = _parse_iso(start)
            if start_dt:
                result["elapsed_seconds"] = int((now - start_dt).total_seconds())
        except Exception:
            pass

    if end:
        result["end"] = end
        try:
            start_dt = _parse_iso(start)
            end_dt = _parse_iso(end)
            if start_dt and end_dt:
                result["duration_seconds"] = int((end_dt - start_dt).total_seconds())
        except Exception:
            pass

    # Live counts during baselining or after completion
    if start:
        counts = _baseline_counts(db, start, end or None)
        result.update(counts)

    return result


def start_baseline(db: Session, note: str = "") -> Dict[str, Any]:
    """Start a new baseline collection window.

    If a window is already in progress (start set, end empty), it is replaced.
    If a window is complete (start+end set), it is also replaced.
    """
    now_iso = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    set_setting(db, "page_protect_baseline_start", now_iso)
    set_setting(db, "page_protect_baseline_end", "")
    set_setting(db, "page_protect_baseline_note", note)
    db.commit()
    return get_baseline(db)


def stop_baseline(db: Session) -> Dict[str, Any]:
    """Stop the current baseline window (set the end timestamp)."""
    start = get_setting(db, "page_protect_baseline_start", "")
    if not start:
        return {"status": "idle", "error": "no baseline in progress"}
    now_iso = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    set_setting(db, "page_protect_baseline_end", now_iso)
    db.commit()
    return get_baseline(db)


def clear_baseline(db: Session) -> Dict[str, Any]:
    """Clear the baseline window entirely."""
    set_setting(db, "page_protect_baseline_start", "")
    set_setting(db, "page_protect_baseline_end", "")
    set_setting(db, "page_protect_baseline_note", "")
    db.commit()
    return {"status": "idle"}


def _parse_iso(s: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string to a naive UTC datetime."""
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _baseline_counts(db: Session, start: str, end: Optional[str]) -> Dict[str, int]:
    """Count scripts and reports within the baseline window."""
    start_dt = _parse_iso(start)
    end_dt = _parse_iso(end) if end else None
    if not start_dt:
        return {"scripts_count": 0, "reports_count": 0, "distinct_ips": 0, "distinct_pages": 0}

    script_q = db.query(PageProtectScript).filter(PageProtectScript.last_seen >= start_dt)
    if end_dt:
        script_q = script_q.filter(PageProtectScript.last_seen <= end_dt)
    scripts_count = script_q.count()

    report_q = db.query(CspReport).filter(CspReport.captured_at >= start_dt)
    if end_dt:
        report_q = report_q.filter(CspReport.captured_at <= end_dt)
    reports_count = report_q.count()

    distinct_ips = report_q.filter(CspReport.client_ip.isnot(None)).group_by(CspReport.client_ip).count()
    distinct_pages = report_q.filter(CspReport.document_uri.isnot(None)).group_by(CspReport.document_uri).count()

    return {
        "scripts_count": scripts_count,
        "reports_count": reports_count,
        "distinct_ips": distinct_ips,
        "distinct_pages": distinct_pages,
    }


# ---------------------------------------------------------------------------
# Policy recommender
# ---------------------------------------------------------------------------

def recommend_policy(
    db: Session,
    backend_ids: Optional[List[int]] = None,
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Recommend a CSP policy based on observed data.

    Uses the script inventory and CSP violation reports within the baseline
    window (if set) or all data (if no baseline). Filters by backend_ids if
    provided.

    Returns a dict with:
      - directives: Dict[str, List[str]] — recommended CSP directives
      - warnings: List[str] — human-readable warnings
      - sources: Dict[str, List[dict]] — per-directive origin details with counts
      - summary: dict — counts and metadata
    """
    baseline = get_baseline(db)
    start_str = baseline.get("start", "")
    end_str = baseline.get("end", "")
    start_dt = _parse_iso(start_str) if start_str else None
    end_dt = _parse_iso(end_str) if end_str else None

    # Build backend name filter for reports (reports store backend_name, not id)
    backend_names: Optional[List[str]] = None
    if backend_ids:
        from ..models.models import Backend
        backend_names = [
            b.name for b in db.query(Backend).filter(Backend.id.in_(backend_ids)).all()
        ]

    # --- Query script inventory ---
    script_q = db.query(PageProtectScript)
    if start_dt:
        script_q = script_q.filter(PageProtectScript.last_seen >= start_dt)
        # No upper bound on scripts — see last_seen drift problem in design.
        # The distinct-IP filter on reports handles post-window attacker traffic.
    scripts = script_q.all()

    # --- Query CSP reports for inline/eval detection ---
    report_q = db.query(CspReport)
    if start_dt:
        report_q = report_q.filter(CspReport.captured_at >= start_dt)
    if end_dt:
        report_q = report_q.filter(CspReport.captured_at <= end_dt)
    if backend_names:
        report_q = report_q.filter(CspReport.backend_name.in_(backend_names))
    reports = report_q.all()

    # --- Build per-directive origin lists from inventory ---
    # Group by resource_type → domain → {urls, occurrence_count}
    by_type: Dict[str, Dict[str, dict]] = {}
    for s in scripts:
        rt = s.resource_type or "other"
        if rt not in _RESOURCE_TYPE_TO_DIRECTIVE:
            continue  # skip "other" — let default-src cover it
        domain = s.domain or _extract_domain(s.url)
        if not domain or domain == "self":
            continue
        by_type.setdefault(rt, {})
        entry = by_type[rt].setdefault(domain, {
            "occurrence_count": 0,
            "distinct_ips": set(),
            "urls": set(),
        })
        entry["occurrence_count"] += s.occurrence_count or 1
        entry["urls"].add(s.url)

    # Enrich with distinct-IP counts from CSP reports
    for r in reports:
        if not r.blocked_uri or r.blocked_uri in ("inline", "eval", "data", "blob", "wasm"):
            continue
        if r.blocked_uri.startswith("'"):
            continue
        domain = _extract_domain(r.blocked_uri)
        if not domain:
            continue
        violated = (r.violated_directive or "").split(" ")[0]
        rt = _DIRECTIVE_TO_RESOURCE_TYPE.get(violated, "")
        if rt and rt in by_type and domain in by_type[rt]:
            if r.client_ip:
                by_type[rt][domain]["distinct_ips"].add(r.client_ip)

    # --- Build directives ---
    directives: Dict[str, List[str]] = {}
    warnings: List[str] = []
    sources_detail: Dict[str, List[dict]] = {}

    # Always start with default-src
    directives["default-src"] = ["'self'"]
    directives["base-uri"] = ["'self'"]
    directives["form-action"] = ["'self'"]

    # object-src: default to 'none' unless we observed object violations
    has_object = any(
        r.violated_directive and r.violated_directive.startswith("object-src")
        for r in reports
    )
    if not has_object:
        directives["object-src"] = ["'none'"]
        warnings.append("object-src set to 'none' (no object/embed violations observed)")

    # Build per-directive source lists
    for rt, domains in by_type.items():
        directive = _RESOURCE_TYPE_TO_DIRECTIVE[rt]
        sources: List[str] = ["'self'"]
        detail_list: List[dict] = []

        for domain, info in sorted(
            domains.items(),
            key=lambda kv: kv[1]["occurrence_count"],
            reverse=True,
        ):
            distinct_ips = len(info["distinct_ips"])
            origin = f"https://{domain}"

            # Filter: require ≥2 distinct IPs unless we have no report data
            # (cold start — trust inventory without IP verification)
            if reports and distinct_ips < _MIN_DISTINCT_IPS and distinct_ips == 0:
                # No CSP reports for this origin at all — it was only seen
                # in the inventory (upserted from a report, but we may not
                # have the reports filtered to this window). Include it but
                # warn.
                warnings.append(
                    f"{origin} in {directive} has no violation reports in window — "
                    f"verify this is a legitimate origin"
                )
            elif reports and distinct_ips < _MIN_DISTINCT_IPS and distinct_ips > 0:
                warnings.append(
                    f"{origin} in {directive} seen from only {distinct_ips} client IP — "
                    f"possible attacker probe, review before keeping"
                )

            if origin not in sources:
                sources.append(origin)
            detail_list.append({
                "origin": origin,
                "occurrence_count": info["occurrence_count"],
                "distinct_ips": distinct_ips,
                "sample_url": next(iter(info["urls"]), ""),
            })

        directives[directive] = sources
        sources_detail[directive] = detail_list

    # --- Detect inline/eval from reports ---
    inline_script = any(
        r.blocked_uri == "inline" and r.violated_directive and r.violated_directive.startswith("script-src")
        for r in reports
    )
    inline_style = any(
        r.blocked_uri == "inline" and r.violated_directive and r.violated_directive.startswith("style-src")
        for r in reports
    )
    eval_violation = any(r.blocked_uri == "eval" for r in reports)
    data_violations = [r for r in reports if r.blocked_uri == "data"]
    blob_violations = [r for r in reports if r.blocked_uri == "blob"]

    if inline_script:
        if "script-src" not in directives:
            directives["script-src"] = ["'self'"]
        directives["script-src"].append("'unsafe-inline'")
        count = sum(1 for r in reports if r.blocked_uri == "inline" and r.violated_directive and r.violated_directive.startswith("script-src"))
        warnings.append(f"'unsafe-inline' added to script-src ({count} inline script violations observed)")

    if inline_style:
        if "style-src" not in directives:
            directives["style-src"] = ["'self'"]
        directives["style-src"].append("'unsafe-inline'")
        count = sum(1 for r in reports if r.blocked_uri == "inline" and r.violated_directive and r.violated_directive.startswith("style-src"))
        warnings.append(f"'unsafe-inline' added to style-src ({count} inline style violations observed)")

    if eval_violation:
        if "script-src" not in directives:
            directives["script-src"] = ["'self'"]
        directives["script-src"].append("'unsafe-eval'")
        count = sum(1 for r in reports if r.blocked_uri == "eval")
        warnings.append(f"'unsafe-eval' added to script-src ({count} eval violations observed)")

    if data_violations:
        # Determine which directive(s) had data: violations
        data_directives = set()
        for r in data_violations:
            v = (r.violated_directive or "").split(" ")[0]
            if v:
                data_directives.add(v)
        for d in data_directives:
            if d not in directives:
                directives[d] = ["'self'"]
            directives[d].append("data:")
        warnings.append(f"data: added to {', '.join(data_directives)} ({len(data_violations)} data: URI violations observed)")

    if blob_violations:
        blob_directives = set()
        for r in blob_violations:
            v = (r.violated_directive or "").split(" ")[0]
            if v:
                blob_directives.add(v)
        for d in blob_directives:
            if d not in directives:
                directives[d] = ["'self'"]
            directives[d].append("blob:")
        warnings.append(f"blob: added to {', '.join(blob_directives)} ({len(blob_violations)} blob: URI violations observed)")

    # --- report-uri ---
    if not report_path:
        report_path = get_setting(db, "page_protect_report_path", _DEFAULTS["report_path"])
    directives["report-uri"] = [report_path]

    # --- Summary ---
    summary = {
        "scripts_analyzed": len(scripts),
        "reports_analyzed": len(reports),
        "baseline_start": start_str,
        "baseline_end": end_str,
        "directives_count": len(directives),
        "backend_filter": backend_names,
    }

    if not scripts and not reports:
        warnings.insert(0, "No observed data in the selected window. This is a minimal safe policy. "
                           "Enable monitoring and let traffic flow to collect data, then re-run the recommender.")

    return {
        "directives": directives,
        "warnings": warnings,
        "sources": sources_detail,
        "summary": summary,
    }
