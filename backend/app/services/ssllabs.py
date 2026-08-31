"""SSL Labs v4 API client and scan management.

Submits hosts to the SSL Labs analyze endpoint (publish=off), polls for
results, and persists full reports. Auto-registers the user's email with
SSL Labs on the "not registered" error, then retries.
"""
import httpx
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import Certificate, SslLabsScan, User
from .settings import get_setting, set_setting

settings = get_settings()

# SSL Labs status values
_STATUS_DNS = "DNS"
_STATUS_IN_PROGRESS = "IN_PROGRESS"
_STATUS_READY = "READY"
_STATUS_ERROR = "ERROR"

_TERMINAL_STATUSES = {_STATUS_READY, _STATUS_ERROR}

# Default retention (overridable via the ssllabs_max_scans_per_host setting)
_DEFAULT_MAX_SCANS_PER_HOST = 5


def _client() -> httpx.Client:
    return httpx.Client(base_url=settings.SSLLABS_API_BASE, timeout=30.0)


def _require_contact_fields(user: User) -> None:
    """Raise 400 if the user is missing any SSL Labs registration field."""
    missing = []
    if not user.email:
        missing.append("email")
    if not user.first_name:
        missing.append("first name")
    if not user.last_name:
        missing.append("last name")
    if not user.organization:
        missing.append("organization")
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                "Complete your profile ("
                + ", ".join(missing)
                + ") before running SSL Labs scans. "
                "Update your profile via the user menu."
            ),
        )


def register_email(user: User) -> None:
    """Register the user's email with SSL Labs."""
    payload = {
        "firstName": user.first_name,
        "lastName": user.last_name,
        "email": user.email,
        "organization": user.organization,
    }
    with _client() as c:
        r = c.post("/register", json=payload)
        if r.status_code >= 400:
            detail = ""
            try:
                body = r.json()
                if isinstance(body, dict) and body.get("errors"):
                    detail = "; ".join(
                        e.get("message", "") for e in body["errors"]
                    )
            except Exception:
                detail = r.text
            raise HTTPException(
                status_code=502,
                detail=f"SSL Labs registration failed: {detail or r.text}",
            )


def _is_not_registered_error(response: httpx.Response) -> bool:
    """Check if the response indicates the email is not registered."""
    if response.status_code == 441:
        return True
    try:
        body = response.json()
    except Exception:
        return False
    if isinstance(body, dict) and isinstance(body.get("errors"), list):
        for err in body["errors"]:
            if err.get("field") == "email" and "register" in (
                err.get("message", "") or ""
            ).lower():
                return True
    return False


def _analyze(host: str, user: User, start_new: bool = False) -> Dict[str, Any]:
    """Call the SSL Labs /analyze endpoint.

    On the "email not registered" error, auto-registers and retries once.
    """
    params: Dict[str, str] = {
        "host": host,
        "publish": "off",
        "all": "on",
    }
    if start_new:
        params["startNew"] = "on"
    headers = {"email": user.email or ""}

    with _client() as c:
        r = c.get("/analyze", params=params, headers=headers)
        if _is_not_registered_error(r):
            register_email(user)
            r = c.get("/analyze", params=params, headers=headers)
        if r.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="SSL Labs rate limit reached. Wait a moment and try again.",
            )
        if r.status_code in (503, 529):
            raise HTTPException(
                status_code=503,
                detail="SSL Labs service is temporarily unavailable. Try again in a few minutes.",
            )
        if r.status_code >= 400:
            detail = ""
            try:
                body = r.json()
                if isinstance(body, dict) and body.get("errors"):
                    detail = "; ".join(
                        e.get("message", "") for e in body["errors"]
                    )
            except Exception:
                detail = r.text
            raise HTTPException(
                status_code=502,
                detail=f"SSL Labs API error: {detail or r.text}",
            )
        return r.json()


def start_scan(host: str, user: User) -> Dict[str, Any]:
    """Start a new SSL Labs assessment for the given host."""
    _require_contact_fields(user)
    return _analyze(host, user, start_new=True)


def poll_scan(host: str, user: User) -> Dict[str, Any]:
    """Poll an in-progress SSL Labs assessment (no startNew)."""
    _require_contact_fields(user)
    return _analyze(host, user, start_new=False)


def derive_hosts_from_cert(cert: Certificate) -> List[str]:
    """Derive scannable hostnames from a certificate's CN and SANs.

    Strips leading ``*.`` wildcard prefixes (SSL Labs cannot scan a literal
    wildcard), drops empty entries, and dedupes preserving order.
    """
    hosts: List[str] = []
    seen = set()

    raw_names: List[str] = []
    if cert.subject_cn:
        raw_names.append(cert.subject_cn)
    if cert.sans:
        raw_names.extend(s.strip() for s in cert.sans.split(",") if s.strip())

    for name in raw_names:
        name = name.strip()
        if not name:
            continue
        # Strip wildcard prefix — SSL Labs scans the base domain
        if name.startswith("*."):
            name = name[2:]
        if not name:
            continue
        if name not in seen:
            seen.add(name)
            hosts.append(name)

    return hosts


def _extract_grade(report: Dict[str, Any]) -> Optional[str]:
    """Extract the best (highest) grade from the report's endpoints."""
    endpoints = report.get("endpoints") or []
    grades = []
    for ep in endpoints:
        grade = ep.get("grade")
        if grade:
            grades.append(grade)
    if not grades:
        return None
    # Sort by grade quality: A+ > A > A- > B > C > D > E > F > T
    # Simple approach: pick the "best" by a rough ordering.
    grade_order = {"A+": 100, "A": 95, "A-": 90, "B": 80, "C": 70, "D": 60,
                   "E": 50, "F": 40, "T": 30}
    best = max(grades, key=lambda g: grade_order.get(g, 0))
    return best


def _host_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the fields we store from a SSL Labs Host object."""
    return {
        "status": report.get("status", _STATUS_IN_PROGRESS),
        "status_message": report.get("statusMessage"),
        "grade": _extract_grade(report) if report.get("status") == _STATUS_READY else None,
        "report": report,
        "start_time": report.get("startTime"),
        "test_time": report.get("testTime"),
        "engine_version": report.get("engineVersion"),
        "criteria_version": report.get("criteriaVersion"),
        "error": report.get("statusMessage") if report.get("status") == _STATUS_ERROR else None,
    }


def create_scan_record(
    db: Session, cert_id: int, host: str, report: Dict[str, Any]
) -> SslLabsScan:
    """Create a new scan record from a SSL Labs Host object."""
    fields = _host_from_report(report)
    scan = SslLabsScan(
        certificate_id=cert_id,
        host=host,
        **fields,
    )
    db.add(scan)
    db.flush()
    db.refresh(scan)
    _prune_scans(db, cert_id, host)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_record(
    db: Session, scan_id: int, report: Dict[str, Any]
) -> Optional[SslLabsScan]:
    """Update an existing scan record from a polled SSL Labs Host object."""
    scan = db.get(SslLabsScan, scan_id)
    if not scan:
        return None
    fields = _host_from_report(report)
    for k, v in fields.items():
        setattr(scan, k, v)
    # Prune if the scan just reached a terminal state
    if fields["status"] in _TERMINAL_STATUSES:
        _prune_scans(db, scan.certificate_id, scan.host)
    db.commit()
    db.refresh(scan)
    return scan


def get_max_scans_per_host(db: Session) -> int:
    """Read the ssllabs_max_scans_per_host setting (default 5)."""
    val = get_setting(db, "ssllabs_max_scans_per_host", str(_DEFAULT_MAX_SCANS_PER_HOST))
    try:
        n = int(val) if val else _DEFAULT_MAX_SCANS_PER_HOST
    except (TypeError, ValueError):
        n = _DEFAULT_MAX_SCANS_PER_HOST
    return max(1, n)


def set_max_scans_per_host(db: Session, value: int) -> int:
    """Set the ssllabs_max_scans_per_host setting."""
    if value < 1 or value > 100:
        raise HTTPException(
            status_code=400,
            detail="max_scans_per_host must be between 1 and 100",
        )
    set_setting(db, "ssllabs_max_scans_per_host", str(value))
    return value


def _prune_scans(db: Session, cert_id: int, host: str) -> None:
    """Delete oldest completed scans beyond the retention limit.

    Only READY/ERROR scans are pruned; in-progress scans are never deleted.
    """
    max_keep = get_max_scans_per_host(db)
    completed = (
        db.query(SslLabsScan)
        .filter(
            SslLabsScan.certificate_id == cert_id,
            SslLabsScan.host == host,
            SslLabsScan.status.in_(_TERMINAL_STATUSES),
        )
        .order_by(SslLabsScan.created_at.desc())
        .all()
    )
    if len(completed) <= max_keep:
        return
    for scan in completed[max_keep:]:
        db.delete(scan)
