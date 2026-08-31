from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..deps import get_current_user, get_db, require_admin, require_write, rate_limit
from ...models.models import Certificate, SslLabsScan, User
from ...schemas.ssllabs import (
    SslLabsHostsResponse,
    SslLabsScanCreate,
    SslLabsScanResponse,
    SslLabsSettingsResponse,
    SslLabsSettingsUpdate,
)
from ...services.ssllabs import (
    create_scan_record,
    derive_hosts_from_cert,
    get_max_scans_per_host,
    poll_scan,
    set_max_scans_per_host,
    start_scan,
    update_scan_record,
)

router = APIRouter()


def _get_cert_or_404(db: Session, cert_id: int) -> Certificate:
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert


@router.get(
    "/certificates/{cert_id}/ssllabs/hosts",
    response_model=SslLabsHostsResponse,
)
def get_ssllabs_hosts(
    cert_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List scannable hosts derived from a certificate's CN and SANs."""
    cert = _get_cert_or_404(db, cert_id)
    return SslLabsHostsResponse(hosts=derive_hosts_from_cert(cert))


@router.get(
    "/certificates/{cert_id}/ssllabs/scans",
    response_model=List[SslLabsScanResponse],
)
def list_ssllabs_scans(
    cert_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List all SSL Labs scan records for a certificate, newest first."""
    _get_cert_or_404(db, cert_id)
    return (
        db.query(SslLabsScan)
        .filter(SslLabsScan.certificate_id == cert_id)
        .order_by(SslLabsScan.host.asc(), SslLabsScan.created_at.desc())
        .all()
    )


@router.get(
    "/certificates/{cert_id}/ssllabs/scans/{scan_id}",
    response_model=SslLabsScanResponse,
)
def get_ssllabs_scan(
    cert_id: int,
    scan_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get a single SSL Labs scan with the full report."""
    scan = db.get(SslLabsScan, scan_id)
    if not scan or scan.certificate_id != cert_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post(
    "/certificates/{cert_id}/ssllabs/scans",
    response_model=SslLabsScanResponse,
)
def start_ssllabs_scan(
    cert_id: int,
    data: SslLabsScanCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Start a new SSL Labs scan for a host derived from the certificate."""
    cert = _get_cert_or_404(db, cert_id)
    valid_hosts = derive_hosts_from_cert(cert)
    if data.host not in valid_hosts:
        raise HTTPException(
            status_code=400,
            detail=f"Host '{data.host}' is not a valid host for this certificate",
        )
    report = start_scan(data.host, user)
    scan = create_scan_record(db, cert_id, data.host, report)
    return scan


@router.post(
    "/certificates/{cert_id}/ssllabs/scans/{scan_id}/poll",
    response_model=SslLabsScanResponse,
)
def poll_ssllabs_scan(
    cert_id: int,
    scan_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Poll an in-progress SSL Labs scan for updated results."""
    scan = db.get(SslLabsScan, scan_id)
    if not scan or scan.certificate_id != cert_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in ("READY", "ERROR"):
        # Already terminal — return as-is without hitting the API
        return scan
    report = poll_scan(scan.host, user)
    updated = update_scan_record(db, scan_id, report)
    if not updated:
        raise HTTPException(status_code=404, detail="Scan not found")
    return updated


@router.delete("/certificates/{cert_id}/ssllabs/scans/{scan_id}")
def delete_ssllabs_scan(
    cert_id: int,
    scan_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Delete a SSL Labs scan record (admin only)."""
    scan = db.get(SslLabsScan, scan_id)
    if not scan or scan.certificate_id != cert_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"status": "ok"}


@router.get(
    "/certificates/{cert_id}/ssllabs/settings",
    response_model=SslLabsSettingsResponse,
)
def get_ssllabs_settings(
    cert_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get the SSL Labs scan retention setting."""
    _get_cert_or_404(db, cert_id)
    return SslLabsSettingsResponse(max_scans_per_host=get_max_scans_per_host(db))


@router.put(
    "/certificates/{cert_id}/ssllabs/settings",
    response_model=SslLabsSettingsResponse,
)
def update_ssllabs_settings(
    cert_id: int,
    data: SslLabsSettingsUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Update the SSL Labs scan retention setting (admin only)."""
    _get_cert_or_404(db, cert_id)
    value = set_max_scans_per_host(db, data.max_scans_per_host)
    return SslLabsSettingsResponse(max_scans_per_host=value)
