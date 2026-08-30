from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from ..deps import get_db, require_admin, rate_limit
from ...schemas.audit import AuditEventResponse, AuditEventFilterOptions
from ...services.audit_events import export_audit_events_csv, list_audit_events, get_audit_event_filter_options

router = APIRouter()


@router.get("/audit-events/filters", response_model=AuditEventFilterOptions)
def get_audit_event_filters_endpoint(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return get_audit_event_filter_options(db)


@router.get("/audit-events", response_model=List[AuditEventResponse])
def list_audit_events_endpoint(
    limit: int = 100,
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    ip_address: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    has_snapshot: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return list_audit_events(
        db,
        limit=limit,
        username=username,
        action=action,
        resource=resource,
        ip_address=ip_address,
        from_date=from_date,
        to_date=to_date,
        has_snapshot=has_snapshot,
    )


@router.get("/audit-events/export")
def export_audit_events_endpoint(
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    ip_address: Optional[str] = Query(None),
    has_snapshot: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    csv_data = export_audit_events_csv(
        db,
        username=username,
        action=action,
        resource=resource,
        ip_address=ip_address,
        from_date=from_date,
        to_date=to_date,
        has_snapshot=has_snapshot,
    )
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-events.csv"},
    )
