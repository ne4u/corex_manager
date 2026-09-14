from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from ...schemas.audit import AuditEventFilterOptions, AuditEventResponse
from ...services.audit_events import export_audit_events_csv, get_audit_event_filter_options, list_audit_events
from ..deps import get_db, rate_limit, require_admin

router = APIRouter()


@router.get("/audit-events/filters", response_model=AuditEventFilterOptions)
def get_audit_event_filters_endpoint(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return get_audit_event_filter_options(db)


@router.get("/audit-events", response_model=list[AuditEventResponse])
def list_audit_events_endpoint(
    limit: int = 100,
    username: str | None = Query(None),
    action: str | None = Query(None),
    resource: str | None = Query(None),
    ip_address: str | None = Query(None),
    from_date: str | None = Query(None, alias="from"),
    to_date: str | None = Query(None, alias="to"),
    has_snapshot: bool | None = Query(None),
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
    from_date: str | None = Query(None, alias="from"),
    to_date: str | None = Query(None, alias="to"),
    username: str | None = Query(None),
    action: str | None = Query(None),
    resource: str | None = Query(None),
    ip_address: str | None = Query(None),
    has_snapshot: bool | None = Query(None),
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
