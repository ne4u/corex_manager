"""Audit event query and export helpers.

Snapshot association is computed dynamically from timestamps rather than
written to the ``snapshot_id`` column at apply time.  The ``last_applied_at``
setting (a single timestamp persisted on every apply) is the source of truth
for pending vs applied.  Individual ``ConfigSnapshot`` records are used
best-effort for grouping events under the apply that bundled them; if a
snapshot record is pruned, its events still show as applied via
``last_applied_at`` and fall into an "Earlier applies" bucket.
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict

from sqlalchemy import or_, func, distinct
from sqlalchemy.orm import Session

from ..models.tasks import ConfigSnapshot
from ..models.models import AuditEvent
from ..schemas.audit import AuditEventResponse, AuditEventFilterOptions


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _get_last_applied_at(db: Session) -> Optional[datetime]:
    """Return the timestamp of the last successful config apply.

    Reads the ``last_applied_at`` setting (set by ``save_config_snapshot``).
    Falls back to the latest ``ConfigSnapshot.created_at`` if the setting
    is missing (e.g. pre-migration databases).  Returns ``None`` if no
    apply has ever happened.
    """
    from .settings import get_setting
    val = get_setting(db, "last_applied_at", "")
    if val:
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except (ValueError, TypeError):
            pass
    # Fallback: use the latest snapshot's created_at
    snap = (
        db.query(ConfigSnapshot)
        .order_by(ConfigSnapshot.created_at.desc())
        .first()
    )
    return snap.created_at if snap else None


def _compute_snapshot_for_events(
    events: List[AuditEvent], db: Session
) -> Dict[int, Optional[ConfigSnapshot]]:
    """Map each event to its applying snapshot (best-effort).

    Returns ``{event_id: ConfigSnapshot or None}``.  The applying snapshot
    is the one with the smallest ``created_at >= event.created_at``.
    Returns ``None`` for events created after all snapshots (pending) or
    when the snapshot record has been pruned.
    """
    if not events:
        return {}
    snapshots = (
        db.query(ConfigSnapshot)
        .order_by(ConfigSnapshot.created_at.asc())
        .all()
    )
    if not snapshots:
        return {e.id: None for e in events}
    result: Dict[int, Optional[ConfigSnapshot]] = {}
    for event in events:
        applying = None
        for snap in snapshots:  # sorted ascending
            if snap.created_at >= event.created_at:
                applying = snap
                break
        result[event.id] = applying
    return result


def _build_audit_event_query(
    db: Session,
    username: Optional[str] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    has_snapshot: Optional[bool] = None,
):
    query = db.query(AuditEvent).order_by(AuditEvent.created_at.desc())
    if username:
        query = query.filter(AuditEvent.username.ilike(f"%{username}%"))
    if action:
        query = query.filter(AuditEvent.action.ilike(f"%{action}%"))
    if resource:
        like = f"%{resource}%"
        query = query.filter(
            or_(AuditEvent.resource_type.ilike(like), AuditEvent.resource_id.ilike(like))
        )
    if ip_address:
        query = query.filter(AuditEvent.ip_address.ilike(f"%{ip_address}%"))
    if start:
        query = query.filter(AuditEvent.created_at >= start)
    if end:
        query = query.filter(AuditEvent.created_at <= end)
    if has_snapshot is True:
        # "Applied": event created at or before the last apply timestamp.
        last_applied = _get_last_applied_at(db)
        if last_applied:
            query = query.filter(AuditEvent.created_at <= last_applied)
        else:
            # No applies ever — nothing is applied.
            query = query.filter(False)
    elif has_snapshot is False:
        # "Pending": event created after the last apply, AND config-affecting.
        # Non-config events (theme, user CRUD, captcha keys, etc.) are excluded
        # — they don't require an apply.
        last_applied = _get_last_applied_at(db)
        if last_applied:
            query = query.filter(
                AuditEvent.created_at > last_applied,
                AuditEvent.config_change.is_(True),
            )
        else:
            # No applies ever — all config-affecting events are pending.
            query = query.filter(AuditEvent.config_change.is_(True))
    return query


def list_audit_events(
    db: Session,
    limit: int = 100,
    username: Optional[str] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    has_snapshot: Optional[bool] = None,
):
    start = _parse_iso(from_date)
    end = _parse_iso(to_date)
    query = _build_audit_event_query(
        db, username, action, resource, ip_address, start, end, has_snapshot
    )
    events = query.limit(limit).all()

    # Compute snapshot association dynamically from timestamps.
    snap_map = _compute_snapshot_for_events(events, db)
    snap_ids = {s.id for s in snap_map.values() if s}
    snaps = (
        {s.id: s for s in db.query(ConfigSnapshot).filter(ConfigSnapshot.id.in_(snap_ids)).all()}
        if snap_ids else {}
    )
    last_applied = _get_last_applied_at(db)

    result = []
    for e in events:
        resp = AuditEventResponse.model_validate(e)
        # Determine applied status from last_applied_at timestamp.
        is_applied = bool(last_applied and e.created_at <= last_applied)
        if is_applied:
            applying = snap_map.get(e.id)
            if applying:
                resp.snapshot_id = applying.id
                resp.snapshot_comment = applying.comment
                resp.snapshot_created_at = applying.created_at
            else:
                # Applied but the snapshot record was pruned.  Keep
                # snapshot_id null but set snapshot_created_at so the
                # frontend can group into "Earlier applies".
                resp.snapshot_id = None
                resp.snapshot_comment = None
                resp.snapshot_created_at = last_applied
        else:
            resp.snapshot_id = None
            resp.snapshot_comment = None
            resp.snapshot_created_at = None
        result.append(resp)
    return result


def export_audit_events_csv(
    db: Session,
    username: Optional[str] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    has_snapshot: Optional[bool] = None,
) -> str:
    start = _parse_iso(from_date)
    end = _parse_iso(to_date)
    query = _build_audit_event_query(
        db, username, action, resource, ip_address, start, end, has_snapshot
    )

    # Pre-fetch snapshots (small list) and last_applied_at for dynamic lookup.
    snapshots = (
        db.query(ConfigSnapshot)
        .order_by(ConfigSnapshot.created_at.asc())
        .all()
    )
    last_applied = _get_last_applied_at(db)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "created_at",
            "user_id",
            "username",
            "action",
            "method",
            "path",
            "resource_type",
            "resource_id",
            "status_code",
            "ip_address",
            "payload",
            "snapshot_id",
            "config_change",
        ]
    )
    for event in query.yield_per(1000):
        # Compute applying snapshot from timestamps.
        applying = None
        if last_applied and event.created_at <= last_applied:
            for snap in snapshots:  # sorted ascending
                if snap.created_at >= event.created_at:
                    applying = snap
                    break
        writer.writerow(
            [
                event.id,
                event.created_at.isoformat() if event.created_at else "",
                event.user_id or "",
                event.username or "",
                event.action,
                event.method,
                event.path,
                event.resource_type or "",
                event.resource_id or "",
                event.status_code or "",
                event.ip_address or "",
                json.dumps(event.payload) if event.payload else "",
                applying.id if applying else "",
                "true" if event.config_change else "false",
            ]
        )
    return output.getvalue()


def get_audit_event_filter_options(db: Session) -> AuditEventFilterOptions:
    """Return distinct values for audit event filter dropdowns."""
    usernames = [
        r[0] for r in
        db.query(distinct(AuditEvent.username))
        .filter(AuditEvent.username.isnot(None))
        .order_by(AuditEvent.username)
        .all()
    ]
    actions = [
        r[0] for r in
        db.query(distinct(AuditEvent.action))
        .order_by(AuditEvent.action)
        .all()
    ]
    resource_types = [
        r[0] for r in
        db.query(distinct(AuditEvent.resource_type))
        .filter(AuditEvent.resource_type.isnot(None))
        .order_by(AuditEvent.resource_type)
        .all()
    ]
    ip_addresses = [
        r[0] for r in
        db.query(distinct(AuditEvent.ip_address))
        .filter(AuditEvent.ip_address.isnot(None))
        .order_by(AuditEvent.ip_address)
        .all()
    ]
    return AuditEventFilterOptions(
        usernames=usernames,
        actions=actions,
        resource_types=resource_types,
        ip_addresses=ip_addresses,
    )
