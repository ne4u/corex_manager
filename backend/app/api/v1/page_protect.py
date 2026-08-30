"""Endpoint router."""
import csv
import io
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_admin, require_write, rate_limit
from ...core.config import get_settings
from ...models.models import *
from ...schemas.page_protect import *
from ...services.page_protect import *
from ...services.tasks import queue_task

settings = get_settings()
router = APIRouter()


# Page Protect (Cloudflare Page Shield-style client-side security)
# ---------------------------------------------------------------------------

@router.get("/page-protect/settings", response_model=PageProtectSettings)
def get_page_protect_settings_route(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    from ...services.page_protect import get_page_protect_settings
    return PageProtectSettings(**get_page_protect_settings(db))


@router.put("/page-protect/settings", response_model=PageProtectSettings)
def update_page_protect_settings_route(
    s_in: PageProtectSettings,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    from ...services.page_protect import update_page_protect_settings
    from ...services.settings import get_setting
    # Gate beacon injection behind Response Transformations — the beacon is
    # injected via the resp_transform filter, so it cannot work without it.
    if s_in.beacon_injection_enabled:
        rt_enabled = get_setting(db, "resp_transform_enabled", str(settings.RESP_TRANSFORM_ENABLED))
        if not rt_enabled or rt_enabled.lower() not in ("true", "1", "yes"):
            raise HTTPException(
                status_code=403,
                detail="Inventory Beacon requires Response Transformations to be enabled in Global Options.",
            )
    result = update_page_protect_settings(db, s_in.model_dump())
    return PageProtectSettings(**result)


@router.get("/page-protect/policies", response_model=List[PageProtectPolicyResponse])
def list_page_protect_policies(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    return db.query(PageProtectPolicy).order_by(PageProtectPolicy.id).all()


@router.post("/page-protect/policies", response_model=PageProtectPolicyResponse)
def create_page_protect_policy(p: PageProtectPolicyCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    existing = db.query(PageProtectPolicy).filter(PageProtectPolicy.name == p.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="A policy with this name already exists")
    obj = PageProtectPolicy(**p.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/page-protect/policies/{pid}", response_model=PageProtectPolicyResponse)
def update_page_protect_policy(pid: int, p_in: PageProtectPolicyUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(PageProtectPolicy, pid)
    if not obj:
        raise HTTPException(status_code=404, detail="Policy not found")
    for k, v in p_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/page-protect/policies/{pid}")
def delete_page_protect_policy(pid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(PageProtectPolicy, pid)
    if not obj:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.get("/page-protect/reports", response_model=List[CspReportResponse])
def list_csp_reports(
    policy_id: Optional[int] = Query(None),
    from_: Optional[datetime] = Query(None, alias="from"),
    to: Optional[datetime] = Query(None),
    backend: Optional[str] = Query(None),
    violated_directive: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    q = db.query(CspReport)
    if policy_id is not None:
        q = q.filter(CspReport.policy_id == policy_id)
    if from_:
        q = q.filter(CspReport.captured_at >= from_)
    if to:
        q = q.filter(CspReport.captured_at <= to)
    if backend:
        q = q.filter(CspReport.backend_name == backend)
    if violated_directive:
        q = q.filter(CspReport.violated_directive == violated_directive)
    return q.order_by(CspReport.captured_at.desc()).limit(limit).all()


@router.get("/page-protect/reports/export")
def export_csp_reports(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    reports = db.query(CspReport).order_by(CspReport.captured_at.desc()).limit(10000).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "captured_at", "client_ip", "document_uri", "violated_directive", "blocked_uri", "backend_name", "listener_name", "report_type"])
    for r in reports:
        writer.writerow([r.id, r.captured_at, r.client_ip, r.document_uri, r.violated_directive, r.blocked_uri, r.backend_name, r.listener_name, r.report_type])
    output.seek(0)
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=csp_reports.csv"})


@router.delete("/page-protect/reports")
def clear_csp_reports(
    policy_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    q = db.query(CspReport)
    if policy_id is not None:
        q = q.filter(CspReport.policy_id == policy_id)
    count = q.delete()
    db.commit()
    return {"status": "ok", "deleted": count}


@router.get("/page-protect/scripts", response_model=List[PageProtectScriptResponse])
def list_page_protect_scripts(
    resource_type: Optional[str] = Query(None),
    hash_changed: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    q = db.query(PageProtectScript)
    if resource_type:
        q = q.filter(PageProtectScript.resource_type == resource_type)
    if hash_changed is not None:
        q = q.filter(PageProtectScript.hash_changed == hash_changed)
    return q.order_by(PageProtectScript.last_seen.desc()).all()


@router.post("/page-protect/scripts", response_model=PageProtectScriptResponse, status_code=201)
def create_page_protect_script(
    s_in: PageProtectScriptCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Manually add a URL to the script/resource inventory for hash monitoring.

    Useful when CSP is in enforce mode (no violation reports generated) or to
    proactively monitor a critical asset before it appears in traffic.
    """
    url = (s_in.url or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    existing = db.query(PageProtectScript).filter(PageProtectScript.url == url).first()
    if existing:
        raise HTTPException(status_code=409, detail="A script with this URL already exists")
    # Extract domain from URL
    domain = None
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname
    except Exception:
        pass
    obj = PageProtectScript(
        url=url,
        resource_type=s_in.resource_type or "script",
        domain=domain,
        notes=s_in.notes,
        source="manual",
        occurrence_count=0,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/page-protect/scripts/{sid}", response_model=PageProtectScriptResponse)
def update_page_protect_script(sid: int, s_in: PageProtectScriptUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(PageProtectScript, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Script not found")
    for k, v in s_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/page-protect/scripts/{sid}")
def delete_page_protect_script(sid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    obj = db.get(PageProtectScript, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Script not found")
    db.delete(obj)
    db.commit()
    return {"status": "ok"}


@router.post("/page-protect/scripts/{sid}/check", response_model=PageProtectScriptResponse)
def check_page_protect_script(sid: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    from ...services.page_protect_hasher import check_script
    obj = db.get(PageProtectScript, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Script not found")
    result = check_script(db, obj)
    if result is None:
        raise HTTPException(status_code=502, detail="Failed to fetch or hash the script URL")
    db.commit()
    db.refresh(obj)
    return obj


@router.post("/page-protect/scripts/{sid}/reset-hash", response_model=PageProtectScriptResponse)
def reset_page_protect_script_hash(
    sid: int,
    recheck: bool = Query(True),
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Reset an asset's hash baseline so the next check starts fresh.

    Useful when a known event (planned deployment, CDN cache purge) changes an
    asset's content — the user resets the hash so the change isn't flagged as a
    supply-chain alert. When ``recheck=True`` (default), an immediate check is
    performed to establish the new baseline right away.
    """
    from ...services.page_protect_hasher import check_script, reset_script_hash
    obj = db.get(PageProtectScript, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Script not found")
    reset_script_hash(db, obj)
    if recheck:
        check_script(db, obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.post("/page-protect/scripts/check-all")
def check_all_page_protect_scripts(db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    from ...services.page_protect_hasher import check_all_scripts
    checked = check_all_scripts(db, force=True)
    return {"status": "ok", "checked": checked}


@router.get("/page-protect/stats", response_model=PageProtectStats)
def get_page_protect_stats(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    from ...services.page_protect import get_stats
    return PageProtectStats(**get_stats(db))


@router.post("/page-protect/sample", response_model=PageProtectSampleResponse)
def sample_page_protect_reports(user=Depends(require_write), _=Depends(rate_limit)):
    """Manually trigger one cycle of CSP report collection from HAProxy logs."""
    from ...services.page_protect_sampler import sample_csp_reports
    stored = sample_csp_reports(force_recent=True)
    return PageProtectSampleResponse(stored=stored)


# ----- Baseline collection window -----

@router.get("/page-protect/baseline", response_model=PageProtectBaselineStatus)
def get_page_protect_baseline(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    """Return the current baseline collection window state."""
    from ...services.page_protect import get_baseline
    return PageProtectBaselineStatus(**get_baseline(db))


@router.post("/page-protect/baseline/start", response_model=PageProtectBaselineStatus)
def start_page_protect_baseline(
    req: PageProtectBaselineStartRequest,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Start a new baseline collection window."""
    from ...services.page_protect import start_baseline
    return PageProtectBaselineStatus(**start_baseline(db, note=req.note))


@router.post("/page-protect/baseline/stop", response_model=PageProtectBaselineStatus)
def stop_page_protect_baseline(db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Stop the current baseline collection window."""
    from ...services.page_protect import stop_baseline
    result = stop_baseline(db)
    if result.get("status") == "idle" and result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return PageProtectBaselineStatus(**result)


@router.delete("/page-protect/baseline", response_model=PageProtectBaselineStatus)
def clear_page_protect_baseline(db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Clear the baseline collection window."""
    from ...services.page_protect import clear_baseline
    return PageProtectBaselineStatus(**clear_baseline(db))


# ----- Policy recommender -----

@router.get("/page-protect/recommend", response_model=PageProtectRecommendResponse)
def get_page_protect_recommendation(
    backend_ids: Optional[str] = Query(None, description="Comma-separated backend IDs to filter"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Recommend a CSP policy based on observed scripts and violation reports."""
    from ...services.page_protect import recommend_policy
    ids: Optional[List[int]] = None
    if backend_ids:
        try:
            ids = [int(x.strip()) for x in backend_ids.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="backend_ids must be comma-separated integers")
    result = recommend_policy(db, backend_ids=ids)
    return PageProtectRecommendResponse(**result)


# ---------------------------------------------------------------------------
