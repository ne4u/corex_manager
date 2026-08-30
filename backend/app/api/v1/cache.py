"""Endpoint router."""
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_admin, require_write, rate_limit
from ...core.config import get_settings
from ...models.models import *
from ...schemas.cache import *
from ...services.cache import *
from ...services.settings import get_setting
from ...services.tasks import queue_task

settings = get_settings()
router = APIRouter()


# Caching
# ---------------------------------------------------------------------------

def _disk_cache_globally_enabled(db: Session) -> bool:
    return get_setting(db, "disk_cache_enabled", str(settings.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")


def _rule_count(db: Session, cache_config_id: int) -> int:
    return db.query(CacheRule).filter(CacheRule.cache_config_id == cache_config_id, CacheRule.enabled == True).count()  # noqa: E712


@router.get("/cache/status", response_model=CacheStatusResponse)
def get_cache_status(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    """Return global cache status (whether disk cache is enabled in Global Options)."""
    return CacheStatusResponse(disk_cache_globally_enabled=_disk_cache_globally_enabled(db))


@router.get("/cache/configs", response_model=List[CacheConfigResponse])
def list_cache_configs(db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    """List all cache configurations (with backend name)."""
    configs = db.query(CacheConfig).all()
    result = []
    for cc in configs:
        backend = db.get(Backend, cc.backend_id)
        resp = CacheConfigResponse.model_validate(cc)
        resp.backend_name = backend.name if backend else ""
        resp.rule_count = _rule_count(db, cc.id)
        result.append(resp)
    return result


@router.post("/cache/configs", response_model=CacheConfigResponse, status_code=201)
def create_cache_config(cc_in: CacheConfigCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Create a cache configuration for a backend."""
    backend = db.get(Backend, cc_in.backend_id)
    if not backend:
        raise HTTPException(status_code=404, detail="Backend not found")
    if backend.protocol == "tcp":
        raise HTTPException(status_code=400, detail="Cache is not supported for TCP-mode backends")
    existing = db.query(CacheConfig).filter(CacheConfig.backend_id == cc_in.backend_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Cache config already exists for this backend")
    if cc_in.disk_cache_enabled and not _disk_cache_globally_enabled(db):
        raise HTTPException(status_code=400, detail="Disk cache is not enabled in Global Options")
    cc = CacheConfig(**cc_in.model_dump())
    db.add(cc)
    db.commit()
    db.refresh(cc)
    resp = CacheConfigResponse.model_validate(cc)
    resp.backend_name = backend.name
    resp.rule_count = _rule_count(db, cc.id)
    return resp


@router.get("/cache/configs/{backend_id}", response_model=CacheConfigResponse)
def get_cache_config(backend_id: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    """Get the cache configuration for a specific backend."""
    cc = db.query(CacheConfig).filter(CacheConfig.backend_id == backend_id).first()
    if not cc:
        raise HTTPException(status_code=404, detail="No cache config for this backend")
    backend = db.get(Backend, backend_id)
    resp = CacheConfigResponse.model_validate(cc)
    resp.backend_name = backend.name if backend else ""
    resp.rule_count = _rule_count(db, cc.id)
    return resp


@router.put("/cache/configs/{backend_id}", response_model=CacheConfigResponse)
def update_cache_config(backend_id: int, cc_in: CacheConfigUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Update the cache configuration for a specific backend."""
    cc = db.query(CacheConfig).filter(CacheConfig.backend_id == backend_id).first()
    if not cc:
        raise HTTPException(status_code=404, detail="No cache config for this backend")
    data = cc_in.model_dump(exclude_unset=True)
    # Validate disk cache global toggle if enabling disk cache
    if data.get("disk_cache_enabled") and not _disk_cache_globally_enabled(db):
        raise HTTPException(status_code=400, detail="Disk cache is not enabled in Global Options")
    for k, v in data.items():
        setattr(cc, k, v)
    db.commit()
    db.refresh(cc)
    backend = db.get(Backend, backend_id)
    resp = CacheConfigResponse.model_validate(cc)
    resp.backend_name = backend.name if backend else ""
    resp.rule_count = _rule_count(db, cc.id)
    return resp


def _get_config_or_404(db: Session, backend_id: int) -> CacheConfig:
    cc = db.query(CacheConfig).filter(CacheConfig.backend_id == backend_id).first()
    if not cc:
        raise HTTPException(status_code=404, detail="No cache config for this backend")
    return cc


@router.get("/cache/configs/{backend_id}/rules", response_model=List[CacheRuleResponse])
def list_cache_rules(backend_id: int, db: Session = Depends(get_db), user=Depends(get_current_user), _=Depends(rate_limit)):
    """List a backend's cacheability rules in evaluation order."""
    cc = _get_config_or_404(db, backend_id)
    rules = db.query(CacheRule).filter(CacheRule.cache_config_id == cc.id).order_by(CacheRule.priority, CacheRule.id).all()
    return rules


@router.post("/cache/configs/{backend_id}/rules", response_model=CacheRuleResponse, status_code=201)
def create_cache_rule(backend_id: int, rule_in: CacheRuleCreate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Append a cacheability rule to a backend's cache config."""
    cc = _get_config_or_404(db, backend_id)
    data = rule_in.model_dump()
    # Append to the end unless an explicit priority was supplied.
    if not data.get("priority"):
        highest = db.query(CacheRule).filter(CacheRule.cache_config_id == cc.id).order_by(CacheRule.priority.desc()).first()
        data["priority"] = (highest.priority + 1) if highest else 0
    rule = CacheRule(cache_config_id=cc.id, **data)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/cache/configs/{backend_id}/rules/{rule_id}", response_model=CacheRuleResponse)
def update_cache_rule(backend_id: int, rule_id: int, rule_in: CacheRuleUpdate, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Update a cacheability rule."""
    from ...services.cache_rules import normalize_pattern

    cc = _get_config_or_404(db, backend_id)
    rule = db.query(CacheRule).filter(CacheRule.id == rule_id, CacheRule.cache_config_id == cc.id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Cache rule not found")
    data = rule_in.model_dump(exclude_unset=True)
    # A partial update may change only one of match_type/pattern, in which case
    # the schema validator cannot normalize. Re-normalize against the merged pair.
    if "pattern" in data or "match_type" in data:
        match_type = data.get("match_type", rule.match_type)
        pattern = data.get("pattern", rule.pattern)
        try:
            data["pattern"] = normalize_pattern(match_type, pattern)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for k, v in data.items():
        setattr(rule, k, v)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/cache/configs/{backend_id}/rules/{rule_id}")
def delete_cache_rule(backend_id: int, rule_id: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Delete a cacheability rule."""
    cc = _get_config_or_404(db, backend_id)
    rule = db.query(CacheRule).filter(CacheRule.id == rule_id, CacheRule.cache_config_id == cc.id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Cache rule not found")
    db.delete(rule)
    db.commit()
    return {"detail": "Cache rule deleted"}


@router.post("/cache/configs/{backend_id}/rules/reorder", response_model=List[CacheRuleResponse])
def reorder_cache_rules(backend_id: int, payload: CacheRuleReorder, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Reorder rules. Evaluation is first-match-wins, so order is significant."""
    cc = _get_config_or_404(db, backend_id)
    rules = db.query(CacheRule).filter(CacheRule.cache_config_id == cc.id).all()
    by_id = {r.id: r for r in rules}
    if set(payload.rule_ids) != set(by_id):
        raise HTTPException(status_code=400, detail="rule_ids must list every rule for this backend exactly once")
    for position, rule_id in enumerate(payload.rule_ids):
        by_id[rule_id].priority = position
    db.commit()
    return db.query(CacheRule).filter(CacheRule.cache_config_id == cc.id).order_by(CacheRule.priority, CacheRule.id).all()


@router.delete("/cache/configs/{backend_id}")
def delete_cache_config(backend_id: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Delete the cache configuration for a backend (disables caching)."""
    cc = db.query(CacheConfig).filter(CacheConfig.backend_id == backend_id).first()
    if not cc:
        raise HTTPException(status_code=404, detail="No cache config for this backend")
    db.delete(cc)
    db.commit()
    return {"detail": "Cache config deleted"}


@router.post("/cache/{backend_id}/clear", response_model=CacheClearResponse)
def clear_backend_cache(backend_id: int, db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Clear the cache for a specific backend (memory + disk)."""
    from ...services.cache import clear_backend_cache as _clear
    return CacheClearResponse(**_clear(db, backend_id))


@router.post("/cache/clear-all", response_model=CacheClearResponse)
def clear_all_caches(db: Session = Depends(get_db), user=Depends(require_write), _=Depends(rate_limit)):
    """Clear all caches (memory + disk) for all backends."""
    from ...services.cache import clear_all_caches as _clear_all
    return CacheClearResponse(**_clear_all(db))


@router.get("/cache/metrics", response_model=CacheMetricsResponse)
def get_cache_metrics(
    from_ts: Optional[datetime] = Query(None, alias="from"),
    to_ts: Optional[datetime] = Query(None, alias="to"),
    step: Optional[int] = Query(None),
    backend_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get time-series cache metrics."""
    from ...services.cache_metrics import get_cache_metrics as _get_metrics
    return CacheMetricsResponse(**_get_metrics(db, from_ts=from_ts, to_ts=to_ts, step=step, backend_id=backend_id))
