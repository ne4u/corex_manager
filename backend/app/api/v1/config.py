from typing import List
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_write, rate_limit

_logger = logging.getLogger(__name__)

from ...schemas.config import (
    ConfigApplyRequest,
    ConfigApplyResponse,
    ConfigRevertRequest,
    ConfigRevertResponse,
    ConfigSnapshotResponse,
    ConfigSnapshotRollbackResponse,
)
from ...schemas.settings import SettingCreate, SettingResponse
from ...services.config import (
    apply_config,
    get_config_diff,
    get_config_status,
    get_max_snapshots_row,
    list_config_snapshots,
    preview_all_configs,
    preview_config,
    revert_config,
    rollback_config_snapshot,
    set_max_snapshots,
)

router = APIRouter()


def _wrap_runtime(fn):
    try:
        return fn()
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        _logger.exception("Unhandled exception in config endpoint: %s", e)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


@router.post("/config/apply", response_model=ConfigApplyResponse)
def apply_config_endpoint(
    s: ConfigApplyRequest = ConfigApplyRequest(),
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return _wrap_runtime(lambda: apply_config(db, user.username, s.comment))


@router.post("/config/revert", response_model=ConfigRevertResponse)
def revert_config_endpoint(
    s: ConfigRevertRequest,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return _wrap_runtime(lambda: revert_config(db, user.username, s.confirm))


@router.get("/config/snapshots", response_model=List[ConfigSnapshotResponse])
def list_config_snapshots_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_config_snapshots(db)


@router.get("/config/snapshots/max", response_model=SettingResponse)
def get_max_snapshots_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return get_max_snapshots_row(db)


@router.put("/config/snapshots/max", response_model=SettingResponse)
def set_max_snapshots_endpoint(
    s_in: SettingCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return _wrap_runtime(lambda: set_max_snapshots(db, s_in.value))


@router.post("/config/snapshots/{snapshot_id}/rollback", response_model=ConfigSnapshotRollbackResponse)
def rollback_config_snapshot_endpoint(
    snapshot_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return _wrap_runtime(lambda: rollback_config_snapshot(db, snapshot_id, user.username))


@router.get("/config/preview")
def preview_config_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return {"config": preview_config(db)}


@router.get("/config/preview-all")
def preview_all_configs_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return preview_all_configs(db)


@router.get("/config/status")
def config_status_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return {"unapplied": get_config_status(db)}


@router.get("/config/diff")
def config_diff_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return get_config_diff(db)
