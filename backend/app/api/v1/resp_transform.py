from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...schemas.resp_transform import (
    ResponseTransformCreate,
    ResponseTransformResponse,
    ResponseTransformUpdate,
    ResponseTransformReorder,
    ResponseTransformValidateRequest,
    ResponseTransformValidateResponse,
)
from ...services.resp_transform import (
    create_response_transform,
    delete_response_transform,
    get_response_transform,
    list_response_transforms,
    update_response_transform,
    reorder_response_transforms,
    validate_response_transform,
)
from ...services.settings import get_setting
from ...core.config import get_settings

router = APIRouter()

_settings = get_settings()


def _require_resp_transform_enabled(db: Session = Depends(get_db)):
    """Dependency that aborts with 403 if the Response Transforms feature is not enabled.

    Mutating endpoints (create/update/delete/reorder) require the feature to be
    enabled in Global Options. Read-only endpoints (list, validate) remain
    accessible so users can review existing rules and test configs before
    enabling the module.
    """
    enabled = get_setting(db, "resp_transform_enabled", str(_settings.RESP_TRANSFORM_ENABLED))
    if not enabled or enabled.lower() not in ("true", "1", "yes"):
        raise HTTPException(
            status_code=403,
            detail="Response Transforms feature is not enabled. Enable it in Global Options.",
        )


@router.get("/resp-transforms", response_model=List[ResponseTransformResponse])
def list_resp_transforms_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_response_transforms(db)


@router.post("/resp-transforms/validate", response_model=ResponseTransformValidateResponse)
def validate_resp_transform_endpoint(
    req: ResponseTransformValidateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    valid, error = validate_response_transform(req)
    return ResponseTransformValidateResponse(valid=valid, error=error)


@router.put("/resp-transforms/reorder")
def reorder_resp_transforms_endpoint(
    req: ResponseTransformReorder,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
    __=Depends(_require_resp_transform_enabled),
):
    reorder_response_transforms(db, req.ordered_ids)
    return {"status": "ok"}


@router.post("/resp-transforms", response_model=ResponseTransformResponse)
def create_resp_transform_endpoint(
    t_in: ResponseTransformCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
    __=Depends(_require_resp_transform_enabled),
):
    return create_response_transform(db, t_in)


@router.put("/resp-transforms/{rid}", response_model=ResponseTransformResponse)
def update_resp_transform_endpoint(
    rid: int,
    t_in: ResponseTransformUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
    __=Depends(_require_resp_transform_enabled),
):
    obj = update_response_transform(db, rid, t_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Response transform not found")
    return obj


@router.delete("/resp-transforms/{rid}")
def delete_resp_transform_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
    __=Depends(_require_resp_transform_enabled),
):
    if not delete_response_transform(db, rid):
        raise HTTPException(status_code=404, detail="Response transform not found")
    return {"status": "ok"}
