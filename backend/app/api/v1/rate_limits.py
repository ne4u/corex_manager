from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...schemas.rate_limits import RateLimitCreate, RateLimitResponse, RateLimitUpdate
from ...services.rate_limits import (
    create_rate_limit,
    delete_rate_limit,
    get_rate_limit,
    list_rate_limits,
    update_rate_limit,
)

router = APIRouter()


@router.get("/rate-limits", response_model=List[RateLimitResponse])
def list_rate_limits_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_rate_limits(db)


@router.post("/rate-limits", response_model=RateLimitResponse)
def create_rate_limit_endpoint(
    r_in: RateLimitCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_rate_limit(db, r_in)


@router.put("/rate-limits/{rid}", response_model=RateLimitResponse)
def update_rate_limit_endpoint(
    rid: int,
    r_in: RateLimitUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_rate_limit(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Rate limit not found")
    return obj


@router.delete("/rate-limits/{rid}")
def delete_rate_limit_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_rate_limit(db, rid):
        raise HTTPException(status_code=404, detail="Rate limit not found")
    return {"status": "ok"}
