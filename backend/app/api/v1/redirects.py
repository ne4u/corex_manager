from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...schemas.redirects import (
    RedirectCreate,
    RedirectResponse,
    RedirectUpdate,
    RewriteCreate,
    RewriteResponse,
    RewriteUpdate,
)
from ...services.redirects import (
    create_redirect,
    create_rewrite,
    delete_redirect,
    delete_rewrite,
    get_redirect,
    get_rewrite,
    list_redirects,
    list_rewrites,
    update_redirect,
    update_rewrite,
)

router = APIRouter()


@router.get("/redirects", response_model=List[RedirectResponse])
def list_redirects_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_redirects(db)


@router.post("/redirects", response_model=RedirectResponse)
def create_redirect_endpoint(
    r_in: RedirectCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = create_redirect(db, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Custom error page not found")
    return obj


@router.put("/redirects/{rid}", response_model=RedirectResponse)
def update_redirect_endpoint(
    rid: int,
    r_in: RedirectUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_redirect(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Redirect or custom error page not found")
    return obj


@router.delete("/redirects/{rid}")
def delete_redirect_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_redirect(db, rid):
        raise HTTPException(status_code=404, detail="Redirect not found")
    return {"status": "ok"}


@router.get("/rewrites", response_model=List[RewriteResponse])
def list_rewrites_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_rewrites(db)


@router.post("/rewrites", response_model=RewriteResponse)
def create_rewrite_endpoint(
    r_in: RewriteCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_rewrite(db, r_in)


@router.put("/rewrites/{rid}", response_model=RewriteResponse)
def update_rewrite_endpoint(
    rid: int,
    r_in: RewriteUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_rewrite(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Rewrite not found")
    return obj


@router.delete("/rewrites/{rid}")
def delete_rewrite_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_rewrite(db, rid):
        raise HTTPException(status_code=404, detail="Rewrite not found")
    return {"status": "ok"}
