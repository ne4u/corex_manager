from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...models.proxy import FcgiApp
from ...schemas.fcgi import FcgiAppCreate, FcgiAppResponse, FcgiAppUpdate
from ...services.fcgi import (
    create_fcgi_app,
    delete_fcgi_app,
    get_fcgi_app,
    list_fcgi_apps,
    update_fcgi_app,
)

router = APIRouter()


@router.get("/fcgi-apps", response_model=List[FcgiAppResponse])
def list_fcgi_apps_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_fcgi_apps(db)


@router.post("/fcgi-apps", response_model=FcgiAppResponse)
def create_fcgi_app_endpoint(
    f_in: FcgiAppCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_fcgi_app(db, f_in)


@router.get("/fcgi-apps/{fid}", response_model=FcgiAppResponse)
def get_fcgi_app_endpoint(
    fid: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    obj = get_fcgi_app(db, fid)
    if not obj:
        raise HTTPException(status_code=404, detail="FCGI application not found")
    return obj


@router.put("/fcgi-apps/{fid}", response_model=FcgiAppResponse)
def update_fcgi_app_endpoint(
    fid: int,
    f_in: FcgiAppUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_fcgi_app(db, fid, f_in)
    if not obj:
        raise HTTPException(status_code=404, detail="FCGI application not found")
    return obj


@router.delete("/fcgi-apps/{fid}")
def delete_fcgi_app_endpoint(
    fid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_fcgi_app(db, fid):
        raise HTTPException(status_code=404, detail="FCGI application not found")
    return {"status": "ok"}
