from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...schemas.error_pages import (
    CustomErrorPageCreate,
    CustomErrorPagePreview,
    CustomErrorPageResponse,
    CustomErrorPageUpdate,
)
from ...services.error_pages import (
    create_error_page,
    delete_error_page,
    get_error_page,
    list_error_pages,
    preview_error_page,
    update_error_page,
)

router = APIRouter()


@router.get("/error-pages", response_model=List[CustomErrorPageResponse])
def list_error_pages_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_error_pages(db)


@router.post("/error-pages", response_model=CustomErrorPageResponse)
def create_error_page_endpoint(
    r_in: CustomErrorPageCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_error_page(db, r_in)


@router.put("/error-pages/{rid}", response_model=CustomErrorPageResponse)
def update_error_page_endpoint(
    rid: int,
    r_in: CustomErrorPageUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_error_page(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Custom response page not found")
    return obj


@router.delete("/error-pages/{rid}")
def delete_error_page_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_error_page(db, rid):
        raise HTTPException(status_code=404, detail="Custom response page not found")
    return {"status": "ok"}


@router.get("/error-pages/{rid}/preview", response_model=CustomErrorPagePreview)
def preview_error_page_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    result = preview_error_page(db, rid)
    if not result:
        raise HTTPException(status_code=404, detail="Custom response page not found")
    rendered, content_type = result
    return CustomErrorPagePreview(content=rendered, content_type=content_type)
