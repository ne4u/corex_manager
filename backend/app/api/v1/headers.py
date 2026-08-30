from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...schemas.headers import (
    RequestHeaderCreate,
    RequestHeaderResponse,
    RequestHeaderUpdate,
    ResponseHeaderCreate,
    ResponseHeaderResponse,
    ResponseHeaderUpdate,
)
from ...services.headers import (
    create_request_header,
    create_response_header,
    delete_request_header,
    delete_response_header,
    get_request_header,
    get_response_header,
    list_request_headers,
    list_response_headers,
    update_request_header,
    update_response_header,
)

router = APIRouter()


@router.get("/response-headers", response_model=List[ResponseHeaderResponse])
def list_response_headers_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_response_headers(db)


@router.post("/response-headers", response_model=ResponseHeaderResponse)
def create_response_header_endpoint(
    r_in: ResponseHeaderCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_response_header(db, r_in)


@router.put("/response-headers/{rid}", response_model=ResponseHeaderResponse)
def update_response_header_endpoint(
    rid: int,
    r_in: ResponseHeaderUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_response_header(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Header not found")
    return obj


@router.delete("/response-headers/{rid}")
def delete_response_header_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_response_header(db, rid):
        raise HTTPException(status_code=404, detail="Header not found")
    return {"status": "ok"}


@router.get("/request-headers", response_model=List[RequestHeaderResponse])
def list_request_headers_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_request_headers(db)


@router.post("/request-headers", response_model=RequestHeaderResponse)
def create_request_header_endpoint(
    r_in: RequestHeaderCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_request_header(db, r_in)


@router.put("/request-headers/{rid}", response_model=RequestHeaderResponse)
def update_request_header_endpoint(
    rid: int,
    r_in: RequestHeaderUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_request_header(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Header not found")
    return obj


@router.delete("/request-headers/{rid}")
def delete_request_header_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_request_header(db, rid):
        raise HTTPException(status_code=404, detail="Header not found")
    return {"status": "ok"}
