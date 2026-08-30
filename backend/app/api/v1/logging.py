from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...schemas.logging import (
    LogDestinationCreate,
    LogDestinationResponse,
    LogDestinationUpdate,
    LoggedFieldCreate,
    LoggedFieldResponse,
    LoggedFieldUpdate,
)
from ...services.logging import (
    create_log_destination,
    create_logged_field,
    delete_log_destination,
    delete_logged_field,
    get_log_destination,
    get_logged_field,
    list_log_destinations,
    list_logged_fields,
    update_log_destination,
    update_logged_field,
)

router = APIRouter()


@router.get("/log-destinations", response_model=List[LogDestinationResponse])
def list_log_destinations_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_log_destinations(db)


@router.post("/log-destinations", response_model=LogDestinationResponse)
def create_log_destination_endpoint(
    r_in: LogDestinationCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_log_destination(db, r_in)


@router.put("/log-destinations/{rid}", response_model=LogDestinationResponse)
def update_log_destination_endpoint(
    rid: int,
    r_in: LogDestinationUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_log_destination(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Log destination not found")
    return obj


@router.delete("/log-destinations/{rid}")
def delete_log_destination_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_log_destination(db, rid):
        raise HTTPException(status_code=404, detail="Log destination not found")
    return {"status": "ok"}


@router.get("/logged-fields", response_model=List[LoggedFieldResponse])
def list_logged_fields_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_logged_fields(db)


@router.post("/logged-fields", response_model=LoggedFieldResponse)
def create_logged_field_endpoint(
    r_in: LoggedFieldCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_logged_field(db, r_in)


@router.put("/logged-fields/{rid}", response_model=LoggedFieldResponse)
def update_logged_field_endpoint(
    rid: int,
    r_in: LoggedFieldUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_logged_field(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Logged field not found")
    return obj


@router.delete("/logged-fields/{rid}")
def delete_logged_field_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_logged_field(db, rid):
        raise HTTPException(status_code=404, detail="Logged field not found")
    return {"status": "ok"}
