from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_write, rate_limit
from ...models.proxy import Listener
from ...schemas.listeners import ListenerCreate, ListenerResponse, ListenerUpdate
from ...services.listeners import (
    create_listener,
    delete_listener,
    get_listener,
    list_listeners,
    update_listener,
)

router = APIRouter()


@router.get("/listeners", response_model=List[ListenerResponse])
def list_listener_endpoints(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_listeners(db)


@router.post("/listeners", response_model=ListenerResponse)
def create_listener_endpoint(
    l_in: ListenerCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_listener(db, l_in)


@router.get("/listeners/{lid}", response_model=ListenerResponse)
def get_listener_endpoint(
    lid: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    obj = get_listener(db, lid)
    if not obj:
        raise HTTPException(status_code=404, detail="Listener not found")
    return obj


@router.put("/listeners/{lid}", response_model=ListenerResponse)
def update_listener_endpoint(
    lid: int,
    l_in: ListenerUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_listener(db, lid, l_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Listener not found")
    return obj


@router.delete("/listeners/{lid}")
def delete_listener_endpoint(
    lid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_listener(db, lid):
        raise HTTPException(status_code=404, detail="Listener not found")
    return {"status": "ok"}
