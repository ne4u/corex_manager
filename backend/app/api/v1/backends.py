from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_write, rate_limit
from ...schemas.backends import (
    BackendCreate,
    BackendResponse,
    BackendRuleCreate,
    BackendRuleResponse,
    BackendRuleUpdate,
    BackendUpdate,
    ServerCreate,
    ServerResponse,
    ServerUpdate,
)
from ...services.backends import (
    add_server,
    create_backend,
    create_backend_rule,
    delete_backend,
    delete_backend_rule,
    delete_server,
    get_backend,
    get_backend_rule,
    get_server,
    list_backend_rules,
    list_backends,
    update_backend,
    update_backend_rule,
    update_server,
)

router = APIRouter()


@router.get("/backends", response_model=List[BackendResponse])
def list_backends_endpoint(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_backends(db)


@router.post("/backends", response_model=BackendResponse)
def create_backend_endpoint(
    b: BackendCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    try:
        return create_backend(db, b)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/backends/{bid}", response_model=BackendResponse)
def get_backend_endpoint(
    bid: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    b = get_backend(db, bid)
    if not b:
        raise HTTPException(status_code=404, detail="Backend not found")
    return b


@router.put("/backends/{bid}", response_model=BackendResponse)
def update_backend_endpoint(
    bid: int,
    b_in: BackendUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    try:
        b = update_backend(db, bid, b_in)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not b:
        raise HTTPException(status_code=404, detail="Backend not found")
    return b


@router.delete("/backends/{bid}")
def delete_backend_endpoint(
    bid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_backend(db, bid):
        raise HTTPException(status_code=404, detail="Backend not found")
    return {"status": "ok"}


@router.post("/backends/{bid}/servers", response_model=ServerResponse)
def add_server_endpoint(
    bid: int,
    s: ServerCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    server = add_server(db, bid, s)
    if not server:
        raise HTTPException(status_code=404, detail="Backend not found")
    return server


@router.put("/servers/{sid}", response_model=ServerResponse)
def update_server_endpoint(
    sid: int,
    s_in: ServerUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    s = update_server(db, sid, s_in)
    if not s:
        raise HTTPException(status_code=404, detail="Server not found")
    return s


@router.delete("/servers/{sid}")
def delete_server_endpoint(
    sid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_server(db, sid):
        raise HTTPException(status_code=404, detail="Server not found")
    return {"status": "ok"}


@router.get("/backend-rules", response_model=List[BackendRuleResponse])
def list_backend_rules_endpoint(
    listener_id: Optional[int] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_backend_rules(db, listener_id)


@router.post("/backend-rules", response_model=BackendRuleResponse)
def create_backend_rule_endpoint(
    r: BackendRuleCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_backend_rule(db, r)


@router.get("/backend-rules/{rid}", response_model=BackendRuleResponse)
def get_backend_rule_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    obj = get_backend_rule(db, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="Rule not found")
    return obj


@router.put("/backend-rules/{rid}", response_model=BackendRuleResponse)
def update_backend_rule_endpoint(
    rid: int,
    r_in: BackendRuleUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_backend_rule(db, rid, r_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Rule not found")
    return obj


@router.delete("/backend-rules/{rid}")
def delete_backend_rule_endpoint(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_backend_rule(db, rid):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "ok"}
