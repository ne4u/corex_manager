from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...schemas.ciphers import CipherSuiteCreate, CipherSuiteResponse, CipherSuiteUpdate
from ...services.ciphers import (
    create_cipher,
    delete_cipher,
    list_ciphers,
    update_cipher,
)
from ..deps import get_current_user, get_db, rate_limit, require_write

router = APIRouter()


@router.get("/ciphers", response_model=list[CipherSuiteResponse])
def list_cipher_suites(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return list_ciphers(db)


@router.post("/ciphers", response_model=CipherSuiteResponse)
def create_cipher_suite(
    c_in: CipherSuiteCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    return create_cipher(db, c_in)


@router.put("/ciphers/{cid}", response_model=CipherSuiteResponse)
def update_cipher_suite(
    cid: int,
    c_in: CipherSuiteUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = update_cipher(db, cid, c_in)
    if not obj:
        raise HTTPException(status_code=404, detail="Cipher suite not found")
    return obj


@router.delete("/ciphers/{cid}")
def delete_cipher_suite(
    cid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if not delete_cipher(db, cid):
        raise HTTPException(status_code=404, detail="Cipher suite not found")
    return {"status": "ok"}
