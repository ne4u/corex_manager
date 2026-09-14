from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...core.valkey_client import cache_delete, cache_get, cache_set
from ...schemas.ciphers import CipherSuiteCreate, CipherSuiteResponse, CipherSuiteUpdate
from ...services.ciphers import (
    create_cipher,
    delete_cipher,
    list_ciphers,
    update_cipher,
)
from ..deps import get_current_user, get_db, rate_limit, require_write

router = APIRouter()

# Cipher suites are reference data that changes only on explicit create/update/
# delete. Cache the serialized list for 5 minutes and invalidate on any write.
_CIPHERS_CACHE_KEY = "ciphers:list"
_CIPHERS_CACHE_TTL = 300


@router.get("/ciphers", response_model=list[CipherSuiteResponse])
def list_cipher_suites(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    cached = cache_get(_CIPHERS_CACHE_KEY)
    if cached is not None:
        return cached
    rows = list_ciphers(db)
    # Serialize via the response schema (mode="json" so datetimes become ISO
    # strings) so the cached payload round-trips through json.loads cleanly and
    # response_model can re-validate it on the hit path.
    payload = [CipherSuiteResponse.model_validate(c).model_dump(mode="json") for c in rows]
    cache_set(_CIPHERS_CACHE_KEY, payload, ttl=_CIPHERS_CACHE_TTL)
    return payload


@router.post("/ciphers", response_model=CipherSuiteResponse)
def create_cipher_suite(
    c_in: CipherSuiteCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = create_cipher(db, c_in)
    cache_delete(_CIPHERS_CACHE_KEY)
    return obj


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
    cache_delete(_CIPHERS_CACHE_KEY)
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
    cache_delete(_CIPHERS_CACHE_KEY)
    return {"status": "ok"}
