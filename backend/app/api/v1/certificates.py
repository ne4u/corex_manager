from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_write, rate_limit
from ...models.models import Certificate, Task
from ...schemas.certificates import (
    AcmeCaResponse,
    CertificateCreate,
    CertificateResponse,
    CertificateUpdate,
    DnsProviderResponse,
)
from ...services.acme_cas import list_acme_cas
from ...services.certificates import (
    _clean_acme_output,
    delete_cert_files,
    generate_certificate,
    upload_custom_certificate,
)
from ...services.dns_providers import get_active_acme_client, list_dns_providers
from ...services.tasks import cancel_task, queue_task

router = APIRouter()


@router.get("/certificates/dns-providers", response_model=DnsProviderResponse)
def list_dns_providers_route(
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    client = get_active_acme_client()
    providers = list_dns_providers()
    return DnsProviderResponse(client=client, providers=providers)


@router.get("/certificates/acme-cas", response_model=AcmeCaResponse)
def list_acme_cas_route(
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return AcmeCaResponse(cas=list_acme_cas())


@router.get("/certificates", response_model=List[CertificateResponse])
def list_certs(
    kind: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    q = db.query(Certificate)
    if kind:
        q = q.filter(Certificate.kind == kind)
    return q.all()


@router.get("/certificates/issue-status")
def get_cert_issue_status(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    import os as _os

    existing_certs = {c.id: c for c in db.query(Certificate).all()}
    tasks = db.query(Task).filter(Task.task_type == "issue_certificate").order_by(Task.created_at.desc()).all()
    by_cert: Dict[int, Dict[str, Any]] = {}
    reconciled = False
    for t in tasks:
        cert_id = (t.payload or {}).get("cert_id")
        if cert_id is None or cert_id in by_cert or cert_id not in existing_certs:
            continue
        if t.status in ("failed", "running", "pending"):
            cert = existing_certs[cert_id]
            if cert.cert_path and _os.path.exists(cert.cert_path):
                t.status = "success"
                t.result = {
                    "status": "ok",
                    "message": "Certificate was issued successfully "
                    "(task status reconciled — the process restarted before "
                    "the task record was updated).",
                }
                t.error = None
                reconciled = True
        result = t.result or {}
        by_cert[cert_id] = {
            "task_id": t.id,
            "status": t.status,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
            "message": _clean_acme_output(result.get("message")) if result.get("message") else None,
            "error": _clean_acme_output(t.error) if t.error else None,
        }
    if reconciled:
        db.commit()
    return {"statuses": by_cert}


@router.post("/certificates", response_model=CertificateResponse)
def create_cert(
    cert_in: CertificateCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    cert = Certificate(**cert_in.model_dump(exclude={"fullchain", "key", "chain"}))
    if cert.provider == "custom" and not cert.domain:
        cert.domain = cert.name
    db.add(cert)
    db.flush()
    db.refresh(cert)
    if cert.provider == "custom":
        if cert.kind == "ca":
            if not cert_in.fullchain and not cert_in.chain:
                db.rollback()
                raise HTTPException(status_code=400, detail="Custom CA certificate requires a certificate chain")
        elif not cert_in.fullchain or not cert_in.key:
            db.rollback()
            raise HTTPException(status_code=400, detail="Custom certificate requires fullchain and private key")
        res = upload_custom_certificate(cert, cert_in.key or "", cert_in.chain or "", cert_in.fullchain or "", db)
        if res.get("status") != "ok":
            db.rollback()
            raise HTTPException(status_code=400, detail=res.get("message"))
    elif cert.provider == "letsencrypt":
        generate_certificate(cert, db, issue=False)
        db.commit()
    return cert


@router.post("/certificates/{cert_id}/issue")
def issue_cert(
    cert_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    task_id = queue_task("issue_certificate", {"cert_id": cert_id})
    return {"status": "ok", "message": "Queued for background processing", "task_id": task_id}


@router.post("/certificates/{cert_id}/upload")
def upload_cert(
    cert_id: int,
    fullchain: str = Form(...),
    key: Optional[str] = Form(""),
    chain: str = Form(""),
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return upload_custom_certificate(cert, key or "", chain, fullchain, db)


@router.post("/certificates/renew")
def renew_all(
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    task_id = queue_task("renew_certificates")
    return {"status": "ok", "message": "Queued for background processing", "task_id": task_id}


@router.put("/certificates/{cert_id}", response_model=CertificateResponse)
def update_cert(
    cert_id: int,
    c_in: CertificateUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    data = c_in.model_dump(exclude_unset=True)
    upload_fields = {"fullchain", "key", "chain"}
    for k, v in data.items():
        if k not in upload_fields:
            setattr(cert, k, v)
    if cert.provider == "custom" and not cert.domain:
        cert.domain = cert.name
    if cert.provider == "custom" and (c_in.fullchain or c_in.chain):
        if cert.kind == "ca" and not (c_in.fullchain or c_in.chain):
            raise HTTPException(status_code=400, detail="Custom CA certificate requires a certificate chain")
        res = upload_custom_certificate(cert, c_in.key or "", c_in.chain or "", c_in.fullchain or "", db)
        if res.get("status") != "ok":
            raise HTTPException(status_code=400, detail=res.get("message"))
    db.commit()
    db.refresh(cert)
    return cert


@router.delete("/certificates/{cert_id}")
def delete_cert(
    cert_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    domain_or_name = cert.domain or cert.name
    cert_tasks = db.query(Task).filter(Task.task_type == "issue_certificate").all()
    for t in cert_tasks:
        if (t.payload or {}).get("cert_id") == cert_id:
            if t.status in ("running", "pending"):
                cancel_task(t.id)
            db.delete(t)
    db.delete(cert)
    db.commit()
    delete_cert_files(domain_or_name)
    return {"status": "ok"}
