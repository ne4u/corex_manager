from sqlalchemy.orm import Session
from ..models.proxy import CipherSuite
from ..schemas.ciphers import CipherSuiteCreate, CipherSuiteUpdate

CIPHER_DEFAULTS = {
    "fips": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256",
    "fedramp": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
    "pci": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384",
    "modern": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305",
}


def list_ciphers(db: Session):
    return db.query(CipherSuite).all()


def get_cipher(db: Session, cid: int):
    return db.query(CipherSuite).filter(CipherSuite.id == cid).first()


def create_cipher(db: Session, c_in: CipherSuiteCreate):
    data = c_in.model_dump()
    if not data.get("ciphers"):
        data["ciphers"] = CIPHER_DEFAULTS.get(data.get("baseline"), "")
    obj = CipherSuite(**data)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_cipher(db: Session, cid: int, c_in: CipherSuiteUpdate):
    obj = get_cipher(db, cid)
    if not obj:
        return None
    data = c_in.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(obj, k, v)
    if not obj.ciphers:
        obj.ciphers = CIPHER_DEFAULTS.get(obj.baseline, "")
    db.commit()
    db.refresh(obj)
    return obj


def delete_cipher(db: Session, cid: int):
    obj = get_cipher(db, cid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
