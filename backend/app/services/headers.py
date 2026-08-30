from sqlalchemy.orm import Session
from ..models.routing import RequestHeader, ResponseHeader
from ..schemas.headers import (
    RequestHeaderCreate,
    RequestHeaderUpdate,
    ResponseHeaderCreate,
    ResponseHeaderUpdate,
)


def list_response_headers(db: Session):
    return db.query(ResponseHeader).all()


def get_response_header(db: Session, rid: int):
    return db.query(ResponseHeader).filter(ResponseHeader.id == rid).first()


def create_response_header(db: Session, r_in: ResponseHeaderCreate):
    data = r_in.model_dump()
    if not data.get("name"):
        data["name"] = data["header"]
    obj = ResponseHeader(**data)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_response_header(db: Session, rid: int, r_in: ResponseHeaderUpdate):
    obj = get_response_header(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    if not obj.name or "header" in r_in.model_dump(exclude_unset=True):
        obj.name = obj.header
    db.commit()
    db.refresh(obj)
    return obj


def delete_response_header(db: Session, rid: int):
    obj = get_response_header(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True


def list_request_headers(db: Session):
    return db.query(RequestHeader).all()


def get_request_header(db: Session, rid: int):
    return db.query(RequestHeader).filter(RequestHeader.id == rid).first()


def create_request_header(db: Session, r_in: RequestHeaderCreate):
    data = r_in.model_dump()
    if not data.get("name"):
        data["name"] = data["header"]
    obj = RequestHeader(**data)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_request_header(db: Session, rid: int, r_in: RequestHeaderUpdate):
    obj = get_request_header(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    if not obj.name or "header" in r_in.model_dump(exclude_unset=True):
        obj.name = obj.header
    db.commit()
    db.refresh(obj)
    return obj


def delete_request_header(db: Session, rid: int):
    obj = get_request_header(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
