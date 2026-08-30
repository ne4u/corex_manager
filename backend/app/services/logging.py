from sqlalchemy.orm import Session
from ..models.logging import LogDestination, LoggedField
from ..schemas.logging import (
    LogDestinationCreate,
    LogDestinationUpdate,
    LoggedFieldCreate,
    LoggedFieldUpdate,
)


def list_log_destinations(db: Session):
    return db.query(LogDestination).all()


def get_log_destination(db: Session, rid: int):
    return db.query(LogDestination).filter(LogDestination.id == rid).first()


def create_log_destination(db: Session, r_in: LogDestinationCreate):
    obj = LogDestination(**r_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_log_destination(db: Session, rid: int, r_in: LogDestinationUpdate):
    obj = get_log_destination(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_log_destination(db: Session, rid: int):
    obj = get_log_destination(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True


def list_logged_fields(db: Session):
    return db.query(LoggedField).all()


def get_logged_field(db: Session, rid: int):
    return db.query(LoggedField).filter(LoggedField.id == rid).first()


def create_logged_field(db: Session, r_in: LoggedFieldCreate):
    obj = LoggedField(**r_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_logged_field(db: Session, rid: int, r_in: LoggedFieldUpdate):
    obj = get_logged_field(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_logged_field(db: Session, rid: int):
    obj = get_logged_field(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
