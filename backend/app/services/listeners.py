from fastapi import HTTPException
from sqlalchemy.orm import Session
from ..models.proxy import Listener
from ..schemas.listeners import ListenerCreate, ListenerUpdate


def list_listeners(db: Session):
    return db.query(Listener).all()


def get_listener(db: Session, lid: int):
    return db.query(Listener).filter(Listener.id == lid).first()


def create_listener(db: Session, l_in: ListenerCreate):
    obj = Listener(**l_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_listener(db: Session, lid: int, l_in: ListenerUpdate):
    obj = get_listener(db, lid)
    if not obj:
        return None
    for k, v in l_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_listener(db: Session, lid: int):
    obj = get_listener(db, lid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
