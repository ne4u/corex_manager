from sqlalchemy.orm import Session
from ..models.proxy import FcgiApp
from ..schemas.fcgi import FcgiAppCreate, FcgiAppUpdate


def list_fcgi_apps(db: Session):
    return db.query(FcgiApp).all()


def get_fcgi_app(db: Session, fid: int):
    return db.query(FcgiApp).filter(FcgiApp.id == fid).first()


def create_fcgi_app(db: Session, f_in: FcgiAppCreate):
    obj = FcgiApp(**f_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_fcgi_app(db: Session, fid: int, f_in: FcgiAppUpdate):
    obj = get_fcgi_app(db, fid)
    if not obj:
        return None
    for k, v in f_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_fcgi_app(db: Session, fid: int):
    obj = get_fcgi_app(db, fid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
