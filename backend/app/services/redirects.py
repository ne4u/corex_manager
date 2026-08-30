from sqlalchemy.orm import Session
from ..models.logging import CustomErrorPage
from ..models.routing import Redirect, Rewrite
from ..schemas.redirects import RedirectCreate, RedirectUpdate, RewriteCreate, RewriteUpdate


def _validate_error_page_id(db: Session, error_page_id: int | None):
    if not error_page_id:
        return True
    return db.get(CustomErrorPage, error_page_id) is not None


def list_redirects(db: Session):
    return db.query(Redirect).order_by(Redirect.priority).all()


def get_redirect(db: Session, rid: int):
    return db.query(Redirect).filter(Redirect.id == rid).first()


def create_redirect(db: Session, r_in: RedirectCreate):
    if r_in.error_page_id and not _validate_error_page_id(db, r_in.error_page_id):
        return None
    obj = Redirect(**r_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_redirect(db: Session, rid: int, r_in: RedirectUpdate):
    obj = get_redirect(db, rid)
    if not obj:
        return None
    data = r_in.model_dump(exclude_unset=True)
    if data.get("error_page_id") and not _validate_error_page_id(db, data["error_page_id"]):
        return None
    for k, v in data.items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_redirect(db: Session, rid: int):
    obj = get_redirect(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True


def list_rewrites(db: Session):
    return db.query(Rewrite).order_by(Rewrite.priority).all()


def get_rewrite(db: Session, rid: int):
    return db.query(Rewrite).filter(Rewrite.id == rid).first()


def create_rewrite(db: Session, r_in: RewriteCreate):
    obj = Rewrite(**r_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_rewrite(db: Session, rid: int, r_in: RewriteUpdate):
    obj = get_rewrite(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_rewrite(db: Session, rid: int):
    obj = get_rewrite(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
