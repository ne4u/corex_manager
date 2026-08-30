from sqlalchemy.orm import Session
from ..models.logging import CustomErrorPage
from ..schemas.error_pages import (
    CustomErrorPageCreate,
    CustomErrorPageUpdate,
)
from ..services.haproxy import render_error_page_preview


def list_error_pages(db: Session):
    return db.query(CustomErrorPage).all()


def get_error_page(db: Session, rid: int):
    return db.query(CustomErrorPage).filter(CustomErrorPage.id == rid).first()


def create_error_page(db: Session, r_in: CustomErrorPageCreate):
    obj = CustomErrorPage(**r_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_error_page(db: Session, rid: int, r_in: CustomErrorPageUpdate):
    obj = get_error_page(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_error_page(db: Session, rid: int):
    obj = get_error_page(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True


def preview_error_page(db: Session, rid: int):
    obj = get_error_page(db, rid)
    if not obj:
        return None
    rendered = render_error_page_preview(obj.content)
    return rendered, obj.content_type or "text/html"
