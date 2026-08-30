from sqlalchemy.orm import Session
from ..models.routing import RateLimit
from ..schemas.rate_limits import RateLimitCreate, RateLimitUpdate


def list_rate_limits(db: Session):
    return db.query(RateLimit).all()


def get_rate_limit(db: Session, rid: int):
    return db.query(RateLimit).filter(RateLimit.id == rid).first()


def create_rate_limit(db: Session, r_in: RateLimitCreate):
    obj = RateLimit(**r_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_rate_limit(db: Session, rid: int, r_in: RateLimitUpdate):
    obj = get_rate_limit(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_rate_limit(db: Session, rid: int):
    obj = get_rate_limit(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
