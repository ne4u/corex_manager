from sqlalchemy.orm import Session

from ..models.routing import RateLimit
from ..schemas.rate_limits import RateLimitCreate, RateLimitUpdate


def list_rate_limits(db: Session):
    return db.query(RateLimit).order_by(RateLimit.priority, RateLimit.id).all()


def get_rate_limit(db: Session, rid: int):
    return db.query(RateLimit).filter(RateLimit.id == rid).first()


def create_rate_limit(db: Session, r_in: RateLimitCreate):
    last = db.query(RateLimit).order_by(RateLimit.priority.desc(), RateLimit.id.desc()).first()
    priority = (last.priority + 1) if last else 0
    obj = RateLimit(**r_in.model_dump(), priority=priority)
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


def reorder_rate_limits(db: Session, ordered_ids: list[int]) -> None:
    """Reassign priorities based on the given ordered list of rate limit IDs."""
    for priority, rid in enumerate(ordered_ids):
        rl = db.get(RateLimit, rid)
        if rl:
            rl.priority = priority
    db.commit()
