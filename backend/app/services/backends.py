from sqlalchemy.orm import Session
from ..models.models import Backend, BackendRule, Server
from ..schemas.backends import (
    BackendBase,
    BackendCreate,
    BackendUpdate,
    BackendRuleCreate,
    BackendRuleUpdate,
    ServerCreate,
    ServerUpdate,
)


def list_backends(db: Session):
    return db.query(Backend).all()


def get_backend(db: Session, bid: int):
    return db.query(Backend).filter(Backend.id == bid).first()


def _validate_backend(backend: dict) -> None:
    """Validate that persistence-related fields are internally consistent."""
    protocol = backend.get("protocol") or "http"
    sticky_sessions = backend.get("sticky_sessions") or False
    stick_table = backend.get("stick_table") or False
    stick_table_type = backend.get("stick_table_type") or "ip"
    cookie_name = backend.get("cookie_name")

    if sticky_sessions:
        if not cookie_name:
            raise ValueError("cookie_name is required when sticky_sessions is enabled")
        if protocol == "tcp":
            raise ValueError("sticky_sessions is only supported for HTTP-based protocols")

    if stick_table and stick_table_type == "cookie":
        if not cookie_name:
            raise ValueError("cookie_name is required when stick_table_type is 'cookie'")
        if protocol == "tcp":
            raise ValueError("stick_table_type 'cookie' is only supported for HTTP-based protocols")


def create_backend(db: Session, b_in: BackendCreate):
    servers = b_in.servers or []
    _validate_backend(b_in.model_dump(exclude={"servers"}))
    backend = Backend(**b_in.model_dump(exclude={"servers"}))
    db.add(backend)
    db.commit()
    db.refresh(backend)
    for s in servers:
        srv = Server(backend_id=backend.id, **s.model_dump())
        db.add(srv)
    db.commit()
    db.refresh(backend)
    return backend


def update_backend(db: Session, bid: int, b_in: BackendUpdate):
    b = get_backend(db, bid)
    if not b:
        return None
    data = b_in.model_dump(exclude_unset=True, exclude={"servers"})
    current = {k: getattr(b, k, None) for k in BackendBase.model_fields.keys()}
    _validate_backend({**current, **data})
    for k, v in data.items():
        setattr(b, k, v)
    db.commit()
    db.refresh(b)
    return b


def delete_backend(db: Session, bid: int):
    b = get_backend(db, bid)
    if not b:
        return False
    db.delete(b)
    db.commit()
    return True


def get_server(db: Session, sid: int):
    return db.query(Server).filter(Server.id == sid).first()


def add_server(db: Session, bid: int, s_in: ServerCreate):
    backend = get_backend(db, bid)
    if not backend:
        return None
    server = Server(backend_id=bid, **s_in.model_dump())
    db.add(server)
    db.commit()
    db.refresh(server)
    return server


def update_server(db: Session, sid: int, s_in: ServerUpdate):
    s = get_server(db, sid)
    if not s:
        return None
    for k, v in s_in.model_dump(exclude_unset=True).items():
        setattr(s, k, v)
    db.commit()
    db.refresh(s)
    return s


def delete_server(db: Session, sid: int):
    s = get_server(db, sid)
    if not s:
        return False
    db.delete(s)
    db.commit()
    return True


def _rule_name(rule: BackendRule) -> str:
    return rule.name or f"{rule.condition_type}_{(rule.condition_name or rule.value or 'rule')}".strip()[:80]


def list_backend_rules(db: Session, listener_id: int = None):
    q = db.query(BackendRule)
    if listener_id:
        q = q.filter(BackendRule.listener_id == listener_id)
    return q.order_by(BackendRule.priority).all()


def get_backend_rule(db: Session, rid: int):
    return db.query(BackendRule).filter(BackendRule.id == rid).first()


def create_backend_rule(db: Session, r_in: BackendRuleCreate):
    obj = BackendRule(**r_in.model_dump())
    obj.name = _rule_name(obj)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_backend_rule(db: Session, rid: int, r_in: BackendRuleUpdate):
    obj = get_backend_rule(db, rid)
    if not obj:
        return None
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    if not obj.name:
        obj.name = _rule_name(obj)
    db.commit()
    db.refresh(obj)
    return obj


def delete_backend_rule(db: Session, rid: int):
    obj = get_backend_rule(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
