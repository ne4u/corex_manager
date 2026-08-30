from fastapi import HTTPException
from sqlalchemy.orm import Session
from ..core.security import get_password_hash
from ..models.auth import User
from ..schemas.users import UserCreate, UserUpdate


def list_users(db: Session):
    return db.query(User).all()


def get_user(db: Session, uid: int):
    return db.query(User).filter(User.id == uid).first()


def create_user(db: Session, u_in: UserCreate):
    if db.query(User).filter(User.username == u_in.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    obj = User(
        username=u_in.username,
        hashed_password=get_password_hash(u_in.password),
        role=u_in.role,
        is_admin=u_in.role == "admin",
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_user(db: Session, uid: int, u_in: UserUpdate, current_user: User):
    user = get_user(db, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user.role != "admin" and current_user.id != uid:
        raise HTTPException(status_code=403, detail="Cannot edit other users")
    data = u_in.model_dump(exclude_unset=True)
    if "password" in data:
        data["hashed_password"] = get_password_hash(data.pop("password"))
    if "role" in data and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can change roles")
    if "role" in data:
        data["is_admin"] = data["role"] == "admin"
    for k, v in data.items():
        setattr(user, k, v)
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, uid: int, current_user: User):
    user = get_user(db, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    db.delete(user)
    db.commit()
    return True
