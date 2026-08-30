from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, get_current_user, require_admin, rate_limit
from ...models.auth import User
from ...schemas.users import UserCreate, UserResponse, UserUpdate
from ...services.users import create_user, delete_user, get_user, list_users, update_user

router = APIRouter()


@router.get("/users", response_model=List[UserResponse])
def list_users_endpoint(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return list_users(db)


@router.post("/users", response_model=UserResponse)
def create_user_endpoint(
    u_in: UserCreate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return create_user(db, u_in)


@router.get("/users/{uid}", response_model=UserResponse)
def get_user_endpoint(
    uid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    user = get_user(db, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user.role != "admin" and current_user.id != uid:
        raise HTTPException(status_code=403, detail="Cannot view other users")
    return user


@router.put("/users/{uid}", response_model=UserResponse)
def update_user_endpoint(
    uid: int,
    u_in: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    return update_user(db, uid, u_in, current_user)


@router.delete("/users/{uid}")
def delete_user_endpoint(
    uid: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    _=Depends(rate_limit),
):
    if not delete_user(db, uid, current_user):
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok"}
