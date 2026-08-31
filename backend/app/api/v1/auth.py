from typing import Optional
from zoneinfo import available_timezones
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, oauth2_scheme, rate_limit, rate_limit_by_ip
from ...models.auth import UserPreference
from ...schemas.users import (
    ChangePasswordRequest,
    LoginResponse,
    TOTPDisableRequest,
    TOTPSetupRequest,
    TOTPVerifyRequest,
    UserPreferenceResponse,
    UserPreferenceUpdate,
    UserResponse,
)
from ...services.auth import (
    authenticate_user,
    change_password,
    create_token_for_user,
    disable_totp,
    get_session_settings,
    logout,
    refresh_token,
    setup_totp,
    verify_totp,
)

# IANA timezones available on this system (cached at import time).
_IANA_TIMEZONES: frozenset[str] = frozenset(available_timezones())


def _validate_timezone(value: str) -> None:
    """Raise 400 if the value is not 'local', 'utc', or a known IANA zone."""
    if value in ("local", "utc"):
        return
    if value not in _IANA_TIMEZONES:
        raise HTTPException(
            status_code=400,
            detail="timezone must be 'local', 'utc', or a valid IANA timezone",
        )


def _validate_datetime_format(value: str) -> None:
    """Raise 400 if the format string is empty or too long."""
    if not value or not value.strip():
        raise HTTPException(
            status_code=400,
            detail="datetime_format must be a non-empty string",
        )
    if len(value) > 64:
        raise HTTPException(
            status_code=400,
            detail="datetime_format must be 64 characters or fewer",
        )

router = APIRouter()


@router.post("/auth/token", response_model=LoginResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    totp_code: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _=Depends(rate_limit_by_ip),
):
    try:
        user = authenticate_user(db, form_data.username, form_data.password, totp_code)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    return create_token_for_user(user, db)


@router.post("/auth/totp/setup")
def totp_setup(
    data: TOTPSetupRequest = TOTPSetupRequest(),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    result = setup_totp(user, data.alias)
    db.commit()
    return result


@router.post("/auth/totp/verify")
def totp_verify(
    data: TOTPVerifyRequest,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    try:
        result = verify_totp(user, data.code)
        db.commit()
        return result
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/auth/totp/disable")
def totp_disable(
    data: TOTPDisableRequest,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    try:
        result = disable_totp(user, data.password)
        db.commit()
        return result
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/auth/logout")
def logout_endpoint(
    token: str = Depends(oauth2_scheme),
    _=Depends(get_current_user),
):
    return logout(token)


@router.get("/auth/me", response_model=UserResponse)
def me(
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return user


@router.post("/auth/refresh")
def refresh_token_endpoint(
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    return refresh_token(user, db)


@router.post("/auth/change-password")
def change_password_endpoint(
    data: ChangePasswordRequest,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    try:
        change_password(db, user, data.current_password, data.new_password)
        db.commit()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "ok"}


@router.get("/auth/session")
def get_session_settings_endpoint(
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    return get_session_settings(user, db)


# ---------------------------------------------------------------------------
# User preferences (theme + custom themes + language + date/time format)
# ---------------------------------------------------------------------------

def _get_or_create_pref(db: Session, user_id: int) -> UserPreference:
    pref = db.query(UserPreference).filter(UserPreference.user_id == user_id).first()
    if not pref:
        pref = UserPreference(user_id=user_id)
        db.add(pref)
        db.commit()
        db.refresh(pref)
    return pref


@router.get("/auth/preferences", response_model=UserPreferenceResponse)
def get_preferences(
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    pref = _get_or_create_pref(db, user.id)
    return pref


@router.put("/auth/preferences", response_model=UserPreferenceResponse)
def update_preferences(
    data: UserPreferenceUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    pref = _get_or_create_pref(db, user.id)
    if data.theme is not None:
        pref.theme = data.theme
    if data.custom_themes is not None:
        pref.custom_themes = data.custom_themes
    if data.language is not None:
        pref.language = data.language
    if data.datetime_format is not None:
        _validate_datetime_format(data.datetime_format)
        pref.datetime_format = data.datetime_format
    if data.timezone is not None:
        _validate_timezone(data.timezone)
        pref.timezone = data.timezone
    db.commit()
    db.refresh(pref)
    return pref
