"""Authentication and session helpers."""
import base64
import io
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
import qrcode
from qrcode.image.svg import SvgImage
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.security import create_access_token, verify_password, get_password_hash
from ..core.valkey_client import revoke_token
from ..models.auth import User
from ..schemas.users import (
    SessionSettingsResponse,
    TOTPSetupResponse,
    TOTPVerifyResponse,
)
from ..services.settings import get_setting

settings = get_settings()


def _session_timeout_minutes(db: Session) -> int:
    raw = get_setting(db, "session_timeout_minutes", str(settings.SESSION_TIMEOUT_MINUTES))
    try:
        return max(5, min(1440, int(raw)))
    except (TypeError, ValueError):
        return max(5, min(1440, settings.SESSION_TIMEOUT_MINUTES))


def _session_warning_seconds(db: Session) -> int:
    raw = get_setting(db, "session_warning_seconds", str(settings.SESSION_WARNING_SECONDS))
    try:
        return max(5, min(120, int(raw)))
    except (TypeError, ValueError):
        return max(5, min(120, settings.SESSION_WARNING_SECONDS))


def authenticate_user(db: Session, username: str, password: str, totp_code: Optional[str] = None):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise ValueError("Invalid credentials")
    if user.totp_enabled:
        if not totp_code:
            raise ValueError("TOTP code required")
        if not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(totp_code.strip()):
            raise ValueError("Invalid TOTP code")
    return user


def create_token_for_user(user: User, db: Session) -> dict:
    expires = timedelta(minutes=_session_timeout_minutes(db))
    token = create_access_token({"sub": user.username, "role": user.role}, expires_delta=expires)
    return {"access_token": token, "token_type": "bearer", "role": user.role}


def setup_totp(user: User, alias: Optional[str] = None):
    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.totp_enabled = False
    account = alias or user.username
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(account, issuer_name="coreX Manager")
    qr = qrcode.QRCode(version=1, box_size=6, border=1, image_factory=SvgImage)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image()
    stream = io.BytesIO()
    img.save(stream)
    qr_code = f"data:image/svg+xml;base64,{base64.b64encode(stream.getvalue()).decode()}"
    return TOTPSetupResponse(secret=secret, provisioning_uri=provisioning_uri, qr_code=qr_code)


def verify_totp(user: User, code: str):
    if not user.totp_secret:
        raise ValueError("TOTP not set up")
    if pyotp.TOTP(user.totp_secret).verify(code.strip()):
        user.totp_enabled = True
        return TOTPVerifyResponse(status="ok", enabled=True)
    raise ValueError("Invalid TOTP code")


def disable_totp(user: User, password: str):
    if not verify_password(password, user.hashed_password):
        raise ValueError("Invalid password")
    user.totp_secret = None
    user.totp_enabled = False
    return TOTPVerifyResponse(status="ok", enabled=False)


def change_password(user: User, current_password: str, new_password: str):
    """Verify the current password and set a new hash on the user object.

    The caller is responsible for committing the session.
    """
    if not verify_password(current_password, user.hashed_password):
        raise ValueError("Current password is incorrect")
    user.hashed_password = get_password_hash(new_password)


def logout(token: str):
    from ..core.security import decode_access_token

    payload = decode_access_token(token)
    if payload:
        exp = payload.get("exp")
        ttl = max(1, int(exp - datetime.now(timezone.utc).timestamp())) if exp else 3600
        revoke_token(token, ttl)
    return {"status": "ok"}


def refresh_token(user: User, db: Session):
    expires = timedelta(minutes=_session_timeout_minutes(db))
    token = create_access_token({"sub": user.username, "role": user.role}, expires_delta=expires)
    return {"access_token": token, "token_type": "bearer"}


def get_session_settings(user: User, db: Session):
    return SessionSettingsResponse(
        timeout_minutes=_session_timeout_minutes(db),
        warning_seconds=_session_warning_seconds(db),
    )
