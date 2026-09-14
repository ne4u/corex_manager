from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class UserBase(BaseModel):
    username: str
    role: str = "operator"
    email: str = Field(min_length=1)
    first_name: str = Field(min_length=1)
    last_name: str = Field(min_length=1)
    organization: str = Field(min_length=1)


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    username: str | None = None
    role: str | None = None
    password: str | None = None
    email: str = Field(min_length=1)
    first_name: str = Field(min_length=1)
    last_name: str = Field(min_length=1)
    organization: str = Field(min_length=1)


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    is_admin: bool
    totp_enabled: bool = False
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    organization: str | None = None
    last_login_at: datetime | None = None
    password_changed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserPreferenceUpdate(BaseModel):
    theme: str | None = None
    custom_themes: dict[str, Any] | None = None
    language: str | None = None
    datetime_format: str | None = None
    timezone: str | None = None


class UserPreferenceResponse(BaseModel):
    theme: str | None = None
    custom_themes: dict[str, Any] | None = None
    language: str | None = None
    datetime_format: str | None = None
    timezone: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ChangePasswordRequest(BaseModel):
    current_password: str
    # min_length=1 here; the service enforces the configured complexity policy
    # with descriptive per-rule errors.
    new_password: str = Field(min_length=1)


class TOTPSetupRequest(BaseModel):
    alias: str | None = None


class TOTPSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code: str


class TOTPVerifyRequest(BaseModel):
    code: str


class TOTPVerifyResponse(BaseModel):
    status: str
    enabled: bool


class TOTPDisableRequest(BaseModel):
    password: str


class SessionSettingsResponse(BaseModel):
    timeout_minutes: int
    warning_seconds: int
    password_expired: bool = False
    password_policy: dict[str, Any] = {}


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    password_expired: bool = False


__all__ = [
    "LoginResponse",
    "SessionSettingsResponse",
    "TOTPDisableRequest",
    "TOTPSetupRequest",
    "TOTPSetupResponse",
    "TOTPVerifyRequest",
    "TOTPVerifyResponse",
    "UserBase",
    "UserCreate",
    "UserPreferenceResponse",
    "UserPreferenceUpdate",
    "UserResponse",
    "UserUpdate",
    "ChangePasswordRequest",
]
