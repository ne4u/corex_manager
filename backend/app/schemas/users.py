from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

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
    username: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None
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
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organization: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserPreferenceUpdate(BaseModel):
    theme: Optional[str] = None
    custom_themes: Optional[Dict[str, Any]] = None
    language: Optional[str] = None
    datetime_format: Optional[str] = None
    timezone: Optional[str] = None


class UserPreferenceResponse(BaseModel):
    theme: Optional[str] = None
    custom_themes: Optional[Dict[str, Any]] = None
    language: Optional[str] = None
    datetime_format: Optional[str] = None
    timezone: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class TOTPSetupRequest(BaseModel):
    alias: Optional[str] = None


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


__all__ = ['SessionSettingsResponse', 'TOTPDisableRequest', 'TOTPSetupRequest', 'TOTPSetupResponse', 'TOTPVerifyRequest', 'TOTPVerifyResponse', 'UserBase', 'UserCreate', 'UserPreferenceResponse', 'UserPreferenceUpdate', 'UserResponse', 'UserUpdate', 'ChangePasswordRequest']
