from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SslLabsScanCreate(BaseModel):
    host: str


class SslLabsScanResponse(BaseModel):
    id: int
    certificate_id: int
    host: str
    status: str
    status_message: str | None = None
    grade: str | None = None
    report: dict[str, Any] | None = None
    start_time: int | None = None
    test_time: int | None = None
    engine_version: str | None = None
    criteria_version: str | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SslLabsHostsResponse(BaseModel):
    hosts: list[str]


class SslLabsSettingsResponse(BaseModel):
    max_scans_per_host: int


class SslLabsSettingsUpdate(BaseModel):
    max_scans_per_host: int = Field(ge=1, le=100)


__all__ = [
    "SslLabsScanCreate",
    "SslLabsScanResponse",
    "SslLabsHostsResponse",
    "SslLabsSettingsResponse",
    "SslLabsSettingsUpdate",
]
