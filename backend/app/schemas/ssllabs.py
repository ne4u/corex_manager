from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SslLabsScanCreate(BaseModel):
    host: str


class SslLabsScanResponse(BaseModel):
    id: int
    certificate_id: int
    host: str
    status: str
    status_message: Optional[str] = None
    grade: Optional[str] = None
    report: Optional[Dict[str, Any]] = None
    start_time: Optional[int] = None
    test_time: Optional[int] = None
    engine_version: Optional[str] = None
    criteria_version: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SslLabsHostsResponse(BaseModel):
    hosts: List[str]


class SslLabsSettingsResponse(BaseModel):
    max_scans_per_host: int


class SslLabsSettingsUpdate(BaseModel):
    max_scans_per_host: int = Field(ge=1, le=100)


__all__ = [
    'SslLabsScanCreate',
    'SslLabsScanResponse',
    'SslLabsHostsResponse',
    'SslLabsSettingsResponse',
    'SslLabsSettingsUpdate',
]
