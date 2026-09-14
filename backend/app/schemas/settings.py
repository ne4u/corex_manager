from typing import Any

from pydantic import BaseModel, ConfigDict


class SettingBase(BaseModel):
    key: str
    value: str | None = None


class SettingCreate(BaseModel):
    value: str | None = None


class SettingResponse(BaseModel):
    id: int | None = None
    key: str
    value: str | None = None

    model_config = ConfigDict(from_attributes=True)


class GeoIpDownloadResponse(BaseModel):
    ok: bool
    results: list[dict[str, Any]]


class GeoIpStatusResponse(BaseModel):
    last_download: str | None = None
    databases: list[dict[str, Any]] = []


class AsnLookupResponse(BaseModel):
    ip: str
    asn: int | None = None
    organization: str | None = None
    network: str | None = None
    city: str | None = None
    country: str | None = None
    country_code: str | None = None


__all__ = [
    "AsnLookupResponse",
    "GeoIpDownloadResponse",
    "GeoIpStatusResponse",
    "SettingBase",
    "SettingCreate",
    "SettingResponse",
]
