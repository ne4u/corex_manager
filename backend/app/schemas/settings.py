from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class SettingBase(BaseModel):
    key: str
    value: Optional[str] = None


class SettingCreate(BaseModel):
    value: Optional[str] = None


class SettingResponse(BaseModel):
    id: Optional[int] = None
    key: str
    value: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class GeoIpDownloadResponse(BaseModel):
    ok: bool
    results: List[Dict[str, Any]]


class GeoIpStatusResponse(BaseModel):
    last_download: Optional[str] = None
    databases: List[Dict[str, Any]] = []


class AsnLookupResponse(BaseModel):
    ip: str
    asn: Optional[int] = None
    organization: Optional[str] = None
    network: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None


__all__ = ['AsnLookupResponse', 'GeoIpDownloadResponse', 'GeoIpStatusResponse', 'SettingBase', 'SettingCreate', 'SettingResponse']
