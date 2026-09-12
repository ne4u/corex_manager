from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

# ─── Network Lists ──────────────────────────────────────────────────────────

class NetworkListEntryInline(BaseModel):
    value: str
    note: Optional[str] = None


class NetworkListBase(BaseModel):
    name: str
    description: Optional[str] = None


class NetworkListCreate(NetworkListBase):
    entries: Optional[List[NetworkListEntryInline]] = None


NetworkListUpdate = _optional_update(NetworkListCreate)


class NetworkListEntryBase(BaseModel):
    value: str
    note: Optional[str] = None


class NetworkListEntryCreate(NetworkListEntryBase):
    pass


NetworkListEntryUpdate = _optional_update(NetworkListEntryBase)


class NetworkListEntryResponse(NetworkListEntryBase):
    id: int
    list_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkListResponse(NetworkListBase):
    id: int
    entry_count: int = 0
    entries: List[NetworkListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── ASN Lists ──────────────────────────────────────────────────────────────

class AsnListEntryInline(BaseModel):
    value: str
    note: Optional[str] = None


class AsnListBase(BaseModel):
    name: str
    description: Optional[str] = None


class AsnListCreate(AsnListBase):
    entries: Optional[List[AsnListEntryInline]] = None


AsnListUpdate = _optional_update(AsnListCreate)


class AsnListEntryBase(BaseModel):
    value: str
    note: Optional[str] = None


class AsnListEntryCreate(AsnListEntryBase):
    pass


AsnListEntryUpdate = _optional_update(AsnListEntryBase)


class AsnListEntryResponse(AsnListEntryBase):
    id: int
    list_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AsnListResponse(AsnListBase):
    id: int
    entry_count: int = 0
    entries: List[AsnListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Geo Lists ─────────────────────────────────────────────────────────────

class GeoListEntryInline(BaseModel):
    value: str
    note: Optional[str] = None


class GeoListBase(BaseModel):
    name: str
    description: Optional[str] = None


class GeoListCreate(GeoListBase):
    entries: Optional[List[GeoListEntryInline]] = None


GeoListUpdate = _optional_update(GeoListCreate)


class GeoListEntryBase(BaseModel):
    value: str
    note: Optional[str] = None


class GeoListEntryCreate(GeoListEntryBase):
    pass


GeoListEntryUpdate = _optional_update(GeoListEntryBase)


class GeoListEntryResponse(GeoListEntryBase):
    id: int
    list_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GeoListResponse(GeoListBase):
    id: int
    entry_count: int = 0
    entries: List[GeoListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── JA4 Lists ──────────────────────────────────────────────────────────────

class Ja4ListEntryInline(BaseModel):
    value: str
    note: Optional[str] = None


class Ja4ListBase(BaseModel):
    name: str
    description: Optional[str] = None


class Ja4ListCreate(Ja4ListBase):
    entries: Optional[List[Ja4ListEntryInline]] = None


Ja4ListUpdate = _optional_update(Ja4ListCreate)


class Ja4ListEntryBase(BaseModel):
    value: str
    note: Optional[str] = None


class Ja4ListEntryCreate(Ja4ListEntryBase):
    pass


Ja4ListEntryUpdate = _optional_update(Ja4ListEntryBase)


class Ja4ListEntryResponse(Ja4ListEntryBase):
    id: int
    list_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Ja4ListResponse(Ja4ListBase):
    id: int
    entry_count: int = 0
    entries: List[Ja4ListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Pattern Lists ─────────────────────────────────────────────────────────

class PatternListEntryInline(BaseModel):
    value: str
    note: Optional[str] = None


class PatternListBase(BaseModel):
    name: str
    description: Optional[str] = None


class PatternListCreate(PatternListBase):
    entries: Optional[List[PatternListEntryInline]] = None


PatternListUpdate = _optional_update(PatternListCreate)


class PatternListEntryBase(BaseModel):
    value: str
    note: Optional[str] = None


class PatternListEntryCreate(PatternListEntryBase):
    pass


PatternListEntryUpdate = _optional_update(PatternListEntryBase)


class PatternListEntryResponse(PatternListEntryBase):
    id: int
    list_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PatternListResponse(PatternListBase):
    id: int
    entry_count: int = 0
    entries: List[PatternListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Shared ────────────────────────────────────────────────────────────────

class GeoCountryOption(BaseModel):
    code: str
    name: str


class DynamicFeedBase(BaseModel):
    name: str
    list_type: str = Field(..., pattern="^(network|asn|ja4)$")
    url: str
    update_interval_hours: int = 24
    description: Optional[str] = None
    enabled: bool = True
    auto_apply: bool = True
    target_list_id: Optional[int] = None


class DynamicFeedCreate(DynamicFeedBase):
    pass


DynamicFeedUpdate = _optional_update(DynamicFeedBase)


class DynamicFeedResponse(DynamicFeedBase):
    id: int
    target_list_id: int
    last_updated_at: Optional[datetime] = None
    last_error: Optional[str] = None
    last_entry_count: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = ['AsnListBase', 'AsnListCreate', 'AsnListEntryBase', 'AsnListEntryCreate', 'AsnListEntryInline', 'AsnListEntryResponse', 'AsnListEntryUpdate', 'AsnListResponse', 'AsnListUpdate', 'DynamicFeedBase', 'DynamicFeedCreate', 'DynamicFeedResponse', 'DynamicFeedUpdate', 'GeoCountryOption', 'GeoListBase', 'GeoListCreate', 'GeoListEntryBase', 'GeoListEntryCreate', 'GeoListEntryInline', 'GeoListEntryResponse', 'GeoListEntryUpdate', 'GeoListResponse', 'GeoListUpdate', 'Ja4ListBase', 'Ja4ListCreate', 'Ja4ListEntryBase', 'Ja4ListEntryCreate', 'Ja4ListEntryInline', 'Ja4ListEntryResponse', 'Ja4ListEntryUpdate', 'Ja4ListResponse', 'Ja4ListUpdate', 'NetworkListBase', 'NetworkListCreate', 'NetworkListEntryBase', 'NetworkListEntryCreate', 'NetworkListEntryInline', 'NetworkListEntryResponse', 'NetworkListEntryUpdate', 'NetworkListResponse', 'NetworkListUpdate', 'PatternListBase', 'PatternListCreate', 'PatternListEntryBase', 'PatternListEntryCreate', 'PatternListEntryInline', 'PatternListEntryResponse', 'PatternListEntryUpdate', 'PatternListResponse', 'PatternListUpdate']
