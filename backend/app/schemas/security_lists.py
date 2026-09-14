from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ._base import _optional_update

# ─── Network Lists ──────────────────────────────────────────────────────────


class NetworkListEntryInline(BaseModel):
    value: str
    note: str | None = None


class NetworkListBase(BaseModel):
    name: str
    description: str | None = None


class NetworkListCreate(NetworkListBase):
    entries: list[NetworkListEntryInline] | None = None


NetworkListUpdate = _optional_update(NetworkListCreate)


class NetworkListEntryBase(BaseModel):
    value: str
    note: str | None = None


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
    entries: list[NetworkListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── ASN Lists ──────────────────────────────────────────────────────────────


class AsnListEntryInline(BaseModel):
    value: str
    note: str | None = None


class AsnListBase(BaseModel):
    name: str
    description: str | None = None


class AsnListCreate(AsnListBase):
    entries: list[AsnListEntryInline] | None = None


AsnListUpdate = _optional_update(AsnListCreate)


class AsnListEntryBase(BaseModel):
    value: str
    note: str | None = None


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
    entries: list[AsnListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Geo Lists ─────────────────────────────────────────────────────────────


class GeoListEntryInline(BaseModel):
    value: str
    note: str | None = None


class GeoListBase(BaseModel):
    name: str
    description: str | None = None


class GeoListCreate(GeoListBase):
    entries: list[GeoListEntryInline] | None = None


GeoListUpdate = _optional_update(GeoListCreate)


class GeoListEntryBase(BaseModel):
    value: str
    note: str | None = None


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
    entries: list[GeoListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── JA4 Lists ──────────────────────────────────────────────────────────────


class Ja4ListEntryInline(BaseModel):
    value: str
    note: str | None = None


class Ja4ListBase(BaseModel):
    name: str
    description: str | None = None


class Ja4ListCreate(Ja4ListBase):
    entries: list[Ja4ListEntryInline] | None = None


Ja4ListUpdate = _optional_update(Ja4ListCreate)


class Ja4ListEntryBase(BaseModel):
    value: str
    note: str | None = None


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
    entries: list[Ja4ListEntryResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Pattern Lists ─────────────────────────────────────────────────────────


class PatternListEntryInline(BaseModel):
    value: str
    note: str | None = None


class PatternListBase(BaseModel):
    name: str
    description: str | None = None


class PatternListCreate(PatternListBase):
    entries: list[PatternListEntryInline] | None = None


PatternListUpdate = _optional_update(PatternListCreate)


class PatternListEntryBase(BaseModel):
    value: str
    note: str | None = None


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
    entries: list[PatternListEntryResponse] = []
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
    description: str | None = None
    enabled: bool = True
    auto_apply: bool = True
    target_list_id: int | None = None


class DynamicFeedCreate(DynamicFeedBase):
    pass


DynamicFeedUpdate = _optional_update(DynamicFeedBase)


class DynamicFeedResponse(DynamicFeedBase):
    id: int
    target_list_id: int
    last_updated_at: datetime | None = None
    last_error: str | None = None
    last_entry_count: int | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    "AsnListBase",
    "AsnListCreate",
    "AsnListEntryBase",
    "AsnListEntryCreate",
    "AsnListEntryInline",
    "AsnListEntryResponse",
    "AsnListEntryUpdate",
    "AsnListResponse",
    "AsnListUpdate",
    "DynamicFeedBase",
    "DynamicFeedCreate",
    "DynamicFeedResponse",
    "DynamicFeedUpdate",
    "GeoCountryOption",
    "GeoListBase",
    "GeoListCreate",
    "GeoListEntryBase",
    "GeoListEntryCreate",
    "GeoListEntryInline",
    "GeoListEntryResponse",
    "GeoListEntryUpdate",
    "GeoListResponse",
    "GeoListUpdate",
    "Ja4ListBase",
    "Ja4ListCreate",
    "Ja4ListEntryBase",
    "Ja4ListEntryCreate",
    "Ja4ListEntryInline",
    "Ja4ListEntryResponse",
    "Ja4ListEntryUpdate",
    "Ja4ListResponse",
    "Ja4ListUpdate",
    "NetworkListBase",
    "NetworkListCreate",
    "NetworkListEntryBase",
    "NetworkListEntryCreate",
    "NetworkListEntryInline",
    "NetworkListEntryResponse",
    "NetworkListEntryUpdate",
    "NetworkListResponse",
    "NetworkListUpdate",
    "PatternListBase",
    "PatternListCreate",
    "PatternListEntryBase",
    "PatternListEntryCreate",
    "PatternListEntryInline",
    "PatternListEntryResponse",
    "PatternListEntryUpdate",
    "PatternListResponse",
    "PatternListUpdate",
]
