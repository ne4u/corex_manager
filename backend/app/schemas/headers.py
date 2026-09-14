from pydantic import BaseModel, ConfigDict

from ._base import _optional_update


class ResponseHeaderBase(BaseModel):
    listener_id: int | None = None
    listener_ids: list[int] | None = None
    header: str
    value: str
    action: str = "override"
    condition: str | None = None


class ResponseHeaderCreate(ResponseHeaderBase):
    pass


ResponseHeaderUpdate = _optional_update(ResponseHeaderBase)


class ResponseHeaderResponse(ResponseHeaderBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class RequestHeaderBase(BaseModel):
    backend_id: int | None = None
    backend_ids: list[int] | None = None
    header: str
    value: str
    action: str = "override"
    condition: str | None = None


class RequestHeaderCreate(RequestHeaderBase):
    pass


RequestHeaderUpdate = _optional_update(RequestHeaderBase)


class RequestHeaderResponse(RequestHeaderBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    "RequestHeaderBase",
    "RequestHeaderCreate",
    "RequestHeaderResponse",
    "RequestHeaderUpdate",
    "ResponseHeaderBase",
    "ResponseHeaderCreate",
    "ResponseHeaderResponse",
    "ResponseHeaderUpdate",
]
