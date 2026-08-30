from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class ResponseHeaderBase(BaseModel):
    listener_id: Optional[int] = None
    listener_ids: Optional[List[int]] = None
    header: str
    value: str
    action: str = "override"
    condition: Optional[str] = None


class ResponseHeaderCreate(ResponseHeaderBase):
    pass


ResponseHeaderUpdate = _optional_update(ResponseHeaderBase)


class ResponseHeaderResponse(ResponseHeaderBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class RequestHeaderBase(BaseModel):
    backend_id: Optional[int] = None
    backend_ids: Optional[List[int]] = None
    header: str
    value: str
    action: str = "override"
    condition: Optional[str] = None


class RequestHeaderCreate(RequestHeaderBase):
    pass


RequestHeaderUpdate = _optional_update(RequestHeaderBase)


class RequestHeaderResponse(RequestHeaderBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = ['RequestHeaderBase', 'RequestHeaderCreate', 'RequestHeaderResponse', 'RequestHeaderUpdate', 'ResponseHeaderBase', 'ResponseHeaderCreate', 'ResponseHeaderResponse', 'ResponseHeaderUpdate']
