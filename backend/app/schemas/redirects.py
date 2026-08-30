from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class RedirectBase(BaseModel):
    listener_id: Optional[int] = None
    listener_ids: Optional[List[int]] = None
    priority: int = 0
    name: str
    source: str
    target: str
    type: str = "permanent"
    code: int = 301
    preserve_query: bool = True
    error_page_id: Optional[int] = None
    error_page_query: Optional[str] = None


class RedirectCreate(RedirectBase):
    pass


RedirectUpdate = _optional_update(RedirectBase)


class RedirectResponse(RedirectBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class RewriteBase(BaseModel):
    listener_id: Optional[int] = None
    listener_ids: Optional[List[int]] = None
    priority: int = 0
    name: str
    host_match: Optional[str] = None
    source_regex: str
    target: str
    type: str = "path"


class RewriteCreate(RewriteBase):
    pass


RewriteUpdate = _optional_update(RewriteBase)


class RewriteResponse(RewriteBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = ['RedirectBase', 'RedirectCreate', 'RedirectResponse', 'RedirectUpdate', 'RewriteBase', 'RewriteCreate', 'RewriteResponse', 'RewriteUpdate']
