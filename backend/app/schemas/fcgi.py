from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class FcgiParam(BaseModel):
    name: str
    value: str
    enabled: bool = True


class FcgiAppBase(BaseModel):
    name: str
    description: Optional[str] = None
    docroot: Optional[str] = None
    index: Optional[str] = None
    path_info: Optional[str] = None
    log_stderr_enabled: bool = False
    log_stderr_target: Optional[str] = None
    keep_conn: bool = True
    mpxs_conns: bool = False
    max_reqs: Optional[int] = Field(default=1, ge=1)
    params: Optional[List[FcgiParam]] = []


class FcgiAppCreate(FcgiAppBase):
    pass


FcgiAppUpdate = _optional_update(FcgiAppBase)


class FcgiAppResponse(FcgiAppBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = ['FcgiAppBase', 'FcgiAppCreate', 'FcgiAppResponse', 'FcgiAppUpdate', 'FcgiParam']
