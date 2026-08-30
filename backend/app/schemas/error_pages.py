from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class CustomErrorPageBase(BaseModel):
    listener_id: Optional[int] = None
    listener_ids: Optional[List[int]] = None
    code: int
    content_type: str = "text/html"
    content: str


class CustomErrorPageCreate(CustomErrorPageBase):
    pass


CustomErrorPageUpdate = _optional_update(CustomErrorPageBase)


class CustomErrorPageResponse(CustomErrorPageBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class CustomErrorPagePreview(BaseModel):
    content: str
    content_type: str = "text/html"


__all__ = ['CustomErrorPageBase', 'CustomErrorPageCreate', 'CustomErrorPagePreview', 'CustomErrorPageResponse', 'CustomErrorPageUpdate']
