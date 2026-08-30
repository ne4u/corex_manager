from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class LogDestinationBase(BaseModel):
    listener_id: Optional[int] = None
    name: str
    target: str
    facility: str = "local0"
    level: str = "info"
    # Deprecated: the log-format is generated globally from LoggedField rows or
    # the JSON default. This field is collected for backwards compat but ignored
    # by the config generator. Use LoggedField rows to customize the log format.
    format: Optional[str] = None
    enabled: bool = True


class LogDestinationCreate(LogDestinationBase):
    pass


LogDestinationUpdate = _optional_update(LogDestinationBase)


class LogDestinationResponse(LogDestinationBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class LoggedFieldBase(BaseModel):
    listener_id: Optional[int] = None
    name: str
    field: str
    enabled: bool = True


class LoggedFieldCreate(LoggedFieldBase):
    pass


LoggedFieldUpdate = _optional_update(LoggedFieldBase)


class LoggedFieldResponse(LoggedFieldBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = ['LogDestinationBase', 'LogDestinationCreate', 'LogDestinationResponse', 'LogDestinationUpdate', 'LoggedFieldBase', 'LoggedFieldCreate', 'LoggedFieldResponse', 'LoggedFieldUpdate']
