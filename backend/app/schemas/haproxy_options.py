from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class HaproxyOption(BaseModel):
    target: str = Field(default="section", pattern="^(section|bind)$")
    directive: str
    value: str
    enabled: bool = True


__all__ = ['HaproxyOption']
