from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class ConfigApplyRequest(BaseModel):
    comment: Optional[str] = None


class ConfigApplyResponse(BaseModel):
    status: str
    message: str
    task_id: int


class ConfigRevertRequest(BaseModel):
    confirm: bool = False


class ConfigRevertResponse(BaseModel):
    status: str
    message: str
    task_id: int


class ConfigSnapshotBase(BaseModel):
    created_at: datetime
    created_by: Optional[str] = None
    comment: Optional[str] = None
    diff: Optional[str] = None
    snapshot_path: Optional[str] = None


class ConfigSnapshotResponse(ConfigSnapshotBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class ConfigSnapshotRollbackResponse(BaseModel):
    status: str
    message: str
    task_id: int


__all__ = ['ConfigApplyRequest', 'ConfigApplyResponse', 'ConfigRevertRequest', 'ConfigRevertResponse', 'ConfigSnapshotBase', 'ConfigSnapshotResponse', 'ConfigSnapshotRollbackResponse']
