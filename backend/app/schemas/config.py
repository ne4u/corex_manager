from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ConfigApplyRequest(BaseModel):
    comment: str | None = None


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
    created_by: str | None = None
    comment: str | None = None
    diff: str | None = None
    snapshot_path: str | None = None


class ConfigSnapshotResponse(ConfigSnapshotBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class ConfigSnapshotRollbackResponse(BaseModel):
    status: str
    message: str
    task_id: int


__all__ = [
    "ConfigApplyRequest",
    "ConfigApplyResponse",
    "ConfigRevertRequest",
    "ConfigRevertResponse",
    "ConfigSnapshotBase",
    "ConfigSnapshotResponse",
    "ConfigSnapshotRollbackResponse",
]
