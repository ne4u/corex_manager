from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    id: int
    created_at: datetime
    user_id: int | None = None
    username: str | None = None
    action: str
    method: str
    path: str
    resource_type: str | None = None
    resource_id: str | None = None
    status_code: int | None = None
    ip_address: str | None = None
    payload: dict[str, Any] | None = None
    snapshot_id: int | None = None
    config_change: bool = True
    snapshot_comment: str | None = None
    snapshot_created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class AuditEventFilterOptions(BaseModel):
    usernames: list[str] = []
    actions: list[str] = []
    resource_types: list[str] = []
    ip_addresses: list[str] = []


__all__ = ["AuditEventResponse", "AuditEventFilterOptions"]
