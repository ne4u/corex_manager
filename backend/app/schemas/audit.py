from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class AuditEventResponse(BaseModel):
    id: int
    created_at: datetime
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    method: str
    path: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    status_code: Optional[int] = None
    ip_address: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    snapshot_id: Optional[int] = None
    config_change: bool = True
    snapshot_comment: Optional[str] = None
    snapshot_created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AuditEventFilterOptions(BaseModel):
    usernames: List[str] = []
    actions: List[str] = []
    resource_types: List[str] = []
    ip_addresses: List[str] = []


__all__ = ['AuditEventResponse', 'AuditEventFilterOptions']
