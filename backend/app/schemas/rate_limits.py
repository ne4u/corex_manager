from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class RateLimitBase(BaseModel):
    listener_id: Optional[int] = None
    name: str
    enabled: Optional[bool] = True
    limit_type: str = Field(..., pattern="^(basic|advanced|waf|response_code)$")
    events: Optional[int] = 100
    window_seconds: Optional[int] = 60
    burst: Optional[int] = 20
    action: Optional[str] = Field(default="block", pattern="^(allow|block|log|tarpit|challenge)$")
    duration_seconds: Optional[int] = 300
    expression: Optional[str] = None
    response_code: Optional[int] = None
    match_status_code: Optional[int] = None
    url_path: Optional[str] = None
    user_agent: Optional[str] = None
    waf_event_threshold: Optional[int] = None
    waf_window_seconds: Optional[int] = None
    waf_block_duration: Optional[int] = None
    rate_key: Optional[str] = "src"
    rate_header: Optional[str] = None
    log: Optional[bool] = True
    no_log: Optional[bool] = False
    # API Armor per-endpoint scoping
    path_pattern: Optional[str] = None
    method: Optional[str] = None
    api_armor_scoped: Optional[bool] = False


class RateLimitCreate(RateLimitBase):
    pass


RateLimitUpdate = _optional_update(RateLimitBase)


class RateLimitResponse(RateLimitBase):
    id: int
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


__all__ = ['RateLimitBase', 'RateLimitCreate', 'RateLimitResponse', 'RateLimitUpdate']
