from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ._base import _optional_update


class RateLimitBase(BaseModel):
    listener_id: int | None = None
    name: str
    enabled: bool | None = True
    limit_type: str = Field(..., pattern="^(basic|advanced|waf|response_code)$")
    events: int | None = 100
    window_seconds: int | None = 60
    burst: int | None = 20
    action: str | None = Field(default="block", pattern="^(allow|block|log|tarpit|challenge)$")
    duration_seconds: int | None = 300
    expression: str | None = None
    response_code: int | None = None
    match_status_code: int | None = None
    url_path: str | None = None
    user_agent: str | None = None
    waf_event_threshold: int | None = None
    waf_window_seconds: int | None = None
    waf_block_duration: int | None = None
    rate_key: str | None = "src"
    rate_header: str | None = None
    log: bool | None = True
    no_log: bool | None = False
    # API Armor per-endpoint scoping
    path_pattern: str | None = None
    method: str | None = None
    api_armor_scoped: bool | None = False


class RateLimitCreate(RateLimitBase):
    pass


RateLimitUpdate = _optional_update(RateLimitBase)


class RateLimitResponse(RateLimitBase):
    id: int
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


__all__ = ["RateLimitBase", "RateLimitCreate", "RateLimitResponse", "RateLimitUpdate"]
