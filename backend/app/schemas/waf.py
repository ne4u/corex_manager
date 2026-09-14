from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ._base import _optional_update

# WAF response actions. "challenge" presents a CAPTCHA interstitial; the
# former "captcha" alias is normalized to "challenge" for backwards compat.
WAF_ACTIONS = ("block", "allow", "log", "redirect", "challenge")
# Rate-limit only produces a deny, so "block" (429) is the meaningful value;
# "challenge" is accepted for compat but behaves as a 403 deny in generation.
WAF_RATE_ACTIONS = ("block", "challenge")


class WafRuleBase(BaseModel):
    listener_id: int | None = None
    backend_id: int | None = None
    name: str
    enabled: bool = True
    rule_set: str = "coraza"
    rule_set_version: str | None = None
    rule_set_url: str | None = None
    rule_set_sha256: str | None = None
    rule_set_auto_update: bool = False
    rule_set_update_interval_hours: int = 24
    rule_set_last_updated_at: datetime | None = None
    rule_set_last_error: str | None = None
    rule_set_plugins: list[str] | None = []
    engine: str = Field(default="On", pattern="^(On|DetectionOnly|Off)$")
    paranoia_level: int = Field(default=1, ge=1, le=4)
    inbound_anomaly_threshold: int = Field(default=5, ge=0)
    outbound_anomaly_threshold: int = Field(default=4, ge=0)
    sec_rules: str | None = None
    action: str = "block"
    redirect_url: str | None = None
    status_code: int | None = Field(default=None, ge=100, le=599)
    captcha_valid_seconds: int = Field(default=3600, ge=0)
    path_pattern: str | None = None
    http_methods: str | None = None
    content_types: str | None = None
    export_rule_ids: bool = False
    rate_enabled: bool = False
    rate_events: int = 100
    rate_window_seconds: int = 60
    rate_key: str = "src"
    rate_header: str | None = None
    rate_action: str = "block"
    rate_duration_seconds: int = 0
    fail_open: bool = False

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        if v is None:
            return v
        v = v.lower()
        # Backwards compat: the former "captcha" action is now "challenge".
        if v == "captcha":
            v = "challenge"
        if v not in WAF_ACTIONS:
            raise ValueError(f"action must be one of {WAF_ACTIONS}")
        return v

    @field_validator("rate_action")
    @classmethod
    def _normalize_rate_action(cls, v: str) -> str:
        if v is None:
            return v
        v = v.lower()
        if v == "captcha":
            v = "challenge"
        if v not in WAF_RATE_ACTIONS:
            raise ValueError(f"rate_action must be one of {WAF_RATE_ACTIONS}")
        return v

    @model_validator(mode="after")
    def _check_rate_enabled_action(self):
        # Rate-based WAF counting only runs in the generator's non-allow branch
        # (it increments counters on Coraza deny/drop verdicts). The "allow"
        # action short-circuits before counters, so rate limiting is a no-op.
        action = getattr(self, "action", None)
        rate_enabled = getattr(self, "rate_enabled", False)
        if action == "allow" and rate_enabled:
            raise ValueError("rate_enabled is not supported with action='allow'")
        return self


class WafRuleCreate(WafRuleBase):
    pass


WafRuleUpdate = _optional_update(WafRuleBase)


class WafRuleResponse(WafRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class WafExceptionBase(BaseModel):
    waf_rule_id: int | None = None
    name: str
    rule_id: str | None = None
    rule_tag: str | None = None
    rule_msg: str | None = None
    zone: str | None = None
    variable: str | None = None
    matcher: str = "equals"
    value: str | None = None
    description: str | None = None
    action: str = Field(default="remove", pattern="^(remove|allow|comment|update)$")
    update_action: str | None = None
    update_target: str | None = None
    condition_variable: str | None = None
    condition_operator: str = "equals"
    condition_value: str | None = None


class WafExceptionCreate(WafExceptionBase):
    pass


WafExceptionUpdate = _optional_update(WafExceptionBase)


class WafExceptionResponse(WafExceptionBase):
    id: int
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class WafExceptionPreviewRequest(WafExceptionBase):
    name: str = ""


class WafExceptionPreviewResponse(BaseModel):
    conditional: list[str]
    unconditional: list[str]


class WafExceptionRuleOption(BaseModel):
    id: str
    msg: str | None = None
    tags: list[str] = []
    hits: int = 0


class WafExceptionMsgOption(BaseModel):
    msg: str
    rule_id: str | None = None
    hits: int = 0


class WafExceptionVariableOption(BaseModel):
    zone: str
    key: str = ""


class WafExceptionOptionsResponse(BaseModel):
    rules: list[WafExceptionRuleOption]
    tags: list[str]
    msgs: list[WafExceptionMsgOption]
    zones: list[str]
    variables: list[WafExceptionVariableOption]
    condition_variables: list[str]


class WafRuleVersionBase(BaseModel):
    waf_rule_id: int
    version: str
    snapshot: dict[str, Any]
    created_by: str | None = None


class WafRuleVersionCreate(WafRuleVersionBase):
    pass


WafRuleVersionUpdate = _optional_update(WafRuleVersionBase)


class WafRuleVersionResponse(WafRuleVersionBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    "WafExceptionBase",
    "WafExceptionCreate",
    "WafExceptionMsgOption",
    "WafExceptionOptionsResponse",
    "WafExceptionPreviewRequest",
    "WafExceptionPreviewResponse",
    "WafExceptionResponse",
    "WafExceptionRuleOption",
    "WafExceptionUpdate",
    "WafExceptionVariableOption",
    "WafRuleBase",
    "WafRuleCreate",
    "WafRuleResponse",
    "WafRuleUpdate",
    "WafRuleVersionBase",
    "WafRuleVersionCreate",
    "WafRuleVersionResponse",
    "WafRuleVersionUpdate",
]
