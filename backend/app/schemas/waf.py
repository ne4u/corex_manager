from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

# WAF response actions. "challenge" presents a CAPTCHA interstitial; the
# former "captcha" alias is normalized to "challenge" for backwards compat.
WAF_ACTIONS = ("block", "allow", "log", "redirect", "challenge")
# Rate-limit only produces a deny, so "block" (429) is the meaningful value;
# "challenge" is accepted for compat but behaves as a 403 deny in generation.
WAF_RATE_ACTIONS = ("block", "challenge")

class WafRuleBase(BaseModel):
    listener_id: Optional[int] = None
    backend_id: Optional[int] = None
    name: str
    enabled: bool = True
    rule_set: str = "coraza"
    rule_set_version: Optional[str] = None
    rule_set_url: Optional[str] = None
    rule_set_sha256: Optional[str] = None
    rule_set_auto_update: bool = False
    rule_set_update_interval_hours: int = 24
    rule_set_last_updated_at: Optional[datetime] = None
    rule_set_last_error: Optional[str] = None
    rule_set_plugins: Optional[List[str]] = []
    engine: str = Field(default="On", pattern="^(On|DetectionOnly|Off)$")
    paranoia_level: int = Field(default=1, ge=1, le=4)
    inbound_anomaly_threshold: int = Field(default=5, ge=0)
    outbound_anomaly_threshold: int = Field(default=4, ge=0)
    sec_rules: Optional[str] = None
    action: str = "block"
    redirect_url: Optional[str] = None
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    captcha_valid_seconds: int = Field(default=3600, ge=0)
    path_pattern: Optional[str] = None
    http_methods: Optional[str] = None
    content_types: Optional[str] = None
    export_rule_ids: bool = False
    rate_enabled: bool = False
    rate_events: int = 100
    rate_window_seconds: int = 60
    rate_key: str = "src"
    rate_header: Optional[str] = None
    rate_action: str = "block"
    rate_duration_seconds: int = 0
    fail_open: bool = False
    siem_integration_id: Optional[int] = None

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
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class WafExceptionBase(BaseModel):
    waf_rule_id: Optional[int] = None
    name: str
    rule_id: Optional[str] = None
    rule_tag: Optional[str] = None
    rule_msg: Optional[str] = None
    zone: Optional[str] = None
    variable: Optional[str] = None
    matcher: str = "equals"
    value: Optional[str] = None
    description: Optional[str] = None
    action: str = Field(default="remove", pattern="^(remove|allow|comment|update)$")
    update_action: Optional[str] = None
    update_target: Optional[str] = None
    condition_variable: Optional[str] = None
    condition_operator: str = "equals"
    condition_value: Optional[str] = None


class WafExceptionCreate(WafExceptionBase):
    pass


WafExceptionUpdate = _optional_update(WafExceptionBase)


class WafExceptionResponse(WafExceptionBase):
    id: int
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class WafSiemIntegrationBase(BaseModel):
    name: str
    integration_type: str = Field(default="webhook", pattern="^(webhook|syslog|elastic)$")
    target: str
    format: str = Field(default="json", pattern="^(json|syslog|cef)$")
    auth_header: Optional[str] = None
    enabled: bool = True


class WafSiemIntegrationCreate(WafSiemIntegrationBase):
    pass


WafSiemIntegrationUpdate = _optional_update(WafSiemIntegrationBase)


class WafSiemIntegrationResponse(WafSiemIntegrationBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WafRuleVersionBase(BaseModel):
    waf_rule_id: int
    version: str
    snapshot: Dict[str, Any]
    created_by: Optional[str] = None


class WafRuleVersionCreate(WafRuleVersionBase):
    pass


WafRuleVersionUpdate = _optional_update(WafRuleVersionBase)


class WafRuleVersionResponse(WafRuleVersionBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = ['WafExceptionBase', 'WafExceptionCreate', 'WafExceptionResponse', 'WafExceptionUpdate', 'WafRuleBase', 'WafRuleCreate', 'WafRuleResponse', 'WafRuleUpdate', 'WafRuleVersionBase', 'WafRuleVersionCreate', 'WafRuleVersionResponse', 'WafRuleVersionUpdate', 'WafSiemIntegrationBase', 'WafSiemIntegrationCreate', 'WafSiemIntegrationResponse', 'WafSiemIntegrationUpdate']
