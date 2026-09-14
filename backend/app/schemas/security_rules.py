from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ._base import _optional_update


class SecurityRuleBase(BaseModel):
    name: str
    enabled: bool = True
    listener_ids: list[int] | None = []
    expression: str
    action: str = Field(
        default="block",
        pattern="^(block|allow|redirect|custom_response|challenge|log|skip_rules|skip_rules_ratelimit|skip_rules_waf|skip_all)$",
    )
    log: bool = True
    no_log: bool = False
    status_code: int | None = Field(default=None, ge=100, le=599)
    redirect_url: str | None = None
    redirect_code: int | None = Field(default=None, ge=300, le=399)
    error_page_id: int | None = None


class SecurityRuleCreate(SecurityRuleBase):
    pass


SecurityRuleUpdate = _optional_update(SecurityRuleBase)


class SecurityRuleResponse(SecurityRuleBase):
    id: int
    priority: int
    expression_ast: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityRuleReorder(BaseModel):
    ordered_ids: list[int]


class SecurityRuleValidateRequest(BaseModel):
    expression: str


class SecurityRuleValidateResponse(BaseModel):
    ok: bool
    ast: dict[str, Any] | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Risk Rules
# ---------------------------------------------------------------------------


class RiskRuleBase(BaseModel):
    name: str
    enabled: bool = True
    listener_ids: list[int] | None = []
    expression: str
    points: int = Field(default=0, ge=-99, le=99)
    category: str | None = None
    log: bool = True
    ruleset_id: int = 1  # default ruleset


class RiskRuleCreate(RiskRuleBase):
    pass


RiskRuleUpdate = _optional_update(RiskRuleBase)


class RiskRuleResponse(RiskRuleBase):
    id: int
    priority: int
    expression_ast: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskRuleReorder(BaseModel):
    ordered_ids: list[int]


class RiskRuleValidateRequest(BaseModel):
    expression: str


class RiskRuleValidateResponse(BaseModel):
    ok: bool
    ast: dict[str, Any] | None = None
    error: str | None = None
    suggested_category: str | None = None


class RiskSeedBaselineResponse(BaseModel):
    created_rules: int
    created_lists: int
    created_rulesets: int
    skipped: int


# ---------------------------------------------------------------------------
# Risk Ruleset schemas
# ---------------------------------------------------------------------------


class RiskRulesetBase(BaseModel):
    name: str
    description: str | None = None
    enabled: bool = True


class RiskRulesetCreate(RiskRulesetBase):
    pass


RiskRulesetUpdate = _optional_update(RiskRulesetBase)


class RiskRulesetResponse(RiskRulesetBase):
    id: int
    slug: str
    priority: int
    rule_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    "RiskRuleBase",
    "RiskRuleCreate",
    "RiskRuleReorder",
    "RiskRuleResponse",
    "RiskRuleUpdate",
    "RiskRuleValidateRequest",
    "RiskRuleValidateResponse",
    "RiskRulesetBase",
    "RiskRulesetCreate",
    "RiskRulesetResponse",
    "RiskRulesetUpdate",
    "RiskSeedBaselineResponse",
    "SecurityRuleBase",
    "SecurityRuleCreate",
    "SecurityRuleReorder",
    "SecurityRuleResponse",
    "SecurityRuleUpdate",
    "SecurityRuleValidateRequest",
    "SecurityRuleValidateResponse",
]
