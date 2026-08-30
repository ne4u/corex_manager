from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class SecurityRuleBase(BaseModel):
    name: str
    enabled: bool = True
    listener_ids: Optional[List[int]] = []
    expression: str
    action: str = Field(default="block", pattern="^(block|allow|redirect|custom_response|challenge|skip_rules|skip_rules_ratelimit|skip_rules_waf|skip_all)$")
    log: bool = True
    no_log: bool = False
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    redirect_url: Optional[str] = None
    redirect_code: Optional[int] = Field(default=None, ge=300, le=399)
    error_page_id: Optional[int] = None


class SecurityRuleCreate(SecurityRuleBase):
    pass


SecurityRuleUpdate = _optional_update(SecurityRuleBase)


class SecurityRuleResponse(SecurityRuleBase):
    id: int
    priority: int
    expression_ast: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityRuleReorder(BaseModel):
    ordered_ids: List[int]


class SecurityRuleValidateRequest(BaseModel):
    expression: str


class SecurityRuleValidateResponse(BaseModel):
    ok: bool
    ast: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Risk Rules
# ---------------------------------------------------------------------------

class RiskRuleBase(BaseModel):
    name: str
    enabled: bool = True
    listener_ids: Optional[List[int]] = []
    expression: str
    points: int = Field(default=0, ge=-99, le=99)
    category: Optional[str] = None
    log: bool = True
    ruleset_id: int = 1  # default ruleset


class RiskRuleCreate(RiskRuleBase):
    pass


RiskRuleUpdate = _optional_update(RiskRuleBase)


class RiskRuleResponse(RiskRuleBase):
    id: int
    priority: int
    expression_ast: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskRuleReorder(BaseModel):
    ordered_ids: List[int]


class RiskRuleValidateRequest(BaseModel):
    expression: str


class RiskRuleValidateResponse(BaseModel):
    ok: bool
    ast: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    suggested_category: Optional[str] = None


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
    description: Optional[str] = None
    enabled: bool = True


class RiskRulesetCreate(RiskRulesetBase):
    pass


RiskRulesetUpdate = _optional_update(RiskRulesetBase)


class RiskRulesetResponse(RiskRulesetBase):
    id: int
    slug: str
    priority: int
    rule_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    'RiskRuleBase', 'RiskRuleCreate', 'RiskRuleReorder', 'RiskRuleResponse',
    'RiskRuleUpdate', 'RiskRuleValidateRequest', 'RiskRuleValidateResponse',
    'RiskRulesetBase', 'RiskRulesetCreate', 'RiskRulesetResponse', 'RiskRulesetUpdate',
    'RiskSeedBaselineResponse',
    'SecurityRuleBase', 'SecurityRuleCreate', 'SecurityRuleReorder',
    'SecurityRuleResponse', 'SecurityRuleUpdate', 'SecurityRuleValidateRequest',
    'SecurityRuleValidateResponse',
]
