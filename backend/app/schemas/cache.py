from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class CacheConfigBase(BaseModel):
    backend_id: int
    # Memory cache (HAProxy native in-memory)
    haproxy_enabled: bool = False
    haproxy_total_max_size: int = Field(default=100, ge=1, le=4095)  # MB
    haproxy_max_object_size: int = Field(default=1000000, ge=1)  # bytes
    haproxy_max_age: int = Field(default=300, ge=1)  # seconds
    haproxy_process_vary: bool = True
    haproxy_max_secondary_entries: int = Field(default=10, ge=0)
    haproxy_cache_condition: Optional[str] = None
    # RFC 7234 compliance for the memory cache. Default False (CDN-style):
    # request-side Cache-Control/Pragma headers are stripped before the cache
    # lookup so a single client's "no-cache" reload does not bypass the shared
    # cache for everyone. When True, the headers are honored per RFC 7234.
    haproxy_rfc7234_compliance: bool = False
    # Disk cache (file-backed, gated by global disk_cache_enabled setting)
    disk_cache_enabled: bool = False
    disk_cache_ttl: int = Field(default=120, ge=1)  # seconds
    disk_cache_grace: int = Field(default=600, ge=0)  # seconds
    disk_cache_purge_enabled: bool = True


class CacheConfigCreate(CacheConfigBase):
    pass


CacheConfigUpdate = _optional_update(CacheConfigBase)


class CacheConfigResponse(CacheConfigBase):
    id: int
    backend_name: str = ""
    # Number of enabled cacheability rules. Zero means nothing is cached, which
    # the UI surfaces as a warning when a tier is enabled.
    rule_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CacheRuleBase(BaseModel):
    """Ordered, first-match-wins cacheability rule.
    
    Request-phase match types (evaluated on request): path, filename, extension, method, query_string
    Response-phase match types (evaluated on response): content_type, status_code
    """
    match_type: str = Field(description="path | filename | extension | method | query_string | content_type | status_code")
    pattern: str = Field(description="e.g. /downloads/, linux.iso, png, GET, nocache, application/json, 200")
    action: str = Field(default="cache", description="cache | bypass")
    tier: str = Field(description="memory | disk (required - choose which cache tier)")
    enabled: bool = True
    priority: int = 0

    @field_validator("match_type")
    @classmethod
    def _check_match_type(cls, v):
        from ..services.cache_rules import MATCH_TYPES
        if v is not None and v not in MATCH_TYPES:
            raise ValueError(f"match_type must be one of: {', '.join(MATCH_TYPES)}")
        return v

    @field_validator("action")
    @classmethod
    def _check_action(cls, v):
        from ..services.cache_rules import ACTIONS
        if v is not None and v not in ACTIONS:
            raise ValueError(f"action must be one of: {', '.join(ACTIONS)}")
        return v

    @field_validator("tier")
    @classmethod
    def _check_tier(cls, v):
        from ..services.cache_rules import TIERS
        if v is not None and v not in TIERS:
            raise ValueError(f"tier must be one of: {', '.join(TIERS)}")
        return v

    @model_validator(mode="after")
    def _normalize(self):
        """Canonicalize the pattern so '/downloads/*' and '*.png' work as typed.

        Both fields are Optional on the derived Update model, so normalization
        only runs when the pair is actually present. A partial update that
        changes only the pattern is normalized by the route, which supplies the
        stored match_type.
        """
        from ..services.cache_rules import normalize_pattern
        if self.match_type is not None and self.pattern is not None:
            self.pattern = normalize_pattern(self.match_type, self.pattern)
        return self


class CacheRuleCreate(CacheRuleBase):
    pass


CacheRuleUpdate = _optional_update(CacheRuleBase)


class CacheRuleResponse(CacheRuleBase):
    id: int
    cache_config_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CacheRuleReorder(BaseModel):
    """New ordering for a cache config's rules, as a list of rule IDs."""
    rule_ids: List[int]


class CacheClearResponse(BaseModel):
    memory_cleared: bool = False
    disk_cleared: bool = False
    message: str = ""


class CacheStatusResponse(BaseModel):
    disk_cache_globally_enabled: bool = False


class CacheMetricsResponse(BaseModel):
    snapshots: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


__all__ = ['CacheClearResponse', 'CacheConfigBase', 'CacheConfigCreate', 'CacheConfigResponse', 'CacheConfigUpdate', 'CacheMetricsResponse', 'CacheRuleBase', 'CacheRuleCreate', 'CacheRuleReorder', 'CacheRuleResponse', 'CacheRuleUpdate', 'CacheStatusResponse']
