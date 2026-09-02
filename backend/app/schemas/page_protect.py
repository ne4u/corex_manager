from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class PageProtectPolicyBase(BaseModel):
    name: str
    enabled: bool = True
    backend_ids: List[int] = Field(default_factory=list)  # [] = all backends
    mode: str = "monitor"  # "monitor" | "enforce"
    sample_rate_percent: int = Field(default=100, ge=1, le=100)
    report_path: str = "/_csp-report"
    directives: Dict[str, List[str]] = Field(default_factory=dict)


class PageProtectPolicyCreate(PageProtectPolicyBase):
    pass


class PageProtectPolicyUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    backend_ids: Optional[List[int]] = None
    mode: Optional[str] = None
    sample_rate_percent: Optional[int] = Field(default=None, ge=1, le=100)
    report_path: Optional[str] = None
    directives: Optional[Dict[str, List[str]]] = None


class PageProtectPolicyResponse(PageProtectPolicyBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CspReportResponse(BaseModel):
    id: int
    policy_id: Optional[int] = None
    captured_at: datetime
    client_ip: Optional[str] = None
    document_uri: Optional[str] = None
    referrer: Optional[str] = None
    violated_directive: Optional[str] = None
    effective_directive: Optional[str] = None
    original_policy: Optional[str] = None
    blocked_uri: Optional[str] = None
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    status_code: Optional[int] = None
    script_sample: Optional[str] = None
    backend_name: Optional[str] = None
    listener_name: Optional[str] = None
    report_type: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PageProtectScriptBase(BaseModel):
    url: str
    resource_type: str = "script"
    domain: Optional[str] = None
    notes: Optional[str] = None


class PageProtectScriptCreate(BaseModel):
    url: str
    resource_type: str = "script"
    notes: Optional[str] = None


class PageProtectScriptUpdate(BaseModel):
    notes: Optional[str] = None
    hash_changed: Optional[bool] = None


class PageProtectScriptResponse(BaseModel):
    id: int
    url: str
    resource_type: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    domain: Optional[str] = None
    first_hash: Optional[str] = None
    first_hash_at: Optional[datetime] = None
    last_hash: Optional[str] = None
    last_hash_at: Optional[datetime] = None
    hash_checked_at: Optional[datetime] = None
    hash_changed: bool
    notes: Optional[str] = None
    source: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PageProtectSettings(BaseModel):
    monitoring_enabled: bool = False
    change_detection_enabled: bool = False
    change_detection_interval_hours: int = 24
    report_retention_days: int = 7
    report_path: str = "/_csp-report"
    beacon_injection_enabled: bool = False
    beacon_path: str = "/_cx-assets"
    beacon_script_path: str = "/_cx-assets.js"
    beacon_content_types: str = "text/html"
    beacon_path_patterns: str = ""
    beacon_backend_ids: list = []
    auto_prune_stale_days: int = 7


class PageProtectStats(BaseModel):
    total_scripts: int = 0
    total_reports: int = 0
    changed_scripts: int = 0
    active_policies: int = 0
    reports_24h: int = 0
    top_violated_directives: List[Dict[str, Any]] = Field(default_factory=list)
    top_blocked_uris: List[Dict[str, Any]] = Field(default_factory=list)


class PageProtectSampleResponse(BaseModel):
    stored: int


class PageProtectBaselineStatus(BaseModel):
    status: str = "idle"  # idle | baselining | complete
    start: Optional[str] = None
    end: Optional[str] = None
    note: str = ""
    elapsed_seconds: Optional[int] = None
    duration_seconds: Optional[int] = None
    scripts_count: Optional[int] = None
    reports_count: Optional[int] = None
    distinct_ips: Optional[int] = None
    distinct_pages: Optional[int] = None


class PageProtectBaselineStartRequest(BaseModel):
    note: str = ""


class PageProtectRecommendSource(BaseModel):
    origin: str
    occurrence_count: int = 0
    distinct_ips: int = 0
    sample_url: str = ""


class PageProtectRecommendSummary(BaseModel):
    scripts_analyzed: int = 0
    reports_analyzed: int = 0
    baseline_start: str = ""
    baseline_end: str = ""
    directives_count: int = 0
    backend_filter: Optional[List[str]] = None


class PageProtectRecommendResponse(BaseModel):
    directives: Dict[str, List[str]] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    sources: Dict[str, List[PageProtectRecommendSource]] = Field(default_factory=dict)
    summary: PageProtectRecommendSummary = Field(default_factory=PageProtectRecommendSummary)


__all__ = ['CspReportResponse', 'PageProtectBaselineStartRequest', 'PageProtectBaselineStatus', 'PageProtectPolicyBase', 'PageProtectPolicyCreate', 'PageProtectPolicyResponse', 'PageProtectPolicyUpdate', 'PageProtectRecommendResponse', 'PageProtectRecommendSource', 'PageProtectRecommendSummary', 'PageProtectSampleResponse', 'PageProtectScriptBase', 'PageProtectScriptCreate', 'PageProtectScriptResponse', 'PageProtectScriptUpdate', 'PageProtectSettings', 'PageProtectStats']
