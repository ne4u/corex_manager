from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PageProtectPolicyBase(BaseModel):
    name: str
    enabled: bool = True
    backend_ids: list[int] = Field(default_factory=list)  # [] = all backends
    mode: str = "monitor"  # "monitor" | "enforce"
    sample_rate_percent: int = Field(default=100, ge=1, le=100)
    report_path: str = "/_csp-report"
    directives: dict[str, list[str]] = Field(default_factory=dict)


class PageProtectPolicyCreate(PageProtectPolicyBase):
    pass


class PageProtectPolicyUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    backend_ids: list[int] | None = None
    mode: str | None = None
    sample_rate_percent: int | None = Field(default=None, ge=1, le=100)
    report_path: str | None = None
    directives: dict[str, list[str]] | None = None


class PageProtectPolicyResponse(PageProtectPolicyBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CspReportResponse(BaseModel):
    id: int
    policy_id: int | None = None
    captured_at: datetime
    client_ip: str | None = None
    document_uri: str | None = None
    referrer: str | None = None
    violated_directive: str | None = None
    effective_directive: str | None = None
    original_policy: str | None = None
    blocked_uri: str | None = None
    source_file: str | None = None
    line_number: int | None = None
    column_number: int | None = None
    status_code: int | None = None
    script_sample: str | None = None
    backend_name: str | None = None
    listener_name: str | None = None
    report_type: str | None = None

    model_config = ConfigDict(from_attributes=True)


class PageProtectScriptBase(BaseModel):
    url: str
    resource_type: str = "script"
    domain: str | None = None
    notes: str | None = None


class PageProtectScriptCreate(BaseModel):
    url: str
    resource_type: str = "script"
    notes: str | None = None
    fetch_method: str = "auto"  # auto | GET | POST

    @field_validator("fetch_method")
    @classmethod
    def validate_fetch_method(cls, v: str) -> str:
        v = (v or "auto").upper()
        if v not in ("AUTO", "GET", "POST"):
            raise ValueError("fetch_method must be 'auto', 'GET', or 'POST'")
        return v


class PageProtectScriptUpdate(BaseModel):
    notes: str | None = None
    hash_changed: bool | None = None
    ignored: bool | None = None
    fetch_method: str | None = None  # auto | GET | POST

    @field_validator("fetch_method")
    @classmethod
    def validate_fetch_method(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.upper()
        if v not in ("AUTO", "GET", "POST"):
            raise ValueError("fetch_method must be 'auto', 'GET', or 'POST'")
        return v


class PageProtectScriptResponse(BaseModel):
    id: int
    url: str
    resource_type: str | None = None
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    domain: str | None = None
    first_hash: str | None = None
    first_hash_at: datetime | None = None
    last_hash: str | None = None
    last_hash_at: datetime | None = None
    hash_checked_at: datetime | None = None
    hash_changed: bool
    ignored: bool = False
    has_content: bool = False
    notes: str | None = None
    source: str | None = None
    fetch_method: str | None = None
    last_fetch_method: str | None = None

    model_config = ConfigDict(from_attributes=True)


class PageProtectSettings(BaseModel):
    monitoring_enabled: bool = False
    change_detection_enabled: bool = False
    change_detection_interval_hours: int = 24
    report_retention_days: int = 7
    report_path: str = "/_csp-report"
    beacon_injection_enabled: bool = False
    beacon_trust_enabled: bool = False
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
    top_violated_directives: list[dict[str, Any]] = Field(default_factory=list)
    top_blocked_uris: list[dict[str, Any]] = Field(default_factory=list)


class PageProtectSampleResponse(BaseModel):
    stored: int


class PageProtectBaselineStatus(BaseModel):
    status: str = "idle"  # idle | baselining | complete
    start: str | None = None
    end: str | None = None
    note: str = ""
    elapsed_seconds: int | None = None
    duration_seconds: int | None = None
    scripts_count: int | None = None
    reports_count: int | None = None
    distinct_ips: int | None = None
    distinct_pages: int | None = None


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
    backend_filter: list[str] | None = None


class PageProtectRecommendResponse(BaseModel):
    directives: dict[str, list[str]] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    sources: dict[str, list[PageProtectRecommendSource]] = Field(default_factory=dict)
    summary: PageProtectRecommendSummary = Field(default_factory=PageProtectRecommendSummary)


__all__ = [
    "CspReportResponse",
    "PageProtectBaselineStartRequest",
    "PageProtectBaselineStatus",
    "PageProtectPolicyBase",
    "PageProtectPolicyCreate",
    "PageProtectPolicyResponse",
    "PageProtectPolicyUpdate",
    "PageProtectRecommendResponse",
    "PageProtectRecommendSource",
    "PageProtectRecommendSummary",
    "PageProtectSampleResponse",
    "PageProtectScriptBase",
    "PageProtectScriptCreate",
    "PageProtectScriptResponse",
    "PageProtectScriptUpdate",
    "PageProtectSettings",
    "PageProtectStats",
]
