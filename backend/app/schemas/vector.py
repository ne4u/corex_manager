from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

VALID_SOURCES = ("corex", "waf", "mcp")
VALID_SINK_TYPES = (
    "aws_s3",
    "azure_logs_ingestion",
    "datadog_logs",
    "elasticsearch",
    "http",
    "new_relic",
    "splunk_hec_logs",
)

# Required option fields per sink type. Secret fields are listed separately so
# the API can encrypt them at rest and mask them on read.
REQUIRED_OPTIONS: Dict[str, List[str]] = {
    "aws_s3": ["bucket", "region"],
    "azure_logs_ingestion": ["endpoint", "dcr_immutable_id", "stream_name"],
    "datadog_logs": ["api_key"],
    "elasticsearch": ["endpoints"],
    "http": ["uri"],
    "new_relic": ["account_id", "license_key"],
    "splunk_hec_logs": ["endpoint", "token"],
}

SECRET_OPTIONS: Dict[str, List[str]] = {
    "aws_s3": ["access_key_id", "secret_access_key", "session_token"],
    "azure_logs_ingestion": ["client_secret"],
    "datadog_logs": ["api_key"],
    "elasticsearch": ["password", "api_key"],
    "http": ["password", "token"],
    "new_relic": ["license_key"],
    "splunk_hec_logs": ["token"],
}

SECRET_MASK = "********"


class VectorSinkBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    type: str
    source: str = "corex"
    options: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("type")
    @classmethod
    def _type_allowed(cls, v: str) -> str:
        if v not in VALID_SINK_TYPES:
            raise ValueError(f"type must be one of: {', '.join(VALID_SINK_TYPES)}")
        return v

    @field_validator("source")
    @classmethod
    def _source_allowed(cls, v: str) -> str:
        if v not in VALID_SOURCES:
            raise ValueError(f"source must be one of: {', '.join(VALID_SOURCES)}")
        return v

    @field_validator("name")
    @classmethod
    def _name_clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be empty")
        return v

    @model_validator(mode="after")
    def _required_options(self):
        if self.enabled:
            for key in REQUIRED_OPTIONS.get(self.type, []):
                val = self.options.get(key)
                # "********" on update means "keep existing secret" — treat as present.
                if val is None or (isinstance(val, str) and not val.strip()):
                    raise ValueError(f"options.{key} is required for sink type '{self.type}'")
        return self


class VectorSinkCreate(VectorSinkBase):
    pass


VectorSinkUpdate = VectorSinkBase


class VectorSinkResponse(VectorSinkBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class VectorSinkTestRequest(BaseModel):
    name: str = "test"
    type: str
    source: str = "corex"
    options: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    sink_id: Optional[int] = None
    send_test_event: bool = False

    @field_validator("type")
    @classmethod
    def _type_allowed(cls, v: str) -> str:
        if v not in VALID_SINK_TYPES:
            raise ValueError(f"type must be one of: {', '.join(VALID_SINK_TYPES)}")
        return v

    @field_validator("source")
    @classmethod
    def _source_allowed(cls, v: str) -> str:
        if v not in VALID_SOURCES:
            raise ValueError(f"source must be one of: {', '.join(VALID_SOURCES)}")
        return v


class VectorSinkTestResponse(BaseModel):
    ok: bool
    output: str


class VectorValidateResponse(BaseModel):
    valid: bool
    output: str


class VectorPreviewResponse(BaseModel):
    config: str


class VectorPipelineResponse(BaseModel):
    sources: Dict[str, bool]
    sinks: List[VectorSinkResponse]
    applied: bool
    runtime: Dict[str, Any]
    vector_status: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    'VectorPipelineResponse', 'VectorPreviewResponse', 'VectorSinkBase',
    'VectorSinkCreate', 'VectorSinkResponse', 'VectorSinkTestRequest',
    'VectorSinkTestResponse', 'VectorSinkUpdate',
    'VectorValidateResponse',
]
