from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship

from .base import Base, utcnow


class OpenApiSpec(Base):
    """Uploaded OpenAPI 3.x specification for API schema validation.

    When enabled, the spec is parsed into per-endpoint JSON Schemas (ApiSchema
    rows with source='openapi') that the Rust schema_validator module enforces
    at the proxy layer.
    """

    __tablename__ = "openapi_specs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    spec = Column(Text, nullable=False)  # raw JSON or YAML text
    spec_json = Column(JSON, nullable=True)  # parsed spec (for quick lookup)
    version = Column(String, nullable=True)  # OpenAPI version (e.g. "3.0.3")
    listener_ids = Column(JSON, default=list, nullable=True)  # [] = all
    backend_ids = Column(JSON, default=list, nullable=True)  # [] = all
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    schemas = relationship("ApiSchema", back_populates="spec", cascade="all, delete-orphan")


class ApiSchema(Base):
    """JSON Schema for a specific endpoint (method + path).

    Schemas come from two sources:
    - source='openapi': extracted from an uploaded OpenApiSpec.
    - source='learned': inferred from observed traffic by the profiler sampler.
    """

    __tablename__ = "api_schemas"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    method = Column(String, nullable=False)  # GET, POST, PUT, PATCH, DELETE
    path = Column(String, nullable=False)  # exact path or pattern (e.g. /api/v1/users)
    schema = Column(JSON, nullable=False)  # JSON Schema for the request body
    spec_id = Column(Integer, ForeignKey("openapi_specs.id"), nullable=True)
    source = Column(String, default="openapi")  # openapi | learned
    enabled = Column(Boolean, default=True)
    sample_count = Column(Integer, default=0)  # for learned schemas: observations
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    spec = relationship("OpenApiSpec", back_populates="schemas")


class AuthPolicy(Base):
    """Authentication validation policy for API endpoints.

    When enabled, the Rust jwt_validator module validates JWT signatures and
    claims (or API keys against an ApiKeyList) at the proxy layer. Failed auth
    can block (401), challenge (redirect to captcha), or log only.
    """

    __tablename__ = "auth_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    listener_ids = Column(JSON, default=list, nullable=True)  # [] = all
    backend_ids = Column(JSON, default=list, nullable=True)  # [] = all
    auth_type = Column(String, default="jwt")  # jwt | api_key | both
    # JWT config
    jwt_algorithm = Column(String, default="hs256")  # hs256 | rs256 | es256
    jwt_secret_env = Column(String, nullable=True)  # env var name for HS256 secret
    jwt_jwks_url = Column(String, nullable=True)  # JWKS URL for RS256/ES256
    jwt_issuer = Column(String, nullable=True)  # expected iss claim
    jwt_audience = Column(String, nullable=True)  # expected aud claim
    jwt_claim_headers = Column(JSON, default=list, nullable=True)  # [{claim, header}] to inject
    # API-key config
    api_key_header = Column(String, nullable=True)  # e.g. X-API-Key
    api_key_list_id = Column(Integer, ForeignKey("api_key_lists.id"), nullable=True)
    # Failure behavior
    on_failure = Column(String, default="block")  # block | challenge | log_only
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    api_key_list = relationship("ApiKeyList", foreign_keys=[api_key_list_id])


class ApiKeyList(Base):
    """Named collection of API keys for proxy-side validation.

    Entries are exact-match strings (not regex). Written to
    {API_ARMOR_DIR}/api-keys/{name}.lst for HAProxy -m str -f matching.
    """

    __tablename__ = "api_key_lists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    entries = relationship("ApiKeyListEntry", back_populates="list", cascade="all, delete-orphan")


class ApiKeyListEntry(Base):
    __tablename__ = "api_key_list_entries"

    id = Column(Integer, primary_key=True, index=True)
    list_id = Column(Integer, ForeignKey("api_key_lists.id"), nullable=False)
    value = Column(String, nullable=False)  # exact API key string
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    list = relationship("ApiKeyList", back_populates="entries")


class ApiProfile(Base):
    """Learned behavioral baseline for an API endpoint.

    Profiles are multi-dimensional: each dimension (body structure, GraphQL
    metrics, content-type, auth, status codes, client signals) stores the set
    of observed normal values. The profiler sampler upserts these from the
    separate API Armor profiling log.
    """

    __tablename__ = "api_profiles"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    method = Column(String, nullable=False)  # GET, POST, etc.
    path = Column(String, nullable=False)  # normalized path (IDs replaced)
    dimensions = Column(JSON, nullable=False)  # learned baseline per dimension
    sample_count = Column(Integer, default=0)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow)
    status_codes = Column(JSON, default=dict, nullable=True)  # {code: count}
    learned = Column(Boolean, default=False)  # confirmed as normal baseline


class ApiAnomaly(Base):
    """A request that deviated from the learned ApiProfile on one or more dimensions.

    Recorded by the profiler sampler when enforcement mode is active and a
    request's dimension values are not in the learned baseline.
    """

    __tablename__ = "api_anomalies"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    method = Column(String, nullable=False)
    path = Column(String, nullable=False)
    dimension = Column(String, nullable=False)  # which dimension was anomalous
    observed_value = Column(Text, nullable=True)  # what was seen
    expected_values = Column(JSON, nullable=True)  # what the baseline expected
    request_id = Column(String, nullable=True)  # HAProxy unique-id
    client_ip = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)


__all__ = [
    "OpenApiSpec",
    "ApiSchema",
    "AuthPolicy",
    "ApiKeyList",
    "ApiKeyListEntry",
    "ApiProfile",
    "ApiAnomaly",
]
