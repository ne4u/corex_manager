"""API Armor endpoint router.

Provides settings management for the API Armor feature (GraphQL protection,
schema validation, auth validation, behavioral profiling). Full CRUD endpoints
for OpenAPI specs, schemas, auth policies, API key lists, profiles, and
anomalies will be added in subsequent phases.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..deps import get_current_user, get_db, require_write, rate_limit
from ...core.config import get_settings
from ...models.api_armor import OpenApiSpec, ApiSchema
from ...services.settings import get_setting, set_setting

settings = get_settings()
router = APIRouter()


class ApiArmorSettings(BaseModel):
    """API Armor feature settings (stored in DB settings table with env fallbacks)."""
    api_armor_enabled: bool = Field(default=False, description="Master toggle for API Armor")
    api_armor_max_body_bytes: int = Field(default=1048576, description="Max request body size for inspection (bytes)")
    api_armor_module_enabled: bool = Field(default=True, description="Use Rust Lua module (true) vs Lua fallback (false)")
    api_armor_schema_learning_enabled: bool = Field(default=False, description="Enable learned schema inference from traffic")
    api_armor_profiling_learning_enabled: bool = Field(default=False, description="Enable behavioral profile learning from traffic")
    api_armor_profile_retention_days: int = Field(default=30, description="Retention for behavioral profiles and anomalies")


def _get_api_armor_settings(db: Session) -> dict:
    """Read all API Armor settings from DB with env fallbacks."""
    return {
        "api_armor_enabled": get_setting(db, "api_armor_enabled", str(settings.API_ARMOR_ENABLED)).lower() in ("true", "1", "yes"),
        "api_armor_max_body_bytes": int(get_setting(db, "api_armor_max_body_bytes", str(settings.API_ARMOR_MAX_BODY_BYTES))),
        "api_armor_module_enabled": get_setting(db, "api_armor_module_enabled", str(settings.API_ARMOR_MODULE_ENABLED)).lower() in ("true", "1", "yes"),
        "api_armor_schema_learning_enabled": get_setting(db, "api_armor_schema_learning_enabled", "false").lower() in ("true", "1", "yes"),
        "api_armor_profiling_learning_enabled": get_setting(db, "api_armor_profiling_learning_enabled", "false").lower() in ("true", "1", "yes"),
        "api_armor_profile_retention_days": int(get_setting(db, "api_armor_profile_retention_days", str(settings.API_ARMOR_PROFILE_RETENTION_DAYS))),
    }


def _update_api_armor_settings(db: Session, updates: dict) -> dict:
    """Update API Armor settings in DB."""
    if "api_armor_enabled" in updates:
        enabling = str(updates["api_armor_enabled"]).lower() in ("true", "1", "yes")
        if enabling:
            # API Armor depends on req_fp subfields at runtime (req_fp_ctype,
            # req_fp_method, req_fp_path, etc. are read by the body parser).
            # Reject enabling API Armor if request fingerprinting is disabled.
            req_fp_on = get_setting(db, "req_fp_enabled", str(settings.REQ_FP_ENABLED)).lower() in ("true", "1", "yes")
            if not req_fp_on:
                raise HTTPException(
                    status_code=400,
                    detail="API Armor requires HTTP Request Fingerprinting to be enabled. "
                           "Enable req_fp in Global Options first.",
                )
        set_setting(db, "api_armor_enabled", str(updates["api_armor_enabled"]).lower())
    if "api_armor_max_body_bytes" in updates:
        val = int(updates["api_armor_max_body_bytes"])
        if val < 1024:
            raise HTTPException(status_code=400, detail="api_armor_max_body_bytes must be at least 1024 bytes")
        set_setting(db, "api_armor_max_body_bytes", str(val))
    if "api_armor_module_enabled" in updates:
        set_setting(db, "api_armor_module_enabled", str(updates["api_armor_module_enabled"]).lower())
    if "api_armor_schema_learning_enabled" in updates:
        set_setting(db, "api_armor_schema_learning_enabled", str(updates["api_armor_schema_learning_enabled"]).lower())
    if "api_armor_profiling_learning_enabled" in updates:
        set_setting(db, "api_armor_profiling_learning_enabled", str(updates["api_armor_profiling_learning_enabled"]).lower())
    if "api_armor_profile_retention_days" in updates:
        val = int(updates["api_armor_profile_retention_days"])
        if val < 1:
            raise HTTPException(status_code=400, detail="api_armor_profile_retention_days must be at least 1")
        set_setting(db, "api_armor_profile_retention_days", str(val))
    db.commit()
    return _get_api_armor_settings(db)


@router.get("/api-armor/settings", response_model=ApiArmorSettings)
def get_api_armor_settings_route(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get API Armor feature settings."""
    return ApiArmorSettings(**_get_api_armor_settings(db))


@router.put("/api-armor/settings", response_model=ApiArmorSettings)
def update_api_armor_settings_route(
    s_in: ApiArmorSettings,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Update API Armor feature settings."""
    result = _update_api_armor_settings(db, s_in.model_dump())
    return ApiArmorSettings(**result)


# ----- Preset Security Rules -----

class PresetRuleResponse(BaseModel):
    """A preset API Armor security rule definition."""
    name: str
    description: str
    expression: str
    action: str
    log: bool
    status_code: Optional[int] = None


class ApplyPresetsRequest(BaseModel):
    """Request to apply preset rules."""
    listener_ids: Optional[List[int]] = None


class ApplyPresetsResponse(BaseModel):
    """Response after applying preset rules."""
    applied: int
    rules: List[dict] = []


@router.get("/api-armor/presets", response_model=List[PresetRuleResponse])
def list_preset_rules(
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List available API Armor preset security rules."""
    from ...services.api_armor_presets import get_preset_rules
    presets = get_preset_rules()
    return [PresetRuleResponse(**p) for p in presets]


@router.post("/api-armor/presets/apply", response_model=ApplyPresetsResponse)
def apply_preset_rules(
    req: ApplyPresetsRequest,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Apply all API Armor preset security rules that don't already exist."""
    from ...services.api_armor_presets import apply_preset_rules as _apply
    created = _apply(db, listener_ids=req.listener_ids)
    return ApplyPresetsResponse(
        applied=len(created),
        rules=[{"id": r.id, "name": r.name} for r in created],
    )


# ----- OpenAPI Specs -----

class OpenApiSpecCreate(BaseModel):
    name: str
    spec: str  # raw JSON or YAML text
    listener_ids: List[int] = Field(default_factory=list)
    backend_ids: List[int] = Field(default_factory=list)


class OpenApiSpecResponse(BaseModel):
    id: int
    name: str
    version: Optional[str] = None
    listener_ids: List[int] = Field(default_factory=list)
    backend_ids: List[int] = Field(default_factory=list)
    enabled: bool = True
    schema_count: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ApiSchemaResponse(BaseModel):
    id: int
    name: str
    method: str
    path: str
    schema_def: dict
    spec_id: Optional[int] = None
    source: str = "openapi"
    enabled: bool = True
    sample_count: int = 0


@router.get("/api-armor/specs", response_model=List[OpenApiSpecResponse])
def list_openapi_specs(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List all uploaded OpenAPI specs."""
    specs = db.query(OpenApiSpec).order_by(OpenApiSpec.id).all()
    result = []
    for s in specs:
        schema_count = db.query(ApiSchema).filter(ApiSchema.spec_id == s.id).count()
        result.append(OpenApiSpecResponse(
            id=s.id,
            name=s.name,
            version=s.version,
            listener_ids=s.listener_ids or [],
            backend_ids=s.backend_ids or [],
            enabled=s.enabled,
            schema_count=schema_count,
            created_at=s.created_at.isoformat() if s.created_at else None,
            updated_at=s.updated_at.isoformat() if s.updated_at else None,
        ))
    return result


@router.post("/api-armor/specs", response_model=OpenApiSpecResponse)
def create_openapi_spec(
    s_in: OpenApiSpecCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Upload and import an OpenAPI spec, extracting per-endpoint schemas."""
    from ...services.api_armor_schemas import import_openapi_spec
    try:
        spec, schemas = import_openapi_spec(
            db,
            name=s_in.name,
            spec_text=s_in.spec,
            listener_ids=s_in.listener_ids,
            backend_ids=s_in.backend_ids,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return OpenApiSpecResponse(
        id=spec.id,
        name=spec.name,
        version=spec.version,
        listener_ids=spec.listener_ids or [],
        backend_ids=spec.backend_ids or [],
        enabled=spec.enabled,
        schema_count=len(schemas),
        created_at=spec.created_at.isoformat() if spec.created_at else None,
        updated_at=spec.updated_at.isoformat() if spec.updated_at else None,
    )


@router.delete("/api-armor/specs/{sid}")
def delete_openapi_spec(
    sid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Delete an OpenAPI spec and its associated schemas."""
    spec = db.get(OpenApiSpec, sid)
    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")
    db.delete(spec)
    db.commit()
    return {"status": "ok"}


@router.get("/api-armor/specs/{sid}/schemas", response_model=List[ApiSchemaResponse])
def list_spec_schemas(
    sid: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List the per-endpoint schemas extracted from an OpenAPI spec."""
    spec = db.get(OpenApiSpec, sid)
    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")
    schemas = db.query(ApiSchema).filter(ApiSchema.spec_id == sid).order_by(ApiSchema.id).all()
    return [ApiSchemaResponse(
        id=s.id,
        name=s.name,
        method=s.method,
        path=s.path,
        schema_def=s.schema,
        spec_id=s.spec_id,
        source=s.source,
        enabled=s.enabled,
        sample_count=s.sample_count or 0,
    ) for s in schemas]


@router.get("/api-armor/schemas", response_model=List[ApiSchemaResponse])
def list_all_schemas(
    method: Optional[str] = None,
    path: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List all API schemas (from OpenAPI specs and learned)."""
    q = db.query(ApiSchema)
    if method:
        q = q.filter(ApiSchema.method == method.upper())
    if path:
        q = q.filter(ApiSchema.path == path)
    if source:
        q = q.filter(ApiSchema.source == source)
    schemas = q.order_by(ApiSchema.id).all()
    return [ApiSchemaResponse(
        id=s.id,
        name=s.name,
        method=s.method,
        path=s.path,
        schema_def=s.schema,
        spec_id=s.spec_id,
        source=s.source,
        enabled=s.enabled,
        sample_count=s.sample_count or 0,
    ) for s in schemas]


@router.put("/api-armor/schemas/{sid}", response_model=ApiSchemaResponse)
def update_schema(
    sid: int,
    s_in: ApiSchemaResponse,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Update an API schema (e.g., edit a learned schema)."""
    schema = db.get(ApiSchema, sid)
    if not schema:
        raise HTTPException(status_code=404, detail="Schema not found")
    schema.enabled = s_in.enabled
    if s_in.schema_def:
        schema.schema = s_in.schema_def
    db.commit()
    db.refresh(schema)
    return ApiSchemaResponse(
        id=schema.id,
        name=schema.name,
        method=schema.method,
        path=schema.path,
        schema_json=schema.schema,
        spec_id=schema.spec_id,
        source=schema.source,
        enabled=schema.enabled,
        sample_count=schema.sample_count or 0,
    )


# ----- Auth Policies -----

class AuthPolicyCreate(BaseModel):
    name: str
    listener_ids: List[int] = Field(default_factory=list)
    backend_ids: List[int] = Field(default_factory=list)
    auth_type: str = "jwt"  # jwt | api_key | both
    jwt_algorithm: str = "hs256"
    jwt_secret_env: Optional[str] = None
    jwt_jwks_url: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_claim_headers: List[dict] = Field(default_factory=list)
    api_key_header: Optional[str] = None
    api_key_list_id: Optional[int] = None
    on_failure: str = "block"  # block | challenge | log_only
    enabled: bool = True


class AuthPolicyResponse(BaseModel):
    id: int
    name: str
    listener_ids: List[int] = Field(default_factory=list)
    backend_ids: List[int] = Field(default_factory=list)
    auth_type: str = "jwt"
    jwt_algorithm: str = "hs256"
    jwt_secret_env: Optional[str] = None
    jwt_jwks_url: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_claim_headers: List[dict] = Field(default_factory=list)
    api_key_header: Optional[str] = None
    api_key_list_id: Optional[int] = None
    on_failure: str = "block"
    enabled: bool = True


@router.get("/api-armor/auth-policies", response_model=List[AuthPolicyResponse])
def list_auth_policies(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List all auth policies."""
    from ...models.api_armor import AuthPolicy
    policies = db.query(AuthPolicy).order_by(AuthPolicy.id).all()
    return [AuthPolicyResponse(
        id=p.id, name=p.name,
        listener_ids=p.listener_ids or [], backend_ids=p.backend_ids or [],
        auth_type=p.auth_type, jwt_algorithm=p.jwt_algorithm,
        jwt_secret_env=p.jwt_secret_env, jwt_jwks_url=p.jwt_jwks_url,
        jwt_issuer=p.jwt_issuer, jwt_audience=p.jwt_audience,
        jwt_claim_headers=p.jwt_claim_headers or [],
        api_key_header=p.api_key_header, api_key_list_id=p.api_key_list_id,
        on_failure=p.on_failure, enabled=p.enabled,
    ) for p in policies]


@router.post("/api-armor/auth-policies", response_model=AuthPolicyResponse)
def create_auth_policy(
    p_in: AuthPolicyCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Create a new auth policy."""
    from ...models.api_armor import AuthPolicy
    existing = db.query(AuthPolicy).filter(AuthPolicy.name == p_in.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Auth policy with this name already exists")
    policy = AuthPolicy(**p_in.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return AuthPolicyResponse(
        id=policy.id, name=policy.name,
        listener_ids=policy.listener_ids or [], backend_ids=policy.backend_ids or [],
        auth_type=policy.auth_type, jwt_algorithm=policy.jwt_algorithm,
        jwt_secret_env=policy.jwt_secret_env, jwt_jwks_url=policy.jwt_jwks_url,
        jwt_issuer=policy.jwt_issuer, jwt_audience=policy.jwt_audience,
        jwt_claim_headers=policy.jwt_claim_headers or [],
        api_key_header=policy.api_key_header, api_key_list_id=policy.api_key_list_id,
        on_failure=policy.on_failure, enabled=policy.enabled,
    )


@router.put("/api-armor/auth-policies/{pid}", response_model=AuthPolicyResponse)
def update_auth_policy(
    pid: int,
    p_in: AuthPolicyCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Update an auth policy."""
    from ...models.api_armor import AuthPolicy
    policy = db.get(AuthPolicy, pid)
    if not policy:
        raise HTTPException(status_code=404, detail="Auth policy not found")
    for k, v in p_in.model_dump().items():
        setattr(policy, k, v)
    db.commit()
    db.refresh(policy)
    return AuthPolicyResponse(
        id=policy.id, name=policy.name,
        listener_ids=policy.listener_ids or [], backend_ids=policy.backend_ids or [],
        auth_type=policy.auth_type, jwt_algorithm=policy.jwt_algorithm,
        jwt_secret_env=policy.jwt_secret_env, jwt_jwks_url=policy.jwt_jwks_url,
        jwt_issuer=policy.jwt_issuer, jwt_audience=policy.jwt_audience,
        jwt_claim_headers=policy.jwt_claim_headers or [],
        api_key_header=policy.api_key_header, api_key_list_id=policy.api_key_list_id,
        on_failure=policy.on_failure, enabled=policy.enabled,
    )


@router.delete("/api-armor/auth-policies/{pid}")
def delete_auth_policy(
    pid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Delete an auth policy."""
    from ...models.api_armor import AuthPolicy
    policy = db.get(AuthPolicy, pid)
    if not policy:
        raise HTTPException(status_code=404, detail="Auth policy not found")
    db.delete(policy)
    db.commit()
    return {"status": "ok"}


# ----- API Key Lists -----

class ApiKeyListCreate(BaseModel):
    name: str
    description: Optional[str] = None
    entries: List[str] = Field(default_factory=list)


class ApiKeyListEntryResponse(BaseModel):
    id: int
    value: str
    note: Optional[str] = None


class ApiKeyListResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    entries: List[ApiKeyListEntryResponse] = Field(default_factory=list)


@router.get("/api-armor/api-key-lists", response_model=List[ApiKeyListResponse])
def list_api_key_lists(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List all API key lists."""
    from ...models.api_armor import ApiKeyList, ApiKeyListEntry
    lists = db.query(ApiKeyList).order_by(ApiKeyList.id).all()
    result = []
    for l in lists:
        entries = db.query(ApiKeyListEntry).filter(ApiKeyListEntry.list_id == l.id).all()
        result.append(ApiKeyListResponse(
            id=l.id, name=l.name, description=l.description,
            entries=[ApiKeyListEntryResponse(id=e.id, value=e.value, note=e.note) for e in entries],
        ))
    return result


@router.post("/api-armor/api-key-lists", response_model=ApiKeyListResponse)
def create_api_key_list(
    k_in: ApiKeyListCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Create a new API key list with entries."""
    from ...models.api_armor import ApiKeyList, ApiKeyListEntry
    existing = db.query(ApiKeyList).filter(ApiKeyList.name == k_in.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="API key list with this name already exists")
    key_list = ApiKeyList(name=k_in.name, description=k_in.description)
    db.add(key_list)
    db.flush()
    for value in k_in.entries:
        entry = ApiKeyListEntry(list_id=key_list.id, value=value)
        db.add(entry)
    db.commit()
    db.refresh(key_list)
    entries = db.query(ApiKeyListEntry).filter(ApiKeyListEntry.list_id == key_list.id).all()
    return ApiKeyListResponse(
        id=key_list.id, name=key_list.name, description=key_list.description,
        entries=[ApiKeyListEntryResponse(id=e.id, value=e.value, note=e.note) for e in entries],
    )


@router.delete("/api-armor/api-key-lists/{lid}")
def delete_api_key_list(
    lid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Delete an API key list and its entries."""
    from ...models.api_armor import ApiKeyList
    key_list = db.get(ApiKeyList, lid)
    if not key_list:
        raise HTTPException(status_code=404, detail="API key list not found")
    db.delete(key_list)
    db.commit()
    return {"status": "ok"}


# ----- Behavioral Profiles & Anomalies -----

class ApiProfileResponse(BaseModel):
    id: int
    listener_id: Optional[int] = None
    method: str
    path: str
    dimensions: dict
    sample_count: int = 0
    learned: bool = False
    status_codes: dict = Field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ApiAnomalyResponse(BaseModel):
    id: int
    listener_id: Optional[int] = None
    method: str
    path: str
    dimension: str
    observed_value: Optional[str] = None
    expected_values: Optional[dict] = None
    request_id: Optional[str] = None
    client_ip: Optional[str] = None
    created_at: Optional[str] = None


@router.get("/api-armor/profiles", response_model=List[ApiProfileResponse])
def list_profiles(
    method: Optional[str] = None,
    path: Optional[str] = None,
    learned: Optional[bool] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List behavioral profiles."""
    from ...models.api_armor import ApiProfile
    q = db.query(ApiProfile)
    if method:
        q = q.filter(ApiProfile.method == method.upper())
    if path:
        q = q.filter(ApiProfile.path == path)
    if learned is not None:
        q = q.filter(ApiProfile.learned == learned)
    profiles = q.order_by(ApiProfile.id).all()
    return [ApiProfileResponse(
        id=p.id, listener_id=p.listener_id, method=p.method, path=p.path,
        dimensions=p.dimensions or {}, sample_count=p.sample_count or 0,
        learned=p.learned, status_codes=p.status_codes or {},
        first_seen=p.first_seen.isoformat() if p.first_seen else None,
        last_seen=p.last_seen.isoformat() if p.last_seen else None,
    ) for p in profiles]


@router.post("/api-armor/profiles/{pid}/finalize", response_model=ApiProfileResponse)
def finalize_profile_route(
    pid: int,
    min_samples: int = 100,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Mark a profile as learned (baseline confirmed)."""
    from ...services.api_armor_profiler import finalize_profile
    success = finalize_profile(db, pid, min_samples=min_samples)
    if not success:
        raise HTTPException(status_code=400, detail="Profile not found or insufficient samples")
    from ...models.api_armor import ApiProfile
    p = db.get(ApiProfile, pid)
    return ApiProfileResponse(
        id=p.id, listener_id=p.listener_id, method=p.method, path=p.path,
        dimensions=p.dimensions or {}, sample_count=p.sample_count or 0,
        learned=p.learned, status_codes=p.status_codes or {},
        first_seen=p.first_seen.isoformat() if p.first_seen else None,
        last_seen=p.last_seen.isoformat() if p.last_seen else None,
    )


@router.delete("/api-armor/profiles/{pid}")
def delete_profile(
    pid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Delete a behavioral profile."""
    from ...models.api_armor import ApiProfile
    profile = db.get(ApiProfile, pid)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    db.delete(profile)
    db.commit()
    return {"status": "ok"}


@router.get("/api-armor/anomalies", response_model=List[ApiAnomalyResponse])
def list_anomalies(
    method: Optional[str] = None,
    path: Optional[str] = None,
    dimension: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List detected anomalies."""
    from ...models.api_armor import ApiAnomaly
    q = db.query(ApiAnomaly)
    if method:
        q = q.filter(ApiAnomaly.method == method.upper())
    if path:
        q = q.filter(ApiAnomaly.path == path)
    if dimension:
        q = q.filter(ApiAnomaly.dimension == dimension)
    anomalies = q.order_by(ApiAnomaly.created_at.desc()).limit(limit).all()
    return [ApiAnomalyResponse(
        id=a.id, listener_id=a.listener_id, method=a.method, path=a.path,
        dimension=a.dimension, observed_value=a.observed_value,
        expected_values=a.expected_values, request_id=a.request_id,
        client_ip=a.client_ip,
        created_at=a.created_at.isoformat() if a.created_at else None,
    ) for a in anomalies]


@router.delete("/api-armor/anomalies")
def clear_anomalies(
    method: Optional[str] = None,
    path: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Clear anomalies (optionally filtered by method/path)."""
    from ...models.api_armor import ApiAnomaly
    q = db.query(ApiAnomaly)
    if method:
        q = q.filter(ApiAnomaly.method == method.upper())
    if path:
        q = q.filter(ApiAnomaly.path == path)
    count = q.delete()
    db.commit()
    return {"status": "ok", "deleted": count}
