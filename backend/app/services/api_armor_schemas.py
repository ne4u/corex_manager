"""API Armor schema management service.

Handles OpenAPI spec import (parsing OpenAPI 3.x JSON/YAML into per-endpoint
JSON Schemas) and learned schema inference (merging observed request bodies
into per-endpoint schemas).
"""
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..models.api_armor import OpenApiSpec, ApiSchema


def parse_openapi_spec(spec_text: str) -> Tuple[Dict, str]:
    """Parse an OpenAPI spec string (JSON or YAML) into a dict.

    Returns (parsed_spec, version_string).
    Raises ValueError on parse failure.
    """
    # Try JSON first
    try:
        spec = json.loads(spec_text)
    except json.JSONDecodeError:
        # Try YAML (simple fallback — requires PyYAML)
        try:
            import yaml
            spec = yaml.safe_load(spec_text)
        except ImportError:
            raise ValueError("Spec is not valid JSON and PyYAML is not installed for YAML parsing")
        except Exception as e:
            raise ValueError(f"Failed to parse spec as YAML: {e}")

    if not isinstance(spec, dict):
        raise ValueError("Spec must be a JSON/YAML object")

    # Detect OpenAPI version
    if "openapi" in spec:
        version = str(spec["openapi"])
    elif "swagger" in spec:
        version = f"swagger/{spec['swagger']}"
    else:
        version = "unknown"

    return spec, version


def extract_schemas_from_openapi(spec: Dict) -> List[Dict]:
    """Extract per-endpoint request body schemas from an OpenAPI spec.

    Returns a list of dicts with keys: method, path, schema, name.
    Only extracts request body schemas (not response schemas).
    """
    schemas = []
    paths = spec.get("paths", {})
    components = spec.get("components", {}).get("schemas", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ["get", "post", "put", "patch", "delete"]:
            if method not in path_item:
                continue

            operation = path_item[method]
            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {})

            # Look for application/json
            json_content = content.get("application/json", {})
            schema_ref = json_content.get("schema", {})

            if not schema_ref:
                continue

            # Resolve $ref if present
            resolved_schema = resolve_ref(schema_ref, components)

            # Build a descriptive name
            operation_id = operation.get("operationId", "")
            name = operation_id or f"{method.upper()} {path}"

            schemas.append({
                "name": name,
                "method": method.upper(),
                "path": normalize_path(path),
                "schema": resolved_schema,
            })

    return schemas


def resolve_ref(schema: Dict, components: Dict) -> Dict:
    """Resolve a $ref reference in an OpenAPI schema.

    Supports both OpenAPI 3.x (#/components/schemas/Name) and
    Swagger 2.0 (#/definitions/Name) reference formats.
    """
    if not isinstance(schema, dict):
        return schema

    if "$ref" not in schema:
        # Recursively resolve refs in nested schemas
        return resolve_nested_refs(schema, components)

    ref = schema["$ref"]
    # Format: #/components/schemas/Name or #/definitions/Name
    parts = ref.lstrip("#/").split("/")
    current: Any = {"components": {"schemas": components}, "definitions": components}
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            # Can't resolve — return as-is
            return schema

    if isinstance(current, dict):
        # Recursively resolve refs in the resolved schema
        return resolve_nested_refs(current, components)

    return schema


def resolve_nested_refs(schema: Any, components: Dict) -> Any:
    """Recursively resolve all $ref references in a schema."""
    if isinstance(schema, dict):
        if "$ref" in schema:
            return resolve_ref(schema, components)
        return {k: resolve_nested_refs(v, components) for k, v in schema.items()}
    if isinstance(schema, list):
        return [resolve_nested_refs(item, components) for item in schema]
    return schema


def normalize_path(path: str) -> str:
    """Normalize an OpenAPI path for matching.

    Converts {param} to :param for HAProxy-style path matching.
    Example: /api/v1/users/{id} → /api/v1/users/:id
    """
    return re.sub(r"\{([^}]+)\}", r":\1", path)


def import_openapi_spec(
    db: Session,
    name: str,
    spec_text: str,
    listener_ids: Optional[List[int]] = None,
    backend_ids: Optional[List[int]] = None,
) -> Tuple[OpenApiSpec, List[ApiSchema]]:
    """Import an OpenAPI spec and create per-endpoint ApiSchema rows.

    Returns (spec, schemas).
    Raises ValueError on parse failure or duplicate name.
    """
    # Check for duplicate name
    existing = db.query(OpenApiSpec).filter(OpenApiSpec.name == name).first()
    if existing:
        raise ValueError(f"OpenAPI spec with name '{name}' already exists")

    # Parse the spec
    spec_dict, version = parse_openapi_spec(spec_text)

    # Create the OpenApiSpec row
    spec = OpenApiSpec(
        name=name,
        spec=spec_text,
        spec_json=spec_dict,
        version=version,
        listener_ids=listener_ids or [],
        backend_ids=backend_ids or [],
        enabled=True,
    )
    db.add(spec)
    db.flush()

    # Extract per-endpoint schemas
    extracted = extract_schemas_from_openapi(spec_dict)

    # Create ApiSchema rows
    schemas = []
    for item in extracted:
        schema = ApiSchema(
            name=item["name"],
            method=item["method"],
            path=item["path"],
            schema=item["schema"],
            spec_id=spec.id,
            source="openapi",
            enabled=True,
        )
        db.add(schema)
        schemas.append(schema)

    db.commit()
    for s in schemas:
        db.refresh(s)

    return spec, schemas


def get_schema_for_endpoint(
    db: Session,
    method: str,
    path: str,
) -> Optional[Dict]:
    """Look up the JSON Schema for a given method + path.

    Returns the schema dict, or None if no matching schema exists.
    Prefers OpenAPI-sourced schemas over learned schemas.
    """
    # Try exact match first
    schema = (
        db.query(ApiSchema)
        .filter(ApiSchema.method == method.upper())
        .filter(ApiSchema.path == path)
        .filter(ApiSchema.enabled == True)  # noqa: E712
        .order_by(ApiSchema.source.desc())  # openapi before learned
        .first()
    )
    if schema:
        return schema.schema

    # Try pattern match (path with :param wildcards)
    # Normalize the input path the same way
    normalized = normalize_path(path)
    all_schemas = (
        db.query(ApiSchema)
        .filter(ApiSchema.method == method.upper())
        .filter(ApiSchema.enabled == True)  # noqa: E712
        .all()
    )
    for s in all_schemas:
        if path_matches(s.path, normalized):
            return s.schema

    return None


def path_matches(pattern: str, path: str) -> bool:
    """Check if a path matches a pattern with :param wildcards.

    Example: /api/v1/users/:id matches /api/v1/users/123
    """
    # Convert :param to regex
    regex = re.sub(r":[^/]+", r"[^/]+", pattern)
    regex = f"^{regex}$"
    return bool(re.match(regex, path))


def merge_learned_schema(
    db: Session,
    method: str,
    path: str,
    body: Dict,
) -> Optional[ApiSchema]:
    """Merge an observed request body into a learned schema for the endpoint.

    If no learned schema exists, creates one. If one exists, merges the
    new observation into it.
    """
    # This is a Python-side merge — the Rust merge_schemas is used by the
    # profiler sampler for high-performance merging. This function is used
    # by the API for manual schema review/editing.

    # Find existing learned schema
    existing = (
        db.query(ApiSchema)
        .filter(ApiSchema.method == method.upper())
        .filter(ApiSchema.path == path)
        .filter(ApiSchema.source == "learned")
        .first()
    )

    # Infer schema from the observed body
    # (Using a simple Python equivalent of the Rust infer_schema)
    new_schema = _infer_schema_python(body)

    if existing:
        # Merge with existing
        old_schema = existing.schema or {}
        merged = _merge_schemas_python(old_schema, new_schema)
        existing.schema = merged
        existing.sample_count = (existing.sample_count or 0) + 1
        db.commit()
        db.refresh(existing)
        return existing
    else:
        # Create new learned schema
        schema = ApiSchema(
            name=f"learned:{method.upper()} {path}",
            method=method.upper(),
            path=path,
            schema=new_schema,
            source="learned",
            enabled=True,
            sample_count=1,
        )
        db.add(schema)
        db.commit()
        db.refresh(schema)
        return schema


def _infer_schema_python(value: Any) -> Dict:
    """Python equivalent of the Rust infer_schema function."""
    if value is None:
        return {"type": "null"}
    elif isinstance(value, bool):
        return {"type": "boolean"}
    elif isinstance(value, int):
        return {"type": "integer"}
    elif isinstance(value, float):
        return {"type": "number"}
    elif isinstance(value, str):
        return {"type": "string", "minLength": 0, "maxLength": len(value)}
    elif isinstance(value, list):
        items = _infer_schema_python(value[0]) if value else {}
        return {"type": "array", "items": items, "minItems": 0, "maxItems": len(value)}
    elif isinstance(value, dict):
        properties = {k: _infer_schema_python(v) for k, v in value.items()}
        required = list(value.keys())
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": True,
        }
    return {}


def _merge_schemas_python(s1: Dict, s2: Dict) -> Dict:
    """Python equivalent of the Rust merge_schemas function."""
    t1 = s1.get("type")
    t2 = s2.get("type")

    if t1 != t2:
        if t1 and t2:
            return {"type": [t1, t2]}
        return {}

    merged = dict(s1)

    if t1 == "object":
        props1 = s1.get("properties", {})
        props2 = s2.get("properties", {})
        merged_props = dict(props1)
        for key, val2 in props2.items():
            if key in merged_props:
                merged_props[key] = _merge_schemas_python(merged_props[key], val2)
            else:
                merged_props[key] = val2

        req1 = set(s1.get("required", []))
        req2 = set(s2.get("required", []))
        merged["properties"] = merged_props
        merged["required"] = list(req1 & req2)

    elif t1 == "string":
        max1 = s1.get("maxLength", 0)
        max2 = s2.get("maxLength", 0)
        min1 = s1.get("minLength", 0)
        min2 = s2.get("minLength", 0)
        merged["maxLength"] = max(max1, max2)
        merged["minLength"] = min(min1, min2)

    return merged
