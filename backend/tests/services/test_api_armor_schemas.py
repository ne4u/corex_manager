"""Tests for API Armor schema management service."""
import json

import pytest

from app.services.api_armor_schemas import (
    parse_openapi_spec,
    extract_schemas_from_openapi,
    normalize_path,
    path_matches,
    import_openapi_spec,
    get_schema_for_endpoint,
    _infer_schema_python,
    _merge_schemas_python,
)
from app.models.api_armor import OpenApiSpec, ApiSchema


# Sample OpenAPI 3.0 spec for testing
SAMPLE_OPENAPI = json.dumps({
    "openapi": "3.0.3",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/api/v1/users": {
            "post": {
                "operationId": "createUser",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string"},
                                    "age": {"type": "integer"}
                                },
                                "required": ["name", "email"]
                            }
                        }
                    }
                }
            },
            "get": {
                "operationId": "listUsers",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                }
            }
        },
        "/api/v1/users/{id}": {
            "put": {
                "operationId": "updateUser",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/UserUpdate"
                            }
                        }
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "UserUpdate": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"}
                }
            }
        }
    }
})


def test_parse_openapi_spec_json():
    """parse_openapi_spec parses JSON specs."""
    spec, version = parse_openapi_spec(SAMPLE_OPENAPI)
    assert version == "3.0.3"
    assert "paths" in spec


def test_parse_openapi_spec_invalid():
    """parse_openapi_spec raises ValueError on invalid input."""
    with pytest.raises(ValueError):
        parse_openapi_spec("not valid json or yaml {{{")


def test_extract_schemas():
    """extract_schemas_from_openapi extracts per-endpoint schemas."""
    spec, _ = parse_openapi_spec(SAMPLE_OPENAPI)
    schemas = extract_schemas_from_openapi(spec)
    assert len(schemas) == 3  # POST /users, GET /users, PUT /users/{id}
    methods = [s["method"] for s in schemas]
    assert "POST" in methods
    assert "GET" in methods
    assert "PUT" in methods


def test_extract_schemas_resolves_ref():
    """extract_schemas_from_openapi resolves $ref references."""
    spec, _ = parse_openapi_spec(SAMPLE_OPENAPI)
    schemas = extract_schemas_from_openapi(spec)
    put_schema = next(s for s in schemas if s["method"] == "PUT")
    assert "$ref" not in json.dumps(put_schema["schema"])
    assert put_schema["schema"]["type"] == "object"
    assert "name" in put_schema["schema"]["properties"]


def test_normalize_path():
    """normalize_path converts {param} to :param."""
    assert normalize_path("/api/v1/users/{id}") == "/api/v1/users/:id"
    assert normalize_path("/api/v1/users/{user_id}/posts/{post_id}") == "/api/v1/users/:user_id/posts/:post_id"
    assert normalize_path("/api/v1/users") == "/api/v1/users"


def test_path_matches():
    """path_matches matches paths with :param wildcards."""
    assert path_matches("/api/v1/users/:id", "/api/v1/users/123")
    assert path_matches("/api/v1/users/:id", "/api/v1/users/abc")
    assert not path_matches("/api/v1/users/:id", "/api/v1/users/123/posts")
    assert path_matches("/api/v1/users", "/api/v1/users")
    assert not path_matches("/api/v1/users", "/api/v1/users/123")


def test_import_openapi_spec(db):
    """import_openapi_spec creates OpenApiSpec and ApiSchema rows."""
    spec, schemas = import_openapi_spec(db, name="test-spec", spec_text=SAMPLE_OPENAPI)
    assert spec.id is not None
    assert spec.version == "3.0.3"
    assert len(schemas) == 3
    assert db.query(OpenApiSpec).count() == 1
    assert db.query(ApiSchema).count() == 3


def test_import_openapi_spec_duplicate_name(db):
    """import_openapi_spec raises ValueError on duplicate name."""
    import_openapi_spec(db, name="test-spec", spec_text=SAMPLE_OPENAPI)
    with pytest.raises(ValueError, match="already exists"):
        import_openapi_spec(db, name="test-spec", spec_text=SAMPLE_OPENAPI)


def test_get_schema_for_endpoint_exact(db):
    """get_schema_for_endpoint finds schema by exact method+path."""
    import_openapi_spec(db, name="test-spec", spec_text=SAMPLE_OPENAPI)
    schema = get_schema_for_endpoint(db, "POST", "/api/v1/users")
    assert schema is not None
    assert schema["type"] == "object"
    assert "name" in schema["properties"]


def test_get_schema_for_endpoint_pattern(db):
    """get_schema_for_endpoint matches path patterns."""
    import_openapi_spec(db, name="test-spec", spec_text=SAMPLE_OPENAPI)
    schema = get_schema_for_endpoint(db, "PUT", "/api/v1/users/123")
    assert schema is not None
    assert schema["type"] == "object"


def test_get_schema_for_endpoint_not_found(db):
    """get_schema_for_endpoint returns None when no schema matches."""
    import_openapi_spec(db, name="test-spec", spec_text=SAMPLE_OPENAPI)
    schema = get_schema_for_endpoint(db, "DELETE", "/api/v1/nope")
    assert schema is None


def test_infer_schema_python_simple():
    """_infer_schema_python infers schema from simple values."""
    assert _infer_schema_python(None) == {"type": "null"}
    assert _infer_schema_python(True) == {"type": "boolean"}
    assert _infer_schema_python(42) == {"type": "integer"}
    assert _infer_schema_python(3.14) == {"type": "number"}
    assert _infer_schema_python("hello")["type"] == "string"


def test_infer_schema_python_object():
    """_infer_schema_python infers schema from objects."""
    schema = _infer_schema_python({"name": "test", "age": 30})
    assert schema["type"] == "object"
    assert "name" in schema["properties"]
    assert "age" in schema["properties"]
    assert set(schema["required"]) == {"name", "age"}


def test_merge_schemas_python_same_type():
    """_merge_schemas_python merges schemas of the same type."""
    s1 = {"type": "string", "maxLength": 10, "minLength": 2}
    s2 = {"type": "string", "maxLength": 20, "minLength": 1}
    merged = _merge_schemas_python(s1, s2)
    assert merged["maxLength"] == 20
    assert merged["minLength"] == 1


def test_merge_schemas_python_different_types():
    """_merge_schemas_python returns union type for different types."""
    s1 = {"type": "string"}
    s2 = {"type": "integer"}
    merged = _merge_schemas_python(s1, s2)
    assert isinstance(merged["type"], list)
    assert "string" in merged["type"]
    assert "integer" in merged["type"]


def test_merge_schemas_python_objects():
    """_merge_schemas_python merges object schemas."""
    s1 = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        "required": ["name", "age"]
    }
    s2 = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "email": {"type": "string"}},
        "required": ["name", "email"]
    }
    merged = _merge_schemas_python(s1, s2)
    assert "name" in merged["properties"]
    assert "age" in merged["properties"]
    assert "email" in merged["properties"]
    # Required = intersection
    assert merged["required"] == ["name"]
