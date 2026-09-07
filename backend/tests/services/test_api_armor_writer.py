"""Tests for the API Armor data-file writer."""
import json
import os

from app.models.api_armor import ApiKeyList, ApiKeyListEntry, ApiProfile, ApiSchema, AuthPolicy, OpenApiSpec
from app.services.api_armor_writer import write_api_armor_files


SAMPLE_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "email": {"type": "string"},
    },
    "required": ["name", "email"],
}


def _import_spec(db):
    from app.services.api_armor_schemas import import_openapi_spec
    spec_text = json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/api/v1/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": SAMPLE_SCHEMA,
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
                                "schema": SAMPLE_SCHEMA,
                            }
                        }
                    }
                }
            },
        },
    })
    return import_openapi_spec(db, name="test-spec", spec_text=spec_text)


def test_write_api_armor_files_creates_schema_index(db, monkeypatch):
    """Writer creates schema-index.json and per-endpoint schema files."""
    import tempfile
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr("app.services.api_armor_writer.settings.API_ARMOR_DIR", tmp)

    _import_spec(db)

    result = write_api_armor_files(db)
    assert result["base_dir"] == tmp
    assert os.path.exists(os.path.join(tmp, "schema-index.json"))
    assert os.path.exists(os.path.join(tmp, "schemas"))

    with open(os.path.join(tmp, "schema-index.json")) as f:
        index = json.load(f)

    assert "schemas" in index
    assert len(index["schemas"]) == 2
    methods = {s["method"] for s in index["schemas"]}
    paths = {s["path_pattern"] for s in index["schemas"]}
    assert methods == {"POST", "PUT"}
    assert "/api/v1/users" in paths
    assert "/api/v1/users/:id" in paths

    # Schema files exist and match the index.
    for entry in index["schemas"]:
        path = os.path.join(tmp, entry["file"])
        assert os.path.exists(path)
        with open(path) as f:
            schema = json.load(f)
        assert schema["type"] == "object"


def test_write_api_armor_files_creates_api_key_files(db, monkeypatch):
    """Writer creates one .lst file per API key list."""
    import tempfile
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr("app.services.api_armor_writer.settings.API_ARMOR_DIR", tmp)

    key_list = ApiKeyList(name="test-keys", description="Test")
    db.add(key_list)
    db.flush()
    for value in ("key1", "key2", "key3"):
        db.add(ApiKeyListEntry(list_id=key_list.id, value=value))
    db.commit()

    result = write_api_armor_files(db)
    keys = result["api_keys"]["lists"]
    assert len(keys) == 1
    assert keys[0]["name"] == "test-keys"
    assert keys[0]["count"] == 3

    with open(keys[0]["path"]) as f:
        lines = f.read().strip().split("\n")
    assert lines == ["key1", "key2", "key3"]


def test_write_api_armor_files_creates_auth_policies(db, monkeypatch):
    """Writer creates auth-policies.json with enabled policies."""
    import tempfile
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr("app.services.api_armor_writer.settings.API_ARMOR_DIR", tmp)

    policy = AuthPolicy(
        name="jwt-policy",
        auth_type="jwt",
        jwt_algorithm="HS256",
        jwt_secret_env="JWT_SECRET",
        jwt_issuer="test-issuer",
        jwt_audience="test-audience",
        on_failure="block",
        enabled=True,
    )
    db.add(policy)
    db.commit()

    result = write_api_armor_files(db)
    path = result["auth_policies"]["path"]
    with open(path) as f:
        data = json.load(f)

    assert len(data["policies"]) == 1
    assert data["policies"][0]["name"] == "jwt-policy"
    assert data["policies"][0]["jwt_issuer"] == "test-issuer"
    assert data["policies"][0]["on_failure"] == "block"


def test_write_api_armor_files_creates_profiles(db, monkeypatch):
    """Writer writes learned profiles to profiles.json."""
    import tempfile
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr("app.services.api_armor_writer.settings.API_ARMOR_DIR", tmp)

    profile = ApiProfile(
        method="POST",
        path="/api/v1/users",
        dimensions={
            "content_type": {"values": ["application/json"], "count": 10},
        },
        sample_count=150,
        learned=True,
    )
    db.add(profile)
    db.add(ApiProfile(method="GET", path="/api/v1/users", dimensions={}, sample_count=1, learned=False))
    db.commit()

    result = write_api_armor_files(db)
    path = result["profiles"]["path"]
    with open(path) as f:
        data = json.load(f)

    assert len(data["profiles"]) == 1
    assert data["profiles"][0]["method"] == "POST"
    assert data["profiles"][0]["path"] == "/api/v1/users"


def test_write_api_armor_files_removes_stale_schemas(db, monkeypatch):
    """Writer removes schema files for schemas that no longer exist."""
    import tempfile
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr("app.services.api_armor_writer.settings.API_ARMOR_DIR", tmp)

    spec, schemas = _import_spec(db)
    write_api_armor_files(db)

    # Delete the spec (cascades to schemas).
    db.delete(spec)
    db.commit()

    result = write_api_armor_files(db)
    assert result["schemas"]["schema_count"] == 0

    schemas_dir = os.path.join(tmp, "schemas")
    # Only the schema-index.json should remain; any .json schema files removed.
    leftover = [f for f in os.listdir(schemas_dir) if f.endswith(".json")]
    assert leftover == []


def test_write_api_armor_files_disabled_schemas_excluded(db, monkeypatch):
    """Disabled schemas are not included in the index."""
    import tempfile
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr("app.services.api_armor_writer.settings.API_ARMOR_DIR", tmp)

    _import_spec(db)
    schema = db.query(ApiSchema).filter(ApiSchema.method == "POST").first()
    schema.enabled = False
    db.commit()

    result = write_api_armor_files(db)
    with open(os.path.join(tmp, "schema-index.json")) as f:
        index = json.load(f)

    assert len(index["schemas"]) == 1
    assert index["schemas"][0]["method"] == "PUT"
