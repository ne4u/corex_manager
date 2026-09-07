"""Tests for API Armor settings API endpoints."""
from app.services.settings import get_setting


def test_get_api_armor_settings(client):
    """GET /api-armor/settings returns default settings."""
    resp = client.get("/api/v1/api-armor/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "api_armor_enabled" in data
    assert "api_armor_max_body_bytes" in data
    assert "api_armor_module_enabled" in data
    assert "api_armor_schema_learning_enabled" in data
    assert "api_armor_profiling_learning_enabled" in data
    assert "api_armor_profile_retention_days" in data
    assert data["api_armor_scope"] == "listener"
    assert data["api_armor_backend_ids"] == []
    assert data["api_armor_path_patterns"] == []


def test_update_api_armor_enabled(client, db):
    """PUT /api-armor/settings updates api_armor_enabled.

    API Armor requires req_fp to be enabled first (it depends on req_fp
    subfields at runtime). Enable req_fp before enabling api_armor.
    """
    from app.services.settings import set_setting
    set_setting(db, "req_fp_enabled", "true")
    db.commit()
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_enabled": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["api_armor_enabled"] is True
    # Verify it was persisted to DB
    assert get_setting(db, "api_armor_enabled").lower() in ("true", "1", "yes")


def test_update_api_armor_max_body_bytes(client, db):
    """PUT /api-armor/settings updates max body bytes."""
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_max_body_bytes": 524288},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["api_armor_max_body_bytes"] == 524288


def test_update_api_armor_max_body_bytes_too_small(client):
    """PUT /api-armor/settings rejects max body bytes < 1024."""
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_max_body_bytes": 512},
    )
    assert resp.status_code == 400


def test_update_api_armor_learning_toggles(client, db):
    """PUT /api-armor/settings updates learning toggles."""
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={
            "api_armor_schema_learning_enabled": True,
            "api_armor_profiling_learning_enabled": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["api_armor_schema_learning_enabled"] is True
    assert data["api_armor_profiling_learning_enabled"] is True


def test_update_api_armor_retention(client, db):
    """PUT /api-armor/settings updates profile retention days."""
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_profile_retention_days": 60},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["api_armor_profile_retention_days"] == 60


def test_update_api_armor_retention_invalid(client):
    """PUT /api-armor/settings rejects retention < 1."""
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_profile_retention_days": 0},
    )
    assert resp.status_code == 400


def test_update_api_armor_scope(client, db):
    """PUT /api-armor/settings updates scope, backend IDs, and path patterns."""
    from app.services.settings import set_setting
    set_setting(db, "req_fp_enabled", "true")
    db.commit()
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={
            "api_armor_enabled": True,
            "api_armor_scope": "path",
            "api_armor_backend_ids": [1, 2],
            "api_armor_path_patterns": ["^/api/v1/.*", "^/graphql$"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["api_armor_scope"] == "path"
    assert data["api_armor_backend_ids"] == [1, 2]
    assert data["api_armor_path_patterns"] == ["^/api/v1/.*", "^/graphql$"]


def test_update_api_armor_scope_invalid(client):
    """PUT /api-armor/settings rejects unknown scope or invalid regex."""
    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_scope": "invalid"},
    )
    assert resp.status_code == 400

    resp = client.put(
        "/api/v1/api-armor/settings",
        json={"api_armor_path_patterns": ["["]},
    )
    assert resp.status_code == 400


# ----- Preset rules -----

def test_list_preset_rules(client):
    """GET /api-armor/presets returns the list of preset rules."""
    resp = client.get("/api/v1/api-armor/presets")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    assert "name" in data[0]
    assert "expression" in data[0]


def test_apply_preset_rules(client, db):
    """POST /api-armor/presets/apply creates security rules."""
    from app.models.models import SecurityRule
    existing = db.query(SecurityRule).count()
    resp = client.post("/api/v1/api-armor/presets/apply", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] > 0
    assert len(data["rules"]) == data["applied"]
    assert db.query(SecurityRule).count() == existing + data["applied"]


def test_apply_preset_rules_idempotent(client, db):
    """POST /api-armor/presets/apply is idempotent."""
    resp1 = client.post("/api/v1/api-armor/presets/apply", json={})
    assert resp1.status_code == 200
    assert resp1.json()["applied"] > 0
    resp2 = client.post("/api/v1/api-armor/presets/apply", json={})
    assert resp2.status_code == 200
    assert resp2.json()["applied"] == 0


def test_apply_preset_rules_with_listeners(client, db):
    """POST /api-armor/presets/apply with listener_ids scopes rules."""
    from app.models.models import SecurityRule
    resp = client.post("/api/v1/api-armor/presets/apply", json={"listener_ids": [1, 2]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] > 0
    # Verify the rules are scoped to the specified listeners
    rules = db.query(SecurityRule).filter(SecurityRule.name.like("API Armor:%")).all()
    for rule in rules:
        assert rule.listener_ids == [1, 2]


# ----- OpenAPI specs -----

import json

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
                                    "email": {"type": "string"}
                                },
                                "required": ["name", "email"]
                            }
                        }
                    }
                }
            }
        }
    }
})


def test_list_specs_empty(client):
    """GET /api-armor/specs returns empty list initially."""
    resp = client.get("/api/v1/api-armor/specs")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_spec(client, db):
    """POST /api-armor/specs imports an OpenAPI spec."""
    resp = client.post("/api/v1/api-armor/specs", json={
        "name": "test-spec",
        "spec": SAMPLE_OPENAPI,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "test-spec"
    assert data["version"] == "3.0.3"
    assert data["schema_count"] == 1


def test_create_spec_duplicate(client, db):
    """POST /api-armor/specs rejects duplicate names."""
    client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    resp = client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    assert resp.status_code == 400


def test_list_specs_after_create(client, db):
    """GET /api-armor/specs returns created specs."""
    client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    resp = client.get("/api/v1/api-armor/specs")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "test-spec"


def test_list_spec_schemas(client, db):
    """GET /api-armor/specs/{sid}/schemas returns extracted schemas."""
    create_resp = client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    sid = create_resp.json()["id"]
    resp = client.get(f"/api/v1/api-armor/specs/{sid}/schemas")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["method"] == "POST"
    assert data[0]["path"] == "/api/v1/users"


def test_delete_spec(client, db):
    """DELETE /api-armor/specs/{sid} removes the spec and its schemas."""
    from app.models.api_armor import OpenApiSpec, ApiSchema
    create_resp = client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    sid = create_resp.json()["id"]
    resp = client.delete(f"/api/v1/api-armor/specs/{sid}")
    assert resp.status_code == 200
    assert db.query(OpenApiSpec).count() == 0
    assert db.query(ApiSchema).count() == 0


def test_list_all_schemas(client, db):
    """GET /api-armor/schemas returns all schemas."""
    client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    resp = client.get("/api/v1/api-armor/schemas")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["source"] == "openapi"


def test_list_schemas_filter_by_method(client, db):
    """GET /api-armor/schemas?method=POST filters by method."""
    client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    resp = client.get("/api/v1/api-armor/schemas?method=POST")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    resp = client.get("/api/v1/api-armor/schemas?method=GET")
    assert resp.status_code == 200
    assert len(resp.json()) == 0


# ----- Auth Policies -----

def test_list_auth_policies_empty(client):
    """GET /api-armor/auth-policies returns empty list initially."""
    resp = client.get("/api/v1/api-armor/auth-policies")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_auth_policy(client, db):
    """POST /api-armor/auth-policies creates a policy."""
    resp = client.post("/api/v1/api-armor/auth-policies", json={
        "name": "test-jwt-policy",
        "auth_type": "jwt",
        "jwt_algorithm": "hs256",
        "jwt_secret_env": "JWT_SECRET",
        "jwt_issuer": "test-issuer",
        "on_failure": "block",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "test-jwt-policy"
    assert data["auth_type"] == "jwt"
    assert data["jwt_secret_env"] == "JWT_SECRET"


def test_create_auth_policy_duplicate(client, db):
    """POST /api-armor/auth-policies rejects duplicate names."""
    client.post("/api/v1/api-armor/auth-policies", json={"name": "test-policy", "auth_type": "jwt"})
    resp = client.post("/api/v1/api-armor/auth-policies", json={"name": "test-policy", "auth_type": "jwt"})
    assert resp.status_code == 409


def test_update_auth_policy(client, db):
    """PUT /api-armor/auth-policies/{pid} updates a policy."""
    create_resp = client.post("/api/v1/api-armor/auth-policies", json={
        "name": "test-policy", "auth_type": "jwt", "jwt_issuer": "old-issuer"
    })
    pid = create_resp.json()["id"]
    resp = client.put(f"/api/v1/api-armor/auth-policies/{pid}", json={
        "name": "test-policy", "auth_type": "jwt", "jwt_issuer": "new-issuer"
    })
    assert resp.status_code == 200
    assert resp.json()["jwt_issuer"] == "new-issuer"


def test_delete_auth_policy(client, db):
    """DELETE /api-armor/auth-policies/{pid} removes a policy."""
    from app.models.api_armor import AuthPolicy
    create_resp = client.post("/api/v1/api-armor/auth-policies", json={"name": "test-policy", "auth_type": "jwt"})
    pid = create_resp.json()["id"]
    resp = client.delete(f"/api/v1/api-armor/auth-policies/{pid}")
    assert resp.status_code == 200
    assert db.query(AuthPolicy).count() == 0


# ----- API Key Lists -----

def test_list_api_key_lists_empty(client):
    """GET /api-armor/api-key-lists returns empty list initially."""
    resp = client.get("/api/v1/api-armor/api-key-lists")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_api_key_list(client, db):
    """POST /api-armor/api-key-lists creates a list with entries."""
    resp = client.post("/api/v1/api-armor/api-key-lists", json={
        "name": "test-keys",
        "description": "Test API keys",
        "entries": ["key1", "key2", "key3"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "test-keys"
    assert len(data["entries"]) == 3


def test_create_api_key_list_duplicate(client, db):
    """POST /api-armor/api-key-lists rejects duplicate names."""
    client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": []})
    resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": []})
    assert resp.status_code == 409


def test_delete_api_key_list(client, db):
    """DELETE /api-armor/api-key-lists/{lid} removes a list."""
    from app.models.api_armor import ApiKeyList
    create_resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": ["k1"]})
    lid = create_resp.json()["id"]
    resp = client.delete(f"/api/v1/api-armor/api-key-lists/{lid}")
    assert resp.status_code == 200
    assert db.query(ApiKeyList).count() == 0


def test_get_api_key_list(client, db):
    """GET /api-armor/api-key-lists/{lid} returns the list and entries."""
    create_resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": ["k1", "k2"]})
    lid = create_resp.json()["id"]
    resp = client.get(f"/api/v1/api-armor/api-key-lists/{lid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "test-keys"
    assert len(data["entries"]) == 2


def test_update_api_key_list(client, db):
    """PUT /api-armor/api-key-lists/{lid} replaces entries."""
    from app.models.api_armor import ApiKeyListEntry
    create_resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": ["k1"]})
    lid = create_resp.json()["id"]
    resp = client.put(f"/api/v1/api-armor/api-key-lists/{lid}", json={
        "name": "updated-keys",
        "description": "Updated",
        "entries": ["new1", "new2"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "updated-keys"
    assert data["description"] == "Updated"
    assert [e["value"] for e in data["entries"]] == ["new1", "new2"]
    assert db.query(ApiKeyListEntry).filter(ApiKeyListEntry.list_id == lid).count() == 2


def test_update_api_key_list_duplicate_name(client, db):
    """PUT /api-armor/api-key-lists/{lid} rejects a duplicate name."""
    client.post("/api/v1/api-armor/api-key-lists", json={"name": "first", "entries": []})
    create_resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "second", "entries": []})
    lid = create_resp.json()["id"]
    resp = client.put(f"/api/v1/api-armor/api-key-lists/{lid}", json={"name": "first", "entries": []})
    assert resp.status_code == 409


def test_create_api_key_entry(client, db):
    """POST /api-armor/api-key-lists/{lid}/entries adds a single entry."""
    create_resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": []})
    lid = create_resp.json()["id"]
    resp = client.post(f"/api/v1/api-armor/api-key-lists/{lid}/entries", json={"value": "new-key", "note": "note"})
    assert resp.status_code == 200
    assert resp.json()["value"] == "new-key"
    assert resp.json()["note"] == "note"
    list_resp = client.get(f"/api/v1/api-armor/api-key-lists/{lid}")
    assert len(list_resp.json()["entries"]) == 1


def test_delete_api_key_entry(client, db):
    """DELETE /api-armor/api-key-lists/{lid}/entries/{eid} removes an entry."""
    create_resp = client.post("/api/v1/api-armor/api-key-lists", json={"name": "test-keys", "entries": ["k1"]})
    lid = create_resp.json()["id"]
    eid = create_resp.json()["entries"][0]["id"]
    resp = client.delete(f"/api/v1/api-armor/api-key-lists/{lid}/entries/{eid}")
    assert resp.status_code == 200
    list_resp = client.get(f"/api/v1/api-armor/api-key-lists/{lid}")
    assert list_resp.json()["entries"] == []


# ----- Schema update / learn -----

def test_update_schema(client, db):
    """PUT /api-armor/schemas/{sid} updates a schema."""
    client.post("/api/v1/api-armor/specs", json={"name": "test-spec", "spec": SAMPLE_OPENAPI})
    schema_resp = client.get("/api/v1/api-armor/schemas")
    sid = schema_resp.json()[0]["id"]
    new_schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
    resp = client.put(f"/api/v1/api-armor/schemas/{sid}", json={
        "id": sid,
        "name": "updated",
        "method": "POST",
        "path": "/api/v1/users",
        "schema_def": new_schema,
        "enabled": True,
        "sample_count": 0,
        "source": "openapi",
    })
    assert resp.status_code == 200
    assert resp.json()["schema_def"] == new_schema
    assert "schema_json" not in resp.json()


def test_learn_schema(client, db):
    """POST /api-armor/schemas/learn merges an observation into a learned schema."""
    resp = client.post("/api/v1/api-armor/schemas/learn", json={
        "method": "POST",
        "path": "/api/v1/users",
        "body": {"name": "alice", "email": "alice@example.com"},
    })
    assert resp.status_code == 200
    assert resp.json()["source"] == "learned"
    assert resp.json()["sample_count"] == 1
    schema_def = resp.json()["schema_def"]
    assert schema_def["type"] == "object"
    assert "name" in schema_def["properties"]

    # Second observation merges.
    resp2 = client.post("/api/v1/api-armor/schemas/learn", json={
        "method": "POST",
        "path": "/api/v1/users",
        "body": {"name": "bob", "age": 30},
    })
    assert resp2.status_code == 200
    assert resp2.json()["sample_count"] == 2


# ----- Profiles & Anomalies -----

def test_list_profiles_empty(client):
    """GET /api-armor/profiles returns an empty list initially."""
    resp = client.get("/api/v1/api-armor/profiles")
    assert resp.status_code == 200
    assert resp.json() == []


def test_finalize_profile(client, db):
    """POST /api-armor/profiles/{pid}/finalize marks a profile learned."""
    from app.models.api_armor import ApiProfile
    profile = ApiProfile(method="POST", path="/api/v1/users", dimensions={}, sample_count=150, learned=False)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    resp = client.post(f"/api/v1/api-armor/profiles/{profile.id}/finalize", params={"min_samples": 100})
    assert resp.status_code == 200
    assert resp.json()["learned"] is True


def test_delete_profile(client, db):
    """DELETE /api-armor/profiles/{pid} removes a profile."""
    from app.models.api_armor import ApiProfile
    profile = ApiProfile(method="POST", path="/api/v1/users", dimensions={}, sample_count=1, learned=False)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    resp = client.delete(f"/api/v1/api-armor/profiles/{profile.id}")
    assert resp.status_code == 200
    assert db.query(ApiProfile).count() == 0


def test_list_anomalies_empty(client):
    """GET /api-armor/anomalies returns an empty list initially."""
    resp = client.get("/api/v1/api-armor/anomalies")
    assert resp.status_code == 200
    assert resp.json() == []


def test_clear_anomalies(client, db):
    """DELETE /api-armor/anomalies clears all anomalies."""
    from app.models.api_armor import ApiAnomaly
    for i in range(3):
        db.add(ApiAnomaly(method="POST", path="/api/v1/users", dimension="content_type"))
    db.commit()
    resp = client.delete("/api/v1/api-armor/anomalies")
    assert resp.status_code == 200
    assert db.query(ApiAnomaly).count() == 0


# ----- Manual ingestion endpoints -----

def test_ingest_profile(client, db):
    """POST /api-armor/profiles/ingest creates/updates a profile."""
    from app.models.api_armor import ApiProfile
    resp = client.post("/api/v1/api-armor/profiles/ingest", json={
        "method": "POST",
        "path": "/api/v1/users",
        "content_type": "application/json",
        "response_status": 201,
    })
    assert resp.status_code == 200
    assert db.query(ApiProfile).count() == 1
    profile = db.query(ApiProfile).first()
    assert profile.method == "POST"
    assert profile.path == "/api/v1/users"
    assert "content_type" in (profile.dimensions or {})


def test_ingest_anomaly(client, db):
    """POST /api-armor/anomalies/ingest records an anomaly."""
    from app.models.api_armor import ApiAnomaly
    resp = client.post("/api/v1/api-armor/anomalies/ingest", json={
        "method": "POST",
        "path": "/api/v1/users",
        "dimension": "content_type",
        "observed_value": "text/xml",
        "expected_values": {"values": ["application/json"]},
    })
    assert resp.status_code == 200
    assert db.query(ApiAnomaly).count() == 1
    data = resp.json()
    assert data["dimension"] == "content_type"
    assert data["observed_value"] == "text/xml"
