"""Tests for MCP Gateway Phase 0 — models, schemas, CRUD API, secrets, and migration."""
import datetime
import os
import tempfile

import pytest


# ---- Model tests ----

def test_mcp_models_importable():
    from app.models.models import (
        Team, UserTeam, McpServer, McpServerReplica, McpIdentity,
        McpPolicy, McpDlpRule, McpSkill, McpSkillVersion, McpGuardrail, McpEvent,
    )
    assert Team.__tablename__ == "teams"
    assert McpServer.__tablename__ == "mcp_servers"
    assert McpEvent.__tablename__ == "mcp_events"


def test_mcp_tables_in_metadata():
    from app.core.database import Base
    table_names = set(Base.metadata.tables.keys())
    assert "teams" in table_names
    assert "user_teams" in table_names
    assert "mcp_servers" in table_names
    assert "mcp_server_replicas" in table_names
    assert "mcp_identities" in table_names
    assert "mcp_policies" in table_names
    assert "mcp_dlp_rules" in table_names
    assert "mcp_skills" in table_names
    assert "mcp_skill_versions" in table_names
    assert "mcp_guardrails" in table_names
    assert "mcp_events" in table_names


# ---- Schema tests ----

def test_mcp_schemas_importable():
    from app.schemas.mcp import (
        TeamCreate, TeamResponse, McpServerCreate, McpServerResponse,
        McpIdentityCreate, McpIdentityResponse, PatCreateResponse,
        McpPolicyCreate, McpDlpRuleCreate, McpSkillCreate, McpGuardrailCreate,
    )
    assert TeamCreate.model_fields["name"].is_required()
    assert "auth_secret" in McpServerCreate.model_fields
    assert "auth_secret" not in McpServerResponse.model_fields
    assert "has_secret" in McpServerResponse.model_fields


# ---- Secrets service tests ----

def test_encrypt_decrypt_secret():
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    # Reset cached fernet
    import app.services.mcp_secrets as ms
    ms._fernet = None
    plaintext = "my-secret-token"
    ciphertext = ms.encrypt_secret(plaintext)
    assert ciphertext != plaintext
    assert ms.decrypt_secret(ciphertext) == plaintext
    ms._fernet = None  # cleanup


def test_decrypt_wrong_key_fails(monkeypatch):
    key1 = "test-mcp-secrets-key-for-fernet-encryption"
    key2 = "different-key-also-long-enough-for-test"
    from app.core.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "MCP_SECRETS_KEY", key1)
    import app.services.mcp_secrets as ms
    ms._fernet = None
    ciphertext = ms.encrypt_secret("hello")
    ms._fernet = None
    monkeypatch.setattr(s, "MCP_SECRETS_KEY", key2)
    with pytest.raises(ValueError, match="decryption failed"):
        ms.decrypt_secret(ciphertext)
    ms._fernet = None


# ---- CRUD API tests ----

def test_list_servers_empty(client):
    resp = client.get("/api/v1/mcp/servers")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_team_and_server(client):
    # Create team
    resp = client.post("/api/v1/mcp/teams", json={
        "name": "Engineering", "slug": "engineering",
    })
    assert resp.status_code == 200
    team = resp.json()
    assert team["name"] == "Engineering"
    tid = team["id"]

    # Create server
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid,
        "name": "my-mcp-server",
        "url": "https://upstream.example.com/mcp",
        "auth_type": "bearer",
        "auth_secret": "secret-token-123",
    })
    assert resp.status_code == 200
    server = resp.json()
    assert server["name"] == "my-mcp-server"
    assert server["has_secret"] is True
    assert "auth_secret" not in server
    assert server["namespace"] == "my-mcp-server"

    # List servers
    resp = client.get("/api/v1/mcp/servers")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    ms._fernet = None


def test_server_secret_never_returned(client):
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    # Create team + server with secret
    client.post("/api/v1/mcp/teams", json={"name": "T1", "slug": "t1"})
    resp = client.get("/api/v1/mcp/teams")
    tid = resp.json()[0]["id"]

    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "srv", "url": "https://up.example.com/mcp",
        "auth_type": "bearer", "auth_secret": "super-secret",
    })

    # GET list
    resp = client.get("/api/v1/mcp/servers")
    data = resp.json()[0]
    assert "auth_secret" not in data
    assert data["has_secret"] is True

    # GET individual via update (PUT returns updated object)
    sid = data["id"]
    resp = client.put(f"/api/v1/mcp/servers/{sid}", json={"display_name": "Updated"})
    assert resp.status_code == 200
    assert "auth_secret" not in resp.json()
    ms._fernet = None


def test_replica_path_mismatch_rejected(client):
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    client.post("/api/v1/mcp/teams", json={"name": "T2", "slug": "t2"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "srv2", "url": "https://up.example.com/mcp",
    })
    sid = resp.json()["id"]

    # Same path — OK
    resp = client.post(f"/api/v1/mcp/servers/{sid}/replicas", json={
        "url": "https://replica.example.com/mcp",
    })
    assert resp.status_code == 200

    # Different path — rejected
    resp = client.post(f"/api/v1/mcp/servers/{sid}/replicas", json={
        "url": "https://replica2.example.com/different-path",
    })
    assert resp.status_code == 400
    assert "path" in resp.json()["detail"].lower()
    ms._fernet = None


def test_namespace_conflict_rejected(client):
    client.post("/api/v1/mcp/teams", json={"name": "T3", "slug": "t3"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "srv-a", "url": "https://a.example.com/mcp",
    })
    # Same name -> same namespace -> conflict
    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "srv-a", "url": "https://b.example.com/mcp",
    })
    assert resp.status_code == 409


def test_create_and_list_identities(client):
    client.post("/api/v1/mcp/teams", json={"name": "T4", "slug": "t4"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/identities", json={
        "team_id": tid, "name": "ci-bot", "kind": "pat",
    })
    assert resp.status_code == 200
    ident = resp.json()
    assert ident["kind"] == "pat"
    assert "pat_hash" not in ident

    resp = client.get("/api/v1/mcp/identities")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_issue_pat(client):
    client.post("/api/v1/mcp/teams", json={"name": "T5", "slug": "t5"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/identities", json={
        "team_id": tid, "name": "ci-pat", "kind": "pat",
    })
    iid = resp.json()["id"]

    resp = client.post(f"/api/v1/mcp/identities/{iid}/tokens")
    assert resp.status_code == 200
    pat_data = resp.json()
    assert pat_data["pat"].startswith("mcp_")
    assert pat_data["prefix"] == pat_data["pat"][:12]  # mcp_ + 8 hex chars


def test_issue_pat_rejects_jwt_identity(client):
    client.post("/api/v1/mcp/teams", json={"name": "T6", "slug": "t6"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/identities", json={
        "team_id": tid, "name": "jwt-ident", "kind": "jwt",
        "jwt_issuer": "https://issuer.example.com",
    })
    iid = resp.json()["id"]

    resp = client.post(f"/api/v1/mcp/identities/{iid}/tokens")
    assert resp.status_code == 400


def test_policies_crud(client):
    client.post("/api/v1/mcp/teams", json={"name": "T7", "slug": "t7"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/policies", json={
        "team_id": tid, "name": "allow-all", "expression": "true",
    })
    assert resp.status_code == 200
    pid = resp.json()["id"]
    assert resp.json()["expression_ast"] is not None

    resp = client.put(f"/api/v1/mcp/policies/{pid}", json={"action": "deny"})
    assert resp.status_code == 200
    assert resp.json()["action"] == "deny"

    resp = client.delete(f"/api/v1/mcp/policies/{pid}")
    assert resp.status_code == 200


def test_policy_create_rejects_invalid_expression(client):
    client.post("/api/v1/mcp/teams", json={"name": "T7a", "slug": "t7a"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/policies", json={
        "team_id": tid, "name": "bad-policy",
        "expression": "tool == 'x' && method == 'y'",
    })
    assert resp.status_code == 400


def test_policy_create_stores_expression_ast(client):
    client.post("/api/v1/mcp/teams", json={"name": "T7b", "slug": "t7b"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/policies", json={
        "team_id": tid, "name": "allow-grok",
        "expression": 'mcp.identity = "grok-agent" and mcp.tool in ["corex-manager__create_security_rule"]',
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["expression_ast"] is not None
    assert data["expression_ast"]["type"] == "and"


def test_policy_update_replaces_expression_ast(client):
    client.post("/api/v1/mcp/teams", json={"name": "T7c", "slug": "t7c"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/policies", json={
        "team_id": tid, "name": "update-me", "expression": "true",
    })
    pid = resp.json()["id"]

    resp = client.put(f"/api/v1/mcp/policies/{pid}", json={
        "expression": 'mcp.tool = "corex-manager__create_security_rule"',
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["expression_ast"]["type"] == "compare"
    assert data["expression_ast"]["field"] == "mcp.tool"


def test_policy_validate_endpoint(client):
    resp = client.post("/api/v1/mcp/policies/validate", json={
        "expression": 'mcp.tool = "corex-manager__x"',
    })
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["ast"] is not None

    resp = client.post("/api/v1/mcp/policies/validate", json={
        "expression": "tool == 'x'",
    })
    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    assert resp.json()["error"] is not None


def test_policy_builder_metadata(client):
    client.post("/api/v1/mcp/teams", json={"name": "T7d", "slug": "t7d"})

    resp = client.get("/api/v1/mcp/policies/builder-metadata")
    assert resp.status_code == 200
    data = resp.json()
    assert "methods" in data
    assert "tools/call" in data["methods"]
    assert "tools" in data
    assert "identities" in data
    assert "teams" in data
    assert "stale_servers" in data
    assert data["refreshing"] is False


def test_policy_builder_metadata_triggers_background_refresh(client, monkeypatch):
    client.post("/api/v1/mcp/teams", json={"name": "T7e", "slug": "t7e"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "test-catalog-server",
        "namespace": "testns", "url": "http://example.com/mcp",
        "enabled": True,
    })
    sid = resp.json()["id"]

    triggered: list = []
    monkeypatch.setattr("app.api.v1.mcp.trigger_background_catalog_refresh", lambda sids: (triggered.extend(sids) or sids))

    resp = client.get("/api/v1/mcp/policies/builder-metadata")
    assert resp.status_code == 200
    data = resp.json()
    assert data["refreshing"] is True
    assert any(s["id"] == sid for s in data["stale_servers"])
    assert sid in triggered


def test_background_refresh_healthy_server_with_missing_catalog(db, monkeypatch):
    """A server that is healthy in the DB but has no Valkey catalog must still be refreshed."""
    from app.services import mcp_policies
    from app.models.mcp import McpServer, Team

    team = Team(name="T-bg", slug="t-bg")
    db.add(team)
    db.commit()

    server = McpServer(
        team_id=team.id,
        name="healthy-but-missing-catalog",
        namespace="hmc",
        url="http://example.com/mcp",
        enabled=True,
        health_status="healthy",
        last_catalog_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(server)
    db.commit()

    refreshed = []
    def _fake_refresh(srv, session):
        refreshed.append(srv.id)
        return {"tools": [{"name": "tool1"}]}
    monkeypatch.setattr(mcp_policies, "refresh_server_catalog", _fake_refresh)
    monkeypatch.setattr(mcp_policies, "_get_server_catalog", lambda server, client: None)

    mcp_policies._background_refresh_thread([server.id])

    assert server.id in refreshed


def test_trigger_background_catalog_refresh_rate_limit(db, monkeypatch):
    """trigger_background_catalog_refresh should not re-trigger within the cooldown window."""
    from app.services import mcp_policies

    # Bypass the test guard and fake the thread worker.
    monkeypatch.delenv("PYTEST_VERSION", raising=False)
    monkeypatch.setattr(mcp_policies, "_background_refresh_thread", lambda *args, **kwargs: None)

    # Freeze and control time.
    class FakeTime:
        @staticmethod
        def time():
            return fake_time[0]
        @staticmethod
        def sleep(x):
            pass

    fake_time = [100.0]
    monkeypatch.setattr(mcp_policies, "time", FakeTime())

    # Save and restore module-level state to keep the test isolated.
    original_last = mcp_policies._last_catalog_refresh_trigger.copy()
    original_in_flight = mcp_policies._refreshing_server_ids.copy()
    try:
        # Clean any leftover state from the module under test.
        mcp_policies._last_catalog_refresh_trigger.clear()
        mcp_policies._refreshing_server_ids.clear()

        # First trigger should succeed and queue the server.
        assert mcp_policies.trigger_background_catalog_refresh([42]) == [42]
        mcp_policies._refreshing_server_ids.discard(42)  # simulate thread completion

        # Second trigger immediately should be on cooldown.
        assert mcp_policies.trigger_background_catalog_refresh([42]) == []

        # Advance past cooldown.
        fake_time[0] = fake_time[0] + mcp_policies._CATALOG_REFRESH_COOLDOWN_SECONDS + 1
        assert mcp_policies.trigger_background_catalog_refresh([42]) == [42]
    finally:
        mcp_policies._last_catalog_refresh_trigger = original_last
        mcp_policies._refreshing_server_ids = original_in_flight


def test_server_catalog_refresh(client, monkeypatch):
    client.post("/api/v1/mcp/teams", json={"name": "T7f", "slug": "t7f"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "refreshable-server",
        "namespace": "refreshns", "url": "http://example.com/mcp",
        "enabled": True,
    })
    sid = resp.json()["id"]

    def _fake_refresh(server, db):
        return {
            "tools": [{"name": "tool1"}],
            "resources": [{"uri": "resource://x"}],
            "prompts": [{"name": "prompt1"}],
        }

    monkeypatch.setattr("app.api.v1.mcp.refresh_server_catalog", _fake_refresh)

    resp = client.post(f"/api/v1/mcp/servers/{sid}/catalog/refresh")
    assert resp.status_code == 200
    data = resp.json()
    assert data["server_id"] == sid
    assert len(data["tools"]) == 1
    assert len(data["resources"]) == 1
    assert len(data["prompts"]) == 1


def test_server_catalog_refresh_fails(client, monkeypatch):
    client.post("/api/v1/mcp/teams", json={"name": "T7g", "slug": "t7g"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "unreachable-server",
        "namespace": "badns", "url": "http://example.com/mcp",
        "enabled": True,
    })
    sid = resp.json()["id"]

    monkeypatch.setattr("app.api.v1.mcp.refresh_server_catalog", lambda server, db: None)

    resp = client.post(f"/api/v1/mcp/servers/{sid}/catalog/refresh")
    assert resp.status_code == 502


def test_dlp_rule_custom_requires_regex(client):
    client.post("/api/v1/mcp/teams", json={"name": "T8", "slug": "t8"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/dlp-rules", json={
        "team_id": tid, "name": "custom-dlp", "detector": "custom",
    })
    assert resp.status_code == 400

    resp = client.post("/api/v1/mcp/dlp-rules", json={
        "team_id": tid, "name": "custom-dlp", "detector": "custom",
        "find_regex": r"\bSECRET\b",
    })
    assert resp.status_code == 200


def test_guardrail_custom_requires_regex(client):
    client.post("/api/v1/mcp/teams", json={"name": "T9", "slug": "t9"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/guardrails", json={
        "team_id": tid, "name": "custom-gr", "pack": "custom",
    })
    assert resp.status_code == 400

    resp = client.post("/api/v1/mcp/guardrails", json={
        "team_id": tid, "name": "custom-gr", "pack": "custom",
        "find_regex": r"jailbreak",
    })
    assert resp.status_code == 200


def test_skill_versioning(client):
    client.post("/api/v1/mcp/teams", json={"name": "T10", "slug": "t10"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/skills", json={
        "team_id": tid, "name": "my-skill",
    })
    sid = resp.json()["id"]

    # Create version 1
    resp = client.post(f"/api/v1/mcp/skills/{sid}/versions", json={
        "body": "# My Skill\nDo the thing.",
    })
    assert resp.status_code == 200
    assert resp.json()["version"] == 1

    # Create version 2
    resp = client.post(f"/api/v1/mcp/skills/{sid}/versions", json={
        "body": "# My Skill v2\nDo it better.",
    })
    assert resp.json()["version"] == 2

    # List versions
    resp = client.get(f"/api/v1/mcp/skills/{sid}/versions")
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    # Publish
    resp = client.post(f"/api/v1/mcp/skills/{sid}/publish")
    assert resp.status_code == 200
    assert resp.json()["published_version_id"] is not None


def test_skill_import_from_raw_url(client, monkeypatch):
    """Import a skill from a raw SKILL.md URL with YAML frontmatter."""
    skill_md = "---\nname: code-review\ndescription: Reviews code\n---\n\n# Code Review\n\nReview the code."
    import httpx as _httpx

    class _MockResp:
        content = skill_md.encode()
        headers = {"content-type": "text/plain"}
        def raise_for_status(self): pass

    monkeypatch.setattr(_httpx, "get", lambda *a, **kw: _MockResp())
    monkeypatch.setattr(_httpx, "head", lambda *a, **kw: _MockResp())

    client.post("/api/v1/mcp/teams", json={"name": "TI1", "slug": "ti1"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/skills/import", json={
        "url": "https://raw.githubusercontent.com/owner/repo/main/skills/code-review/SKILL.md",
        "team_id": tid,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["name"] == "code-review"
    assert data["description"] == "Reviews code"
    assert data["published_version_id"] is not None  # auto-published


def test_skill_import_from_zip(client, monkeypatch):
    """Import a skill from a ZIP archive containing SKILL.md."""
    import io, zipfile
    import httpx as _httpx

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("SKILL.md", "---\nname: my-skill\n---\n\n# My Skill\n\nDo stuff.")
        zf.writestr("helper.py", "print('hello')")
    buf.seek(0)

    class _MockResp:
        content = buf.getvalue()
        headers = {"content-type": "application/zip"}
        def raise_for_status(self): pass

    monkeypatch.setattr(_httpx, "get", lambda *a, **kw: _MockResp())
    monkeypatch.setattr(_httpx, "head", lambda *a, **kw: _MockResp())

    client.post("/api/v1/mcp/teams", json={"name": "TI2", "slug": "ti2"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/skills/import", json={
        "url": "https://example.com/skills/my-skill.zip",
        "team_id": tid,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["name"] == "my-skill"
    assert data["published_version_id"] is not None


def test_skill_import_duplicate_name(client, monkeypatch):
    """Importing a skill with a name that already exists returns 409."""
    skill_md = "---\nname: existing-skill\n---\n\n# Existing"
    import httpx as _httpx

    class _MockResp:
        content = skill_md.encode()
        headers = {"content-type": "text/plain"}
        def raise_for_status(self): pass

    monkeypatch.setattr(_httpx, "get", lambda *a, **kw: _MockResp())
    monkeypatch.setattr(_httpx, "head", lambda *a, **kw: _MockResp())

    client.post("/api/v1/mcp/teams", json={"name": "TI3", "slug": "ti3"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    # First import succeeds
    resp = client.post("/api/v1/mcp/skills/import", json={
        "url": "https://raw.githubusercontent.com/owner/repo/main/SKILL.md",
        "team_id": tid,
    })
    assert resp.status_code == 200

    # Second import with same name fails
    resp = client.post("/api/v1/mcp/skills/import", json={
        "url": "https://raw.githubusercontent.com/owner/repo/main/SKILL.md",
        "team_id": tid,
    })
    assert resp.status_code == 409


def test_skill_import_no_publish(client, monkeypatch):
    """Import with auto_publish=false creates a draft skill."""
    skill_md = "---\nname: draft-skill\n---\n\n# Draft"
    import httpx as _httpx

    class _MockResp:
        content = skill_md.encode()
        headers = {"content-type": "text/plain"}
        def raise_for_status(self): pass

    monkeypatch.setattr(_httpx, "get", lambda *a, **kw: _MockResp())
    monkeypatch.setattr(_httpx, "head", lambda *a, **kw: _MockResp())

    client.post("/api/v1/mcp/teams", json={"name": "TI4", "slug": "ti4"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/skills/import", json={
        "url": "https://raw.githubusercontent.com/owner/repo/main/SKILL.md",
        "team_id": tid,
        "auto_publish": False,
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["published_version_id"] is None


def test_skill_import_name_override(client, monkeypatch):
    """Import with explicit name override."""
    skill_md = "---\nname: original\n---\n\n# Original"
    import httpx as _httpx

    class _MockResp:
        content = skill_md.encode()
        headers = {"content-type": "text/plain"}
        def raise_for_status(self): pass

    monkeypatch.setattr(_httpx, "get", lambda *a, **kw: _MockResp())
    monkeypatch.setattr(_httpx, "head", lambda *a, **kw: _MockResp())

    client.post("/api/v1/mcp/teams", json={"name": "TI5", "slug": "ti5"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/skills/import", json={
        "url": "https://raw.githubusercontent.com/owner/repo/main/SKILL.md",
        "team_id": tid,
        "name": "custom-name",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "custom-name"


def test_skill_parse_skill_md():
    """Test the _parse_skill_md helper function."""
    from app.api.v1.mcp import _parse_skill_md

    # With frontmatter
    content = "---\nname: test\ndescription: A test\n---\n\n# Body\n\nContent here."
    fm, body = _parse_skill_md(content)
    assert fm["name"] == "test"
    assert fm["description"] == "A test"
    assert body.startswith("# Body")

    # Without frontmatter
    content = "# Just markdown\n\nNo frontmatter."
    fm, body = _parse_skill_md(content)
    assert fm == {}
    assert body == "# Just markdown\n\nNo frontmatter."


def test_skill_resolve_url():
    """Test the _resolve_skill_url helper function."""
    from app.api.v1.mcp import _resolve_skill_url

    # Raw URL passes through
    assert _resolve_skill_url("https://raw.githubusercontent.com/owner/repo/main/SKILL.md") == \
        "https://raw.githubusercontent.com/owner/repo/main/SKILL.md"

    # GitHub blob URL converts to raw
    assert _resolve_skill_url("https://github.com/owner/repo/blob/main/skills/foo/SKILL.md") == \
        "https://raw.githubusercontent.com/owner/repo/main/skills/foo/SKILL.md"

    # Non-HTTP, non-shorthand returns None
    assert _resolve_skill_url("not-a-url") is None


def test_skill_derive_name_from_url():
    """Test the _derive_name_from_url helper function."""
    from app.api.v1.mcp import _derive_name_from_url

    assert _derive_name_from_url("https://raw.githubusercontent.com/owner/repo/main/skills/my-skill/SKILL.md") == "my-skill"
    assert _derive_name_from_url("https://raw.githubusercontent.com/owner/repo/main/SKILL.md") == "main"
    assert _derive_name_from_url("https://example.com/download/my-cool-skill.zip") == "my-cool-skill.zip"


def test_snapshot_excludes_mcp_events():
    from app.services.haproxy import _SNAPSHOT_EXCLUDED
    assert "mcp_events" in _SNAPSHOT_EXCLUDED


def test_audit_skips_mcp_secret_paths():
    from app.services.audit import _PAYLOAD_SKIP_PATHS
    assert "/mcp/servers" in _PAYLOAD_SKIP_PATHS
    assert "/mcp/identities" in _PAYLOAD_SKIP_PATHS


def test_auth0_sync_rejects_missing_config(client):
    client.post("/api/v1/mcp/teams", json={"name": "TAuth0", "slug": "tauth0"})
    tid = client.get("/api/v1/mcp/teams").json()[-1]["id"]

    resp = client.post("/api/v1/mcp/auth0/sync", json={
        "team_id": tid,
        "dry_run": True,
    })
    assert resp.status_code == 400
    assert "not fully configured" in resp.json()["detail"].lower()


def test_build_config_bundle_derives_auth0_jwt(monkeypatch, db):
    from app.services import mcp_config

    monkeypatch.setattr(mcp_config.settings, "AUTH0_DOMAIN", "dev-tenant.us.auth0.com")
    monkeypatch.setattr(mcp_config.settings, "AUTH0_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(mcp_config.settings, "AUTH0_MCP_AUDIENCE", "https://corex-manager/mcp")
    monkeypatch.setattr(mcp_config.settings, "MCP_JWT_ISSUER", None)
    monkeypatch.setattr(mcp_config.settings, "MCP_JWT_AUDIENCE", None)
    monkeypatch.setattr(mcp_config.settings, "MCP_JWT_JWKS_URL", None)

    bundle = mcp_config.build_config_bundle(db)
    assert bundle["jwt_issuer"] == "https://dev-tenant.us.auth0.com/"
    assert bundle["jwt_audience"] == "https://corex-manager/mcp"
    assert bundle["jwt_jwks_url"] == "https://dev-tenant.us.auth0.com/.well-known/jwks.json"
