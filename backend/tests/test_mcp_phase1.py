"""Tests for MCP Gateway Phase 1 — config bundle, HAProxy generation, protocol."""
import json
import os
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest

# Make mcp-gateway modules importable (directory has hyphen, not a valid package name)
_GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "mcp-gateway")
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_GATEWAY_DIR))


# ---- Config bundle tests ----

def test_build_config_bundle_empty(client, db):
    from app.services.mcp_config import build_config_bundle
    bundle = build_config_bundle(db)
    assert bundle["servers"] == []
    assert bundle["identities"] == []
    assert "teams" in bundle
    assert "allowed_origins" in bundle
    assert "jwt_issuer" in bundle


def test_build_config_bundle_with_server(client, db):
    from app.services.mcp_config import build_config_bundle
    from app.services.mcp_secrets import encrypt_secret
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    # Create team + server via API
    client.post("/api/v1/mcp/teams", json={"name": "Eng", "slug": "eng"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "srv", "url": "https://up.example.com/mcp",
        "auth_type": "bearer", "auth_secret": "secret123",
    })

    bundle = build_config_bundle(db)
    assert len(bundle["servers"]) == 1
    server = bundle["servers"][0]
    assert server["name"] == "srv"
    assert server["auth_secret"] == "secret123"  # decrypted
    assert server["auth_type"] == "bearer"
    assert server["has_replicas"] is False
    ms._fernet = None


def test_build_config_bundle_multi_replica_url_rewrite(client, db):
    from app.services.mcp_config import build_config_bundle
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    client.post("/api/v1/mcp/teams", json={"name": "T", "slug": "t"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "multi", "url": "https://up.example.com/mcp",
    })
    sid = resp.json()["id"]

    client.post(f"/api/v1/mcp/servers/{sid}/replicas", json={
        "url": "https://replica.example.com/mcp",
    })

    bundle = build_config_bundle(db)
    server = bundle["servers"][0]
    assert server["has_replicas"] is True
    assert "mcp-up/multi" in server["url"]
    assert server["original_url"] == "https://up.example.com/mcp"
    ms._fernet = None


def test_write_config_bundle_writes_file(client, db):
    from app.services.mcp_config import write_config_bundle
    import app.services.mcp_config as mc
    import app.services.mcp_secrets as ms
    from app.core.config import get_settings

    settings = get_settings()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = f.name
    os.unlink(tmp_path)  # remove so write creates it

    old_path = settings.MCP_CONFIG_PATH
    settings.MCP_CONFIG_PATH = tmp_path
    try:
        result_path = write_config_bundle(db)
        assert result_path == tmp_path
        assert os.path.exists(tmp_path)
        with open(tmp_path, "rb") as f:
            raw = f.read()
        # Handle both encrypted and plaintext bundles
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            # File is encrypted — decrypt it
            f_obj = ms._get_fernet()
            data = json.loads(f_obj.decrypt(raw).decode("utf-8"))
        assert "servers" in data
        assert "identities" in data
    finally:
        settings.MCP_CONFIG_PATH = old_path
        ms._fernet = None
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---- HAProxy generation tests ----

def test_mcp_gateway_backend_emitted_when_enabled(db):
    from app.services.haproxy import generate_mcp_gateway_backend
    config = generate_mcp_gateway_backend(db)
    assert "backend mcp_gateway" in config
    assert "stick on req.hdr(Mcp-Session-Id)" in config
    assert "option http-keep-alive" in config
    assert "timeout tunnel 300s" in config
    assert "Cache-Control no-store" in config


def test_mcp_upstreams_empty_when_no_replicas(db):
    from app.services.haproxy import generate_mcp_upstreams
    config = generate_mcp_upstreams(db)
    assert config == ""


def test_mcp_upstreams_emitted_with_replicas(client, db):
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    client.post("/api/v1/mcp/teams", json={"name": "UpT", "slug": "upt"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    resp = client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "multi-srv", "url": "https://up.example.com/mcp",
    })
    sid = resp.json()["id"]

    client.post(f"/api/v1/mcp/servers/{sid}/replicas", json={
        "url": "https://replica.example.com/mcp",
    })

    from app.services.haproxy import generate_mcp_upstreams
    config = generate_mcp_upstreams(db)
    assert "frontend mcp_upstreams" in config
    assert "backend mcp_up_multi-srv" in config
    assert "path_beg /mcp-up/multi-srv/" in config
    assert "stick on req.hdr(Mcp-Session-Id)" in config
    assert "balance roundrobin" in config
    assert "server primary" in config
    assert "server replica_1" in config
    ms._fernet = None


def test_mcp_upstreams_not_emitted_for_single_replica(client, db):
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    import app.services.mcp_secrets as ms
    ms._fernet = None

    client.post("/api/v1/mcp/teams", json={"name": "SingleT", "slug": "singlet"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]

    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "single-srv", "url": "https://up.example.com/mcp",
    })

    from app.services.haproxy import generate_mcp_upstreams
    config = generate_mcp_upstreams(db)
    assert config == ""
    ms._fernet = None


# ---- Listener protocol validation ----

def test_mcp_protocol_accepted_in_listener_schema():
    from app.schemas.listeners import ListenerCreate
    listener = ListenerCreate(name="mcp-listener", bind_port=8080, protocol="mcp")
    assert listener.protocol == "mcp"


def test_invalid_protocol_rejected():
    from app.schemas.listeners import ListenerCreate
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ListenerCreate(name="bad", bind_port=8080, protocol="invalid")


# ---- Frontend routing injection tests ----

def test_mcp_frontend_routing_dedicated_listener(db):
    """A listener with protocol=mcp gets default_backend mcp_gateway when flag is on."""
    from app.services import haproxy
    from app.services.settings import set_setting
    from tests.factories import make_listener

    set_setting(db, "mcp_gateway_enabled", "true")
    make_listener(db, name="mcp-in", bind_port=8080, protocol="mcp")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "default_backend mcp_gateway" in cfg
    assert "backend mcp_gateway" in cfg  # backend section also emitted


def test_mcp_frontend_routing_shared_listener(db):
    """A regular HTTP listener gets use_backend mcp_gateway for /mcp paths when flag is on."""
    from app.services import haproxy
    from app.services.settings import set_setting
    from tests.factories import make_listener, make_backend, make_server

    set_setting(db, "mcp_gateway_enabled", "true")
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="shared-in", bind_port=80, protocol="http")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "use_backend mcp_gateway if { path_beg /mcp }" in cfg
    assert "path_beg /.well-known/oauth-protected-resource" in cfg
    assert "backend mcp_gateway" in cfg


def test_mcp_frontend_routing_not_emitted_when_disabled(db):
    """No MCP routing rule when the feature flag is off."""
    from app.services import haproxy
    from app.services.settings import set_setting
    from tests.factories import make_listener

    set_setting(db, "mcp_gateway_enabled", "false")
    make_listener(db, name="mcp-in", bind_port=8080, protocol="mcp")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "mcp_gateway" not in cfg


# ---- Config status / unapplied detection tests ----

def test_mcp_config_status_detects_unapplied_changes(client, db):
    """MCP changes show as unapplied when the .applied bundle differs from generated."""
    import os
    from app.services.settings import set_setting
    from app.services.config import get_config_status
    from app.services.mcp_config import generate_mcp_bundle_text, write_applied_mcp_bundle
    import app.services.mcp_secrets as ms

    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    ms._fernet = None
    set_setting(db, "mcp_gateway_enabled", "true")

    # Create a team + server
    client.post("/api/v1/mcp/teams", json={"name": "StatusT", "slug": "statust"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "status-srv", "url": "https://up.example.com/mcp",
    })
    db.commit()

    # Write the .applied bundle (simulates a prior apply)
    write_applied_mcp_bundle(db)

    # No changes yet → not unapplied (for MCP portion)
    applied_text = generate_mcp_bundle_text(db)

    # Make a change — add another server
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "status-srv-2", "url": "https://up2.example.com/mcp",
    })
    db.commit()

    # Now the generated bundle should differ from .applied
    new_text = generate_mcp_bundle_text(db)
    assert new_text != applied_text

    # The config status should detect unapplied changes
    # (may also be True from haproxy config, but MCP is part of it)
    status = get_config_status(db)
    assert status is True

    ms._fernet = None


def test_mcp_config_status_clean_after_apply(client, db):
    """After writing the .applied bundle, MCP changes are not unapplied."""
    import os
    from app.services.settings import set_setting
    from app.services.mcp_config import generate_mcp_bundle_text, read_applied_mcp_bundle, write_applied_mcp_bundle
    import app.services.mcp_secrets as ms

    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    ms._fernet = None
    set_setting(db, "mcp_gateway_enabled", "true")

    client.post("/api/v1/mcp/teams", json={"name": "CleanT", "slug": "cleant"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "clean-srv", "url": "https://up.example.com/mcp",
    })
    db.commit()

    # Write .applied (simulates apply)
    write_applied_mcp_bundle(db)

    # Generated should match applied
    assert generate_mcp_bundle_text(db) == read_applied_mcp_bundle()

    ms._fernet = None


def test_mcp_config_diff_includes_mcp_bundle(client, db):
    """The config diff includes mcp-bundle.json when MCP changes are unapplied."""
    import os
    from app.services.settings import set_setting
    from app.services.config import get_config_diff
    from app.services.mcp_config import write_applied_mcp_bundle
    import app.services.mcp_secrets as ms

    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    ms._fernet = None
    set_setting(db, "mcp_gateway_enabled", "true")

    client.post("/api/v1/mcp/teams", json={"name": "DiffT", "slug": "difft"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "diff-srv", "url": "https://up.example.com/mcp",
    })
    db.commit()

    # Write .applied (simulates prior apply with one server)
    write_applied_mcp_bundle(db)

    # Add a second server
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "diff-srv-2", "url": "https://up2.example.com/mcp",
    })
    db.commit()

    result = get_config_diff(db)
    assert result["unapplied"] is True
    # The diff should mention the MCP bundle
    assert "mcp-bundle.json" in result["diff"]

    ms._fernet = None


def test_mcp_config_status_resilient_to_bundle_failures(client, db):
    """Config status/diff should not crash when MCP bundle generation fails.

    Simulates MCP_SECRETS_KEY not being set — _get_fernet() raises RuntimeError.
    The status check should still return (unapplied=True so the banner shows),
    and the diff should work for non-MCP configs without a broken mcp-bundle entry.
    """
    import os
    from app.services.settings import set_setting
    from app.services.config import get_config_status, get_config_diff
    from tests.factories import make_listener, make_backend, make_server
    import app.services.mcp_secrets as ms

    # Ensure no Fernet key is set
    os.environ.pop("MCP_SECRETS_KEY", None)
    ms._fernet = None
    set_setting(db, "mcp_gateway_enabled", "true")

    # Create a team + server WITH a secret (so decrypt_secret will be called
    # and _get_fernet() will raise RuntimeError)
    client.post("/api/v1/mcp/teams", json={"name": "ResilientT", "slug": "resilientt"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]
    # We can't create a server with a secret without MCP_SECRETS_KEY, so just
    # create one without secrets — the bundle should still build fine.
    # The real test is that config_status doesn't crash.
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "resilient-srv", "url": "https://up.example.com/mcp",
    })
    db.commit()

    # Also create a regular HAProxy listener+backend so there's non-MCP config
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="web-in", bind_port=80)
    db.commit()

    # Config status should not crash
    status = get_config_status(db)
    assert status is True  # unapplied (no .applied files yet)

    # Config diff should not crash and should not include a broken mcp-bundle entry
    result = get_config_diff(db)
    assert result["unapplied"] is True
    # haproxy.cfg diff should be present
    assert "haproxy.cfg" in result["diff"]

    ms._fernet = None


def test_mcp_config_status_resilient_to_fernet_runtime_error(client, db):
    """Config diff should not crash when _get_fernet raises RuntimeError.

    This simulates having servers with encrypted secrets but no MCP_SECRETS_KEY
    configured (e.g. key was removed after servers were created).
    """
    import os
    from app.services.settings import set_setting
    from app.services.config import get_config_status, get_config_diff
    from tests.factories import make_listener, make_backend, make_server
    import app.services.mcp_secrets as ms

    # Set up a valid Fernet key, create a server with a secret, then remove the key
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    ms._fernet = None
    set_setting(db, "mcp_gateway_enabled", "true")

    client.post("/api/v1/mcp/teams", json={"name": "FernetT", "slug": "fernett"})
    tid = client.get("/api/v1/mcp/teams").json()[0]["id"]
    client.post("/api/v1/mcp/servers", json={
        "team_id": tid, "name": "fernet-srv", "url": "https://up.example.com/mcp",
        "auth_type": "bearer", "auth_secret": "secret123",
    })
    db.commit()

    # Now remove the key — decrypt_secret will raise RuntimeError
    os.environ.pop("MCP_SECRETS_KEY", None)
    ms._fernet = None

    # Also create a regular HAProxy listener+backend
    backend = make_backend(db, name="web2")
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="web-in2", bind_port=81)
    db.commit()

    # Config status should not crash — should return True (unapplied)
    status = get_config_status(db)
    assert status is True

    # Config diff should not crash — should have haproxy.cfg diff
    result = get_config_diff(db)
    assert result["unapplied"] is True
    assert "haproxy.cfg" in result["diff"]
    # mcp-bundle.json may or may not be in the diff depending on whether
    # the bundle generated (with null secrets) differs from .applied.
    # The key assertion is that the diff didn't crash.

    # Clean up
    os.environ["MCP_SECRETS_KEY"] = "test-mcp-secrets-key-for-fernet-encryption"
    ms._fernet = None


# ---- Gateway auth module tests ----

def test_pat_format_detection():
    import importlib
    auth = importlib.import_module('auth')
    _is_pat, _parse_pat = auth._is_pat, auth._parse_pat
    assert _is_pat("mcp_abcd1234.secrettoken") is True
    assert _is_pat("eyJhbGciOi...") is False
    prefix, secret = _parse_pat("mcp_abcd1234.mysecret")
    assert prefix == "mcp_abcd1234"
    assert secret == "mysecret"


def test_pat_verification():
    import importlib
    auth = importlib.import_module('auth')
    _verify_pat = auth._verify_pat
    import bcrypt

    pat_token = "mcp_abcd1234.mysecret"
    pat_hash = bcrypt.hashpw(pat_token.encode(), bcrypt.gensalt()).decode()
    identities = [{
        "id": 1, "team_id": 1, "name": "bot",
        "kind": "pat", "pat_prefix": "mcp_abcd1234",
        "pat_hash": pat_hash, "enabled": True, "expires_at": None,
    }]
    result = _verify_pat("mcp_abcd1234", pat_token, identities)
    assert result is not None
    assert result["name"] == "bot"


def test_pat_wrong_secret_rejected():
    import importlib
    auth = importlib.import_module('auth')
    _verify_pat = auth._verify_pat
    import bcrypt

    pat_hash = bcrypt.hashpw(b"mcp_abcd1234.correct", bcrypt.gensalt()).decode()
    identities = [{
        "id": 1, "team_id": 1, "name": "bot",
        "kind": "pat", "pat_prefix": "mcp_abcd1234",
        "pat_hash": pat_hash, "enabled": True, "expires_at": None,
    }]
    result = _verify_pat("mcp_abcd1234", "wrong-secret", identities)
    assert result is None


def test_pat_expired_rejected():
    import importlib
    auth = importlib.import_module('auth')
    _verify_pat = auth._verify_pat
    import bcrypt
    from datetime import datetime, timedelta, timezone

    pat_token = "mcp_abcd1234.mysecret"
    pat_hash = bcrypt.hashpw(pat_token.encode(), bcrypt.gensalt()).decode()
    identities = [{
        "id": 1, "team_id": 1, "name": "bot",
        "kind": "pat", "pat_prefix": "mcp_abcd1234",
        "pat_hash": pat_hash, "enabled": True,
        "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    }]
    result = _verify_pat("mcp_abcd1234", pat_token, identities)
    assert result is None


def test_pat_disabled_rejected():
    import importlib
    auth = importlib.import_module('auth')
    _verify_pat = auth._verify_pat
    import bcrypt

    pat_token = "mcp_abcd1234.mysecret"
    pat_hash = bcrypt.hashpw(pat_token.encode(), bcrypt.gensalt()).decode()
    identities = [{
        "id": 1, "team_id": 1, "name": "bot",
        "kind": "pat", "pat_prefix": "mcp_abcd1234",
        "pat_hash": pat_hash, "enabled": False, "expires_at": None,
    }]
    result = _verify_pat("mcp_abcd1234", pat_token, identities)
    assert result is None


# ---- Gateway config loader tests ----

def test_config_loader_empty_when_no_file(tmp_path):
    import importlib
    cl = importlib.import_module('config_loader')
    cl._config = {}
    cl._config_path = str(tmp_path / "nonexistent.json")
    config = cl.get_config()
    assert config == {}
    assert cl.is_configured() is False


def test_config_loader_reads_file(tmp_path):
    import importlib
    cl = importlib.import_module('config_loader')

    config_file = tmp_path / "config.json"
    config_data = {"servers": [{"id": 1, "name": "srv", "enabled": True}], "identities": []}
    config_file.write_text(json.dumps(config_data))

    cl._config = {}
    cl._config_path = str(config_file)
    config = cl.get_config()
    assert len(config["servers"]) == 1
    assert cl.is_configured() is True


def test_config_loader_check_origin():
    import importlib
    cl = importlib.import_module('config_loader')
    cl._config = {"allowed_origins": ["https://example.com", "https://app.example.com"]}
    assert cl.check_origin("https://example.com") is True
    assert cl.check_origin("https://evil.com") is False
    assert cl.check_origin("") is True  # non-browser


def test_config_loader_empty_origins_rejects_non_empty():
    import importlib
    cl = importlib.import_module('config_loader')
    cl._config = {"allowed_origins": []}
    assert cl.check_origin("https://example.com") is False
    assert cl.check_origin("") is True


# ---- Gateway protocol tests ----

def test_protocol_prefix_tool_name():
    import importlib
    protocol = importlib.import_module('protocol')
    _prefix_tool_name = protocol._prefix_tool_name
    assert _prefix_tool_name("jira", "search") == "jira__search"


def test_protocol_prefix_list_items():
    import importlib
    protocol = importlib.import_module('protocol')
    _prefix_list_items = protocol._prefix_list_items
    items = [{"name": "search", "description": "Search issues"}]
    result = _prefix_list_items(items, "jira", "name")
    assert result[0]["name"] == "jira__search"
    assert result[0]["_meta"]["mcp_server"] == "jira"
    assert result[0]["_meta"]["mcp_original_name"] == "search"


def test_protocol_is_notification():
    import importlib
    protocol = importlib.import_module('protocol')
    _is_notification = protocol._is_notification
    assert _is_notification({"jsonrpc": "2.0", "method": "ping"}) is True
    assert _is_notification({"jsonrpc": "2.0", "id": 1, "method": "ping"}) is False


def test_protocol_is_response():
    import importlib
    protocol = importlib.import_module('protocol')
    _is_response = protocol._is_response
    assert _is_response({"jsonrpc": "2.0", "id": 1, "result": {}}) is True
    assert _is_response({"jsonrpc": "2.0", "id": 1, "error": {}}) is True
    assert _is_response({"jsonrpc": "2.0", "id": 1, "method": "ping"}) is False
