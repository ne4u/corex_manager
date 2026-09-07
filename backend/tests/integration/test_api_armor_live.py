"""Live HAProxy integration tests for API Armor.

These tests are skipped unless ``RUN_INTEGRATION_TESTS=1`` is set in the
environment. They exercise the real HAProxy -> Rust API Armor runtime path:

- schema validation (invalid JSON body -> 400)
- API-key authentication (missing/wrong key -> 401, valid key -> proxied)
- JWT authentication (missing/invalid/expired -> 401, valid -> proxied)
- GraphQL depth/complexity/validity enforcement
- behavioral profile anomaly detection
- runtime data files

Required environment:

- ``HAPROXY_INTEGRATION_URL`` (default: http://localhost)
- ``BACKEND_INTEGRATION_URL`` (default: https://localhost:8000)
- ``ADMIN_PASSWORD`` for the backend admin account (default: admin)

The tests configure an API Armor-enabled listener for each scenario through the
backend API, then send requests through HAProxy and assert the HTTP status
codes. Each test cleans up its own resources.
"""
import json
import os
import secrets
import time
import urllib.request
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_INTEGRATION_TESTS"),
        reason="Set RUN_INTEGRATION_TESTS=1 to run live HAProxy integration tests",
    ),
]

HAPROXY_URL = os.environ.get("HAPROXY_INTEGRATION_URL", "http://localhost")
BACKEND_URL = os.environ.get("BACKEND_INTEGRATION_URL", "https://localhost:8000")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

JWT_SECRET = "test-jwt-secret-do-not-use-in-production"
JWT_ISSUER = "test-issuer"
JWT_AUDIENCE = "test-audience"


def _haproxy_available() -> bool:
    try:
        req = urllib.request.Request(HAPROXY_URL, method="GET")
        with urllib.request.urlopen(req, timeout=2, context=None) as resp:
            return resp.status in (200, 403, 404)
    except Exception:
        return False


def _api_call(token, method, path, payload=None, raw=False):
    import ssl
    import urllib.request

    url = f"{BACKEND_URL}/api/v1/{path.lstrip('/')}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method.upper(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        body = resp.read().decode()
        if raw:
            return body
        return json.loads(body) if body else {}


def _get_token() -> str:
    import ssl
    import urllib.request

    if not ADMIN_PASSWORD:
        pytest.skip("Set ADMIN_PASSWORD for live integration tests")

    data = f"username=admin&password={ADMIN_PASSWORD}&grant_type=password".encode()
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/auth/token",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read().decode())["access_token"]


def _wait_for_haproxy():
    """Poll HAProxy until it responds."""
    import requests

    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            r = requests.get(HAPROXY_URL, timeout=2)
            if r.status_code in (200, 400, 403, 404):
                return
        except Exception:
            pass
        time.sleep(0.5)
    pytest.fail("HAProxy never became reachable")


def _wait_for_task(token, task_id, timeout=120):
    """Poll a background config-apply task until it completes or fails."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = _api_call(token, "get", f"tasks/{task_id}")
        if task["status"] in ("success", "failed"):
            return task
        time.sleep(0.5)
    pytest.fail(f"Config apply task {task_id} did not complete")


def _delete_test_resources(token, suffix=None):
    """Delete listeners and backends created by these tests."""
    # Listeners first because they reference backends.
    for l in _api_call(token, "get", "listeners"):
        if l["name"].startswith("api-armor") and (suffix is None or l["name"].endswith(suffix)):
            _api_call(token, "delete", f"listeners/{l['id']}")
    for b in _api_call(token, "get", "backends"):
        if b["name"].startswith("api-test") and (suffix is None or b["name"].endswith(suffix)):
            _api_call(token, "delete", f"backends/{b['id']}")

    # Clean up test API Armor resources by name prefix.
    for sr in _api_call(token, "get", "security-rules"):
        if sr["name"].startswith("API Armor") and (suffix is None or sr["name"].endswith(suffix)):
            _api_call(token, "delete", f"security-rules/{sr['id']}")

    for p in _api_call(token, "get", "api-armor/auth-policies"):
        if p["name"].startswith(("api-key-policy-", "jwt-policy-")) and (suffix is None or p["name"].endswith(suffix)):
            _api_call(token, "delete", f"api-armor/auth-policies/{p['id']}")

    for kl in _api_call(token, "get", "api-armor/api-key-lists"):
        if kl["name"].startswith("test-keys-") and (suffix is None or kl["name"].endswith(suffix)):
            _api_call(token, "delete", f"api-armor/api-key-lists/{kl['id']}")

    for s in _api_call(token, "get", "api-armor/specs"):
        if s["name"].startswith("test-spec-") and (suffix is None or s["name"].endswith(suffix)):
            _api_call(token, "delete", f"api-armor/specs/{s['id']}")

    # Profiles have no name; this integration suite only uses /api/v1/test POST.
    for p in _api_call(token, "get", "api-armor/profiles"):
        if p["method"] == "POST" and p["path"] == "/api/v1/test":
            _api_call(token, "delete", f"api-armor/profiles/{p['id']}")

    # Queue an apply so the proxy state is refreshed after the teardown changes.
    # We do not wait here; the next setup's _apply_and_wait will wait for the
    # final configuration with the new listener in place.
    _api_call(token, "post", "config/apply", {})


def _api_settings(token):
    """Enable request fingerprinting and API Armor for the live stack."""
    _api_call(token, "put", "settings/req_fp_enabled", {"value": "true"})
    _api_call(token, "put", "settings/req_fp_parse_body", {"value": "true"})
    _api_call(token, "put", "settings/api_armor_enabled", {"value": "true"})
    _api_call(token, "put", "settings/api_armor_module_enabled", {"value": "true"})
    _api_call(token, "put", "settings/api_armor_max_body_bytes", {"value": "1048576"})


def _make_backend(token, suffix, variant=""):
    return _api_call(token, "post", "backends", {
        "name": f"api-test{variant}-{suffix}",
        "mode": "http",
        "protocol": "http",
        "algorithm": "roundrobin",
        "health_check_enabled": True,
        "health_check_uri": "/api/v1/health",
        "health_check_method": "GET",
        "servers": [{
            "name": "api",
            "address": "api",
            "port": 8000,
            "weight": 100,
            "check": True,
            "ssl": True,
            "verify": "none",
            "check_ssl": True,
        }],
    })


def _make_listener(token, suffix, be_id, variant="", options=None):
    return _api_call(token, "post", "listeners", {
        "name": f"api-armor{variant}-{suffix}",
        "bind_address": "0.0.0.0",
        "bind_port": 80,
        "mode": "http",
        "protocol": "http",
        "enabled": True,
        "default_backend_id": be_id,
        "options": options or {"api_armor": True},
    })


def _import_spec(token, suffix, variant="", with_body_schema=True):
    if with_body_schema:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/api/v1/test": {
                    "post": {
                        "operationId": "createTest",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"name": {"type": "string"}},
                                        "required": ["name"],
                                    }
                                }
                            },
                        },
                    }
                }
            },
        }
    else:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {"/api/v1/test": {"post": {"operationId": "createTest"}}},
        }
    _api_call(token, "post", "api-armor/specs", {
        "name": f"test-spec{variant}-{suffix}",
        "spec": json.dumps(spec),
    })
    # Enable the schema for the /api/v1/test POST endpoint if one exists.
    schemas = _api_call(token, "get", "api-armor/schemas")
    for s in schemas:
        if s["path"] == "/api/v1/test" and s["method"] == "POST":
            s["enabled"] = True
            _api_call(token, "put", f"api-armor/schemas/{s['id']}", s)


def _apply_and_wait(token):
    result = _api_call(token, "post", "config/apply", {})
    task_id = result.get("task_id")
    if task_id:
        _wait_for_task(token, task_id)
    # Give HAProxy a moment to finish the graceful worker handoff.
    time.sleep(2)
    _wait_for_haproxy()


@pytest.fixture(scope="function")
def api_key_setup():
    """Create a live API Armor listener with API-key auth, then clean up."""
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    token = _get_token()
    suffix = secrets.token_hex(4)

    _delete_test_resources(token)
    _api_settings(token)
    be = _make_backend(token, suffix)
    listener = _make_listener(token, suffix, be["id"])
    _import_spec(token, suffix)

    key_list = _api_call(token, "post", "api-armor/api-key-lists", {
        "name": f"test-keys-{suffix}",
        "description": "",
        "entries": ["secret-key"],
    })

    _api_call(token, "post", "api-armor/auth-policies", {
        "name": f"api-key-policy-{suffix}",
        "auth_type": "api_key",
        "api_key_header": "X-Api-Key",
        "api_key_list_id": key_list["id"],
        "on_failure": "block",
        "enabled": True,
        "listener_ids": [listener["id"]],
    })

    _apply_and_wait(token)

    yield suffix

    _delete_test_resources(token, suffix)


def test_haproxy_api_armor_schema_validation(api_key_setup):
    """An invalid JSON body (name: integer) is rejected with 400."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": 123},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 400, f"expected 400 for invalid schema, got {r.status_code}"


def test_haproxy_api_armor_auth_missing(api_key_setup):
    """A valid JSON body with no API key is rejected with 401."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 401, f"expected 401 for missing API key, got {r.status_code}"


def test_haproxy_api_armor_auth_invalid(api_key_setup):
    """A valid JSON body with a wrong API key is rejected with 401."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json", "X-Api-Key": "wrong-key"},
        timeout=10,
    )
    assert r.status_code == 401, f"expected 401 for wrong API key, got {r.status_code}"


def test_haproxy_api_armor_auth_valid(api_key_setup):
    """A valid JSON body with the correct API key is proxied (404 from backend)."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json", "X-Api-Key": "secret-key"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 (proxied, no route), got {r.status_code}"


@pytest.fixture(scope="function")
def jwt_setup():
    """Create a live API Armor listener with JWT auth, then clean up."""
    token = _get_token()
    suffix = secrets.token_hex(4)

    _delete_test_resources(token)
    _api_settings(token)
    be = _make_backend(token, suffix, variant="-jwt")
    listener = _make_listener(token, suffix, be["id"], variant="-jwt")
    _import_spec(token, suffix, variant="-jwt")

    _api_call(token, "post", "api-armor/auth-policies", {
        "name": f"jwt-policy-{suffix}",
        "auth_type": "jwt",
        "jwt_secret_env": "JWT_SECRET",
        "jwt_issuer": JWT_ISSUER,
        "jwt_audience": JWT_AUDIENCE,
        "on_failure": "block",
        "enabled": True,
        "listener_ids": [listener["id"]],
    })

    _apply_and_wait(token)

    yield suffix

    _delete_test_resources(token, suffix)


def _make_jwt(claims, secret=JWT_SECRET, algorithm="HS256"):
    try:
        import jwt as pyjwt
    except ImportError as exc:
        pytest.skip(f"PyJWT required for JWT live tests: {exc}")
    return pyjwt.encode(claims, secret, algorithm=algorithm)


def test_haproxy_api_armor_jwt_missing(jwt_setup):
    """A valid JSON body with no Authorization header is rejected with 401."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 401, f"expected 401 for missing JWT, got {r.status_code}"


def test_haproxy_api_armor_jwt_valid(jwt_setup):
    """A valid JWT is accepted and the request is proxied."""
    import requests

    now = int(time.time())
    token = _make_jwt({"sub": "user1", "iss": JWT_ISSUER, "aud": JWT_AUDIENCE, "exp": now + 300})
    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 (proxied, no route), got {r.status_code}"


def test_haproxy_api_armor_jwt_invalid_claims(jwt_setup):
    """JWTs with wrong issuer, audience, or signature are rejected with 401."""
    import requests

    now = int(time.time())
    wrong_iss = _make_jwt({"sub": "user1", "iss": "wrong", "aud": JWT_AUDIENCE, "exp": now + 300})
    wrong_aud = _make_jwt({"sub": "user1", "iss": JWT_ISSUER, "aud": "wrong", "exp": now + 300})
    bad_secret = _make_jwt({"sub": "user1", "iss": JWT_ISSUER, "aud": JWT_AUDIENCE, "exp": now + 300}, secret="wrong-secret-for-testing-only-32bytes-long")
    expired = _make_jwt({"sub": "user1", "iss": JWT_ISSUER, "aud": JWT_AUDIENCE, "exp": now - 10})

    for name, t in [
        ("wrong issuer", wrong_iss),
        ("wrong audience", wrong_aud),
        ("wrong secret", bad_secret),
        ("expired", expired),
    ]:
        r = requests.post(
            f"{HAPROXY_URL}/api/v1/test",
            json={"name": "hello"},
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {t}"},
            timeout=10,
        )
        assert r.status_code == 401, f"{name}: expected 401, got {r.status_code}"


@pytest.fixture(scope="function")
def graphql_setup():
    """Create a live API Armor listener with GraphQL security rules."""
    token = _get_token()
    suffix = secrets.token_hex(4)

    _delete_test_resources(token)
    _api_settings(token)
    be = _make_backend(token, suffix, variant="-gql")
    listener = _make_listener(token, suffix, be["id"], variant="-gql")
    _import_spec(token, suffix, variant="-gql", with_body_schema=False)

    # Add GraphQL security rules directly to this listener.
    rules = [
        {
            "name": f"API Armor: Block invalid GraphQL queries-{suffix}",
            "enabled": True,
            "listener_ids": [listener["id"]],
            "expression": "graphql.valid = false",
            "action": "block",
            "log": True,
            "status_code": 400,
        },
        {
            "name": f"API Armor: Block GraphQL query depth > 10-{suffix}",
            "enabled": True,
            "listener_ids": [listener["id"]],
            "expression": "graphql.depth > 10",
            "action": "block",
            "log": True,
            "status_code": 400,
        },
        {
            "name": f"API Armor: Block GraphQL complexity > 1000-{suffix}",
            "enabled": True,
            "listener_ids": [listener["id"]],
            "expression": "graphql.complexity > 1000",
            "action": "block",
            "log": True,
            "status_code": 400,
        },
    ]
    for rule in rules:
        _api_call(token, "post", "security-rules", rule)

    _apply_and_wait(token)

    yield suffix

    _delete_test_resources(token, suffix)


def test_haproxy_api_armor_graphql_valid_raw(graphql_setup):
    """A simple raw GraphQL query is proxied."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        data="{ user { name } }",
        headers={"Content-Type": "application/graphql"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 for valid GraphQL, got {r.status_code}"


def test_haproxy_api_armor_graphql_valid_json(graphql_setup):
    """A GraphQL query sent as JSON is proxied."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"query": "{ user { name } }"},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 for JSON GraphQL, got {r.status_code}"


def test_haproxy_api_armor_graphql_empty(graphql_setup):
    """An empty GraphQL query is rejected with 400."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        data="",
        headers={"Content-Type": "application/graphql"},
        timeout=10,
    )
    assert r.status_code == 400, f"expected 400 for empty GraphQL, got {r.status_code}"


def test_haproxy_api_armor_graphql_depth_limit(graphql_setup):
    """A GraphQL query deeper than 10 is rejected with 400."""
    import requests

    # The parser counts nested selection sets beyond the root, so 12 nested
    # braces yields a depth greater than 10.
    deep = "{ " + " { ".join(["a"] * 12) + " x " + " } " * 12
    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        data=deep,
        headers={"Content-Type": "application/graphql"},
        timeout=10,
    )
    assert r.status_code == 400, f"expected 400 for deep GraphQL, got {r.status_code}"


def test_haproxy_api_armor_graphql_complexity_limit(graphql_setup):
    """A GraphQL query with complexity > 1000 is rejected with 400."""
    import requests

    query = "query { " + " ".join([f"f{i}: user {{ name email }}" for i in range(180)]) + " }"
    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        data=query,
        headers={"Content-Type": "application/graphql"},
        timeout=10,
    )
    assert r.status_code == 400, f"expected 400 for complex GraphQL, got {r.status_code}"


@pytest.fixture(scope="function")
def profile_setup():
    """Create a listener, learn a behavioral profile, then clean up."""
    token = _get_token()
    suffix = secrets.token_hex(4)

    _delete_test_resources(token)
    _api_settings(token)
    be = _make_backend(token, suffix, variant="-profile")
    _make_listener(token, suffix, be["id"], variant="-profile")
    _import_spec(token, suffix, variant="-profile", with_body_schema=False)

    _apply_and_wait(token)

    # Ingest a baseline observation and finalize the profile.
    _api_call(token, "post", "api-armor/profiles/ingest", {
        "method": "POST",
        "path": "/api/v1/test",
        "content_type": "application/json",
        "auth_type": "n",
    })
    profiles = _api_call(token, "get", "api-armor/profiles", {"method": "POST", "path": "/api/v1/test"})
    profile = next((p for p in profiles if p["method"] == "POST" and p["path"] == "/api/v1/test"), None)
    if not profile:
        pytest.fail("profile was not created by ingest")
    _api_call(token, "post", f"api-armor/profiles/{profile['id']}/finalize?min_samples=1", {})

    # Re-apply so the Rust module sees the learned profile.
    _apply_and_wait(token)

    yield suffix

    _delete_test_resources(token, suffix)


def test_haproxy_api_armor_profile_baseline(profile_setup):
    """A request matching the learned profile (JSON, no auth) is proxied."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 for baseline request, got {r.status_code}"


def test_haproxy_api_armor_profile_anomaly(profile_setup):
    """A request with an unexpected content-type is rejected with 403."""
    import requests

    r = requests.post(
        f"{HAPROXY_URL}/api/v1/test",
        data="name=hello",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    assert r.status_code == 403, f"expected 403 for profile anomaly, got {r.status_code}"


def test_haproxy_api_armor_data_files_written(api_key_setup):
    """The API Armor runtime data bundle exists in the shared data directory."""
    data_dir = Path(__file__).resolve().parents[3] / "data" / "haproxy" / "api-armor"
    assert data_dir.exists()
    assert (data_dir / "schema-index.json").exists()
    assert (data_dir / "auth-policies.json").exists()
    assert (data_dir / "api-keys").exists()
