#!/usr/bin/env python3
"""Live HAProxy integration test for API Armor.

Requires the Docker Compose stack to be running with the API Armor-enabled
HAProxy image and the backend reachable on https://localhost:8000.
"""
import json
import os
import sys
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://localhost:8000"
HAPROXY = "http://localhost"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
SUFFIX = os.environ.get("RUN_ID", str(int(time.time()))[-4:])


def api(path: str, method: str = "get", **kwargs):
    headers = kwargs.pop("headers", {})
    if getattr(api, "token", None):
        headers["Authorization"] = f"Bearer {api.token}"
    url = f"{BASE}/api/v1/{path.lstrip('/')}"
    return requests.request(method, url, headers=headers, verify=False, **kwargs)


def login() -> str:
    r = requests.post(
        f"{BASE}/api/v1/auth/token",
        data={"username": "admin", "password": ADMIN_PASSWORD, "grant_type": "password"},
        verify=False,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def cleanup_test_resources() -> None:
    for b in api("backends").json():
        if b["name"].startswith("api-test"):
            api(f"backends/{b['id']}", "delete")
    # Delete any listener on the test port (80) to avoid a bind conflict with
    # the temporary listener we are about to create. Listener deletion cascades
    # to its backend rules, so we don't need to clean those separately.
    for l in api("listeners").json():
        if l["name"].startswith("api-armor-test") or l.get("bind_port") == 80:
            api(f"listeners/{l['id']}", "delete")


def set_setting(key: str, value: str) -> None:
    r = api(f"settings/{key}", "put", json={"value": value})
    print(f"  set {key}={value} -> {r.status_code}")
    r.raise_for_status()


def create_backend() -> int:
    payload = {
        "name": f"api-test-{SUFFIX}",
        "mode": "http",
        "protocol": "http",
        "algorithm": "roundrobin",
        "health_check_enabled": True,
        "health_check_uri": "/api/v1/health",
        "health_check_method": "GET",
        "servers": [
            {
                "name": "api",
                "address": "api",
                "port": 8000,
                "weight": 100,
                "check": True,
                "ssl": True,
                "verify": "none",
                "check_ssl": True,
            }
        ],
    }
    r = api("backends", "post", json=payload)
    print(f"  create backend -> {r.status_code} {r.text[:200]}")
    r.raise_for_status()
    return r.json()["id"]


def create_listener(backend_id: int) -> int:
    payload = {
        "name": f"api-armor-test-{SUFFIX}",
        "bind_address": "0.0.0.0",
        "bind_port": 80,
        "mode": "http",
        "protocol": "http",
        "enabled": True,
        "default_backend_id": backend_id,
        "options": {"api_armor": True},
    }
    r = api("listeners", "post", json=payload)
    print(f"  create listener -> {r.status_code} {r.text[:200]}")
    r.raise_for_status()
    return r.json()["id"]


def import_spec() -> dict:
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
    r = api("api-armor/specs", "post", json={"name": f"test-spec-{SUFFIX}", "spec": json.dumps(spec)})
    print(f"  import spec -> {r.status_code} {r.text[:200]}")
    r.raise_for_status()
    return r.json()


def get_and_enable_schema() -> dict:
    r = api("api-armor/schemas")
    r.raise_for_status()
    for s in r.json():
        if s["path"] == "/api/v1/test" and s["method"] == "POST":
            s["enabled"] = True
            upd = api(f"api-armor/schemas/{s['id']}", "put", json=s)
            print(f"  enable schema {s['id']} -> {upd.status_code}")
            upd.raise_for_status()
            return s
    raise RuntimeError("schema not found")


def create_key_list() -> int:
    r = api(
        "api-armor/api-key-lists",
        "post",
        json={"name": f"test-keys-{SUFFIX}", "description": "", "entries": ["secret-key"]},
    )
    print(f"  create key list -> {r.status_code} {r.text[:200]}")
    r.raise_for_status()
    return r.json()["id"]


def create_auth_policy(listener_id: int, key_list_id: int) -> int:
    payload = {
        "name": f"api-key-policy-{SUFFIX}",
        "auth_type": "api_key",
        "api_key_header": "X-Api-Key",
        "api_key_list_id": key_list_id,
        "on_failure": "block",
        "enabled": True,
        "listener_ids": [listener_id],
    }
    r = api("api-armor/auth-policies", "post", json=payload)
    print(f"  create auth policy -> {r.status_code} {r.text[:200]}")
    r.raise_for_status()
    return r.json()["id"]


def apply_config() -> None:
    r = api("config/apply", "post", json={})
    print(f"  apply config -> {r.status_code} {r.text[:500]}")
    r.raise_for_status()


def wait_haproxy(timeout: int = 60) -> bool:
    # Wait until the API Armor frontend is serving 404 for '/' (backend up).
    for _ in range(timeout * 2):
        try:
            r = requests.get(HAPROXY, timeout=2)
            if r.status_code in (200, 404, 403):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main() -> int:
    print("Logging in...")
    api.token = login()
    print("Authenticated")

    print("\nCleaning up previous test resources...")
    cleanup_test_resources()

    print("\nConfiguring global settings...")
    set_setting("req_fp_enabled", "true")
    set_setting("req_fp_parse_body", "true")
    set_setting("api_armor_enabled", "true")
    set_setting("api_armor_module_enabled", "true")
    set_setting("api_armor_max_body_bytes", "1048576")

    print("\nCreating backend and listener...")
    backend_id = create_backend()
    listener_id = create_listener(backend_id)

    print("\nImporting OpenAPI spec and enabling schema...")
    import_spec()
    schema = get_and_enable_schema()
    print(f"Schema: {schema['method']} {schema['path']} enabled")

    print("\nCreating API key list and auth policy...")
    key_list_id = create_key_list()
    create_auth_policy(listener_id, key_list_id)

    print("\nApplying HAProxy configuration...")
    apply_config()
    time.sleep(3)  # allow reload to start

    print("\nWaiting for HAProxy to be reachable...")
    if not wait_haproxy():
        print("ERROR: HAProxy not reachable")
        return 1
    print("HAProxy reachable")

    print("\n--- Live HAProxy tests ---")

    # Test 1: invalid JSON body -> schema validation should reject (400/422)
    r = requests.post(
        f"{HAPROXY}/api/v1/test",
        json={"name": 123},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    print(f"1. Invalid JSON body (name=123) -> {r.status_code}")
    ok1 = r.status_code in (400, 422)

    # Test 2: valid JSON, missing API key -> auth should reject (401/403)
    r = requests.post(
        f"{HAPROXY}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    print(f"2. Valid JSON, missing API key -> {r.status_code}")
    ok2 = r.status_code in (401, 403)

    # Test 3: valid JSON + invalid API key -> 403
    r = requests.post(
        f"{HAPROXY}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json", "X-Api-Key": "wrong-key"},
        timeout=10,
    )
    print(f"3. Valid JSON, wrong API key -> {r.status_code}")
    ok3 = r.status_code in (401, 403)

    # Test 4: valid JSON + valid API key -> proxied to backend (404 because no route)
    r = requests.post(
        f"{HAPROXY}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json", "X-Api-Key": "secret-key"},
        timeout=10,
    )
    print(f"4. Valid JSON, valid API key -> {r.status_code}")
    ok4 = r.status_code == 404  # backend returns 404 for unknown /api/v1/test

    print("\n--- Results ---")
    for i, ok in enumerate([ok1, ok2, ok3, ok4], 1):
        print(f"Test {i}: {'PASS' if ok else 'FAIL'}")

    return 0 if all([ok1, ok2, ok3, ok4]) else 1


if __name__ == "__main__":
    sys.exit(main())
