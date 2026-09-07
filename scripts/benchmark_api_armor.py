#!/usr/bin/env python3
"""Benchmark API Armor overhead vs a plain HAProxy listener.

Sets up two listeners on the running Docker Compose stack:
  - Port 80:  API Armor enabled (schema + API-key auth + GraphQL + profile rules)
  - Port 443: plain HAProxy baseline (same backend, no API Armor)

Then runs k6 against both and prints a side-by-side summary.

Requires:
  - Docker Compose stack running (api, corex, postgres, valkey)
  - k6 installed locally (https://grafana.com/docs/k6/latest/)
  - ADMIN_PASSWORD env var set if admin password is not "admin"

Examples:
  ADMIN_PASSWORD=admin python scripts/benchmark_api_armor.py
  ADMIN_PASSWORD=admin RATE=1000 DURATION=60s python scripts/benchmark_api_armor.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://localhost:8000"
HAPROXY_ARMOR = "http://localhost"
HAPROXY_BASELINE = "http://localhost:443"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
SUFFIX = os.environ.get("RUN_ID", str(int(time.time()))[-4:])
RATE = os.environ.get("RATE", "500")
DURATION = os.environ.get("DURATION", "30s")
K6 = shutil.which("k6") or "/opt/homebrew/bin/k6"
BACKEND_HOST = os.environ.get("BACKEND_HOST", "api")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8000"))
BACKEND_SSL = os.environ.get("BACKEND_SSL", "true").lower() == "true"
HEALTH_URI = os.environ.get("HEALTH_URI", "/api/v1/health")


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
        if b["name"].startswith("api-bench"):
            api(f"backends/{b['id']}", "delete")
    for l in api("listeners").json():
        if l["name"].startswith("api-bench"):
            api(f"listeners/{l['id']}", "delete")
    for p in api("api-armor/auth-policies").json():
        if p["name"].startswith("api-bench"):
            api(f"api-armor/auth-policies/{p['id']}", "delete")
    for k in api("api-armor/api-key-lists").json():
        if k["name"].startswith("api-bench"):
            api(f"api-armor/api-key-lists/{k['id']}", "delete")
    for s in api("api-armor/specs").json():
        if s["name"].startswith("api-bench"):
            api(f"api-armor/specs/{s['id']}", "delete")
    for r in api("security-rules").json():
        if r["name"].startswith("API Armor Bench"):
            api(f"security-rules/{r['id']}", "delete")
    for p in api("api-armor/profiles").json():
        if p.get("method") == "POST" and p.get("path") == "/api/v1/test":
            api(f"api-armor/profiles/{p['id']}", "delete")


def set_setting(key: str, value: str) -> None:
    r = api(f"settings/{key}", "put", json={"value": value})
    print(f"  set {key}={value} -> {r.status_code}")
    r.raise_for_status()


def create_backend() -> int:
    payload = {
        "name": f"api-bench-{SUFFIX}",
        "mode": "http",
        "protocol": "http",
        "algorithm": "roundrobin",
        "health_check_enabled": True,
        "health_check_uri": HEALTH_URI,
        "health_check_method": "GET",
        "servers": [
            {
                "name": "backend",
                "address": BACKEND_HOST,
                "port": BACKEND_PORT,
                "weight": 100,
                "check": True,
                "ssl": BACKEND_SSL,
                "verify": "none",
                "check_ssl": BACKEND_SSL,
            }
        ],
    }
    r = api("backends", "post", json=payload)
    print(f"  create backend -> {r.status_code}")
    r.raise_for_status()
    return r.json()["id"]


def create_baseline_listener(backend_id: int) -> int:
    payload = {
        "name": f"api-bench-baseline-{SUFFIX}",
        "bind_address": "0.0.0.0",
        "bind_port": 443,
        "mode": "http",
        "protocol": "http",
        "enabled": True,
        "default_backend_id": backend_id,
        "options": {"api_armor": False},
    }
    r = api("listeners", "post", json=payload)
    print(f"  create baseline listener (port 443) -> {r.status_code}")
    r.raise_for_status()
    return r.json()["id"]


def create_armor_listener(backend_id: int) -> int:
    payload = {
        "name": f"api-bench-armor-{SUFFIX}",
        "bind_address": "0.0.0.0",
        "bind_port": 80,
        "mode": "http",
        "protocol": "http",
        "enabled": True,
        "default_backend_id": backend_id,
        "options": {"api_armor": True},
    }
    r = api("listeners", "post", json=payload)
    print(f"  create API Armor listener (port 80) -> {r.status_code}")
    r.raise_for_status()
    return r.json()["id"]


def import_spec() -> dict:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Bench API", "version": "1.0.0"},
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
    r = api("api-armor/specs", "post", json={"name": f"api-bench-spec-{SUFFIX}", "spec": json.dumps(spec)})
    print(f"  import spec -> {r.status_code}")
    r.raise_for_status()
    return r.json()


def get_and_enable_schema(spec_id: int) -> dict:
    r = api(f"api-armor/specs/{spec_id}/schemas")
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
        json={"name": f"api-bench-keys-{SUFFIX}", "description": "", "entries": ["bench-key"]},
    )
    print(f"  create key list -> {r.status_code}")
    r.raise_for_status()
    return r.json()["id"]


def create_auth_policy(listener_id: int, key_list_id: int) -> int:
    payload = {
        "name": f"api-bench-policy-{SUFFIX}",
        "auth_type": "api_key",
        "api_key_header": "X-Api-Key",
        "api_key_list_id": key_list_id,
        "on_failure": "block",
        "enabled": True,
        "listener_ids": [listener_id],
    }
    r = api("api-armor/auth-policies", "post", json=payload)
    print(f"  create auth policy -> {r.status_code}")
    r.raise_for_status()
    return r.json()["id"]


def create_graphql_rules(listener_id: int) -> None:
    rules = [
        {
            "name": "API Armor Bench: GraphQL depth",
            "expression": "graphql.depth > 10",
            "action": "block",
            "status_code": 400,
            "enabled": True,
            "listener_ids": [listener_id],
        },
        {
            "name": "API Armor Bench: GraphQL complexity",
            "expression": "graphql.complexity > 1000",
            "action": "block",
            "status_code": 400,
            "enabled": True,
            "listener_ids": [listener_id],
        },
    ]
    for rule in rules:
        r = api("security-rules", "post", json=rule)
        print(f"  create rule '{rule['name']}' -> {r.status_code}")
        r.raise_for_status()


def ingest_and_finalize_profile() -> None:
    r = api(
        "api-armor/profiles/ingest",
        "post",
        json={
            "method": "POST",
            "path": "/api/v1/test",
            "content_type": "application/json",
            "auth_type": "api_key",
        },
    )
    print(f"  ingest profile -> {r.status_code}")
    r.raise_for_status()
    profiles = api("api-armor/profiles").json()
    for p in profiles:
        if p["method"] == "POST" and p["path"] == "/api/v1/test":
            r = api(f"api-armor/profiles/{p['id']}/finalize?min_samples=1", "post")
            print(f"  finalize profile {p['id']} -> {r.status_code}")
            r.raise_for_status()
            return
    raise RuntimeError("profile not found")


def apply_config() -> None:
    r = api("config/apply", "post", json={})
    print(f"  apply config -> {r.status_code}")
    r.raise_for_status()


def wait_haproxy(url: str, timeout: int = 60) -> bool:
    for _ in range(timeout * 2):
        try:
            r = requests.post(
                f"{url}/api/v1/test",
                json={"name": "hello"},
                headers={"Content-Type": "application/json"},
                timeout=2,
            )
            if r.status_code in (200, 404, 401, 403, 400):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _k6_summary(path: str) -> dict:
    """Parse k6 summary JSON for the fields we care about."""
    with open(path) as f:
        data = json.load(f)
    metrics = data.get("metrics", {})
    http_reqs = metrics.get("http_reqs", {})
    durations = metrics.get("http_req_duration", {})
    failed = metrics.get("http_req_failed", {})
    failed_rate = round(failed.get("value", 0) * 100, 3)
    # k6 v0.54+ / fork stores failed as a Rate with passes/fails/value.
    # value is the fraction of failed requests. Confirm by recalculating.
    passes = failed.get("passes", 0)
    fails = failed.get("fails", 0)
    if passes + fails > 0:
        failed_rate = round((passes / (passes + fails)) * 100, 3)
    return {
        "rps": round(http_reqs.get("rate", 0), 2),
        "count": int(http_reqs.get("count", 0)),
        "p50": round(durations.get("med", 0), 2),
        "p90": round(durations.get("p(90)", 0), 2),
        "p95": round(durations.get("p(95)", 0), 2),
        "p99": round(durations.get("p(99)", 0) or durations.get("p(95)", 0), 2),
        "failed_rate": failed_rate,
        "avg": round(durations.get("avg", 0), 2),
        "min": round(durations.get("min", 0), 2),
        "max": round(durations.get("max", 0), 2),
    }


def run_k6(name: str, url: str, key: str = "") -> dict:
    print(f"\n--- Running k6: {name} ({url}) ---")
    k6_script = os.path.join(os.path.dirname(__file__), "benchmark_api_armor.k6.js")
    summary_file = os.path.join(tempfile.gettempdir(), f"k6-summary-{name.lower().replace(' ', '-')}.json")
    env = os.environ.copy()
    env["URL"] = url
    env["KEY"] = key
    env["RATE"] = RATE
    env["DURATION"] = DURATION
    try:
        proc = subprocess.run(
            [K6, "run", f"--summary-export={summary_file}", k6_script],
            env=env,
            text=True,
            check=False,
            capture_output=True,
        )
    except FileNotFoundError:
        print(f"ERROR: k6 not found at {K6}")
        print("Install k6: https://grafana.com/docs/k6/latest/")
        sys.exit(1)

    if not os.path.exists(summary_file):
        print("k6 stdout:")
        print(proc.stdout[-2000:])
        print("k6 stderr:")
        print(proc.stderr[-2000:])
        raise RuntimeError("k6 did not produce a summary file")

    return _k6_summary(summary_file)


def run_smoke_test(armor_url: str, baseline_url: str) -> None:
    print("\n--- Smoke tests ---")
    # Baseline should 200 or 404 depending on backend
    r = requests.post(
        f"{baseline_url}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    print(f"Baseline -> {r.status_code} (expected 200 or 404)")
    # Armor with key should 200 or 404
    r = requests.post(
        f"{armor_url}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json", "X-Api-Key": "bench-key"},
        timeout=5,
    )
    print(f"API Armor valid -> {r.status_code} (expected 200 or 404)")
    # Armor without key should 401
    r = requests.post(
        f"{armor_url}/api/v1/test",
        json={"name": "hello"},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    print(f"API Armor missing key -> {r.status_code} (expected 401)")


def print_summary(baseline: dict, armor: dict) -> None:
    print("\n" + "=" * 70)
    print("Benchmark summary")
    print("=" * 70)
    print(f"{'Metric':<20} {'Baseline (plain HAProxy)':<25} {'API Armor':<25}")
    print("-" * 70)
    print(f"{'RPS':<20} {baseline['rps']:<25} {armor['rps']:<25}")
    print(f"{'Total requests':<20} {baseline['count']:<25} {armor['count']:<25}")
    print(f"{'Avg latency (ms)':<20} {baseline['avg']:<25} {armor['avg']:<25}")
    print(f"{'p50 latency (ms)':<20} {baseline['p50']:<25} {armor['p50']:<25}")
    print(f"{'p90 latency (ms)':<20} {baseline['p90']:<25} {armor['p90']:<25}")
    print(f"{'p95 latency (ms)':<20} {baseline['p95']:<25} {armor['p95']:<25}")
    print(f"{'Min latency (ms)':<20} {baseline['min']:<25} {armor['min']:<25}")
    print(f"{'Max latency (ms)':<20} {baseline['max']:<25} {armor['max']:<25}")
    print(f"{'Failed %':<20} {baseline['failed_rate']:<25} {armor['failed_rate']:<25}")
    if baseline["avg"] > 0 and baseline["rps"] > 0:
        overhead = round(((armor["avg"] - baseline["avg"]) / baseline["avg"]) * 100, 1)
        rps_drop = round(((baseline["rps"] - armor["rps"]) / baseline["rps"]) * 100, 1)
        print("-" * 70)
        print(f"Avg latency overhead: {overhead}%")
        print(f"RPS drop: {rps_drop}%")
    print("=" * 70)


def main() -> int:
    if not shutil.which(K6) and not os.path.exists(K6):
        print("ERROR: k6 not found. Install it: https://grafana.com/docs/k6/latest/")
        return 1

    print("Logging in...")
    api.token = login()
    print("Authenticated")

    print("\nCleaning up previous benchmark resources...")
    cleanup_test_resources()

    print("\nConfiguring global settings...")
    set_setting("req_fp_enabled", "true")
    set_setting("req_fp_parse_body", "true")
    set_setting("api_armor_enabled", "true")
    set_setting("api_armor_module_enabled", "true")
    set_setting("api_armor_max_body_bytes", "1048576")

    print("\nCreating backend and listeners...")
    backend_id = create_backend()
    baseline_id = create_baseline_listener(backend_id)
    armor_id = create_armor_listener(backend_id)

    print("\nImporting OpenAPI spec and enabling schema...")
    spec = import_spec()
    get_and_enable_schema(spec["id"])

    print("\nCreating API key list and auth policy...")
    key_list_id = create_key_list()
    create_auth_policy(armor_id, key_list_id)

    print("\nCreating GraphQL security rules...")
    create_graphql_rules(armor_id)

    print("\nIngesting and finalizing behavioral profile...")
    ingest_and_finalize_profile()

    print("\nApplying HAProxy configuration...")
    apply_config()
    time.sleep(3)

    print("\nWaiting for HAProxy listeners...")
    if not wait_haproxy(HAPROXY_BASELINE):
        print("ERROR: baseline listener not reachable")
        return 1
    if not wait_haproxy(HAPROXY_ARMOR):
        print("ERROR: API Armor listener not reachable")
        return 1
    print("HAProxy listeners ready")

    run_smoke_test(HAPROXY_ARMOR, HAPROXY_BASELINE)

    baseline = run_k6("Baseline", HAPROXY_BASELINE)
    armor = run_k6("API Armor", HAPROXY_ARMOR, key="bench-key")

    print_summary(baseline, armor)
    return 0


if __name__ == "__main__":
    sys.exit(main())
