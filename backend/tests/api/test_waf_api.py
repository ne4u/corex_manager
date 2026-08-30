import os
from datetime import datetime, timezone

import pytest

from app.models.models import WafMetric, WafRule
from app.services import coraza_config
from tests.factories import (
    make_backend,
    make_listener,
    make_siem_integration,
    make_waf_exception,
    make_waf_rule,
)


def test_list_waf_rules(client, db):
    rule = make_waf_rule(db, name="waf")
    res = client.get("/api/v1/waf-rules")
    print("RESPONSE:", res.status_code, res.text)
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["name"] == rule.name


def test_create_waf_rule(client, db):
    res = client.post(
        "/api/v1/waf-rules",
        json={
            "name": "new-waf",
            "action": "block",
            "rule_set": "coraza",
            "engine": "On",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "new-waf"
    assert db.query(WafRule).count() == 1


def test_update_waf_rule(client, db):
    rule = make_waf_rule(db, name="waf", action="block")
    res = client.put(
        f"/api/v1/waf-rules/{rule.id}",
        json={"action": "allow"},
    )
    assert res.status_code == 200
    assert res.json()["action"] == "allow"


def test_create_waf_rule_normalizes_captcha_to_challenge(client, db):
    # The former "captcha" action is converged into "challenge"; old clients
    # that still send "captcha" should be accepted and normalized.
    res = client.post(
        "/api/v1/waf-rules",
        json={"name": "legacy-captcha", "action": "captcha"},
    )
    assert res.status_code == 200
    assert res.json()["action"] == "challenge"


def test_create_waf_rule_rejects_unknown_action(client, db):
    res = client.post(
        "/api/v1/waf-rules",
        json={"name": "bad-action", "action": "tarpit"},
    )
    assert res.status_code == 422


def test_create_waf_rule_rejects_rate_enabled_with_allow(client, db):
    # Rate-based counting is a no-op for the "allow" action (the generator
    # short-circuits before the counters), so the combination is rejected.
    res = client.post(
        "/api/v1/waf-rules",
        json={"name": "allow-rate", "action": "allow", "rate_enabled": True},
    )
    assert res.status_code == 422


def test_create_waf_rule_normalizes_rate_action_captcha(client, db):
    res = client.post(
        "/api/v1/waf-rules",
        json={"name": "legacy-rate", "action": "block", "rate_enabled": True, "rate_action": "captcha"},
    )
    assert res.status_code == 200
    assert res.json()["rate_action"] == "challenge"


def test_delete_waf_rule(client, db):
    rule = make_waf_rule(db, name="waf")
    res = client.delete(f"/api/v1/waf-rules/{rule.id}")
    assert res.status_code == 200
    assert db.query(WafRule).count() == 0


def test_waf_exception_crud(client, db):
    rule = make_waf_rule(db, name="waf")
    payload = {
        "waf_rule_id": rule.id,
        "name": "ex",
        "rule_id": "123",
        "action": "remove",
    }
    res = client.post("/api/v1/waf-exceptions", json=payload)
    assert res.status_code == 200
    ex_id = res.json()["id"]

    res = client.get("/api/v1/waf-exceptions")
    assert res.status_code == 200
    assert len(res.json()) == 1

    res = client.put(f"/api/v1/waf-exceptions/{ex_id}", json={"name": "updated"})
    assert res.status_code == 200
    assert res.json()["name"] == "updated"

    res = client.delete(f"/api/v1/waf-exceptions/{ex_id}")
    assert res.status_code == 200


def test_waf_siem_integration_crud(client, db):
    payload = {
        "name": "siem",
        "integration_type": "webhook",
        "target": "http://example.com/webhook",
        "format": "json",
    }
    res = client.post("/api/v1/waf/siem-integrations", json=payload)
    assert res.status_code == 200
    siem_id = res.json()["id"]

    res = client.put(f"/api/v1/waf/siem-integrations/{siem_id}", json={"target": "http://example.com/new"})
    assert res.status_code == 200
    assert res.json()["target"] == "http://example.com/new"

    res = client.delete(f"/api/v1/waf/siem-integrations/{siem_id}")
    assert res.status_code == 200


def test_waf_rule_version_snapshot_and_restore(client, db):
    rule = make_waf_rule(db, name="waf", action="block")
    res = client.post(f"/api/v1/waf/rules/{rule.id}/snapshot?version=v1")
    assert res.status_code == 200
    version_id = res.json()["id"]
    assert res.json()["version"] == "v1"

    res = client.put(f"/api/v1/waf-rules/{rule.id}", json={"action": "allow"})
    assert res.status_code == 200

    res = client.post(f"/api/v1/waf/rules/{rule.id}/restore/{version_id}")
    assert res.status_code == 200
    assert res.json()["action"] == "block"

    res = client.get("/api/v1/waf/rule-versions")
    assert res.status_code == 200
    assert len(res.json()) == 1


def test_waf_rule_version_auto_prune(client, db):
    rule = make_waf_rule(db, name="waf-prune", action="block")
    # Lower the per-rule max to 3
    res = client.put("/api/v1/waf/rule-versions/max", json={"value": "3"})
    assert res.status_code == 200
    assert res.json()["value"] == "3"

    for i in range(5):
        res = client.post(f"/api/v1/waf/rules/{rule.id}/snapshot?version=v{i}")
        assert res.status_code == 200

    res = client.get("/api/v1/waf/rule-versions", params={"waf_rule_id": rule.id})
    assert res.status_code == 200
    versions = res.json()
    assert len(versions) == 3
    # The 3 newest (v2, v3, v4) are kept; v0 and v1 are pruned
    kept = {v["version"] for v in versions}
    assert kept == {"v2", "v3", "v4"}


def test_waf_rule_version_max_zero_unlimited(client, db):
    rule = make_waf_rule(db, name="waf-unlimited", action="block")
    res = client.put("/api/v1/waf/rule-versions/max", json={"value": "0"})
    assert res.status_code == 200
    assert res.json()["value"] == "0"

    for i in range(5):
        res = client.post(f"/api/v1/waf/rules/{rule.id}/snapshot?version=v{i}")
        assert res.status_code == 200

    res = client.get("/api/v1/waf/rule-versions", params={"waf_rule_id": rule.id})
    assert res.status_code == 200
    assert len(res.json()) == 5


def test_waf_rule_version_delete(client, db):
    rule = make_waf_rule(db, name="waf-delete", action="block")
    res = client.post(f"/api/v1/waf/rules/{rule.id}/snapshot?version=v1")
    assert res.status_code == 200
    vid = res.json()["id"]

    res = client.delete(f"/api/v1/waf/rule-versions/{vid}")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # Second delete returns 404
    res = client.delete(f"/api/v1/waf/rule-versions/{vid}")
    assert res.status_code == 404

    # Gone from list
    res = client.get("/api/v1/waf/rule-versions", params={"waf_rule_id": rule.id})
    assert res.status_code == 200
    assert len(res.json()) == 0


def test_waf_rule_version_max_get_set_validation(client, db):
    # Default is 10 from env/config
    res = client.get("/api/v1/waf/rule-versions/max")
    assert res.status_code == 200
    assert res.json()["value"] == "10"

    # Set to 5
    res = client.put("/api/v1/waf/rule-versions/max", json={"value": "5"})
    assert res.status_code == 200
    assert res.json()["value"] == "5"

    # Persists
    res = client.get("/api/v1/waf/rule-versions/max")
    assert res.status_code == 200
    assert res.json()["value"] == "5"

    # Negative rejected
    res = client.put("/api/v1/waf/rule-versions/max", json={"value": "-1"})
    assert res.status_code == 400

    # Non-integer rejected
    res = client.put("/api/v1/waf/rule-versions/max", json={"value": "abc"})
    assert res.status_code == 400

    # 0 is allowed (unlimited)
    res = client.put("/api/v1/waf/rule-versions/max", json={"value": "0"})
    assert res.status_code == 200
    assert res.json()["value"] == "0"


def test_waf_rules_export_import(client, db):
    make_waf_rule(db, name="waf")
    res = client.get("/api/v1/waf/rules/export")
    assert res.status_code == 200
    data = res.json()
    assert len(data["rules"]) == 1

    # Rename before re-import so the unique name constraint does not fire
    data["rules"][0]["name"] = "waf-copy"
    res = client.post("/api/v1/waf/rules/import", json=data)
    assert res.status_code == 200
    assert db.query(WafRule).count() == 2


def test_waf_rule_refresh_rule_set_success(client, db, tmp_path, monkeypatch):
    """POST /waf/rules/{id}/refresh-rule-set triggers a download."""
    from app.services import rule_set_downloader
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    rule = make_waf_rule(db, name="remote-waf", rule_set="remote", rule_set_url="https://example.com/rules.conf")

    from unittest.mock import MagicMock, patch
    mock_resp = MagicMock()
    mock_resp.text = 'SecRule REQUEST_URI "@rx ." "id:1,phase:1,deny"'
    mock_resp.raise_for_status = MagicMock()

    with patch("app.services.rule_set_downloader.requests.get", return_value=mock_resp):
        with patch("app.services.coraza_config.write_coraza_spoa_config"):
            res = client.post(f"/api/v1/waf/rules/{rule.id}/refresh-rule-set")

    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_waf_rule_refresh_rule_set_not_remote(client, db):
    """POST /waf/rules/{id}/refresh-rule-set returns 400 for non-remote rules."""
    rule = make_waf_rule(db, name="crs-waf", rule_set="crs")
    res = client.post(f"/api/v1/waf/rules/{rule.id}/refresh-rule-set")
    assert res.status_code == 400


def test_waf_rule_refresh_rule_set_no_url(client, db):
    """POST /waf/rules/{id}/refresh-rule-set returns 400 when no URL is set."""
    rule = make_waf_rule(db, name="remote-waf", rule_set="remote", rule_set_url=None)
    res = client.post(f"/api/v1/waf/rules/{rule.id}/refresh-rule-set")
    assert res.status_code == 400


def test_waf_health(client, db, temp_coraza_paths, monkeypatch):
    monkeypatch.setattr(coraza_config, "write_coraza_spoa_config", lambda db, restart=False: "")
    res = client.get("/api/v1/waf/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("ok", "degraded")
    assert "coraza_spoa_reachable" in data
    assert "config_present" in data
    assert "log_present" in data


def test_waf_logs(client, temp_coraza_paths):
    log_path = temp_coraza_paths["log"]
    with open(log_path, "w") as f:
        f.write('{"action":"deny"}\n')
    res = client.get("/api/v1/waf/logs")
    assert res.status_code == 200
    data = res.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["raw"] == '{"action":"deny"}'


def test_waf_logs_coraza_spoa_match_format(client, temp_coraza_paths):
    """Coraza SPOA main emits zerolog JSON with a nested "match" object."""
    import json

    log_path = temp_coraza_paths["log"]
    line = json.dumps({
        "level": "error",
        "time": "2025-06-30T17:18:08Z",
        "match": {
            "client": "192.168.1.50",
            "file": "@owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
            "line": 2810,
            "rule_id": 920420,
            "msg": "Request content type is not allowed by policy",
            "data": "|application/dns-message|",
            "severity": "critical",
            "version": "OWASP_CRS/4.18.0-dev",
            "tags": ["attack-protocol"],
            "server": "10.1.1.2",
            "uri": "/",
            "unique_id": "ABCDEF123456",
            "disruptive": True,
            "phase": "request-headers",
        },
    })
    with open(log_path, "w") as f:
        f.write(line + "\n")
    res = client.get("/api/v1/waf/logs")
    assert res.status_code == 200
    data = res.json()
    assert len(data["events"]) == 1
    event = data["events"][0]
    assert event["action"] == "deny"
    assert event["rule_id"] == "920420"
    assert event["severity"] == "critical"
    assert event["client"] == "192.168.1.50"
    assert event["uri"] == "/"
    assert event["unique_id"] == "ABCDEF123456"
    assert event["msg"] == "Request content type is not allowed by policy"


def test_waf_haproxy_stats(client, db):
    now = datetime.now(timezone.utc)
    db.add(
        WafMetric(
            captured_at=now.replace(tzinfo=None),
            action="deny",
            rule_id="1",
            severity="CRITICAL",
            msg="XSS",
            client="1.2.3.4",
            country="US",
            uri="/a",
        )
    )
    db.add(
        WafMetric(
            captured_at=now.replace(tzinfo=None),
            action="drop",
            rule_id="2",
            severity="HIGH",
            msg="SQLi",
            client="5.6.7.8",
            country="CA",
            uri="/b",
        )
    )
    db.commit()
    res = client.get("/api/v1/waf/haproxy-stats?from=2020-01-01T00:00:00&to=2099-01-01T00:00:00&breakdown=action")
    assert res.status_code == 200
    data = res.json()
    assert data["breakdown"] == "action"
    assert data["totals"] == {"deny": 1, "drop": 1}


def test_captcha_challenge_page(client, monkeypatch):
    # Test that the challenge page includes the redirect URL from Valkey context.
    # The redirect is now stored server-side to prevent open redirect attacks.
    test_cid = "test_token_12345"
    context = {"i": 1, "t": "waf", "n": "test_rule", "r": "req_123", "u": "/foo"}

    # Mock cache_get to return our test context (Valkey may not be running in tests)
    def mock_cache_get(key):
        if key == f"cap:cid:{test_cid}":
            return context
        return None

    monkeypatch.setattr("app.core.valkey_client.cache_get", mock_cache_get)

    res = client.get(f"/api/v1/waf/captcha?cid={test_cid}")
    assert res.status_code == 200
    assert "Security Check" in res.text
    assert 'name="redirect"' in res.text
    assert 'value="/foo"' in res.text


def test_verify_captcha_stores_client_binding_hash(client, db, monkeypatch):
    """The verify-captcha endpoint must store a client-binding hash (IP +
    User-Agent + JA4) in Valkey, not just a static "1" value. This binds
    the _cv cookie to the client that solved the challenge so it cannot be
    replayed from a different client."""
    from app.services.captcha_providers import CapProvider, compute_cv_binding_hash

    # Mock the Cap provider's verify to succeed without a network call
    async def mock_verify(self, token, secret, remote_ip=None):
        return True
    monkeypatch.setattr(CapProvider, "verify", mock_verify)

    # Capture the set_cv_token call to inspect the binding hash
    captured = {}
    def mock_set_cv_token(token, binding_hash, ttl):
        captured["token"] = token
        captured["binding_hash"] = binding_hash
        captured["ttl"] = ttl
        return True
    monkeypatch.setattr("app.core.valkey_client.set_cv_token", mock_set_cv_token)

    # Ensure captcha settings are configured (conftest already sets CAPTCHA_SECRET)
    from app.services.settings import set_setting
    set_setting(db, "captcha_valid_seconds", "3600")

    res = client.post(
        "/api/v1/waf/verify-captcha",
        data={
            "redirect": "/protected",
            "cap_token": "fake-cap-token",
            "rule_id": "1",
            "rule_type": "waf",
            "rule_name": "test_rule",
        },
        headers={
            "User-Agent": "Mozilla/5.0 (Test Browser)",
            "X-JA4-Fingerprint": "t13d1516h2_8daaf6152771_b186095e22b6",
        },
        follow_redirects=False,
    )

    assert res.status_code == 302
    # The _cv cookie should be set in the response
    cookies = res.headers.get("set-cookie", "")
    assert "_cv=" in cookies

    # The binding hash must have been stored, and it must match the hash
    # computed from the test request's client IP + UA + JA4.
    assert "binding_hash" in captured
    assert len(captured["binding_hash"]) == 32

    # The TestClient connects from 127.0.0.1 (testclient default)
    expected_hash = compute_cv_binding_hash(
        "testclient",  # FastAPI TestClient uses "testclient" as the host
        "Mozilla/5.0 (Test Browser)",
        "t13d1516h2_8daaf6152771_b186095e22b6",
    )
    assert captured["binding_hash"] == expected_hash
    assert captured["ttl"] == 3600


@pytest.mark.skip(reason="requires containerized HAProxy/Coraza stack")
def test_config_apply_generates_waf_config(client, db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    res = client.post("/api/v1/config/apply")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


# ---- CRS management endpoints ----

def _make_crs_zip_bytes(version: str = "4.0.0") -> bytes:
    """Build a minimal CRS ZIP in memory for testing."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        top = f"coreruleset-{version}-minimal"
        zf.writestr(f"{top}/crs-setup.conf.example", "# CRS setup\n")
        zf.writestr(f"{top}/rules/REQUEST-901.conf", "# rule\n")
    return buf.getvalue()


def _mock_github_api(tag: str = "v4.0.0"):
    from unittest.mock import MagicMock
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "tag_name": tag,
        "assets": [
            {"name": f"coreruleset-{tag.lstrip('v')}-minimal.zip",
             "browser_download_url": f"https://example.com/crs/{tag}/minimal.zip"},
        ],
    }
    resp.raise_for_status = MagicMock()
    return resp


def _mock_zip_response(zip_bytes: bytes):
    from unittest.mock import MagicMock
    resp = MagicMock()
    resp.content = zip_bytes
    resp.raise_for_status = MagicMock()
    return resp


def test_crs_status_embedded(client, db):
    """GET /waf/crs/status returns embedded mode when no active version."""
    res = client.get("/api/v1/waf/crs/status")
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "embedded"
    assert data["active_version"] is None


def test_crs_download_success(client, db, tmp_path, monkeypatch):
    """POST /waf/crs/download downloads and extracts CRS."""
    from app.services import crs_downloader
    from unittest.mock import patch
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    zip_bytes = _make_crs_zip_bytes("4.0.0")

    with patch("app.services.crs_downloader.requests.get",
               side_effect=[_mock_github_api("v4.0.0"), _mock_zip_response(zip_bytes)]):
        with patch("app.services.coraza_config.write_coraza_spoa_config"):
            res = client.post("/api/v1/waf/crs/download")

    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["version"] == "v4.0.0"

    # Verify status changed
    res2 = client.get("/api/v1/waf/crs/status")
    assert res2.json()["mode"] == "filesystem"
    assert res2.json()["active_version"] == "4.0.0"


def test_crs_download_github_rate_limit(client, db, tmp_path, monkeypatch):
    """POST /waf/crs/download returns 400 on GitHub API rate limit."""
    from app.services import crs_downloader
    from unittest.mock import MagicMock, patch
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))

    api_resp = MagicMock()
    api_resp.status_code = 403
    api_resp.json.return_value = {}
    api_resp.raise_for_status = MagicMock()

    with patch("app.services.crs_downloader.requests.get", return_value=api_resp):
        res = client.post("/api/v1/waf/crs/download")

    assert res.status_code == 400
    assert "rate limit" in res.json()["detail"].lower()


def test_crs_list_snapshots(client, db):
    """GET /waf/crs/snapshots returns snapshot list."""
    import json
    from app.services.settings import set_setting
    set_setting(db, "crs_snapshot_1", json.dumps({
        "id": 1, "version": "v4.0.0", "dir_version": "4.0.0",
        "file_hash": "abc", "file_path": "/x",
        "created_at": "2024-01-01T00:00:00", "created_by": "tester",
    }))
    res = client.get("/api/v1/waf/crs/snapshots")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["version"] == "v4.0.0"


def test_crs_rollback_success(client, db, tmp_path, monkeypatch):
    """POST /waf/crs/rollback/{id} switches active version."""
    import json
    from app.services import crs_downloader
    from app.services.settings import set_setting
    from unittest.mock import patch
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))

    # Create two version dirs
    for v in ["3.3.0", "4.0.0"]:
        d = os.path.join(str(tmp_path), v)
        os.makedirs(d)
        with open(os.path.join(d, "crs-setup.conf.example"), "w") as f:
            f.write("# setup\n")

    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v3.3.0", "dir_version": "3.3.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_active_version", "4.0.0")

    with patch("app.services.coraza_config.write_coraza_spoa_config"):
        res = client.post("/api/v1/waf/crs/rollback/1")

    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert res.json()["version"] == "3.3.0"


def test_crs_rollback_not_found(client, db):
    """POST /waf/crs/rollback/{id} returns 400 for invalid snapshot."""
    res = client.post("/api/v1/waf/crs/rollback/999")
    assert res.status_code == 400


def test_crs_delete_snapshot(client, db, tmp_path, monkeypatch):
    """DELETE /waf/crs/snapshots/{id} removes the snapshot."""
    import json
    from app.services import crs_downloader
    from app.services.settings import set_setting
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v3.3.0", "dir_version": "3.3.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_active_version", "4.0.0")

    res = client.delete("/api/v1/waf/crs/snapshots/1")
    assert res.status_code == 200
    assert res.json()["ok"] is True

    # Verify snapshot is gone
    res2 = client.get("/api/v1/waf/crs/snapshots")
    assert len(res2.json()) == 0


def test_crs_delete_active_snapshot_fails(client, db, tmp_path, monkeypatch):
    """DELETE /waf/crs/snapshots/{id} returns 400 for active version."""
    import json
    from app.services import crs_downloader
    from app.services.settings import set_setting
    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_snapshot_1", json.dumps({"id": 1, "version": "v4.0.0", "dir_version": "4.0.0", "file_hash": "aaa", "file_path": "/x", "created_at": "2024-01-01T00:00:00", "created_by": "a"}))
    set_setting(db, "crs_active_version", "4.0.0")

    res = client.delete("/api/v1/waf/crs/snapshots/1")
    assert res.status_code == 400


def test_crs_set_pinned_version(client, db):
    """PUT /waf/crs/pinned-version sets the pinned version."""
    res = client.put("/api/v1/waf/crs/pinned-version", json={"value": "4.1.0"})
    assert res.status_code == 200
    assert res.json()["value"] == "4.1.0"

    # Verify status reflects the pin
    res2 = client.get("/api/v1/waf/crs/status")
    assert res2.json()["pinned_version"] == "4.1.0"


def test_crs_set_pinned_version_empty(client, db):
    """PUT /waf/crs/pinned-version with empty value clears the pin."""
    from app.services.settings import set_setting
    set_setting(db, "crs_pinned_version", "4.0.0")
    res = client.put("/api/v1/waf/crs/pinned-version", json={"value": ""})
    assert res.status_code == 200
    res2 = client.get("/api/v1/waf/crs/status")
    assert res2.json()["pinned_version"] is None or res2.json()["pinned_version"] == ""
