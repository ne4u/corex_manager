"""Tests for the Page Protect API endpoints."""
from tests.factories import make_page_protect_policy, make_csp_report, make_page_protect_script


def test_get_settings_default(client):
    r = client.get("/api/v1/page-protect/settings")
    assert r.status_code == 200
    data = r.json()
    assert data["monitoring_enabled"] is False
    assert data["change_detection_enabled"] is False
    assert data["report_path"] == "/_csp-report"


def test_update_settings(client, db):
    r = client.put("/api/v1/page-protect/settings", json={
        "monitoring_enabled": True,
        "change_detection_enabled": True,
        "change_detection_interval_hours": 12,
        "report_retention_days": 14,
        "report_path": "/_csp-report",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["monitoring_enabled"] is True
    assert data["change_detection_enabled"] is True
    assert data["change_detection_interval_hours"] == 12
    assert data["report_retention_days"] == 14


def test_beacon_requires_resp_transform(client, db):
    """Enabling beacon injection without resp_transform should be rejected."""
    # resp_transform_enabled defaults to off
    r = client.put("/api/v1/page-protect/settings", json={
        "monitoring_enabled": True,
        "change_detection_enabled": True,
        "change_detection_interval_hours": 12,
        "report_retention_days": 14,
        "report_path": "/_csp-report",
        "beacon_injection_enabled": True,
        "beacon_path": "/_cx-assets",
        "beacon_script_path": "/_cx-assets.js",
        "beacon_content_types": "text/html",
        "beacon_path_patterns": "",
        "beacon_backend_ids": [],
    })
    assert r.status_code == 403
    assert "Response Transformations" in r.json()["detail"]


def test_beacon_allowed_when_resp_transform_enabled(client, db):
    """Enabling beacon injection with resp_transform on should succeed."""
    from app.services.settings import set_setting
    set_setting(db, "resp_transform_enabled", "true")
    r = client.put("/api/v1/page-protect/settings", json={
        "monitoring_enabled": True,
        "change_detection_enabled": True,
        "change_detection_interval_hours": 12,
        "report_retention_days": 14,
        "report_path": "/_csp-report",
        "beacon_injection_enabled": True,
        "beacon_path": "/_cx-assets",
        "beacon_script_path": "/_cx-assets.js",
        "beacon_content_types": "text/html",
        "beacon_path_patterns": "",
        "beacon_backend_ids": [],
    })
    assert r.status_code == 200
    assert r.json()["beacon_injection_enabled"] is True


def test_list_policies_empty(client):
    r = client.get("/api/v1/page-protect/policies")
    assert r.status_code == 200
    assert r.json() == []


def test_create_policy(client):
    r = client.post("/api/v1/page-protect/policies", json={
        "name": "test-policy",
        "enabled": True,
        "backend_ids": [],
        "mode": "monitor",
        "sample_rate_percent": 100,
        "report_path": "/_csp-report",
        "directives": {"script-src": ["'self'"]},
    })
    assert r.status_code == 200
    data = r.json()
    assert data["id"] is not None
    assert data["name"] == "test-policy"
    assert data["mode"] == "monitor"


def test_create_policy_duplicate_name(client, db):
    make_page_protect_policy(db, name="dup")
    db.commit()
    r = client.post("/api/v1/page-protect/policies", json={
        "name": "dup",
        "enabled": True,
        "backend_ids": [],
        "mode": "monitor",
        "sample_rate_percent": 100,
        "report_path": "/_csp-report",
        "directives": {},
    })
    assert r.status_code == 409


def test_update_policy(client, db):
    p = make_page_protect_policy(db, name="p1")
    db.commit()
    r = client.put(f"/api/v1/page-protect/policies/{p.id}", json={"mode": "enforce"})
    assert r.status_code == 200
    assert r.json()["mode"] == "enforce"


def test_update_policy_not_found(client):
    r = client.put("/api/v1/page-protect/policies/999", json={"mode": "enforce"})
    assert r.status_code == 404


def test_delete_policy(client, db):
    p = make_page_protect_policy(db, name="p1")
    db.commit()
    r = client.delete(f"/api/v1/page-protect/policies/{p.id}")
    assert r.status_code == 200
    r = client.get("/api/v1/page-protect/policies")
    assert r.json() == []


def test_list_reports(client, db):
    make_csp_report(db, violated_directive="script-src", backend_name="be1")
    make_csp_report(db, violated_directive="img-src", backend_name="be2", blocked_uri="https://evil2.example.com/img.png")
    db.commit()
    r = client.get("/api/v1/page-protect/reports")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2


def test_list_reports_filter_by_directive(client, db):
    make_csp_report(db, violated_directive="script-src")
    make_csp_report(db, violated_directive="img-src")
    db.commit()
    r = client.get("/api/v1/page-protect/reports?violated_directive=script-src")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["violated_directive"] == "script-src"


def test_clear_reports(client, db):
    make_csp_report(db)
    make_csp_report(db)
    db.commit()
    r = client.delete("/api/v1/page-protect/reports")
    assert r.status_code == 200
    assert r.json()["deleted"] == 2
    r = client.get("/api/v1/page-protect/reports")
    assert r.json() == []


def test_export_reports(client, db):
    make_csp_report(db)
    db.commit()
    r = client.get("/api/v1/page-protect/reports/export")
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")


def test_list_scripts(client, db):
    make_page_protect_script(db, url="https://cdn1.example.com/a.js", resource_type="script")
    make_page_protect_script(db, url="https://cdn2.example.com/b.js", resource_type="connect")
    db.commit()
    r = client.get("/api/v1/page-protect/scripts")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2


def test_list_scripts_filter_by_type(client, db):
    make_page_protect_script(db, url="https://cdn1.example.com/a.js", resource_type="script")
    make_page_protect_script(db, url="https://cdn2.example.com/b.js", resource_type="connect")
    db.commit()
    r = client.get("/api/v1/page-protect/scripts?resource_type=script")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["resource_type"] == "script"


def test_list_scripts_filter_by_changed(client, db):
    make_page_protect_script(db, url="https://cdn1.example.com/a.js", hash_changed=False)
    make_page_protect_script(db, url="https://cdn2.example.com/b.js", hash_changed=True)
    db.commit()
    r = client.get("/api/v1/page-protect/scripts?hash_changed=true")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["hash_changed"] is True


def test_update_script_notes(client, db):
    s = make_page_protect_script(db)
    db.commit()
    r = client.put(f"/api/v1/page-protect/scripts/{s.id}", json={"notes": "trusted CDN"})
    assert r.status_code == 200
    assert r.json()["notes"] == "trusted CDN"


def test_delete_script(client, db):
    s = make_page_protect_script(db)
    db.commit()
    r = client.delete(f"/api/v1/page-protect/scripts/{s.id}")
    assert r.status_code == 200
    r = client.get("/api/v1/page-protect/scripts")
    assert r.json() == []


def test_create_script_success(client, db):
    """Manually adding a URL creates a new inventory entry with source=manual."""
    r = client.post("/api/v1/page-protect/scripts", json={
        "url": "https://cdn.example.com/new.js",
        "resource_type": "script",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["url"] == "https://cdn.example.com/new.js"
    assert data["source"] == "manual"
    assert data["domain"] == "cdn.example.com"
    assert data["occurrence_count"] == 0


def test_create_script_duplicate_409(client, db):
    """Adding a URL that already exists returns 409."""
    make_page_protect_script(db, url="https://cdn.example.com/existing.js")
    db.commit()
    r = client.post("/api/v1/page-protect/scripts", json={
        "url": "https://cdn.example.com/existing.js",
    })
    assert r.status_code == 409


def test_create_script_invalid_url_400(client, db):
    """Non-http URLs are rejected."""
    r = client.post("/api/v1/page-protect/scripts", json={
        "url": "javascript:alert(1)",
    })
    assert r.status_code == 400


def test_create_script_extracts_domain(client, db):
    """Domain is auto-extracted from the URL."""
    r = client.post("/api/v1/page-protect/scripts", json={
        "url": "https://fonts.googleapis.com/css?family=Roboto",
        "resource_type": "style",
    })
    assert r.status_code == 201
    assert r.json()["domain"] == "fonts.googleapis.com"


def test_reset_hash_clears_fields(client, db):
    """POST /scripts/{sid}/reset-hash with recheck=false clears hash fields."""
    from app.models.models import PageProtectScript
    s = make_page_protect_script(db, url="https://cdn.example.com/a.js", hash_changed=True)
    s.first_hash = "abc123"
    s.last_hash = "abc123"
    s.first_hash_at = s.last_seen
    s.hash_checked_at = s.last_seen
    db.commit()
    r = client.post(f"/api/v1/page-protect/scripts/{s.id}/reset-hash?recheck=false")
    assert r.status_code == 200
    data = r.json()
    assert data["first_hash"] is None
    assert data["last_hash"] is None
    assert data["hash_changed"] is False
    assert data["hash_checked_at"] is None


def test_reset_hash_404(client, db):
    """Reset on non-existent script returns 404."""
    r = client.post("/api/v1/page-protect/scripts/99999/reset-hash?recheck=false")
    assert r.status_code == 404


def test_stats(client, db):
    make_page_protect_policy(db, enabled=True)
    make_csp_report(db)
    make_page_protect_script(db, hash_changed=True)
    db.commit()
    r = client.get("/api/v1/page-protect/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_scripts"] == 1
    assert data["total_reports"] == 1
    assert data["changed_scripts"] == 1
    assert data["active_policies"] == 1


def test_sample_reports(client, monkeypatch):
    monkeypatch.setattr("app.services.page_protect_sampler.sample_csp_reports", lambda **kw: 7)
    r = client.post("/api/v1/page-protect/sample")
    assert r.status_code == 200
    assert r.json()["stored"] == 7
