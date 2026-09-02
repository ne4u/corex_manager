"""Unit tests for the Page Protect core service."""
import json

from app.services.page_protect import (
    build_csp_header,
    build_report_to_header,
    parse_csp_report,
    extract_script_info,
    upsert_script_inventory,
    prune_stale_scripts,
    get_stats,
)


def test_build_csp_header_basic():
    directives = {"default-src": ["'self'"], "script-src": ["'self'", "https://cdn.example.com"]}
    result = build_csp_header(directives)
    assert "default-src 'self'" in result
    assert "script-src 'self' https://cdn.example.com" in result
    assert ";" in result


def test_build_csp_header_with_flag_directive():
    directives = {"default-src": ["'self'"], "upgrade-insecure-requests": []}
    result = build_csp_header(directives)
    assert "upgrade-insecure-requests" in result
    assert "default-src 'self'" in result


def test_build_csp_header_empty():
    result = build_csp_header({})
    assert result == ""


def test_build_csp_header_appends_report_uri():
    directives = {"default-src": ["'self'"]}
    result = build_csp_header(directives, report_uri="/_csp-report")
    assert "default-src 'self'" in result
    assert "report-uri /_csp-report" in result


def test_build_csp_header_does_not_override_existing_report_uri():
    directives = {"default-src": ["'self'"], "report-uri": ["https://other.example.com/report"]}
    result = build_csp_header(directives, report_uri="/_csp-report")
    assert "default-src 'self'" in result
    assert "report-uri https://other.example.com/report" in result
    assert "report-uri /_csp-report" not in result


def test_build_report_to_header():
    result = build_report_to_header("/_csp-report")
    parsed = json.loads(result)
    assert parsed["group"] == "csp-endpoint"
    assert parsed["endpoints"][0]["url"] == "/_csp-report"


def test_parse_csp_report_uri_format():
    body = json.dumps({
        "csp-report": {
            "document-uri": "https://example.com/page",
            "referrer": "https://google.com",
            "violated-directive": "script-src",
            "effective-directive": "script-src",
            "original-policy": "default-src 'self'",
            "blocked-uri": "https://evil.example.com/script.js",
            "source-file": "https://example.com/page",
            "line-number": 42,
            "column-number": 10,
            "status-code": 200,
        }
    })
    result = parse_csp_report(body)
    assert result is not None
    assert result["report_type"] == "csp"
    assert result["document_uri"] == "https://example.com/page"
    assert result["violated_directive"] == "script-src"
    assert result["blocked_uri"] == "https://evil.example.com/script.js"
    assert result["line_number"] == 42


def test_parse_csp_report_reporting_api_format():
    body = json.dumps({
        "type": "csp-violation",
        "body": {
            "documentURL": "https://example.com/page",
            "referrer": "https://google.com",
            "effectiveDirective": "script-src",
            "originalPolicy": "default-src 'self'",
            "blockedURL": "https://evil.example.com/script.js",
            "lineNumber": 42,
            "columnNumber": 10,
            "statusCode": 200,
            "sample": "console.log(1)",
        }
    })
    result = parse_csp_report(body)
    assert result is not None
    assert result["report_type"] == "reporting-api"
    assert result["document_uri"] == "https://example.com/page"
    assert result["violated_directive"] == "script-src"
    assert result["blocked_uri"] == "https://evil.example.com/script.js"
    assert result["script_sample"] == "console.log(1)"


def test_parse_csp_report_array_batch():
    body = json.dumps([
        {"csp-report": {"violated-directive": "script-src", "blocked-uri": "https://evil1.example.com/a.js"}},
        {"csp-report": {"violated-directive": "img-src", "blocked-uri": "https://evil2.example.com/b.png"}},
    ])
    result = parse_csp_report(body)
    assert result is not None
    assert result["blocked_uri"] == "https://evil1.example.com/a.js"


def test_parse_csp_report_invalid_json():
    result = parse_csp_report("not json")
    assert result is None


def test_parse_csp_report_bare_dict():
    body = json.dumps({
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.example.com/script.js",
        "document-uri": "https://example.com/page",
    })
    result = parse_csp_report(body)
    assert result is not None
    assert result["violated_directive"] == "script-src"
    assert result["blocked_uri"] == "https://evil.example.com/script.js"


def test_extract_script_info_script():
    report = {"violated_directive": "script-src", "blocked_uri": "https://cdn.example.com/lib.js"}
    result = extract_script_info(report)
    assert result is not None
    assert result["url"] == "https://cdn.example.com/lib.js"
    assert result["resource_type"] == "script"
    assert result["domain"] == "cdn.example.com"


def test_extract_script_info_connect():
    report = {"violated_directive": "connect-src", "blocked_uri": "https://api.example.com/data"}
    result = extract_script_info(report)
    assert result is not None
    assert result["resource_type"] == "connect"


def test_extract_script_info_inline_keyword():
    report = {"violated_directive": "script-src", "blocked_uri": "inline"}
    result = extract_script_info(report)
    assert result is None


def test_extract_script_info_no_blocked_uri():
    report = {"violated_directive": "script-src"}
    result = extract_script_info(report)
    assert result is None


def test_extract_script_info_unknown_directive():
    report = {"violated_directive": "manifest-src", "blocked_uri": "https://x.example.com/manifest.json"}
    result = extract_script_info(report)
    assert result is not None
    assert result["resource_type"] == "other"


def test_upsert_script_inventory_new(db):
    script = upsert_script_inventory(db, "https://cdn.example.com/a.js", "script", "cdn.example.com")
    db.commit()
    assert script.id is not None
    assert script.url == "https://cdn.example.com/a.js"
    assert script.occurrence_count == 1
    assert script.domain == "cdn.example.com"


def test_upsert_script_inventory_existing(db):
    from app.models.models import PageProtectScript
    # First insert
    upsert_script_inventory(db, "https://cdn.example.com/a.js", "script", "cdn.example.com")
    db.commit()
    # Second insert (upsert)
    upsert_script_inventory(db, "https://cdn.example.com/a.js", "script", "cdn.example.com")
    db.commit()
    scripts = db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/a.js").all()
    assert len(scripts) == 1
    assert scripts[0].occurrence_count == 2


def test_get_stats_empty(db):
    stats = get_stats(db)
    assert stats["total_scripts"] == 0
    assert stats["total_reports"] == 0
    assert stats["changed_scripts"] == 0
    assert stats["active_policies"] == 0
    assert stats["reports_24h"] == 0


def test_get_stats_with_data(db):
    from tests.factories import make_page_protect_policy, make_csp_report, make_page_protect_script
    make_page_protect_policy(db, enabled=True)
    make_page_protect_policy(db, name="p2", enabled=False)
    make_csp_report(db)
    make_page_protect_script(db, hash_changed=True)
    make_page_protect_script(db, url="https://other.example.com/b.js", domain="other.example.com")
    db.commit()
    stats = get_stats(db)
    assert stats["total_scripts"] == 2
    assert stats["total_reports"] == 1
    assert stats["changed_scripts"] == 1
    assert stats["active_policies"] == 1
    assert stats["reports_24h"] == 1


def test_parse_beacon_data_valid(db):
    """parse_beacon_data extracts resources from a beacon POST body."""
    from app.services.page_protect import parse_beacon_data
    body = json.dumps({
        "page": "https://example.com/app",
        "resources": [
            {"url": "https://cdn.example.com/a.js", "resource_type": "script", "domain": "cdn.example.com"},
            {"url": "https://fonts.example.com/font.woff", "resource_type": "font", "domain": "fonts.example.com"},
        ],
        "ts": 1234567890,
    })
    resources = parse_beacon_data(body)
    assert len(resources) == 2
    assert resources[0]["url"] == "https://cdn.example.com/a.js"
    assert resources[0]["resource_type"] == "script"
    assert resources[1]["domain"] == "fonts.example.com"


def test_parse_beacon_data_filters_non_http(db):
    """parse_beacon_data skips non-http URLs (data:, blob:, etc.)."""
    from app.services.page_protect import parse_beacon_data
    body = {
        "resources": [
            {"url": "https://cdn.example.com/a.js", "resource_type": "script"},
            {"url": "data:text/plain,hello", "resource_type": "other"},
            {"url": "blob:https://example.com/abc", "resource_type": "other"},
        ],
    }
    resources = parse_beacon_data(body)
    assert len(resources) == 1
    assert resources[0]["url"] == "https://cdn.example.com/a.js"


def test_parse_beacon_data_invalid_json(db):
    """parse_beacon_data returns empty list for invalid JSON."""
    from app.services.page_protect import parse_beacon_data
    assert parse_beacon_data("not json") == []
    assert parse_beacon_data(None) == []
    assert parse_beacon_data({}) == []


def test_store_beacon_resources_upserts(db):
    """store_beacon_resources creates inventory entries with source='beacon'."""
    from app.services.page_protect import store_beacon_resources
    from app.models.models import PageProtectScript
    resources = [
        {"url": "https://cdn.example.com/a.js", "resource_type": "script", "domain": "cdn.example.com"},
        {"url": "https://cdn.example.com/b.js", "resource_type": "script", "domain": "cdn.example.com"},
    ]
    count = store_beacon_resources(db, resources)
    assert count == 2
    scripts = db.query(PageProtectScript).all()
    assert len(scripts) == 2
    assert all(s.source == "beacon" for s in scripts)


def test_build_beacon_rule(db):
    """build_beacon_rule produces a valid resp_transform inject rule."""
    from app.services.page_protect import build_beacon_rule
    pp_settings = {
        "beacon_content_types": "text/html",
        "beacon_path_patterns": "/app,/dashboard",
    }
    rule = build_beacon_rule(pp_settings, "/_cx-assets.js")
    assert rule["transform_type"] == "inject"
    assert rule["inject_position"] == "before"
    assert rule["content_types"] == ["text/html"]
    assert rule["path_patterns"] == ["/app", "/dashboard"]
    assert "<script src=\"/_cx-assets.js?v=" in rule["inject_string"]
    assert rule["inject_string"].endswith("\"></script>")
    assert rule["find_regex"] == "</head>|</body>"


def test_prune_stale_scripts_deletes_old_unseen(db):
    """prune_stale_scripts deletes rows where both last_seen and last_hash_at are stale."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    s = make_page_protect_script(db, url="https://cdn.example.com/old.js", last_hash="abc", last_hash_at=old, last_seen=old)
    db.commit()
    pruned = prune_stale_scripts(db, 7)
    assert pruned == 1
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/old.js").first() is None


def test_prune_stale_scripts_preserves_changed(db):
    """prune_stale_scripts preserves rows with hash_changed=True even if stale."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    s = make_page_protect_script(db, url="https://cdn.example.com/changed.js", hash_changed=True, last_hash="abc", last_hash_at=old, last_seen=old)
    db.commit()
    pruned = prune_stale_scripts(db, 7)
    assert pruned == 0
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/changed.js").first() is not None


def test_prune_stale_scripts_preserves_recent_last_seen(db):
    """prune_stale_scripts preserves rows where last_seen is recent (still seen in traffic)."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    recent = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    s = make_page_protect_script(db, url="https://cdn.example.com/recent.js", last_hash="abc", last_hash_at=old, last_seen=recent)
    db.commit()
    pruned = prune_stale_scripts(db, 7)
    assert pruned == 0
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/recent.js").first() is not None


def test_prune_stale_scripts_preserves_recent_last_hash_at(db):
    """prune_stale_scripts preserves rows where last_hash_at is recent (hasher can still fetch)."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    recent = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    s = make_page_protect_script(db, url="https://cdn.example.com/still-live.js", last_hash="abc", last_hash_at=recent, last_seen=old)
    db.commit()
    pruned = prune_stale_scripts(db, 7)
    assert pruned == 0
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/still-live.js").first() is not None


def test_prune_stale_scripts_prunes_null_last_hash_at(db):
    """prune_stale_scripts prunes rows where last_hash_at is NULL (never successfully checked) and last_seen is stale."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    s = make_page_protect_script(db, url="https://cdn.example.com/never-checked.js", last_hash=None, last_hash_at=None, last_seen=old)
    db.commit()
    pruned = prune_stale_scripts(db, 7)
    assert pruned == 1
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/never-checked.js").first() is None


def test_prune_stale_scripts_prunes_manual_source(db):
    """prune_stale_scripts prunes manually-added entries too (no source exemption)."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    s = make_page_protect_script(db, url="https://cdn.example.com/manual-old.js", source="manual", last_hash="abc", last_hash_at=old, last_seen=old)
    db.commit()
    pruned = prune_stale_scripts(db, 7)
    assert pruned == 1
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/manual-old.js").first() is None


def test_prune_stale_scripts_disabled_when_zero(db):
    """prune_stale_scripts with stale_days=0 disables pruning (no rows deleted)."""
    from datetime import datetime, timezone, timedelta
    from tests.factories import make_page_protect_script
    from app.models.models import PageProtectScript
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=365)
    s = make_page_protect_script(db, url="https://cdn.example.com/very-old.js", last_hash="abc", last_hash_at=old, last_seen=old)
    db.commit()
    pruned = prune_stale_scripts(db, 0)
    assert pruned == 0
    assert db.query(PageProtectScript).filter(PageProtectScript.url == "https://cdn.example.com/very-old.js").first() is not None
