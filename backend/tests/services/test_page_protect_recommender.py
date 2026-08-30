"""Tests for the CSP policy recommender and baseline window."""
from datetime import datetime, timedelta, timezone

from app.services.page_protect import (
    recommend_policy,
    get_baseline,
    start_baseline,
    stop_baseline,
    clear_baseline,
)
from app.services.settings import set_setting
from tests.factories import (
    make_backend,
    make_csp_report,
    make_page_protect_script,
)


# --- Baseline window ---

def test_baseline_idle_by_default(db):
    result = get_baseline(db)
    assert result["status"] == "idle"


def test_start_baseline_sets_start(db):
    result = start_baseline(db, note="test baseline")
    assert result["status"] == "baselining"
    assert result["start"]
    assert result["note"] == "test baseline"
    assert "elapsed_seconds" in result


def test_stop_baseline_sets_end(db):
    start_baseline(db)
    result = stop_baseline(db)
    assert result["status"] == "complete"
    assert result["start"]
    assert result["end"]
    assert "duration_seconds" in result


def test_clear_baseline_resets(db):
    start_baseline(db)
    stop_baseline(db)
    result = clear_baseline(db)
    assert result["status"] == "idle"


def test_start_baseline_replaces_existing(db):
    start_baseline(db, note="first")
    start_baseline(db, note="second")
    result = get_baseline(db)
    assert result["note"] == "second"
    assert result["status"] == "baselining"


def test_stop_baseline_without_start_returns_error(db):
    result = stop_baseline(db)
    assert result["status"] == "idle"
    assert result.get("error")


# --- Recommender: cold start ---

def test_recommend_cold_start_minimal_policy(db):
    """With no scripts and no reports, return a minimal safe policy."""
    result = recommend_policy(db)
    d = result["directives"]
    assert "default-src" in d
    assert d["default-src"] == ["'self'"]
    assert d["base-uri"] == ["'self'"]
    assert d["form-action"] == ["'self'"]
    assert d["object-src"] == ["'none'"]
    assert "report-uri" in d
    assert any("No observed data" in w for w in result["warnings"])


# --- Recommender: script inventory ---

def test_recommend_includes_script_origins(db):
    make_page_protect_script(db, url="https://cdn.example.com/app.js",
                             resource_type="script", domain="cdn.example.com")
    make_page_protect_script(db, url="https://www.googletagmanager.com/gtm.js",
                             resource_type="script", domain="www.googletagmanager.com")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "script-src" in d
    assert "'self'" in d["script-src"]
    assert "https://cdn.example.com" in d["script-src"]
    assert "https://www.googletagmanager.com" in d["script-src"]


def test_recommend_groups_by_origin_not_full_url(db):
    """Multiple URLs from the same domain should produce one origin entry."""
    make_page_protect_script(db, url="https://cdn.example.com/app.js",
                             resource_type="script", domain="cdn.example.com")
    make_page_protect_script(db, url="https://cdn.example.com/vendor.js",
                             resource_type="script", domain="cdn.example.com")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert d["script-src"].count("https://cdn.example.com") == 1


def test_recommend_includes_connect_origins(db):
    make_page_protect_script(db, url="https://api.stripe.com/charges",
                             resource_type="connect", domain="api.stripe.com")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "connect-src" in d
    assert "https://api.stripe.com" in d["connect-src"]


def test_recommend_includes_img_origins(db):
    make_page_protect_script(db, url="https://images.example.com/logo.png",
                             resource_type="img", domain="images.example.com")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "img-src" in d
    assert "https://images.example.com" in d["img-src"]


def test_recommend_skips_other_resource_type(db):
    """resource_type 'other' should not get its own directive — default-src covers it."""
    make_page_protect_script(db, url="https://misc.example.com/thing",
                             resource_type="other", domain="misc.example.com")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    # No directive should contain the misc origin
    for sources in d.values():
        assert "https://misc.example.com" not in sources


# --- Recommender: inline/eval ---

def test_recommend_adds_unsafe_inline_for_scripts(db):
    make_csp_report(db, violated_directive="script-src", blocked_uri="inline",
                    client_ip="1.2.3.4")
    make_csp_report(db, violated_directive="script-src", blocked_uri="inline",
                    client_ip="5.6.7.8")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "script-src" in d
    assert "'unsafe-inline'" in d["script-src"]
    assert any("unsafe-inline" in w and "script-src" in w for w in result["warnings"])


def test_recommend_adds_unsafe_inline_for_styles(db):
    make_csp_report(db, violated_directive="style-src", blocked_uri="inline",
                    client_ip="1.2.3.4")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "style-src" in d
    assert "'unsafe-inline'" in d["style-src"]


def test_recommend_adds_unsafe_eval(db):
    make_csp_report(db, violated_directive="script-src", blocked_uri="eval",
                    client_ip="1.2.3.4")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "'unsafe-eval'" in d.get("script-src", [])


# --- Recommender: data: and blob: ---

def test_recommend_adds_data_uri(db):
    make_csp_report(db, violated_directive="img-src", blocked_uri="data",
                    client_ip="1.2.3.4")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    assert "img-src" in d
    assert "data:" in d["img-src"]


def test_recommend_adds_blob_uri(db):
    make_csp_report(db, violated_directive="worker-src", blocked_uri="blob",
                    client_ip="1.2.3.4")
    db.commit()
    result = recommend_policy(db)
    d = result["directives"]
    # worker-src maps to "other" in the directive map, but the recommender
    # should still add blob: to the violated directive
    assert "worker-src" in d
    assert "blob:" in d["worker-src"]


# --- Recommender: object-src ---

def test_recommend_object_src_none_when_no_violations(db):
    result = recommend_policy(db)
    assert result["directives"]["object-src"] == ["'none'"]


def test_recommend_object_src_with_origins_when_violations(db):
    make_csp_report(db, violated_directive="object-src",
                    blocked_uri="https://flash.example.com/swf", client_ip="1.2.3.4")
    db.commit()
    result = recommend_policy(db)
    # object-src should not be 'none' if there are object violations
    # (the violation itself doesn't add to the inventory, but the recommender
    # should not set 'none' when object-src violations exist)
    assert result["directives"].get("object-src") != ["'none'"]


# --- Recommender: baseline window filtering ---

def test_recommend_filters_by_baseline_window(db):
    """Reports outside the baseline window should be excluded."""
    from app.services.page_protect import start_baseline, stop_baseline
    # Create an old report (before baseline)
    old_report = make_csp_report(db, violated_directive="script-src",
                                 blocked_uri="https://old.example.com/old.js",
                                 client_ip="1.2.3.4")
    old_report.captured_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
    db.commit()

    # Start and stop baseline (window = now)
    start_baseline(db)
    import time
    time.sleep(0.1)
    stop_baseline(db)
    db.commit()

    # Create a new report (after baseline end)
    new_report = make_csp_report(db, violated_directive="script-src",
                                 blocked_uri="inline", client_ip="5.6.7.8")
    new_report.captured_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=5)
    db.commit()

    result = recommend_policy(db)
    # The old report should be filtered out (before baseline start)
    # The new report should be filtered out (after baseline end)
    # So no inline violations should be detected
    d = result["directives"]
    assert "'unsafe-inline'" not in d.get("script-src", [])


# --- Recommender: backend filtering ---

def test_recommend_filters_by_backend_ids(db):
    backend1 = make_backend(db, name="be1")
    backend2 = make_backend(db, name="be2")
    db.commit()
    # Report from be1
    make_csp_report(db, violated_directive="script-src", blocked_uri="inline",
                    client_ip="1.2.3.4", backend_name="be1")
    # Report from be2
    make_csp_report(db, violated_directive="script-src", blocked_uri="eval",
                    client_ip="5.6.7.8", backend_name="be2")
    db.commit()
    result = recommend_policy(db, backend_ids=[backend1.id])
    d = result["directives"]
    # Only be1's inline violation should be included
    assert "'unsafe-inline'" in d.get("script-src", [])
    assert "'unsafe-eval'" not in d.get("script-src", [])


# --- Recommender: sources detail ---

def test_recommend_includes_sources_detail(db):
    make_page_protect_script(db, url="https://cdn.example.com/app.js",
                             resource_type="script", domain="cdn.example.com")
    db.commit()
    result = recommend_policy(db)
    sources = result["sources"]
    assert "script-src" in sources
    entry = sources["script-src"][0]
    assert entry["origin"] == "https://cdn.example.com"
    assert entry["occurrence_count"] > 0


# --- Recommender: report-uri ---

def test_recommend_includes_report_uri(db):
    result = recommend_policy(db)
    assert "report-uri" in result["directives"]
    assert len(result["directives"]["report-uri"]) == 1


def test_recommend_uses_custom_report_path(db):
    result = recommend_policy(db, report_path="/custom-csp")
    assert result["directives"]["report-uri"] == ["/custom-csp"]
