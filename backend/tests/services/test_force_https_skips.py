"""Tests for features skipped on force_https (non-SSL) listeners.

A force_https listener exists solely to redirect HTTP traffic to HTTPS.
Browser-facing features that are either dead (never fire on a redirect-only
listener) or insecure (would serve captcha over plaintext HTTP) are skipped:

  - Captcha challenge actions (security rules, WAF rules, rate limits)
  - Cap CAPTCHA proxy (is_cap_proxy ACL, _cv cookie validation, cap backends)
  - Page Protect CSP report capture
  - Page Protect beacon JS serving + beacon trust tracking
  - JA4 fingerprint header (lua.ja4_fp returns empty on non-TLS)

These features fire on the HTTPS listener after the redirect.
"""
from app.services import haproxy
from app.services.haproxy import generate_frontend
from app.services.settings import set_setting
from tests.factories import (
    make_backend,
    make_listener,
    make_rate_limit,
    make_security_rule,
    make_server,
    make_waf_rule,
)


def _make_force_https_listener(db, name="force_tls", bind_port=80):
    """Create a force_https (non-SSL) listener for testing."""
    listener = make_listener(db, name=name, bind_port=bind_port, ssl_enabled=False)
    listener.force_https = True
    db.commit()
    return listener


def _section(cfg, frontend_name):
    """Extract a frontend section from the generated config."""
    marker = f"frontend {frontend_name}"
    if marker not in cfg:
        return ""
    return cfg.split(marker)[1].split("\nfrontend ")[0]


# ---------------------------------------------------------------------------
# Change 1 + 2: Security rule challenge actions skipped on force_https
# ---------------------------------------------------------------------------

def test_security_rule_challenge_skipped_on_force_https(db):
    """A challenge-action security rule is NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    make_security_rule(db, name="risky", expression='http.host = "example.com"', action="challenge")

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "force_tls")

    # The captcha redirect should NOT be emitted
    assert "captcha_redirect" not in section, "Challenge redirect emitted on force_https listener"
    assert "captcha_store_ctx" not in section, "captcha_store_ctx emitted on force_https listener"
    assert "captcha_scheme" not in section, "captcha_scheme emitted on force_https listener"
    # The cap proxy ACL and _cv cookie validation should NOT be emitted
    assert "is_cap_proxy" not in section, "is_cap_proxy ACL emitted on force_https listener"
    assert "cap_cv_val" not in section, "_cv cookie validation emitted on force_https listener"
    # The cap backends should NOT be referenced
    assert "cap_api_proxy" not in section, "cap_api_proxy backend emitted on force_https listener"
    assert "cap_service_proxy" not in section, "cap_service_proxy backend emitted on force_https listener"


def test_security_rule_challenge_still_emitted_on_ssl_listener(db):
    """A challenge-action security rule IS emitted on a regular SSL listener (no regression)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_security_rule(db, name="risky", expression='http.host = "example.com"', action="challenge")

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "https_in")

    assert "captcha_redirect" in section, "Challenge redirect NOT emitted on SSL listener"
    assert "captcha_store_ctx" in section, "captcha_store_ctx NOT emitted on SSL listener"
    assert "is_cap_proxy" in section, "is_cap_proxy ACL NOT emitted on SSL listener"


def test_security_rule_block_still_emitted_on_force_https(db):
    """A block-action security rule IS emitted on a force_https listener (block before redirect)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    make_security_rule(db, name="blocker", expression='http.host = "evil.com"', action="block")

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "force_tls")

    # Block rules should still fire before the redirect
    assert "http-request deny" in section, "Block rule NOT emitted on force_https listener"
    assert "evil.com" in section, "Block rule condition NOT emitted on force_https listener"


# ---------------------------------------------------------------------------
# Change 3: WAF challenge actions skipped on force_https
# ---------------------------------------------------------------------------

def test_waf_challenge_skipped_on_force_https(db):
    """A challenge-action WAF rule is NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="challenge")

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "force_tls")

    # The WAF challenge redirect should NOT be emitted
    assert "captcha_redirect" not in section, "WAF challenge redirect emitted on force_https listener"
    assert "captcha_store_ctx" not in section, "WAF captcha_store_ctx emitted on force_https listener"


def test_waf_challenge_still_emitted_on_ssl_listener(db):
    """A challenge-action WAF rule IS emitted on a regular SSL listener (no regression)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="challenge")

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "https_in")

    assert "captcha_redirect" in section, "WAF challenge redirect NOT emitted on SSL listener"


# ---------------------------------------------------------------------------
# Change 4: Rate limit challenge actions skipped on force_https
# ---------------------------------------------------------------------------

def test_rate_limit_challenge_skipped_on_force_https(db):
    """A challenge-action basic rate limit is NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    make_rate_limit(db, listener_id=listener.id, name="rl_challenge", limit_type="basic",
                    action="challenge", events=5, window_seconds=30)

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "force_tls")

    assert "captcha_redirect" not in section, "Rate limit challenge redirect emitted on force_https"
    assert "captcha_store_ctx" not in section, "Rate limit captcha_store_ctx emitted on force_https"


def test_rate_limit_challenge_still_emitted_on_ssl_listener(db):
    """A challenge-action basic rate limit IS emitted on a regular SSL listener (no regression)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_rate_limit(db, listener_id=listener.id, name="rl_challenge", limit_type="basic",
                    action="challenge", events=5, window_seconds=30)

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "https_in")

    assert "captcha_redirect" in section, "Rate limit challenge redirect NOT emitted on SSL listener"


def test_rate_limit_block_still_emitted_on_force_https(db):
    """A block-action rate limit IS emitted on a force_https listener (block before redirect)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    make_rate_limit(db, listener_id=listener.id, name="rl_block", limit_type="basic",
                    action="block", events=5, window_seconds=30)

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "force_tls")

    # The rate limit deny should still fire
    assert "deny_status 429" in section or "deny_status" in section, \
        "Block rate limit NOT emitted on force_https listener"


# ---------------------------------------------------------------------------
# Change 5: Page Protect (CSP report + beacon) skipped on force_https
# ---------------------------------------------------------------------------

def test_page_protect_csp_report_skipped_on_force_https(db):
    """CSP report capture is NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)

    cfg = generate_frontend(
        listener, db, page_protect_enabled=True, page_protect_report_path="/_csp-report",
    )

    assert "is_csp_report" not in cfg, "CSP report ACL emitted on force_https listener"
    # The log-format always includes the csp_report field, but the capture
    # rules (wait-for-body, set-var, return 204) should NOT be emitted.
    assert "wait-for-body time 5s if is_csp_report" not in cfg, \
        "CSP report body capture emitted on force_https listener"
    assert "set-var(txn.csp_report) req.body if is_csp_report" not in cfg, \
        "CSP report set-var emitted on force_https listener"
    assert "return status 204 if is_csp_report" not in cfg, \
        "CSP report return emitted on force_https listener"


def test_page_protect_beacon_skipped_on_force_https(db):
    """Beacon JS serving + beacon trust is NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)

    cfg = generate_frontend(
        listener, db,
        page_protect_enabled=True,
        page_protect_beacon={"enabled": True, "trust_enabled": True},
    )

    assert "is_beacon_script" not in cfg, "Beacon script ACL emitted on force_https listener"
    assert "is_asset_beacon" not in cfg, "Asset beacon ACL emitted on force_https listener"
    assert "beacon_trust_table" not in cfg, "Beacon trust tracking emitted on force_https listener"
    assert "txn.cxid" not in cfg, "cxid generation emitted on force_https listener"
    assert "Server-Timing" not in cfg, "Server-Timing header emitted on force_https listener"


def test_page_protect_csp_report_still_emitted_on_ssl_listener(db):
    """CSP report capture IS emitted on a regular SSL listener (no regression)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)

    cfg = generate_frontend(
        listener, db, page_protect_enabled=True, page_protect_report_path="/_csp-report",
    )

    assert "is_csp_report" in cfg, "CSP report ACL NOT emitted on SSL listener"
    assert "set-var(txn.csp_report) req.body if is_csp_report" in cfg, \
        "CSP report capture NOT emitted on SSL listener"


# ---------------------------------------------------------------------------
# Change 7: Request fingerprint skipped on force_https
# ---------------------------------------------------------------------------

def test_req_fp_capture_skipped_on_force_https(db):
    """lua.req_fp_capture and lua.req_fp_response are NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)

    cfg = generate_frontend(listener, db, req_fp_enabled=True)

    assert "lua.req_fp_capture" not in cfg, "req_fp_capture emitted on force_https listener"
    assert "lua.req_fp_response" not in cfg, "req_fp_response emitted on force_https listener"


def test_req_fp_capture_still_emitted_on_ssl_listener(db):
    """lua.req_fp_capture and lua.req_fp_response ARE emitted on a regular SSL listener (no regression)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)

    cfg = generate_frontend(listener, db, req_fp_enabled=True)

    assert "lua.req_fp_capture" in cfg, "req_fp_capture NOT emitted on SSL listener"
    assert "lua.req_fp_response" in cfg, "req_fp_response NOT emitted on SSL listener"


def test_req_fp_body_buffering_skipped_on_force_https(db):
    """req_fp body buffering (is_req_fp_body ACL) is NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)

    cfg = generate_frontend(listener, db, req_fp_enabled=True, req_fp_parse_body=True)

    assert "is_req_fp_body" not in cfg, "req_fp body buffering emitted on force_https listener"


def test_geoip_set_vars_still_emitted_on_force_https(db, monkeypatch):
    """GeoIP set-vars ARE emitted on a force_https listener — security rules may reference geoip fields."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)

    # Patch GeoIP to be available so the set-vars are emitted
    monkeypatch.setattr(haproxy, "_geoip_lua_module_available", lambda: True)

    cfg = generate_frontend(listener, db, req_fp_enabled=True)

    # GeoIP set-vars must be present so geoip-based security rules work
    # before the redirect. The set-vars don't depend on req_fp.
    assert "txn.geo_country" in cfg, "GeoIP country set-var NOT emitted on force_https listener"
    assert "txn.geoip_tz" in cfg, "GeoIP timezone set-var NOT emitted on force_https listener"


# ---------------------------------------------------------------------------
# Change 8: Risk scoring skipped on force_https
# ---------------------------------------------------------------------------

def test_risk_scoring_skipped_on_force_https(db):
    """Risk scoring (risk_capture, match flags, risk_compute) is NOT emitted on a force_https listener."""
    from tests.factories import make_security_rule
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    # Add a security rule so emit_security_rules doesn't early-return
    make_security_rule(db, name="blocker", expression='http.host = "evil.com"', action="block")

    cfg = generate_frontend(listener, db, req_fp_enabled=True)

    assert "lua.risk_capture" not in cfg, "risk_capture emitted on force_https listener"
    assert "lua.risk_compute" not in cfg, "risk_compute emitted on force_https listener"
    # risk match flags are set-var(txn.risk.match_<id>) lines — the log-format
    # always references txn.risk.score (which will be empty/0), so we only
    # check for the match flag set-vars, not the log-format reference.
    assert "set-var(txn.risk.match_" not in cfg, "risk match flags emitted on force_https listener"


def test_risk_scoring_still_emitted_on_ssl_listener(db):
    """Risk scoring IS emitted on a regular SSL listener (no regression)."""
    from tests.factories import make_security_rule
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_security_rule(db, name="blocker", expression='http.host = "evil.com"', action="block")

    cfg = generate_frontend(listener, db, req_fp_enabled=True)

    assert "lua.risk_capture" in cfg, "risk_capture NOT emitted on SSL listener"
    assert "lua.risk_compute" in cfg, "risk_compute NOT emitted on SSL listener"


# ---------------------------------------------------------------------------
# Change 9: API Armor skipped on force_https (depends on req_fp)
# ---------------------------------------------------------------------------

def test_api_armor_skipped_on_force_https(db):
    """API Armor body buffering and deeper analysis are NOT emitted on a force_https listener."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)
    listener.options = {"api_armor": True}
    db.commit()

    cfg = generate_frontend(listener, db, req_fp_enabled=True, api_armor_enabled=True)

    assert "is_api_armor" not in cfg, "API Armor ACL emitted on force_https listener"
    assert "lua.api_body_parse" not in cfg, "API Armor deeper analysis emitted on force_https listener"
    assert "txn.api_body" not in cfg, "API Armor body buffering emitted on force_https listener"


def test_api_armor_still_emitted_on_ssl_listener(db):
    """API Armor IS emitted on a regular SSL listener (no regression)."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    listener.options = {"api_armor": True}
    db.commit()

    cfg = generate_frontend(listener, db, req_fp_enabled=True, api_armor_enabled=True)

    assert "is_api_armor" in cfg, "API Armor ACL NOT emitted on SSL listener"
    assert "lua.api_body_parse" in cfg, "API Armor deeper analysis NOT emitted on SSL listener"


# ---------------------------------------------------------------------------
# Integration: force_https redirect still emitted
# ---------------------------------------------------------------------------

def test_force_https_redirect_still_emitted(db):
    """The force_https redirect to HTTPS is still emitted after all skips."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    listener = _make_force_https_listener(db)

    cfg = haproxy.generate_config(db)
    section = _section(cfg, "force_tls")

    assert "http-request redirect scheme https code 301" in section, \
        "Force HTTPS redirect NOT emitted"
