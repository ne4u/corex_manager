from app.services import coraza_config, haproxy
from tests.factories import (
    make_backend,
    make_listener,
    make_rate_limit,
    make_server,
    make_waf_rule,
)


def test_generate_config_no_waf(db):
    backend = make_backend(db)
    make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter spoe engine coraza" not in cfg
    assert "backend coraza-spoa" not in cfg


def test_generate_config_waf_disabled_globally(db, monkeypatch):
    backend = make_backend(db)
    make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=None)
    monkeypatch.setattr(haproxy.settings, "CORAZA_SPOA_ENABLED", False)
    cfg = haproxy.generate_config(db)
    assert "filter spoe engine coraza" not in cfg
    assert "backend coraza-spoa" not in cfg


def test_generate_config_global_rule_attached(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=None)
    cfg = haproxy.generate_config(db)
    assert "filter spoe engine coraza" in cfg
    assert "backend coraza-spoa" in cfg
    assert f"http-request set-var(txn.coraza.app) str(haproxy-waf-listener-{listener.id})" in cfg


def test_generate_config_listener_specific_app(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = haproxy.generate_config(db)
    assert f"haproxy-waf-listener-{listener.id}" in cfg


def test_generate_config_waf_action_block(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="block", status_code=403)
    cfg = haproxy.generate_config(db)
    assert 'http-request deny deny_status 403 default-errorfiles if { var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'http-response deny deny_status 403 default-errorfiles if { var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }' in cfg


def test_generate_config_waf_emits_combined_action_var(db):
    """WAF config should set txn.action (combined) alongside txn.waf.action."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="block", status_code=403)
    cfg = haproxy.generate_config(db)
    assert "set-var(txn.waf.action) var(txn.coraza.action)" in cfg
    assert "set-var(txn.action) var(txn.coraza.action)" in cfg


def test_generate_config_waf_drop_uses_deny_not_silent_drop(db):
    """Coraza 'drop' action should use deny (logged), not silent-drop (unlogged)."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="block", status_code=403)
    cfg = haproxy.generate_config(db)
    assert 'http-request deny deny_status 403 default-errorfiles if { var(txn.coraza.action) -m str drop } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'http-response deny deny_status 403 default-errorfiles if { var(txn.coraza.action) -m str drop } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert "silent-drop" not in cfg


def test_generate_config_waf_action_allow(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="allow")
    cfg = haproxy.generate_config(db)
    assert "http-request allow if { var(txn.coraza.action) -m str allow }" in cfg
    assert "http-response allow if { var(txn.coraza.action) -m str allow }" in cfg
    assert "deny deny_status 403 hdr waf-block" not in cfg


def test_generate_config_waf_action_log(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="log")
    cfg = haproxy.generate_config(db)
    assert "declare capture response len 64" in cfg
    assert "http-request capture req.hdr(Host) len 64" in cfg
    assert "http-response capture res.hdr(Server) id 0" in cfg


def test_generate_config_waf_action_redirect_with_url(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        action="redirect",
        redirect_url="/blocked",
    )
    cfg = haproxy.generate_config(db)
    assert 'http-request redirect location /blocked code 302 if { var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'http-response redirect location /blocked code 302 if { var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }' in cfg


def test_generate_config_waf_action_redirect_without_url(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="redirect")
    cfg = haproxy.generate_config(db)
    assert 'http-request deny deny_status 403' in cfg


def test_generate_config_waf_action_challenge(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="challenge")
    cfg = haproxy.generate_config(db)
    # The cookie check now uses a Valkey-backed opaque token validated by a
    # Lua action instead of the old trivially-forgeable "req.cook(cap_valid)
    # -m found" check. The cookie is named "_cv" and the token is looked up
    # in Valkey via lua.captcha_validate_cookie.
    assert "txn.captcha_cookie_valid" in cfg
    assert "lua.captcha_validate_cookie" in cfg
    assert "req.cook(_cv)" in cfg
    assert "/waf/captcha" in cfg
    # The redirect URL is now stored server-side in Valkey (via captcha_redirect
    # and lua.captcha_store_ctx) to prevent open redirect attacks. The challenge
    # URL contains only the opaque cid token, not the redirect destination.
    assert "cid=%[var(txn.captcha_cid_token)]" in cfg
    assert "lua.captcha_store_ctx" in cfg
    assert "txn.captcha_redirect" in cfg
    # The _cv token is bound to the client via a hash of IP + User-Agent + JA4.
    # The HAProxy config sets txn vars for each component before the Lua
    # validation action, so the action can recompute and compare the hash.
    assert "set-var(txn.cap_cv_ip) src" in cfg
    assert "set-var(txn.cap_cv_ua) req.fhdr(user-agent)" in cfg
    assert "set-var(txn.cap_cv_ja4) lua.ja4_fp" in cfg
    # The JA4 fingerprint is forwarded to backends so the captcha verify
    # endpoint can compute the same binding hash.
    assert 'set-header X-JA4-Fingerprint' in cfg


def test_generate_config_waf_action_challenge_ja4_disabled(db):
    """When JA4 is disabled, the JA4 txn var and X-JA4-Fingerprint header
    must not be emitted (lua.ja4_fp fetch would be unknown). The IP and UA
    binding vars are still emitted."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, action="challenge")
    from app.services.settings import set_setting
    set_setting(db, "ja4_enabled", "false")
    cfg = haproxy.generate_config(db)
    assert "set-var(txn.cap_cv_ip) src" in cfg
    assert "set-var(txn.cap_cv_ua) req.fhdr(user-agent)" in cfg
    assert "set-var(txn.cap_cv_ja4)" not in cfg
    assert "X-JA4-Fingerprint" not in cfg


def test_generate_config_waf_fail_open(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, fail_open=True)
    cfg = haproxy.generate_config(db)
    assert "var(txn.coraza.error)" not in cfg


def test_generate_config_waf_fail_closed(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id, fail_open=False)
    cfg = haproxy.generate_config(db)
    assert "http-request deny deny_status 500 default-errorfiles if { var(txn.coraza.error) -m int gt 0 }" in cfg


def test_generate_coraza_spoe_config_export_rule_ids(db):
    """Rule ID export is always enabled — SPOE config always has exportRuleIDs=bool(true)."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = haproxy.generate_coraza_spoe_config(db)
    assert "exportRuleIDs=bool(true)" in cfg


def test_generate_coraza_spoe_config_no_response_message(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = haproxy.generate_coraza_spoe_config(db)
    assert "spoe-message coraza-res" not in cfg
    assert "spoe-group coraza-res" not in cfg
    assert "coraza-res" not in cfg


def test_generate_coraza_spoe_config_no_log_global(db):
    """SPOE config should not log to global (stdout) to avoid polluting JSON logs."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = haproxy.generate_coraza_spoe_config(db)
    assert "log         global" not in cfg
    assert "log global" not in cfg


def test_generate_coraza_spoe_config_max_frame_size_default_bufsize(db):
    """HAProxy caps max-frame-size at tune.bufsize - 4; with the 16KB default that is 16380."""
    cfg = haproxy.generate_coraza_spoe_config(db)
    assert "max-frame-size 16380" in cfg


def test_generate_coraza_spoe_config_max_frame_size_capped_at_coraza_limit(db):
    """A large user tune.bufsize must not push max-frame-size above Coraza's 65535."""
    import json
    from app.services.settings import set_setting
    set_setting(db, "haproxy_global_options", json.dumps([{"enabled": True, "directive": "tune.bufsize", "value": "1048576"}]))
    db.commit()
    cfg = haproxy.generate_coraza_spoe_config(db)
    assert "max-frame-size 65535" in cfg


def test_generate_coraza_spoe_config_max_frame_size_64k_bufsize(db):
    """tune.bufsize 65536 → max-frame-size 65532 (65535 would be rejected by HAProxy)."""
    import json
    from app.services.settings import set_setting
    set_setting(db, "haproxy_global_options", json.dumps([{"enabled": True, "directive": "tune.bufsize", "value": "65536"}]))
    db.commit()
    cfg = haproxy.generate_coraza_spoe_config(db)
    assert "max-frame-size 65532" in cfg


def test_generate_config_waf_rate_limit(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    make_rate_limit(db, listener_id=listener.id, waf_event_threshold=5)
    cfg = haproxy.generate_config(db)
    assert 'http-request sc-inc-gpc0(0) if { var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'http-request sc-inc-gpc0(0) if { var(txn.coraza.action) -m str drop } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'sc_gpc0_rate(0) gt 5' in cfg
    assert "store " in cfg and "gpc0_rate" in cfg


def test_generate_config_waf_rule_rate_limit(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        rate_enabled=True,
        rate_events=10,
        rate_window_seconds=120,
    )
    cfg = haproxy.generate_config(db)
    assert 'http-request sc-inc-gpc1(0) if { var(txn.coraza.action) -m str deny } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'http-request sc-inc-gpc1(0) if { var(txn.coraza.action) -m str drop } !{ var(txn.sec.skip_waf) -m found }' in cfg
    assert 'sc_gpc1_rate(0) gt 10' in cfg
    assert "deny_status 429" in cfg
    assert "expire 120s" in cfg
    assert "gpc1_rate(120s)" in cfg


def test_generate_config_waf_rate_key_header(db):
    """Rate key=header: string stick table backend + track-sc1 on header."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        rate_enabled=True,
        rate_events=50,
        rate_window_seconds=60,
        rate_key="header",
        rate_header="X-API-Key",
    )
    cfg = haproxy.generate_config(db)
    # String stick table backend
    assert "backend waf_rate_" in cfg
    assert "type string len 256" in cfg
    assert "gpc1_rate(60s)" in cfg
    # Track on sc1 with header
    assert "track-sc1 req.hdr(X-API-Key)" in cfg
    # Counter and threshold on sc1
    assert "sc-inc-gpc1(1)" in cfg
    assert "sc_gpc1_rate(1) gt 50" in cfg


def test_generate_config_waf_rate_key_path(db):
    """Rate key=path: string stick table backend + track-sc1 on path."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        rate_enabled=True,
        rate_events=30,
        rate_window_seconds=30,
        rate_key="path",
    )
    cfg = haproxy.generate_config(db)
    assert "track-sc1 path" in cfg
    assert "sc-inc-gpc1(1)" in cfg
    assert "sc_gpc1_rate(1) gt 30" in cfg


def test_generate_config_waf_rate_key_user_id(db):
    """Rate key=user_id: string stick table backend + track-sc1 on X-User-ID header."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        rate_enabled=True,
        rate_events=20,
        rate_window_seconds=60,
        rate_key="user_id",
    )
    cfg = haproxy.generate_config(db)
    # Debug: print relevant lines
    for line in cfg.splitlines():
        if "track" in line or "waf_rate" in line or "stick-table" in line or "gpc1" in line:
            print(f"DEBUG: {line!r}")
    assert "track-sc1 req.hdr(X-User-ID)" in cfg
    assert "sc-inc-gpc1(1)" in cfg
    assert "sc_gpc1_rate(1) gt 20" in cfg


def test_generate_config_waf_rate_key_user_id_custom_header(db):
    """Rate key=user_id with custom header: track-sc1 on the specified header."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        rate_enabled=True,
        rate_events=20,
        rate_window_seconds=60,
        rate_key="user_id",
        rate_header="X-Auth-User",
    )
    cfg = haproxy.generate_config(db)
    assert "track-sc1 req.hdr(X-Auth-User)" in cfg


def test_waf_enabled_false_when_no_listener_matches(db):
    backend = make_backend(db)
    make_listener(db, backend=backend)
    other_backend = make_backend(db, name="other")
    make_waf_rule(db, name="waf", listener_id=None, backend_id=other_backend.id)
    assert haproxy._waf_enabled(db) is False


def test_waf_enabled_true_when_listener_matches(db):
    backend = make_backend(db)
    make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=None, backend_id=backend.id)
    assert haproxy._waf_enabled(db) is True


# ---- Rate limit window/duration template variables + block duration ----

def test_waf_rule_rate_limit_sets_window_var(db):
    """WafRule rate limiting sets txn.rate_limit_window before the deny."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=120)
    cfg = haproxy.generate_config(db)
    assert "set-var(txn.rate_limit_window) str(120)" in cfg


def test_waf_rule_rate_limit_sets_duration_var(db):
    """WafRule rate limiting with duration sets txn.rate_limit_duration."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_duration_seconds=300)
    cfg = haproxy.generate_config(db)
    assert "set-var(txn.rate_limit_duration) str(300)" in cfg


def test_listener_rate_limit_default_429(db):
    """Listener basic rate limit denies with 429 by default."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=60, response_code=None)
    cfg = haproxy.generate_config(db)
    assert "deny_status 429" in cfg


def test_listener_rate_limit_custom_response_code(db):
    """Listener rate limit uses response_code when set."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=60, response_code=503)
    cfg = haproxy.generate_config(db)
    assert "deny_status 503" in cfg


def test_listener_rate_limit_sets_vars(db):
    """Listener rate limit sets window and duration vars."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=30, duration_seconds=120)
    cfg = haproxy.generate_config(db)
    assert "set-var(txn.rate_limit_window) str(30)" in cfg
    assert "set-var(txn.rate_limit_duration) str(120)" in cfg


def test_block_duration_emits_block_table(db):
    """Block table backend emitted when WafRule has duration > 0."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_duration_seconds=300)
    cfg = haproxy.generate_config(db)
    assert "backend block_table_" in cfg
    assert "stick-table type ip" in cfg
    assert "expire 300s" in cfg


def test_block_duration_emits_track_sc2(db):
    """track-sc2 emitted when block duration > 0."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_duration_seconds=300)
    cfg = haproxy.generate_config(db)
    assert "track-sc2 src table block_table_" in cfg


def test_block_duration_emits_block_deny(db):
    """Block deny (sc_get_gpc0(2) gt 0) emitted when block duration > 0."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_duration_seconds=300)
    cfg = haproxy.generate_config(db)
    assert "sc_get_gpc0(2) gt 0" in cfg


def test_block_duration_emits_block_increment(db):
    """Block increment emitted with rate exceeded condition when duration > 0."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_duration_seconds=300)
    cfg = haproxy.generate_config(db)
    assert "sc-inc-gpc0(2)" in cfg
    assert "sc_get_gpc0(2) eq 0" in cfg


def test_no_block_duration_no_block_table(db):
    """No block table when all durations are 0."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_duration_seconds=0)
    cfg = haproxy.generate_config(db)
    assert "block_table_" not in cfg


def test_block_duration_listener_rate_limit(db):
    """Listener rate limit with duration emits block table and tracking."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=60, duration_seconds=180)
    cfg = haproxy.generate_config(db)
    assert "backend block_table_" in cfg
    assert "track-sc2 src table block_table_" in cfg
    assert "sc_get_gpc0(2) gt 0" in cfg
    assert "sc-inc-gpc0(2)" in cfg


def test_block_duration_non_src_key(db):
    """String block table emitted for non-src rate key with duration."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_key="user_id", rate_header="X-User-ID",
                  rate_duration_seconds=300)
    cfg = haproxy.generate_config(db)
    assert "backend block_table_str_" in cfg
    assert "track-sc2 req.hdr(X-User-ID) table block_table_str_" in cfg


def test_response_code_rate_limit_emits_sc3_tracking(db):
    """response_code rate limit emits track-sc3 with dedicated resp_code_table."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="response_code",
                    events=10, window_seconds=30, match_status_code=503)
    cfg = haproxy.generate_config(db)
    assert "track-sc3 src table resp_code_table_" in cfg


def test_response_code_rate_limit_emits_resp_code_backend(db):
    """response_code rate limit emits a resp_code_table stick-table backend."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="response_code",
                    events=10, window_seconds=30, match_status_code=503)
    cfg = haproxy.generate_config(db)
    assert "backend resp_code_table_" in cfg
    assert "gpc0_rate(30s)" in cfg


def test_response_code_rate_limit_uses_gpc0_rate_sc3(db):
    """response_code rate limit uses sc_gpc0_rate(3) and sc-inc-gpc0(3), not gpc2."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="response_code",
                    events=10, window_seconds=30, match_status_code=503)
    cfg = haproxy.generate_config(db)
    assert "sc_gpc0_rate(3) gt 10" in cfg
    assert "sc-inc-gpc0(3)" in cfg
    assert "gpc2_rate" not in cfg
    assert "sc-inc-gpc2" not in cfg


def test_response_code_rate_limit_match_status(db):
    """response_code rate limit increments on the configured status code."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="response_code",
                    events=10, window_seconds=30, match_status_code=503)
    cfg = haproxy.generate_config(db)
    assert "http-after-response sc-inc-gpc0(3) if { status 503 }" in cfg


def test_response_code_rate_limit_no_frontend_stick_table(db):
    """response_code-only listener does not emit a frontend stick-table."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="response_code",
                    events=10, window_seconds=30, match_status_code=503)
    cfg = haproxy.generate_config(db)
    # The frontend should NOT have a stick-table (only the resp_code_table backend should)
    assert "tcp-request connection track-sc0 src" not in cfg


def test_response_code_rate_limit_with_block_duration(db):
    """response_code rate limit with duration emits block table on sc2."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="response_code",
                    events=10, window_seconds=30, match_status_code=503,
                    duration_seconds=120)
    cfg = haproxy.generate_config(db)
    assert "backend block_table_" in cfg
    assert "track-sc2 src table block_table_" in cfg
    assert "sc_get_gpc0(2) gt 0" in cfg


# ---------------------------------------------------------------------------
# RateLimit-page non-src rate key tests (basic/advanced/waf types)
# ---------------------------------------------------------------------------

def test_rate_limit_basic_non_src_header(db):
    """basic rate limit with rate_key=header tracks sc1 and checks sc_http_req_rate(1)."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=60, rate_key="header",
                    rate_header="X-API-Key")
    cfg = haproxy.generate_config(db)
    # String stick table backend for RateLimit non-src
    assert "backend rl_rate_" in cfg
    assert "track-sc1 req.hdr(X-API-Key) table rl_rate_" in cfg
    # Uses sc1 (not sc0) for the rate check
    assert "sc_http_req_rate(1) gt 50" in cfg
    # Frontend stick-table should NOT have http_req_rate as a store
    # (only non-src RL on listener, so the store goes on the string table)
    stick_table_line = [l for l in cfg.splitlines() if "stick-table type ip" in l]
    assert stick_table_line, "Expected frontend stick-table"
    assert "http_req_rate" not in stick_table_line[0]


def test_rate_limit_basic_non_src_path(db):
    """basic rate limit with rate_key=path tracks sc1 on path."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=30, window_seconds=30, rate_key="path")
    cfg = haproxy.generate_config(db)
    assert "track-sc1 path table rl_rate_" in cfg
    assert "sc_http_req_rate(1) gt 30" in cfg


def test_rate_limit_basic_non_src_user_id(db):
    """basic rate limit with rate_key=user_id tracks sc1 on X-User-ID header."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=20, window_seconds=60, rate_key="user_id")
    cfg = haproxy.generate_config(db)
    assert "track-sc1 req.hdr(X-User-ID) table rl_rate_" in cfg
    assert "sc_http_req_rate(1) gt 20" in cfg


def test_rate_limit_basic_src_uses_sc0(db):
    """basic rate limit with rate_key=src (default) still uses sc0."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=100, window_seconds=60)
    cfg = haproxy.generate_config(db)
    assert "sc_http_req_rate(0) gt 100" in cfg
    assert "track-sc1" not in cfg
    assert "backend rl_rate_" not in cfg


def test_rate_limit_emits_combined_action_var(db):
    """Rate limit config should set txn.action (combined) alongside txn.ratelimit.action."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=100, window_seconds=60)
    cfg = haproxy.generate_config(db)
    assert "set-var(txn.ratelimit.action) str(blocked)" in cfg
    assert "set-var(txn.action) str(blocked)" in cfg


def test_rate_limit_advanced_non_src_header(db):
    """advanced rate limit with rate_key=header uses sc1 for rate check."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="advanced",
                    events=40, window_seconds=60, rate_key="header",
                    rate_header="X-Token", expression='path_beg /api')
    cfg = haproxy.generate_config(db)
    assert "track-sc1 req.hdr(X-Token) table rl_rate_" in cfg
    assert "sc_http_req_rate(1) gt 40" in cfg


def test_rate_limit_waf_non_src_header(db):
    """waf rate limit with rate_key=header uses sc1 for gpc0 rate check."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="waf",
                    waf_event_threshold=5, waf_window_seconds=60,
                    rate_key="header", rate_header="X-API-Key")
    cfg = haproxy.generate_config(db)
    assert "track-sc1 req.hdr(X-API-Key) table rl_rate_" in cfg
    # WAF-type uses gpc0_rate on sc1
    assert "sc-inc-gpc0(1)" in cfg
    assert "sc_gpc0_rate(1) gt 5" in cfg


def test_rate_limit_non_src_with_block_duration(db):
    """Non-src rate limit with block duration uses string block table on sc2."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=10, window_seconds=60, rate_key="header",
                    rate_header="X-API-Key", duration_seconds=300,
                    action="tarpit")
    cfg = haproxy.generate_config(db)
    assert "backend block_table_str_" in cfg
    assert "track-sc2 req.hdr(X-API-Key) table block_table_str_" in cfg


def test_rate_limit_non_src_rl_rate_backend_stores(db):
    """rl_rate backend has http_req_rate store for basic/advanced non-src."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=60, rate_key="path")
    cfg = haproxy.generate_config(db)
    rl_backend_section = cfg.split("backend rl_rate_")[1].split("\n")[1] if "backend rl_rate_" in cfg else ""
    assert "http_req_rate(60s)" in rl_backend_section


def test_rate_limit_waf_non_src_rl_rate_backend_stores(db):
    """rl_rate backend has gpc0_rate store for waf-type non-src."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="waf",
                    waf_event_threshold=5, waf_window_seconds=60,
                    rate_key="path")
    cfg = haproxy.generate_config(db)
    assert "backend rl_rate_" in cfg
    rl_backend_section = cfg.split("backend rl_rate_")[1].split("\n")[1] if "backend rl_rate_" in cfg else ""
    assert "gpc0_rate(60s)" in rl_backend_section


def test_rate_limit_mixed_src_and_non_src(db):
    """Listener with both src and non-src basic rate limits: both sc0 and sc1 used."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    name="src-rl", events=100, window_seconds=60, rate_key="src")
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    name="path-rl", events=50, window_seconds=30, rate_key="path")
    cfg = haproxy.generate_config(db)
    # src RL uses sc0
    assert "sc_http_req_rate(0) gt 100" in cfg
    # non-src RL uses sc1
    assert "sc_http_req_rate(1) gt 50" in cfg
    assert "track-sc1 path table rl_rate_" in cfg
    # Frontend stick-table should still have http_req_rate for the src RL
    assert "http_req_rate(" in cfg


# ---------------------------------------------------------------------------
# WAF rule ASN rate key tests
# ---------------------------------------------------------------------------

def test_waf_rule_rate_key_asn_falls_back_to_src(db, monkeypatch):
    """WAF rule with rate_key=asn falls back to src when no ASN DB or map exists."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_key="asn")
    # Ensure no ASN lookup is available
    monkeypatch.setattr(haproxy, "_geoip_lua_module_available", lambda: False)
    monkeypatch.setattr(haproxy, "_haproxy_supports_geoip2", lambda: False)
    monkeypatch.setattr(haproxy.os.path, "exists", lambda p: False)
    cfg = haproxy.generate_config(db)
    # Should fall back to src — no sc1 tracking, no string table
    assert "track-sc1" not in cfg
    assert "backend waf_rate_" not in cfg


def test_waf_rule_rate_key_asn_with_map(db, monkeypatch, tmp_path):
    """WAF rule with rate_key=asn uses map_ip when ASN map file exists."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    asn_map = tmp_path / "asn.map"
    asn_map.write_text("1.0.0.0/8 AS123\n")
    make_waf_rule(db, name="waf", listener_id=listener.id,
                  rate_enabled=True, rate_events=10, rate_window_seconds=60,
                  rate_key="asn")
    monkeypatch.setattr(haproxy, "_geoip_lua_module_available", lambda: False)
    monkeypatch.setattr(haproxy, "_haproxy_supports_geoip2", lambda: False)
    monkeypatch.setattr(haproxy.settings, "GEOIP_ASN_MAP_PATH", str(asn_map))
    cfg = haproxy.generate_config(db)
    assert f"track-sc1 src,map_ip({asn_map}) table waf_rate_" in cfg
    assert "backend waf_rate_" in cfg


def test_rate_limit_basic_non_src_asn_with_map(db, monkeypatch, tmp_path):
    """RateLimit basic with rate_key=asn uses map_ip when ASN map file exists."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    asn_map = tmp_path / "asn.map"
    asn_map.write_text("1.0.0.0/8 AS123\n")
    make_rate_limit(db, listener_id=listener.id, limit_type="basic",
                    events=50, window_seconds=60, rate_key="asn")
    monkeypatch.setattr(haproxy, "_geoip_lua_module_available", lambda: False)
    monkeypatch.setattr(haproxy, "_haproxy_supports_geoip2", lambda: False)
    monkeypatch.setattr(haproxy.settings, "GEOIP_ASN_MAP_PATH", str(asn_map))
    cfg = haproxy.generate_config(db)
    assert f"track-sc1 src,map_ip({asn_map}) table rl_rate_" in cfg
    assert "sc_http_req_rate(1) gt 50" in cfg
