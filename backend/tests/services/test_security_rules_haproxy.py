"""Tests for security rules HAProxy emission."""
from app.services import haproxy
from app.services.security_rules import emit_security_rules, parse_expression, translate
from tests.factories import (
    make_backend,
    make_listener,
    make_rate_limit,
    make_security_rule,
    make_server,
    make_waf_rule,
)


def test_emit_security_rules_block(db):
    listener = make_listener(db)
    make_security_rule(db, name="block-wp", expression='http.request.uri.path = "/wp-login.php"', action="block")
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "http-request deny" in joined
    assert "deny_status 403" in joined
    assert "txn.sec.done" in joined


def test_emit_security_rules_allow(db):
    listener = make_listener(db)
    make_security_rule(db, name="allow-api", expression='http.host = "api.example.com"', action="allow")
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "txn.sec.done" in joined
    assert "deny" not in joined


def test_emit_security_rules_skip_waf(db):
    listener = make_listener(db)
    make_security_rule(db, name="skip-waf", expression='http.host = "safe.com"', action="skip_rules_waf")
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "txn.sec.skip_waf" in joined
    assert "txn.sec.done" in joined


def test_emit_security_rules_skip_ratelimit(db):
    listener = make_listener(db)
    make_security_rule(db, name="skip-rl", expression='http.host = "safe.com"', action="skip_rules_ratelimit")
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "txn.sec.skip_ratelimit" in joined
    assert "txn.sec.done" in joined


def test_emit_security_rules_skip_all(db):
    listener = make_listener(db)
    make_security_rule(db, name="skip-all", expression='http.host = "safe.com"', action="skip_all")
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "txn.sec.skip_waf" in joined
    assert "txn.sec.skip_ratelimit" in joined
    assert "txn.sec.done" in joined


def test_emit_security_rules_log(db):
    listener = make_listener(db)
    make_security_rule(db, name="log-rule", expression='http.host = "x"', action="block", log=True)
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "txn.sec.action" in joined
    assert "txn.action" in joined
    assert 'set-var(txn.action) str(block)' in joined
    assert "txn.sec.rule" in joined
    assert "log-rule" in joined
    assert "X-Security-Log" not in joined


def test_emit_security_rules_no_log(db):
    listener = make_listener(db)
    make_security_rule(db, name="silent-rule", expression='http.host = "x"', action="block", no_log=True)
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "set-log-level silent" in joined


def test_emit_security_rules_log_false(db):
    listener = make_listener(db)
    make_security_rule(db, name="quiet-rule", expression='http.host = "x"', action="block", log=False)
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "txn.sec.action" not in joined
    assert "txn.action" not in joined
    assert "txn.sec.rule" not in joined


def test_emit_security_rules_name_with_spaces(db):
    listener = make_listener(db)
    make_security_rule(db, name="block hosting providers", expression='http.host = "x"', action="block")
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert 'set-var(txn.sec.rule) str("block hosting providers")' in joined
    assert 'set-var(txn.sec.action) str(block)' in joined


def test_emit_security_rules_custom_status(db):
    listener = make_listener(db)
    make_security_rule(db, name="custom-status", expression='http.host = "x"', action="block", status_code=451)
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "deny_status 451" in joined


def test_emit_security_rules_first_match_guard(db):
    listener = make_listener(db)
    make_security_rule(db, name="r1", expression='http.host = "a"', action="block", priority=0)
    make_security_rule(db, name="r2", expression='http.host = "b"', action="block", priority=1)
    lines: list = []
    emit_security_rules(listener, db, lines)
    # Every rule should be guarded by !txn.sec.done
    assert all("!{ var(txn.sec.done) -m found }" in l for l in lines if "http-request" in l)


def test_emit_security_rules_listener_scoping(db):
    listener1 = make_listener(db, name="l1")
    listener2 = make_listener(db, name="l2")
    make_security_rule(db, name="scoped", expression='http.host = "x"', action="block", listener_ids=[listener1.id])
    lines1: list = []
    emit_security_rules(listener1, db, lines1)
    lines2: list = []
    emit_security_rules(listener2, db, lines2)
    assert len(lines1) > 0
    assert len(lines2) == 0


def test_emit_security_rules_disabled_skipped(db):
    listener = make_listener(db)
    make_security_rule(db, name="disabled", expression='http.host = "x"', action="block", enabled=False)
    lines: list = []
    emit_security_rules(listener, db, lines)
    assert len(lines) == 0


def test_generate_global_section_lua_load():
    """Global section should include JA4 Lua prerequisites before lua-load."""
    cfg = haproxy.generate_global_section()
    assert "lua-load /etc/haproxy/ja4.lua" in cfg
    assert "tune.lua.bool-sample-conversion normal" in cfg
    assert "tune.ssl.capture-buffer-size 336" in cfg
    # tune settings must come before lua-load
    assert cfg.index("tune.lua.bool-sample-conversion") < cfg.index("lua-load /etc/haproxy/ja4.lua")
    assert cfg.index("tune.ssl.capture-buffer-size") < cfg.index("lua-load /etc/haproxy/ja4.lua")
    # req_fp is now a Rust cdylib loaded via the combined modules.lua loader
    # (only when req_fp_enabled). The standalone lua-load line is removed.
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_generate_global_section_stick_counters():
    """Global section should set tune.stick-counters 4 for sc3 support."""
    cfg = haproxy.generate_global_section()
    assert "tune.stick-counters 4" in cfg


def test_generate_global_section_stick_counters_user_override():
    """User-supplied tune.stick-counters should override the default when >= 4."""
    cfg = haproxy.generate_global_section(
        global_options=[{"enabled": True, "directive": "tune.stick-counters", "value": "8"}]
    )
    assert "tune.stick-counters 8" in cfg
    assert "tune.stick-counters 4" not in cfg
    # req_fp is now a Rust cdylib, not loaded via standalone lua-load
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_generate_global_section_stick_counters_minimum_floor():
    """Values below 4 are clamped so sc3 support is never broken."""
    cfg = haproxy.generate_global_section(
        global_options=[{"enabled": True, "directive": "tune.stick-counters", "value": "2"}]
    )
    assert "tune.stick-counters 4" in cfg
    assert "tune.stick-counters 2" not in cfg


def test_generate_global_section_ja4_disabled():
    """With ja4_enabled=False, ja4 lua-load and tune directives should be absent."""
    cfg = haproxy.generate_global_section(ja4_enabled=False)
    assert "lua-load /etc/haproxy/ja4.lua" not in cfg
    assert "tune.ssl.capture-buffer-size" not in cfg
    # tune.lua.bool-sample-conversion is always emitted (before any lua-load)
    assert "tune.lua.bool-sample-conversion" in cfg
    # req_fp is now a Rust cdylib, not loaded via standalone lua-load
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_generate_global_section_nbthread_default(monkeypatch):
    """With no explicit nbthread, the default is based on CPU count."""
    monkeypatch.setattr(haproxy, "_default_nbthread", lambda: 4)
    cfg = haproxy.generate_global_section()
    assert "nbthread 4" in cfg


def test_generate_global_section_nbthread_user_tunable(monkeypatch):
    """A user-supplied nbthread option should override the CPU default."""
    monkeypatch.setattr(haproxy, "_default_nbthread", lambda: 4)
    cfg = haproxy.generate_global_section(
        global_options=[{"enabled": True, "directive": "nbthread", "value": "8"}]
    )
    assert "nbthread 8" in cfg
    assert "nbthread 4" not in cfg


def test_generate_global_section_nbthread_disabled_override(monkeypatch):
    """A disabled user nbthread option is ignored and CPU default is still applied."""
    monkeypatch.setattr(haproxy, "_default_nbthread", lambda: 4)
    cfg = haproxy.generate_global_section(
        global_options=[{"enabled": False, "directive": "nbthread", "value": "8"}]
    )
    assert "nbthread 4" in cfg
    assert "nbthread 8" not in cfg


def test_generate_global_section_multi_filter_bufsize():
    """When 3+ Lua response filters are active, tune.bufsize is automatically emitted."""
    cfg = haproxy.generate_global_section(
        compression_enabled=True,
        resp_transform_enabled=True,
        img_2_webp_enabled=True,
    )
    assert "tune.bufsize" in cfg


def test_generate_global_section_multi_filter_bufsize_two_filters():
    """With only 2 Lua response filters, tune.bufsize is not auto-emitted."""
    cfg = haproxy.generate_global_section(
        compression_enabled=True,
        resp_transform_enabled=True,
        img_2_webp_enabled=False,
    )
    assert "tune.bufsize" not in cfg


def test_generate_global_section_multi_filter_bufsize_user_override():
    """User-supplied tune.bufsize takes precedence over the multi-filter default."""
    cfg = haproxy.generate_global_section(
        compression_enabled=True,
        resp_transform_enabled=True,
        img_2_webp_enabled=True,
        global_options=[{"enabled": True, "directive": "tune.bufsize", "value": "131072"}],
    )
    assert "tune.bufsize 131072" in cfg
    # The auto-emitted default should not also appear
    assert cfg.count("tune.bufsize") == 1


def test_generate_global_section_multi_filter_bufsize_img2webp_wins():
    """IMG_2_WEBP_BUFSIZE takes precedence over the multi-filter default."""
    from app.core.config import get_settings
    s = get_settings()
    orig = s.IMG_2_WEBP_BUFSIZE
    try:
        s.IMG_2_WEBP_BUFSIZE = 131072
        cfg = haproxy.generate_global_section(
            compression_enabled=True,
            resp_transform_enabled=True,
            img_2_webp_enabled=True,
        )
        assert "tune.bufsize 131072" in cfg
        assert cfg.count("tune.bufsize") == 1
    finally:
        s.IMG_2_WEBP_BUFSIZE = orig


def test_generate_config_with_security_rule(db):
    """Full config generation with a security rule should include the rule lines."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_security_rule(db, name="block-wp", expression='http.request.uri.path = "/wp-login.php"', action="block")
    cfg = haproxy.generate_config(db)
    assert "txn.sec.done" in cfg
    assert 'http-request deny' in cfg
    assert 'wp-login.php' in cfg


def test_generate_config_rate_limit_gated_by_skip(db):
    """Rate limit deny lines should be gated by !skip_ratelimit."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_rate_limit(db, listener_id=listener.id, limit_type="basic", events=10)
    cfg = haproxy.generate_config(db)
    assert "!{ var(txn.sec.skip_ratelimit) -m found }" in cfg


def test_generate_config_waf_gated_by_skip(db):
    """WAF send-spoe-group should be gated by !skip_waf."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = haproxy.generate_config(db)
    assert "send-spoe-group coraza coraza-req if !{ var(txn.sec.skip_waf) -m found }" in cfg


def test_generate_config_emission_order(db):
    """Security rules should appear before rate-limit deny lines, which appear before WAF send-spoe-group."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_security_rule(db, name="sec", expression='http.host = "x"', action="block")
    make_rate_limit(db, listener_id=listener.id, limit_type="basic", events=10)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = haproxy.generate_config(db)

    # Find the indices of each phase's marker line
    sec_idx = cfg.find("txn.sec.done")
    rl_idx = cfg.find("sc_http_req_rate(0) gt")
    waf_idx = cfg.find("send-spoe-group coraza coraza-req")

    assert sec_idx >= 0, "Security rule lines not found"
    assert rl_idx >= 0, "Rate limit lines not found"
    assert waf_idx >= 0, "WAF lines not found"
    assert sec_idx < rl_idx, f"Security rules (idx {sec_idx}) should come before rate limit (idx {rl_idx})"
    assert rl_idx < waf_idx, f"Rate limit (idx {rl_idx}) should come before WAF (idx {waf_idx})"


def test_generate_config_lua_load_in_global(db):
    """Generated config should have lua-load in the global section."""
    backend = make_backend(db)
    make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "lua-load /etc/haproxy/ja4.lua" in cfg
    # req_fp is now a Rust cdylib loaded via combined modules.lua loader
    # (only when req_fp_enabled). The standalone lua-load line is removed.
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_generate_frontend_req_fp_disabled(db):
    """With req_fp_enabled=False (default), neither req_fp directive should be present."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_frontend(listener, db, req_fp_enabled=False)
    assert "http-request lua.req_fp_capture" not in cfg
    assert "http-response lua.req_fp" not in cfg


def test_generate_frontend_req_fp_enabled(db):
    """With req_fp_enabled=True, both req_fp directives should be emitted."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    cfg = haproxy.generate_frontend(listener, db, req_fp_enabled=True)
    assert "http-request lua.req_fp_capture" in cfg
    assert "http-response lua.req_fp" in cfg


def test_generate_frontend_req_fp_before_response_headers(db):
    """lua.req_fp must run before any http-response set-header so txn.req_fp is populated."""
    from app.models.models import ResponseHeader
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    hdr = ResponseHeader(name="req-fp", header="X-Req-FP", value="%[var(txn.req_fp)]", action="set", listener_ids=[])
    db.add(hdr)
    db.commit()
    cfg = haproxy.generate_frontend(listener, db, req_fp_enabled=True)
    lua_idx = cfg.find("http-response lua.req_fp")
    hdr_idx = cfg.find("http-response set-header X-Req-FP")
    assert lua_idx >= 0, "lua.req_fp line not found"
    assert hdr_idx >= 0, "set-header X-Req-FP line not found"
    assert lua_idx < hdr_idx, "lua.req_fp must come before set-header that references txn.req_fp"


def test_response_headers_guarded_against_varnish_fetch(db):
    """Response header rules must carry !{ var(txn.is_varnish_fetch) -m found }
    so they don't fire twice when Varnish fetches through HAProxy (once on the
    origin→Varnish fetch, once on the Varnish→client delivery). Uses the txn
    var (set during the request phase in generate_frontend) because req.hdr_cnt
    is incompatible with http-response rules in HAProxy 3.4+."""
    from app.models.models import ResponseHeader
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    # set-header with no user condition
    db.add(ResponseHeader(name="set-nocond", header="X-Custom-Set", value="value1", action="set", listener_ids=[]))
    # add-header with no user condition (the one that produces duplicate values)
    db.add(ResponseHeader(name="add-nocond", header="X-Custom-Add", value="value2", action="add", listener_ids=[]))
    # set-header with a user condition
    db.add(ResponseHeader(name="set-cond", header="X-Custom-Cond", value="value3", action="set", listener_ids=[], condition="{ status 200 }"))
    # del-header with no user condition (value column is NOT NULL but unused for del)
    db.add(ResponseHeader(name="del-nocond", header="X-Custom-Del", value="unused", action="del", listener_ids=[]))
    db.commit()
    cfg = haproxy.generate_frontend(listener, db)
    # All response header rules should be guarded with !{ var(txn.is_varnish_fetch) -m found }
    assert 'http-response set-header X-Custom-Set "value1" if !{ var(txn.is_varnish_fetch) -m found }' in cfg
    assert 'http-response add-header X-Custom-Add "value2" if !{ var(txn.is_varnish_fetch) -m found }' in cfg
    assert 'http-response set-header X-Custom-Cond "value3" if { status 200 } !{ var(txn.is_varnish_fetch) -m found }' in cfg
    assert "http-response del-header X-Custom-Del if !{ var(txn.is_varnish_fetch) -m found }" in cfg


def test_alt_svc_guarded_against_varnish_fetch(db):
    """Alt-Svc response header must carry !is_varnish_fetch so it's not baked
    into Varnish cache objects and duplicated on cache-hit delivery."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend, name="quic_in", bind_port=443, ssl_enabled=True)
    listener.quic = True
    db.commit()
    make_server(db, backend.id)
    cfg = haproxy.generate_frontend(listener, db)
    assert "http-response set-header Alt-Svc" in cfg
    assert "!{ var(txn.is_varnish_fetch) -m found }" in cfg


def test_csp_guarded_against_varnish_fetch(db):
    """CSP response header (Page Protect) must carry a
    !{ var(txn.is_varnish_fetch) -m found } guard so it's not baked into Varnish
    cache objects. Uses the txn var (set during the request phase in
    generate_frontend) because req.hdr_cnt is incompatible with http-response
    rules in HAProxy 3.4+."""
    from tests.factories import make_page_protect_policy
    backend = make_backend(db, name="protected_be")
    make_server(db, backend.id)
    make_page_protect_policy(db, backend_ids=[backend.id], mode="enforce", directives={"default-src": ["'self'"]})
    db.commit()
    cfg = haproxy.generate_backend(backend, db, page_protect_enabled=True)
    assert "http-response set-header Content-Security-Policy" in cfg
    assert "!{ var(txn.is_varnish_fetch) -m found }" in cfg


def test_generate_config_req_fp_via_setting(db):
    """generate_config should emit both req_fp directives when the req_fp_enabled setting is true."""
    from app.services.settings import set_setting
    backend = make_backend(db)
    make_listener(db, backend=backend)
    make_server(db, backend.id)
    set_setting(db, "req_fp_enabled", "true")
    cfg = haproxy.generate_config(db)
    assert "http-request lua.req_fp_capture" in cfg
    assert "http-response lua.req_fp" in cfg


def test_generate_config_ja4_disabled_via_setting(db):
    """generate_config should omit ja4 lua-load when the ja4_enabled setting is false."""
    from app.services.settings import set_setting
    backend = make_backend(db)
    make_listener(db, backend=backend)
    make_server(db, backend.id)
    set_setting(db, "ja4_enabled", "false")
    cfg = haproxy.generate_config(db)
    assert "lua-load /etc/haproxy/ja4.lua" not in cfg
    # req_fp is now a Rust cdylib, not loaded via standalone lua-load
    assert "lua-load /etc/haproxy/req_fp.lua" not in cfg


def test_emit_security_rules_redirect(db):
    listener = make_listener(db)
    make_security_rule(
        db, name="redirect-rule", expression='http.host = "bad.com"',
        action="redirect", redirect_url="https://example.com/blocked", redirect_code=301,
    )
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "http-request redirect location https://example.com/blocked code 301" in joined
    assert "txn.sec.done" in joined


def test_emit_security_rules_redirect_default_code(db):
    listener = make_listener(db)
    make_security_rule(
        db, name="redirect-default", expression='http.host = "bad.com"',
        action="redirect", redirect_url="/blocked",
    )
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "code 302" in joined


def test_emit_security_rules_custom_response(db):
    from app.models.models import CustomErrorPage
    listener = make_listener(db)
    ep = CustomErrorPage(code=403, content_type="text/html", content="<h1>Blocked</h1>")
    db.add(ep)
    db.flush()
    make_security_rule(
        db, name="custom-response", expression='http.host = "bad.com"',
        action="custom_response", status_code=403, error_page_id=ep.id,
    )
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    assert "http-request return status 403" in joined
    assert "lf-file" in joined
    assert "txn.sec.done" in joined


def test_emit_security_rules_custom_response_no_page_falls_back(db):
    listener = make_listener(db)
    make_security_rule(
        db, name="custom-no-page", expression='http.host = "bad.com"',
        action="custom_response", status_code=451,
    )
    lines: list = []
    emit_security_rules(listener, db, lines)
    joined = "\n".join(lines)
    # Falls back to deny with status code
    assert "http-request deny deny_status 451" in joined


def test_generate_config_with_redirect_rule(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_security_rule(
        db, name="redirect-rule", expression='http.host = "bad.com"',
        action="redirect", redirect_url="https://example.com/safe", redirect_code=301,
    )
    cfg = haproxy.generate_config(db)
    assert "http-request redirect location https://example.com/safe code 301" in cfg


def test_generate_config_with_custom_response_rule(db):
    from app.models.models import CustomErrorPage
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    ep = CustomErrorPage(code=418, content_type="text/html", content="<h1>Teapot</h1>")
    db.add(ep)
    db.flush()
    make_security_rule(
        db, name="teapot-rule", expression='http.host = "teapot.com"',
        action="custom_response", status_code=418, error_page_id=ep.id,
    )
    cfg = haproxy.generate_config(db)
    assert "http-request return status 418" in cfg
    assert "lf-file" in cfg


# --- GeoIP tests -----------------------------------------------------------
#
# Three tiers of GeoIP lookup:
#   1. Rust Lua module (primary) — lua.geoip2-lookup-city/asn converters
#   2. Native geoip2 converter — when HAProxy is built with geoip2
#   3. map_ip fallback files — country/ASN only (legacy last resort)
#
# The existing tests below cover tiers 2 and 3 (Lua module disabled).
# New tests at the end cover tier 1 (Lua module enabled).


def _patch_geoip2(monkeypatch, supported: bool):
    """Patch _haproxy_supports_geoip2 to a fixed boolean and clear its cache.
    Also disables the Rust Lua module so the geoip2/map_ip paths are tested."""
    from app.services import haproxy as haproxy_mod

    monkeypatch.setattr(haproxy_mod, "_geoip2_support_cache", supported)
    monkeypatch.setattr(haproxy_mod, "_haproxy_supports_geoip2", lambda: supported)
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "GEOIP_LUA_MODULE_ENABLED", False)


def test_translate_geoip_country_uses_geoip2_when_supported(db, tmp_path, monkeypatch):
    _patch_geoip2(monkeypatch, True)
    from app.core.config import get_settings

    s = get_settings()
    mmdb = tmp_path / "GeoLite2-Country.mmdb"
    mmdb.write_bytes(b"")  # placeholder; only existence is checked
    monkeypatch.setattr(s, "GEOIP_DB_PATH", str(mmdb))
    cond, phase = translate(parse_expression('ip.geoip.country = "US"'), db)
    assert "geoip2(" in cond
    assert "country.iso_code" in cond
    assert "map_ip" not in cond
    assert phase == "request"


def test_translate_geoip_country_falls_back_to_map_ip(db, tmp_path, monkeypatch):
    _patch_geoip2(monkeypatch, False)
    from app.core.config import get_settings

    s = get_settings()
    country_map = tmp_path / "geo_country.map"
    country_map.write_text("")
    monkeypatch.setattr(s, "GEOIP_COUNTRY_MAP_PATH", str(country_map))
    cond, _ = translate(parse_expression('ip.geoip.country = "US"'), db)
    assert "src,map_ip(" in cond
    assert "geo_country.map" in cond
    assert "geoip2" not in cond
    assert "-m str US" in cond


def test_translate_geoip_asn_falls_back_to_map_ip(db, tmp_path, monkeypatch):
    _patch_geoip2(monkeypatch, False)
    from app.core.config import get_settings

    s = get_settings()
    asn_map = tmp_path / "geo_asn.map"
    asn_map.write_text("")
    monkeypatch.setattr(s, "GEOIP_ASN_MAP_PATH", str(asn_map))
    cond, _ = translate(parse_expression('ip.geoip.asnum = "AS12345"'), db)
    assert "src,map_ip(" in cond
    assert "geo_asn.map" in cond
    assert "geoip2" not in cond
    assert "-m str AS12345" in cond


def test_translate_geoip_city_raises_without_geoip2(db, monkeypatch):
    _patch_geoip2(monkeypatch, False)
    from app.services.security_rules import validate_expression

    ok, _ast, err = validate_expression('ip.geoip.city = "Berlin"', db)
    assert ok is False
    assert err is not None
    assert "geoip2" in err


def test_translate_geoip_country_in_list_falls_back(db, tmp_path, monkeypatch):
    """A geo-list reference against ip.geoip.country should use map_ip + -f."""
    _patch_geoip2(monkeypatch, False)
    from app.core.config import get_settings
    from app.models.models import GeoList, GeoListEntry
    from app.services.security_lists import write_security_list_files

    s = get_settings()
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    monkeypatch.setattr(s, "SECURITY_LISTS_DIR", str(lists_dir))
    country_map = tmp_path / "geo_country.map"
    country_map.write_text("")
    monkeypatch.setattr(s, "GEOIP_COUNTRY_MAP_PATH", str(country_map))

    gl = GeoList(name="blocked-countries")
    db.add(gl)
    db.flush()
    db.add(GeoListEntry(list_id=gl.id, value="US"))
    db.commit()
    write_security_list_files(db)

    cond, _ = translate(parse_expression("ip.geoip.country in $geo:blocked-countries"), db)
    assert "src,map_ip(" in cond
    assert "-f " in cond
    assert "blocked-countries.lst" in cond
    assert "geoip2" not in cond


def test_default_json_log_format_map_ip_fallback(tmp_path, monkeypatch):
    """Log enrichment should use map_ip when geoip2 is unavailable + maps exist."""
    _patch_geoip2(monkeypatch, False)
    from app.core.config import get_settings

    s = get_settings()
    country_map = tmp_path / "geo_country.map"
    asn_map = tmp_path / "geo_asn.map"
    country_map.write_text("")
    asn_map.write_text("")
    monkeypatch.setattr(s, "GEOIP_COUNTRY_MAP_PATH", str(country_map))
    monkeypatch.setattr(s, "GEOIP_ASN_MAP_PATH", str(asn_map))

    fmt = haproxy._default_json_log_format(ja4_enabled=False)
    assert '"country":"%[src,map_ip(' in fmt
    assert '"asn":"%[src,map_ip(' in fmt
    assert "geoip2" not in fmt


def test_default_json_log_format_geoip2_when_supported(tmp_path, monkeypatch):
    """Log enrichment should use geoip2 when supported + .mmdb files exist."""
    _patch_geoip2(monkeypatch, True)
    from app.core.config import get_settings

    s = get_settings()
    country_mmdb = tmp_path / "GeoLite2-Country.mmdb"
    asn_mmdb = tmp_path / "GeoLite2-ASN.mmdb"
    country_mmdb.write_bytes(b"")
    asn_mmdb.write_bytes(b"")
    monkeypatch.setattr(s, "GEOIP_DB_PATH", str(country_mmdb))
    monkeypatch.setattr(s, "ASN_DB_PATH", str(asn_mmdb))

    fmt = haproxy._default_json_log_format(ja4_enabled=False)
    assert "geoip2(" in fmt
    assert "country.iso_code" in fmt
    assert "autonomous_system_number" in fmt
    assert "map_ip" not in fmt


def test_default_json_log_format_omits_country_when_no_geoip2_and_no_map(tmp_path, monkeypatch):
    """Without geoip2 and without map files, country/asn fields are omitted."""
    _patch_geoip2(monkeypatch, False)
    from app.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "GEOIP_COUNTRY_MAP_PATH", str(tmp_path / "missing-country.map"))
    monkeypatch.setattr(s, "GEOIP_ASN_MAP_PATH", str(tmp_path / "missing-asn.map"))

    fmt = haproxy._default_json_log_format(ja4_enabled=False)
    assert "country" not in fmt
    assert '"asn"' not in fmt
    assert "geoip2" not in fmt
    assert "map_ip" not in fmt


def test_default_json_log_format_includes_user_agent():
    """The default JSON log-format should capture the request User-Agent header.

    The value references capture.req.hdr(1) (the second http-request capture
    slot — Host is slot 0) because req.hdr() is not reliably available at
    log time. The json converter escapes quotes/special characters in the
    UA so they don't break the emitted JSON log line.
    """
    fmt = haproxy._default_json_log_format(ja4_enabled=False)
    assert '"user_agent":"%[capture.req.hdr(1),json]"' in fmt


def test_default_json_log_format_combined_action_field():
    """The default JSON log-format should use a single combined 'action' field
    instead of separate sec_action/rl_action/waf_action fields.
    """
    fmt = haproxy._default_json_log_format(ja4_enabled=False)
    assert '"action":"%[var(txn.action)]"' in fmt
    assert "sec_action" not in fmt
    assert "rl_action" not in fmt
    assert "waf_action" not in fmt


def test_global_options_change_detected_by_config_status(db, monkeypatch, tmp_path):
    """Saving advanced HAProxy global options should make get_config_status detect unapplied changes.

    Regression: the "unapplied changes" banner was not appearing after saving
    advanced HAProxy options because the config status check was not comparing
    the generated config (which reads haproxy_global_options from DB) against
    the .applied snapshot on disk.
    """
    import json
    import os
    from app.core.config import get_settings
    from app.services.settings import set_setting
    from app.services.config import get_config_status, get_config_diff

    s = get_settings()
    # Redirect config paths to temp dir so we control the .applied files and
    # don't pick up real on-disk state from data/.
    cfg_path = str(tmp_path / "haproxy.cfg")
    monkeypatch.setattr(s, "HAPROXY_CONFIG_PATH", cfg_path)
    monkeypatch.setattr(s, "CORAZA_SPOA_ENABLED", False)
    # Isolate security-list and resp-transform dirs (empty → no files to compare).
    monkeypatch.setattr(s, "SECURITY_LISTS_DIR", str(tmp_path / "lists"))
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(tmp_path / "resp-transform"))

    # 1. Generate baseline config with NO global options and write .applied
    baseline = haproxy.generate_config(db)
    with open(cfg_path, "w") as f:
        f.write(baseline)
    with open(f"{cfg_path}.applied", "w") as f:
        f.write(baseline)

    # Baseline the risk_rules_data.lua file too — _config_status_data compares
    # it, so without an .applied snapshot it would falsely report unapplied.
    try:
        from app.services.risk_scoring import generate_risk_rules_data, _risk_rules_data_path
        rrd_path = _risk_rules_data_path()
        rrd = generate_risk_rules_data(db)
        os.makedirs(os.path.dirname(rrd_path), exist_ok=True)
        with open(rrd_path, "w") as f:
            f.write(rrd)
        with open(f"{rrd_path}.applied", "w") as f:
            f.write(rrd)
    except Exception:
        pass  # risk scoring not configured — skip

    # Baseline resp-transform files — _config_status_data always generates
    # query_detokenize.json, so without an .applied snapshot it would falsely
    # report unapplied.
    try:
        from app.services.resp_transform import generate_resp_transform_file_contents
        rt_dir = str(tmp_path / "resp-transform")
        os.makedirs(rt_dir, exist_ok=True)
        rt_gen = generate_resp_transform_file_contents(db)
        for fname, content in rt_gen.items():
            fpath = os.path.join(rt_dir, fname)
            with open(fpath, "w") as f:
                f.write(content)
            with open(f"{fpath}.applied", "w") as f:
                f.write(content)
    except Exception:
        pass  # resp transform not configured — skip

    # 2. Status should be False (no changes)
    assert get_config_status(db) is False

    # 3. Save global options (same shape as the frontend PUT)
    set_setting(db, "haproxy_global_options", json.dumps([
        {"target": "section", "directive": "tune.ssl.lifetime", "value": "16834", "enabled": True},
        {"target": "section", "directive": "tune.stick-counters", "value": "4", "enabled": False},
        {"target": "section", "directive": "tune.h2.initial-window-size", "value": "10485760", "enabled": True},
    ]))
    db.commit()

    # 4. Status should now be True (unapplied changes detected)
    assert get_config_status(db) is True

    # 5. Diff should include the new options
    diff_result = get_config_diff(db)
    assert diff_result["unapplied"] is True
    assert "tune.ssl.lifetime 16834" in diff_result["diff"]
    assert "tune.h2.initial-window-size 10485760" in diff_result["diff"]


# --- GeoIP Rust Lua module tests (tier 1 — primary) ------------------------


def _patch_geoip_lua(monkeypatch, enabled: bool = True):
    """Enable the Rust Lua module and create placeholder MMDB files."""
    from app.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "GEOIP_LUA_MODULE_ENABLED", enabled)


def _create_mmdb_files(tmp_path, monkeypatch):
    """Create placeholder City + ASN MMDB files and patch settings paths."""
    from app.core.config import get_settings

    s = get_settings()
    city_mmdb = tmp_path / "GeoLite2-City.mmdb"
    asn_mmdb = tmp_path / "GeoLite2-ASN.mmdb"
    city_mmdb.write_bytes(b"")
    asn_mmdb.write_bytes(b"")
    monkeypatch.setattr(s, "GEOIP_CITY_DB_PATH", str(city_mmdb))
    monkeypatch.setattr(s, "ASN_DB_PATH", str(asn_mmdb))
    return s


def test_translate_geoip_country_uses_lua_module(db, tmp_path, monkeypatch):
    """With the Lua module enabled, country uses lua.geoip2-lookup-city."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)
    cond, phase = translate(parse_expression('ip.geoip.country = "US"'), db)
    assert 'lua.geoip2-lookup-city("country","iso_code")' in cond
    assert "geoip2(" not in cond  # native geoip2 not used
    assert "map_ip" not in cond
    assert "-m str US" in cond
    assert phase == "request"


def test_translate_geoip_asn_uses_lua_module(db, tmp_path, monkeypatch):
    """With the Lua module enabled, ASN uses lua.geoip2-lookup-asn."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)
    cond, _ = translate(parse_expression('ip.geoip.asnum = "AS12345"'), db)
    assert 'lua.geoip2-lookup-asn("autonomous_system_number")' in cond
    assert "geoip2(" not in cond
    assert "map_ip" not in cond
    assert "-m str AS12345" in cond


def test_translate_geoip_city_uses_lua_module(db, tmp_path, monkeypatch):
    """With the Lua module enabled, city uses lua.geoip2-lookup-city."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)
    cond, _ = translate(parse_expression('ip.geoip.city = "Berlin"'), db)
    assert 'lua.geoip2-lookup-city("city","names","en")' in cond
    assert "geoip2(" not in cond


def test_translate_geoip_all_fields_lua(db, tmp_path, monkeypatch):
    """All 9 geoip fields should produce Lua converter calls when enabled."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)
    test_cases = [
        ('ip.geoip.country = "US"', "lua.geoip2-lookup-city"),
        ('ip.geoip.asnum = "AS12345"', "lua.geoip2-lookup-asn"),
        ('ip.geoip.continent = "EU"', "lua.geoip2-lookup-city"),
        ('ip.geoip.city = "Berlin"', "lua.geoip2-lookup-city"),
        ('ip.geoip.region = "CA"', "lua.geoip2-lookup-city"),
        ('ip.geoip.postal_code = "12345"', "lua.geoip2-lookup-city"),
        ('ip.geoip.timezone = "America/Los_Angeles"', "lua.geoip2-lookup-city"),
        ("ip.geoip.latitude = 37", "lua.geoip2-lookup-city"),
        ("ip.geoip.longitude = -122", "lua.geoip2-lookup-city"),
    ]
    for expr, expected_converter in test_cases:
        cond, _ = translate(parse_expression(expr), db)
        assert expected_converter in cond, f"Expression {expr!r} did not produce {expected_converter}: {cond}"


def test_translate_geoip_country_in_list_uses_lua(db, tmp_path, monkeypatch):
    """A geo-list reference with the Lua module should use the Lua converter + -f."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)
    from app.core.config import get_settings
    from app.models.models import GeoList, GeoListEntry
    from app.services.security_lists import write_security_list_files

    s = get_settings()
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    monkeypatch.setattr(s, "SECURITY_LISTS_DIR", str(lists_dir))

    gl = GeoList(name="blocked-countries")
    db.add(gl)
    db.flush()
    db.add(GeoListEntry(list_id=gl.id, value="US"))
    db.commit()
    write_security_list_files(db)

    cond, _ = translate(parse_expression("ip.geoip.country in $geo:blocked-countries"), db)
    assert "lua.geoip2-lookup-city" in cond
    assert "-f " in cond
    assert "blocked-countries.lst" in cond


def test_translate_geoip_falls_back_to_geoip2_when_lua_disabled(db, tmp_path, monkeypatch):
    """With the Lua module disabled, country uses native geoip2 when supported."""
    _patch_geoip2(monkeypatch, True)
    from app.core.config import get_settings

    s = get_settings()
    mmdb = tmp_path / "GeoLite2-Country.mmdb"
    mmdb.write_bytes(b"")
    monkeypatch.setattr(s, "GEOIP_DB_PATH", str(mmdb))
    cond, _ = translate(parse_expression('ip.geoip.country = "US"'), db)
    assert "geoip2(" in cond
    assert "lua.geoip2-lookup" not in cond


def test_default_json_log_format_lua_module(tmp_path, monkeypatch):
    """Log enrichment should use Lua converters when the module is enabled."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)

    fmt = haproxy._default_json_log_format(ja4_enabled=False)
    assert 'lua.geoip2-lookup-city' in fmt
    assert 'lua.geoip2-lookup-asn' in fmt
    assert '"country"' in fmt
    assert '"asn"' in fmt
    assert '"city"' in fmt
    assert "geoip2(" not in fmt  # native geoip2 not used
    assert "map_ip" not in fmt


def test_generate_geoip2_loader_content(tmp_path, monkeypatch):
    """The generated geoip2.lua loader should contain current DB paths + interval."""
    from app.core.config import get_settings

    s = get_settings()
    city_path = tmp_path / "GeoLite2-City.mmdb"
    asn_path = tmp_path / "GeoLite2-ASN.mmdb"
    city_path.write_bytes(b"")
    asn_path.write_bytes(b"")
    monkeypatch.setattr(s, "GEOIP_CITY_DB_PATH", str(city_path))
    monkeypatch.setattr(s, "ASN_DB_PATH", str(asn_path))
    monkeypatch.setattr(s, "GEOIP_LUA_RELOAD_INTERVAL_SECONDS", 7200)

    loader = haproxy._generate_geoip2_loader()
    assert 'require("haproxy_geoip2_module")' in loader
    assert "geoip2.register" in loader
    assert str(city_path) in loader
    assert str(asn_path) in loader
    assert "reload_interval = 7200" in loader


def test_generate_global_section_lua_module(tmp_path, monkeypatch):
    """Global section should emit lua-load-per-thread when the Lua module is enabled."""
    _patch_geoip_lua(monkeypatch, True)
    _create_mmdb_files(tmp_path, monkeypatch)
    # Point HAPROXY_CONFIG_PATH at tmp_path so the loader is written there
    from app.core.config import get_settings
    s = get_settings()
    cfg_path = tmp_path / "haproxy.cfg"
    monkeypatch.setattr(s, "HAPROXY_CONFIG_PATH", str(cfg_path))

    cfg = haproxy.generate_global_section()
    assert "lua-load-per-thread" in cfg
    assert "lua-prepend-path /etc/haproxy/?.so cpath" in cfg
    assert "insecure-fork-wanted" in cfg
    # The combined loader file should have been written
    assert (tmp_path / "modules.lua").exists()
