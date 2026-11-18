"""Tests for the editable Cap widget/WASM asset URLs and the 'service' source.

The widget script used to be frozen at a pinned jsDelivr URL. It is now a
DB-editable setting (env fallback), with an option to serve the assets from
the installed Cap instance via the /_cap service proxy (Cap standalone >=1.0.9
exposes /assets/widget.js and /assets/cap_wasm_bg.wasm).
"""

from app.core.config import get_settings
from app.services.captcha_providers import CapProvider, resolve_cap_widget_assets
from app.services.settings import set_setting


def _cfg():
    return get_settings()


def test_resolve_defaults_to_env_cdn_url(db):
    cfg = _cfg()
    widget_url, wasm_url = resolve_cap_widget_assets(cfg, db)
    assert widget_url == cfg.CAPTCHA_WIDGET_CDN_URL
    assert wasm_url == cfg.CAPTCHA_WIDGET_WASM_URL


def test_resolve_uses_db_url_overrides(db):
    set_setting(db, "cap_widget_cdn_url", "https://cdn.jsdelivr.net/npm/@cap.js/widget@0.2.0/cap.min.js")
    set_setting(db, "cap_widget_wasm_url", "/static/cap_wasm_bg.wasm")
    widget_url, wasm_url = resolve_cap_widget_assets(_cfg(), db)
    assert widget_url == "https://cdn.jsdelivr.net/npm/@cap.js/widget@0.2.0/cap.min.js"
    assert wasm_url == "/static/cap_wasm_bg.wasm"


def test_resolve_service_source_uses_cap_instance_paths(db):
    set_setting(db, "cap_widget_source", "service")
    # Custom URLs must be ignored in service mode.
    set_setting(db, "cap_widget_cdn_url", "https://example.com/custom.js")
    widget_url, wasm_url = resolve_cap_widget_assets(_cfg(), db)
    assert widget_url == "/_cap/assets/widget.js"
    assert wasm_url == "/_cap/assets/cap_wasm_bg.wasm"


def test_render_script_html_default(db):
    cfg = _cfg()
    html = CapProvider().render_script_html(cfg, db)
    assert f'src="{cfg.CAPTCHA_WIDGET_CDN_URL}"' in html
    assert f'window.CAP_CUSTOM_WASM_URL = "{cfg.CAPTCHA_WIDGET_WASM_URL}"' in html


def test_render_script_html_custom_url(db):
    set_setting(db, "cap_widget_cdn_url", "https://static.example.com/cap.js")
    html = CapProvider().render_script_html(_cfg(), db)
    assert 'src="https://static.example.com/cap.js"' in html


def test_render_script_html_service_source(db):
    set_setting(db, "cap_widget_source", "service")
    html = CapProvider().render_script_html(_cfg(), db)
    assert 'src="/_cap/assets/widget.js"' in html
    assert 'window.CAP_CUSTOM_WASM_URL = "/_cap/assets/cap_wasm_bg.wasm"' in html
    assert "cdn.jsdelivr" not in html


def test_render_script_html_escapes_url_chars(db):
    # URL validation normally rejects quotes, but the renderer must still
    # HTML-escape anything it embeds.
    set_setting(db, "cap_widget_cdn_url", "https://x.test/w.js?a=1&b=2")
    html = CapProvider().render_script_html(_cfg(), db)
    assert "a=1&amp;b=2" in html


def test_csp_includes_custom_remote_origin(db):
    set_setting(db, "cap_widget_cdn_url", "https://static.example.com/cap.js")
    csp = CapProvider().get_csp_directives(_cfg(), db)
    assert "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://static.example.com 'wasm-unsafe-eval'" in csp
    assert "connect-src 'self' https://cdn.jsdelivr.net https://static.example.com" in csp


def test_csp_service_source_same_origin(db):
    # Same-origin /_cap paths are covered by 'self' — no extra hosts.
    set_setting(db, "cap_widget_source", "service")
    csp = CapProvider().get_csp_directives(_cfg(), db)
    assert "_cap" not in csp
    assert "'self'" in csp


# ---------------------------------------------------------------------------
# Settings API
# ---------------------------------------------------------------------------


def test_settings_get_exposes_widget_fields(client):
    res = client.get("/api/v1/captcha/settings")
    assert res.status_code == 200
    data = res.json()
    assert data["cap_widget_source"] == "cdn"
    assert data["cap_widget_cdn_url"] == get_settings().CAPTCHA_WIDGET_CDN_URL
    assert data["cap_widget_wasm_url"] == get_settings().CAPTCHA_WIDGET_WASM_URL


def test_settings_update_widget_fields(client, db):
    res = client.put(
        "/api/v1/captcha/settings",
        json={
            "cap_widget_source": "service",
            "cap_widget_cdn_url": "https://cdn.jsdelivr.net/npm/@cap.js/widget@0.2.0/cap.min.js",
            "cap_widget_wasm_url": "/static/cap.wasm",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["cap_widget_source"] == "service"
    assert data["cap_widget_cdn_url"] == "https://cdn.jsdelivr.net/npm/@cap.js/widget@0.2.0/cap.min.js"
    assert data["cap_widget_wasm_url"] == "/static/cap.wasm"
    # And the renderer picks them up.
    widget_url, wasm_url = resolve_cap_widget_assets(get_settings(), db)
    assert widget_url == "/_cap/assets/widget.js"


def test_settings_update_widget_source_invalid(client):
    res = client.put("/api/v1/captcha/settings", json={"cap_widget_source": "bogus"})
    assert res.status_code == 400


def test_settings_update_widget_url_invalid(client):
    for bad in ("javascript:alert(1)", 'https://x.test/a"onclick=', "ftp://x/a.js", "not a url"):
        res = client.put("/api/v1/captcha/settings", json={"cap_widget_cdn_url": bad})
        assert res.status_code == 400, bad


def test_settings_update_widget_url_empty_resets_to_env(client):
    client.put("/api/v1/captcha/settings", json={"cap_widget_cdn_url": "https://x.test/cap.js"})
    res = client.put("/api/v1/captcha/settings", json={"cap_widget_cdn_url": ""})
    assert res.status_code == 200
    assert res.json()["cap_widget_cdn_url"] == get_settings().CAPTCHA_WIDGET_CDN_URL
