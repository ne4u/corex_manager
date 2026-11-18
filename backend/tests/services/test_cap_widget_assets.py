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


# ---------------------------------------------------------------------------
# Cap assets detection endpoint (suggest CDN URLs from the installed instance)
# ---------------------------------------------------------------------------


class _FakeRes:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = b"{}" if payload is not None else b""
        self.text = ""

    def json(self):
        return self._payload


def _patch_cap_api(monkeypatch, routes):
    async def fake_call(method, path, json_body=None):
        return routes.get(path, _FakeRes(404))

    monkeypatch.setattr("app.api.v1.captcha._cap_api_call", fake_call)


def _patch_probe(monkeypatch, status=None):
    """Stub the live /assets/widget.js probe. status=None = unreachable."""

    import httpx as _httpx

    class _FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, timeout=6):
            if status is None:
                raise ConnectionError("no route")
            return _FakeRes(status)

    monkeypatch.setattr(_httpx, "AsyncClient", _FakeClient)


def _patch_valkey(monkeypatch, store):
    """Give the endpoint a fake shared-Valkey view (Cap's asset:* keys)."""

    class _FakeCli:
        def get(self, key):
            return store.get(key)

        def exists(self, key):
            return key in store

    monkeypatch.setattr("app.core.valkey_client._get_client", lambda: _FakeCli())


def test_cap_assets_endpoint_suggests_versioned_urls(client, monkeypatch):
    _patch_cap_api(
        monkeypatch,
        {
            "/settings/assets": _FakeRes(
                200,
                {
                    "enabled": True,
                    "widget": "0.1.58",
                    "wasm": "0.0.8",
                    "builtWith": {"widget": "0.1.57", "wasm": "0.0.7"},
                },
            ),
            "/about": _FakeRes(200, {"ver": "4.0.15"}),
        },
    )
    _patch_probe(monkeypatch, 200)
    _patch_valkey(monkeypatch, {})
    res = client.get("/api/v1/captcha/cap-assets")
    assert res.status_code == 200
    d = res.json()
    assert d["available"] is True
    assert d["enabled"] is True
    assert d["cap_version"] == "4.0.15"
    assert d["widget_version"] == "0.1.58"
    assert d["wasm_version"] == "0.0.8"
    assert d["suggested_widget_url"] == "https://cdn.jsdelivr.net/npm/@cap.js/widget@0.1.58/cap.min.js"
    assert d["suggested_wasm_url"] == "https://cdn.jsdelivr.net/npm/@cap.js/wasm@0.0.8/browser/cap_wasm_bg.wasm"


def test_cap_assets_endpoint_falls_back_to_built_with(client, monkeypatch):
    _patch_cap_api(
        monkeypatch,
        {
            "/settings/assets": _FakeRes(
                200, {"enabled": False, "builtWith": {"widget": "0.1.60", "wasm": "0.0.9"}}
            ),
            "/about": _FakeRes(404),
        },
    )
    _patch_probe(monkeypatch, 404)
    _patch_valkey(monkeypatch, {})
    d = client.get("/api/v1/captcha/cap-assets").json()
    assert d["available"] is True
    assert d["enabled"] is False
    assert d["suggested_widget_url"].endswith("widget@0.1.60/cap.min.js")
    assert d["suggested_wasm_url"].endswith("wasm@0.0.9/browser/cap_wasm_bg.wasm")


def test_cap_assets_endpoint_unsupported_instance(client, monkeypatch):
    # Older cap-standalone without the assets server: no API, no cached
    # Valkey keys, and the /assets probe 404s — still counts as "detected"
    # (service reachable, just disabled).
    _patch_cap_api(monkeypatch, {})
    _patch_probe(monkeypatch, 404)
    _patch_valkey(monkeypatch, {})
    d = client.get("/api/v1/captcha/cap-assets").json()
    assert d["available"] is True
    assert d["enabled"] is False
    assert d["suggested_widget_url"].endswith("widget@latest/cap.min.js")


def test_cap_assets_endpoint_no_info_at_all(client, monkeypatch):
    # Nothing answered — no API, no Valkey keys, no probe response.
    _patch_cap_api(monkeypatch, {})
    _patch_probe(monkeypatch, None)
    _patch_valkey(monkeypatch, {})
    d = client.get("/api/v1/captcha/cap-assets").json()
    assert d["available"] is False
    assert d["error"]


def test_cap_assets_endpoint_valkey_fallback(client, monkeypatch):
    # cap-standalone has no /settings/assets, but both standalone and capd
    # write asset:cache-config into the shared Valkey.
    import json as _json

    _patch_cap_api(monkeypatch, {})
    _patch_valkey(
        monkeypatch,
        {
            "asset:cache-config": _json.dumps(
                {"versions": {"widget": "0.1.58", "wasm": "0.0.8"}, "lastUpdate": 1}
            ),
            "asset:widget.js": "(()=>{})",
        },
    )
    _patch_probe(monkeypatch, 200)
    d = client.get("/api/v1/captcha/cap-assets").json()
    assert d["available"] is True
    assert d["enabled"] is True
    assert d["widget_version"] == "0.1.58"
    assert d["wasm_version"] == "0.0.8"
    assert d["suggested_widget_url"].endswith("widget@0.1.58/cap.min.js")


def test_cap_assets_endpoint_unreachable(client, monkeypatch):
    async def boom(method, path, json_body=None):
        raise ConnectionError("refused")

    monkeypatch.setattr("app.api.v1.captcha._cap_api_call", boom)
    _patch_probe(monkeypatch, None)
    _patch_valkey(monkeypatch, {})
    d = client.get("/api/v1/captcha/cap-assets").json()
    assert d["available"] is False
    assert "unreachable" in d["error"]


# ---------------------------------------------------------------------------
# Asset existence validation endpoint
# ---------------------------------------------------------------------------


def test_validate_assets_uses_form_urls(client, monkeypatch):
    from app.api.v1.captcha import CapAssetCheck

    seen = []

    async def fake_probe(name, url, cap_path):
        seen.append((name, url))
        return CapAssetCheck(name=name, url=url, ok=True, status=200)

    monkeypatch.setattr("app.api.v1.captcha._probe_asset_url", fake_probe)
    res = client.post(
        "/api/v1/captcha/validate-assets",
        json={
            "cap_widget_source": "cdn",
            "cap_widget_cdn_url": "https://x.test/cap.js",
            "cap_widget_wasm_url": "https://x.test/cap.wasm",
        },
    )
    assert res.status_code == 200
    assert res.json()["ok"] is True
    assert ("widget", "https://x.test/cap.js") in seen
    assert ("wasm", "https://x.test/cap.wasm") in seen


def test_validate_assets_service_mode_checks_cap_paths(client, monkeypatch):
    from app.api.v1.captcha import CapAssetCheck

    seen = []

    async def fake_probe(name, url, cap_path):
        seen.append(url)
        return CapAssetCheck(name=name, url=url, ok=False, status=404)

    monkeypatch.setattr("app.api.v1.captcha._probe_asset_url", fake_probe)
    res = client.post("/api/v1/captcha/validate-assets", json={"cap_widget_source": "service"})
    assert "/_cap/assets/widget.js" in seen
    assert "/_cap/assets/cap_wasm_bg.wasm" in seen
    assert res.json()["ok"] is False


def test_validate_assets_empty_input_falls_back_to_defaults(client, monkeypatch):
    from app.api.v1.captcha import CapAssetCheck

    seen = []

    async def fake_probe(name, url, cap_path):
        seen.append(url)
        return CapAssetCheck(name=name, url=url, ok=True, status=200)

    monkeypatch.setattr("app.api.v1.captcha._probe_asset_url", fake_probe)
    client.post("/api/v1/captcha/validate-assets", json={"cap_widget_source": "cdn", "cap_widget_cdn_url": ""})
    assert get_settings().CAPTCHA_WIDGET_CDN_URL in seen


def test_probe_maps_cap_path_to_service_url(monkeypatch):
    import asyncio
    import httpx as _httpx
    from app.api.v1.captcha import _probe_asset_url

    targets = []

    class _Resp:
        status_code = 200

    class _FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def head(self, url, timeout=8):
            targets.append(url)
            return _Resp()

    monkeypatch.setattr(_httpx, "AsyncClient", _FakeClient)
    r = asyncio.run(_probe_asset_url("widget", "/_cap/assets/widget.js", "/_cap"))
    assert r.ok and r.status == 200
    assert targets == [f"{get_settings().CAPTCHA_SERVICE_URL.rstrip('/')}/assets/widget.js"]


def test_probe_head_405_falls_back_to_get(monkeypatch):
    import asyncio
    import httpx as _httpx
    from app.api.v1.captcha import _probe_asset_url

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    class _FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def head(self, url, timeout=8):
            return _Resp(405)

        async def get(self, url, timeout=8):
            return _Resp(200)

    monkeypatch.setattr(_httpx, "AsyncClient", _FakeClient)
    r = asyncio.run(_probe_asset_url("widget", "https://x.test/cap.js", "/_cap"))
    assert r.ok and r.status == 200


def test_probe_same_origin_non_cap_path_unchecked():
    import asyncio
    from app.api.v1.captcha import _probe_asset_url

    r = asyncio.run(_probe_asset_url("widget", "/static/cap.js", "/_cap"))
    assert r.checked is False
    assert not r.ok


def test_probe_unreachable_url(monkeypatch):
    import asyncio
    import httpx as _httpx
    from app.api.v1.captcha import _probe_asset_url

    class _FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def head(self, url, timeout=8):
            raise ConnectionError("refused")

    monkeypatch.setattr(_httpx, "AsyncClient", _FakeClient)
    r = asyncio.run(_probe_asset_url("widget", "https://down.test/cap.js", "/_cap"))
    assert r.checked and not r.ok
    assert r.error
