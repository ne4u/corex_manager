"""Tests for image conversion filter emission in haproxy config generation.

Image conversion (on-the-fly JPEG/PNG/GIF to WebP) is applied per-backend in
the `backend` section. It uses the `lua.img_2_webp` filter registered by
the haproxy-img-2-webp Rust Lua module, which is loaded globally when the
`img_2_webp_enabled` toggle is on (default off).

The filter performs content negotiation based on the Accept header — no
rewrite rules or src-link replacement needed. Converted responses include
`Vary: Accept` for correct caching.
"""
from app.services import haproxy
from tests.factories import make_backend, make_fcgi_app, make_server


def test_no_img_2_webp_by_default(db):
    """A backend with no img_2_webp options emits no filter directives."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter lua.img_2_webp" not in cfg


def test_img_2_webp_emits_filter_when_enabled(db):
    """Per-backend img_2_webp_enabled emits filter lua.img_2_webp when module is on."""
    backend = make_backend(db)
    backend.options = {"img_2_webp_enabled": True, "img_2_webp_quality": 75}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "filter lua.img_2_webp" in cfg
    assert "quality:75" in cfg


def test_img_2_webp_skipped_when_module_not_enabled(db):
    """Per-backend option set but global module off emits a comment, not a filter."""
    backend = make_backend(db)
    backend.options = {"img_2_webp_enabled": True}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=False)
    assert "filter lua.img_2_webp" not in cfg
    assert "img_2_webp: enabled for this backend but module not enabled" in cfg


def test_img_2_webp_not_emitted_when_per_backend_disabled(db):
    """Per-backend img_2_webp_enabled=False emits nothing even when module is on."""
    backend = make_backend(db)
    backend.options = {"img_2_webp_enabled": False}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "filter lua.img_2_webp" not in cfg


def test_img_2_webp_default_quality(db):
    """Default quality (80) is used when img_2_webp_quality is not set."""
    backend = make_backend(db)
    backend.options = {"img_2_webp_enabled": True}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "filter lua.img_2_webp" in cfg
    assert "quality:80" in cfg


def test_img_2_webp_quality_clamped(db):
    """Quality is clamped to 0-100 range."""
    backend = make_backend(db)
    backend.options = {"img_2_webp_enabled": True, "img_2_webp_quality": 150}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "quality:100" in cfg


def test_img_2_webp_max_size_and_max_dim(db):
    """max_size and max_dim options are emitted in the filter line."""
    backend = make_backend(db)
    backend.options = {
        "img_2_webp_enabled": True,
        "img_2_webp_max_size": 5000000,
        "img_2_webp_max_dim": 2048,
    }
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "max_size:5000000" in cfg
    assert "max_dim:2048" in cfg


def test_img_2_webp_source_types(db):
    """source_types option is emitted as type: argument."""
    backend = make_backend(db)
    backend.options = {
        "img_2_webp_enabled": True,
        "img_2_webp_source_types": "image/jpeg,image/png",
    }
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "type:image/jpeg,image/png" in cfg


def test_img_2_webp_not_emitted_for_tcp_backend(db):
    """TCP backends (protocol=tcp) do not get image conversion filters."""
    backend = make_backend(db, protocol="tcp", mode="tcp")
    backend.options = {"img_2_webp_enabled": True}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "filter lua.img_2_webp" not in cfg


def test_img_2_webp_skipped_for_fcgi_backend(db):
    """FCGI backends skip image conversion (HAProxy 3.4 fcgi_flt_check bug)."""
    fcgi_app = make_fcgi_app(db)
    backend = make_backend(db, fcgi_app_id=fcgi_app.id)
    backend.options = {"img_2_webp_enabled": True}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "filter lua.img_2_webp" not in cfg
    assert "img_2_webp: skipped for FCGI backend" in cfg


def test_global_section_loads_module_when_enabled(db):
    """Global section emits lua-load-per-thread with combined loader when img_2_webp_enabled."""
    backend = make_backend(db)
    backend.options = {"img_2_webp_enabled": True}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "lua-load-per-thread" in cfg
    assert "lua-prepend-path /etc/haproxy/?.so cpath" in cfg


def test_global_section_no_module_when_disabled(db):
    """Global section does not load img_2_webp module when disabled."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=False)
    # The combined loader may still be emitted if other modules (geoip, etc.)
    # are enabled, but img_2_webp should not be in the loader content.
    # We check that the img_2_webp require line is not present.
    assert 'haproxy_img_2_webp_module' not in cfg


def test_different_backends_different_settings(db):
    """Two backends can have different image conversion settings simultaneously."""
    be1 = make_backend(db, name="be_with_convert")
    be1.options = {"img_2_webp_enabled": True, "img_2_webp_quality": 90}
    make_server(db, be1.id)

    be2 = make_backend(db, name="be_without_convert")
    be2.options = {"img_2_webp_enabled": False}
    make_server(db, be2.id)

    cfg = haproxy.generate_config(db, img_2_webp_enabled_override=True)
    assert "filter lua.img_2_webp" in cfg
    assert "quality:90" in cfg
    # be2 should not have the filter
    be2_section = cfg[cfg.index("backend be_without_convert"):]
    be2_section_end = be2_section.find("\n\n")
    be2_section = be2_section[:be2_section_end] if be2_section_end != -1 else be2_section
    assert "filter lua.img_2_webp" not in be2_section
