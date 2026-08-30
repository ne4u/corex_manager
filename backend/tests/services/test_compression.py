"""Tests for response compression filter emission in haproxy config generation.

Compression is applied per-backend (in the `backend` section), not per-listener.
This lets different backends use different algorithms (e.g. zstd for APIs,
brotli for static content, none for streaming). gzip/deflate/raw-deflate are
HAProxy-native (no Rust module). brotli/zstd require the haproxy-compression
Rust Lua module, which is loaded globally when the single `compression_enabled`
toggle is on.
"""
from app.services import haproxy
from tests.factories import make_backend, make_listener, make_server


def test_no_compression_by_default(db):
    """A backend with no compression options emits no filter directives."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter compression" not in cfg
    assert "filter lua.compress" not in cfg


def test_gzip_emits_native_compression_filter(db):
    """gzip algorithm uses HAProxy's native filter compression (no Lua module)."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "gzip", "compression_content_types": "text/,application/json"}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter compression" in cfg
    assert "compression algo gzip" in cfg
    assert "compression type text/ application/json" in cfg
    assert "filter lua.compress" not in cfg


def test_gzip_offload(db):
    """gzip with offload emits the compression offload directive."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "gzip", "compression_offload": True}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "compression offload" in cfg


def test_deflate_emits_native_compression_filter(db):
    """deflate algorithm uses HAProxy's native filter compression."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "deflate"}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter compression" in cfg
    assert "compression algo deflate" in cfg
    assert "filter lua.compress" not in cfg


def test_raw_deflate_emits_native_compression_filter(db):
    """raw-deflate algorithm uses HAProxy's native filter compression."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "raw-deflate"}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter compression" in cfg
    assert "compression algo raw-deflate" in cfg
    assert "filter lua.compress" not in cfg


def test_brotli_emits_lua_filter_when_enabled(db):
    """brotli algorithm emits filter lua.compress br ... when compression module is enabled."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "brotli", "compression_quality": 7}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "filter lua.compress br quality:7" in cfg
    assert "filter compression" not in cfg


def test_brotli_skipped_when_not_enabled(db):
    """brotli algorithm is silently skipped (comment only) when compression module is disabled."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "brotli"}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=False)
    assert "filter lua.compress" not in cfg
    assert "brotli requested but compression module not enabled" in cfg


def test_zstd_emits_lua_filter_when_enabled(db):
    """zstd algorithm emits filter lua.compress zstd ... when compression module is enabled."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "zstd", "compression_level": 9}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "filter lua.compress zstd level:9" in cfg


def test_zstd_skipped_when_not_enabled(db):
    """zstd algorithm is silently skipped when compression module is disabled."""
    backend = make_backend(db)
    backend.options = {"compression_algorithm": "zstd"}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=False)
    assert "filter lua.compress" not in cfg
    assert "zstd requested but compression module not enabled" in cfg


def test_global_section_loads_module_when_enabled(db):
    """Global section emits lua-load-per-thread with combined loader when compression_enabled."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "lua-load-per-thread" in cfg
    assert "lua-prepend-path /etc/haproxy/?.so cpath" in cfg


def test_global_section_no_module_when_disabled(db):
    """Global section does not load compress.lua when compression module is disabled."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=False)
    assert "compress.lua" not in cfg


def test_compression_not_emitted_for_tcp_backend(db):
    """TCP backends (protocol=tcp) do not get compression filters."""
    backend = make_backend(db, protocol="tcp", mode="tcp")
    backend.options = {"compression_algorithm": "gzip"}
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter compression" not in cfg


def test_brotli_with_offload_and_content_types(db):
    """brotli with offload and content types emits all args in the filter line."""
    backend = make_backend(db)
    backend.options = {
        "compression_algorithm": "brotli",
        "compression_quality": 5,
        "compression_window": 20,
        "compression_content_types": "text/,application/json",
        "compression_offload": True,
    }
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "filter lua.compress br quality:5 window:20 offload type:text/,application/json" in cfg


def test_different_backends_different_algorithms(db):
    """Two backends can use different compression algorithms simultaneously."""
    be_brotli = make_backend(db, name="be_brotli")
    be_brotli.options = {"compression_algorithm": "brotli", "compression_quality": 5}
    make_server(db, be_brotli.id)

    be_zstd = make_backend(db, name="be_zstd")
    be_zstd.options = {"compression_algorithm": "zstd", "compression_level": 3}
    make_server(db, be_zstd.id)

    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "filter lua.compress br quality:5" in cfg
    assert "filter lua.compress zstd level:3" in cfg
