"""Tests for response transform filter emission in haproxy config generation.

Response transforms are applied per-backend (in the `backend` section), like
compression. The haproxy-resp-transform Rust Lua module is loaded globally
via the combined modules.lua loader when the `resp_transform_enabled` toggle
is on. Per-backend JSON config files are written to RESP_TRANSFORM_DIR.
"""
import json
import os

from app.services import haproxy
from app.services import resp_transform as rt_svc
from tests.factories import make_backend, make_fcgi_app, make_listener, make_response_transform, make_server


def test_no_transform_by_default(db):
    """A backend with no response transforms emits no filter directives."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "filter lua.resp_transform" not in cfg


def test_replace_emits_filter_when_enabled(db):
    """A replace rule emits filter lua.resp_transform when the module is enabled."""
    backend = make_backend(db, name="be_replace")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_replace",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="<title>(.*?)</title>",
        replace_string="<title>REDACTED</title>",
        content_types="text/html",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform file:" in cfg
    assert "be_replace.json" in cfg


def test_transform_skipped_when_not_enabled(db):
    """Transform rules exist but module disabled → comment only, no filter."""
    backend = make_backend(db, name="be_skip")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_skip",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=False)
    assert "filter lua.resp_transform" not in cfg
    assert "resp_transform: rules exist but module not enabled" in cfg


def test_global_section_loads_module_when_enabled(db):
    """Global section emits lua-load-per-thread with combined loader when enabled."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "lua-load-per-thread" in cfg
    assert "lua-prepend-path /etc/haproxy/?.so cpath" in cfg


def test_global_section_no_module_when_disabled(db):
    """Global section does not load resp_transform when disabled (and no other modules needed)."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=False)
    # The combined loader is only emitted when at least one Rust module is needed.
    # With no compression and no geoip and no resp_transform, no lua-load-per-thread.
    # (geoip may or may not be available depending on the test env, so we just
    # check that resp_transform is not in the loader content)
    assert "resp_transform" not in cfg or "resp_transform: rules exist" in cfg


def test_transform_not_emitted_for_tcp_backend(db):
    """TCP backends (protocol=tcp) do not get response transform filters."""
    backend = make_backend(db, protocol="tcp", mode="tcp")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_tcp",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform" not in cfg


def test_transform_scoped_to_specific_backend(db):
    """A transform scoped to backend A does not emit a filter for backend B."""
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_b")
    make_server(db, be_b.id)
    make_response_transform(
        db,
        name="rt_scoped",
        backend_id=be_a.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "be_a.json" in cfg
    assert "be_b.json" not in cfg


def test_transform_scoped_via_backend_ids(db):
    """A transform scoped via backend_ids applies to listed backends."""
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_b")
    make_server(db, be_b.id)
    make_response_transform(
        db,
        name="rt_ids",
        backend_ids=[be_a.id, be_b.id],
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "be_a.json" in cfg
    assert "be_b.json" in cfg


def test_transform_global_applies_to_all_backends(db):
    """A transform with no backend_id/backend_ids applies to all backends."""
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_b")
    make_server(db, be_b.id)
    make_response_transform(
        db,
        name="rt_global",
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "be_a.json" in cfg
    assert "be_b.json" in cfg


def test_disabled_transform_not_emitted(db):
    """A disabled transform does not emit a filter."""
    backend = make_backend(db, name="be_disabled")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_disabled",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
        enabled=False,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform" not in cfg


def test_write_resp_transform_files(db, tmp_path, monkeypatch):
    """write_resp_transform_files writes JSON config files per backend."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "RESP_TRANSFORM_DIR", str(tmp_path))

    backend = make_backend(db, name="be_file")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_file",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="<title>(.*?)</title>",
        replace_string="<title>NEW</title>",
        content_types="text/html",
    )
    result = rt_svc.write_resp_transform_files(db)
    assert "be_file.json" in result["written"]
    filepath = os.path.join(str(tmp_path), "be_file.json")
    with open(filepath) as f:
        config = json.load(f)
    assert len(config["rules"]) == 1
    assert config["rules"][0]["transform_type"] == "replace"
    assert config["rules"][0]["find_regex"] == "<title>(.*?)</title>"
    assert config["rules"][0]["replace_string"] == "<title>NEW</title>"
    assert config["rules"][0]["content_types"] == ["text/html"]


def test_write_resp_transform_files_removes_stale(db, tmp_path, monkeypatch):
    """Stale config files for backends with no rules are removed."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "RESP_TRANSFORM_DIR", str(tmp_path))

    # Write a stale file first
    stale_path = os.path.join(str(tmp_path), "stale_backend.json")
    with open(stale_path, "w") as f:
        f.write('{"rules": []}')

    backend = make_backend(db, name="be_active")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_active",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    result = rt_svc.write_resp_transform_files(db)
    assert "be_active.json" in result["written"]
    assert "stale_backend.json" in result["removed"]
    assert not os.path.exists(stale_path)


def test_mask_rule_in_config_file(db, tmp_path, monkeypatch):
    """Mask rules with detector mode are correctly serialized to JSON."""
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "RESP_TRANSFORM_DIR", str(tmp_path))

    backend = make_backend(db, name="be_mask")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_mask",
        backend_id=backend.id,
        transform_type="mask",
        mask_mode="detector",
        detector="email",
        token_mode="tokenize",
        token_prefix="TOK_",
        token_ttl=3600,
        content_types="application/json",
    )
    rt_svc.write_resp_transform_files(db)
    filepath = os.path.join(str(tmp_path), "be_mask.json")
    with open(filepath) as f:
        config = json.load(f)
    rule = config["rules"][0]
    assert rule["transform_type"] == "mask"
    assert rule["mask_mode"] == "detector"
    assert rule["detector"] == "email"
    assert rule["token_mode"] == "tokenize"
    assert rule["token_prefix"] == "TOK_"
    assert rule["token_ttl"] == 3600


# ---------------------------------------------------------------------------
# FCGI + resp_transform interaction
#
# HAProxy 3.4's fcgi_flt_check() (src/fcgi-app.c) has a bug: it rejects ANY
# non-cache/non-compression filter alongside use-fcgi-app, regardless of whether
# an explicit `filter fcgi-app` is declared. The cache filter's check
# (cache_store_check in src/cache.c) properly uses a CACHE_FLT_F_IMPLICIT_DECL
# flag to only reject implicit declarations, but the fcgi-app check is missing
# this flag. As a workaround, we skip resp_transform (and Lua-based brotli/zstd
# compression) for FCGI backends and emit a warning comment.
# ---------------------------------------------------------------------------


def test_fcgi_app_with_resp_transform_skips_filter(db):
    """A backend using use-fcgi-app with resp_transform rules must NOT emit
    `filter lua.resp_transform` — HAProxy 3.4's fcgi_flt_check bug rejects Lua
    filters alongside use-fcgi-app regardless of explicit filter declarations.
    A warning comment is emitted instead."""
    fcgi_app = make_fcgi_app(db, name="php-containers")
    backend = make_backend(db, name="be_fcgi_rt", fcgi_app_id=fcgi_app.id)
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_fcgi",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "use-fcgi-app php-containers" in cfg
    # The resp_transform filter must NOT be emitted for FCGI backends
    assert "filter lua.resp_transform" not in cfg
    # A warning comment should be present
    assert "resp_transform rules exist" in cfg
    assert "fcgi_flt_check" in cfg


def test_fcgi_app_without_resp_transform_no_filter(db):
    """A backend using use-fcgi-app with no resp_transform emits no
    resp_transform filter or warning."""
    fcgi_app = make_fcgi_app(db, name="php-only")
    backend = make_backend(db, name="be_fcgi_no_rt", fcgi_app_id=fcgi_app.id)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "use-fcgi-app php-only" in cfg
    assert "filter lua.resp_transform" not in cfg
    assert "resp_transform rules exist" not in cfg


def test_fcgi_app_with_resp_transform_disabled_no_filter(db):
    """A backend using use-fcgi-app where resp_transform rules exist but the
    module is disabled emits the standard 'not enabled' comment, not the FCGI
    warning."""
    fcgi_app = make_fcgi_app(db, name="php-disabled")
    backend = make_backend(db, name="be_fcgi_rt_disabled", fcgi_app_id=fcgi_app.id)
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_disabled_fcgi",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=False)
    assert "use-fcgi-app php-disabled" in cfg
    assert "filter lua.resp_transform" not in cfg
    assert "resp_transform: rules exist but module not enabled" in cfg
    # Should NOT have the FCGI warning (module is disabled, so no conflict)
    assert "fcgi_flt_check" not in cfg


def test_fcgi_app_with_cache_still_works(db):
    """Cache filter (HAProxy native) is allowed alongside use-fcgi-app —
    fcgi_flt_check explicitly skips cache_store_flt_id."""
    from tests.factories import make_cache_config, make_cache_rule

    fcgi_app = make_fcgi_app(db, name="php-cache")
    backend = make_backend(db, name="be_fcgi_cache", fcgi_app_id=fcgi_app.id)
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="html", action="cache", tier="memory")
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "use-fcgi-app php-cache" in cfg
    assert "filter cache" in cfg


def test_fcgi_app_with_gzip_compression_still_works(db):
    """Native gzip compression (filter compression) is allowed alongside
    use-fcgi-app — fcgi_flt_check explicitly skips http_comp_*_flt_id."""
    fcgi_app = make_fcgi_app(db, name="php-gzip")
    backend = make_backend(db, name="be_fcgi_gzip", fcgi_app_id=fcgi_app.id)
    backend.options = {"compression_algorithm": "gzip"}
    db.commit()
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "use-fcgi-app php-gzip" in cfg
    assert "filter compression" in cfg


def test_fcgi_app_with_brotli_compression_skipped(db):
    """Brotli compression (lua.compress) is a Lua filter and must be skipped
    for FCGI backends — same fcgi_flt_check bug as resp_transform."""
    fcgi_app = make_fcgi_app(db, name="php-brotli")
    backend = make_backend(db, name="be_fcgi_brotli", fcgi_app_id=fcgi_app.id)
    backend.options = {"compression_algorithm": "brotli"}
    db.commit()
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db, compression_enabled_override=True)
    assert "use-fcgi-app php-brotli" in cfg
    assert "filter lua.compress" not in cfg
    assert "brotli skipped for FCGI" in cfg


def test_non_fcgi_backend_with_resp_transform_still_emits_filter(db):
    """A non-FCGI backend with resp_transform rules still emits the filter
    normally — the FCGI workaround only applies to FCGI backends."""
    backend = make_backend(db, name="be_normal_rt")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_normal",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform" in cfg
    assert "fcgi_flt_check" not in cfg


# ---------------------------------------------------------------------------
# detokenize_query — query-string detokenization emission
# ---------------------------------------------------------------------------


def test_detokenize_query_emitted_when_enabled(db):
    """A mask rule with detokenize_query=True emits the Lua action + set-query."""
    backend = make_backend(db, name="be_detok")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_detok",
        backend_id=backend.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "http-request lua.detokenize_query" in cfg
    assert "http-request set-query %[var(txn.detok_query)]" in cfg
    assert "SSN_" in cfg


def test_detokenize_query_not_emitted_when_false(db):
    """A mask rule with detokenize_query=False does not emit the Lua action."""
    backend = make_backend(db, name="be_no_detok")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_no_detok",
        backend_id=backend.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=False,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "http-request lua.detokenize_query" not in cfg
    assert "http-request set-query %[var(txn.detok_query)]" not in cfg


def test_detokenize_query_not_emitted_for_non_mask_rules(db):
    """A replace rule with detokenize_query=True does not emit the Lua action."""
    backend = make_backend(db, name="be_replace_detok")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_replace_detok",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
        detokenize_query=True,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "http-request lua.detokenize_query" not in cfg


def test_detokenize_query_not_emitted_for_unmatched_backend(db):
    """A mask rule with detokenize_query=True scoped to backend A does not
    emit the action for backend B."""
    be_a = make_backend(db, name="be_detok_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_detok_b")
    make_server(db, be_b.id)
    make_response_transform(
        db,
        name="rt_detok_scoped",
        backend_id=be_a.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    # The action should appear for be_a's section but not be_b's
    assert "http-request lua.detokenize_query" in cfg
    # Verify it's in be_a's section, not be_b's
    be_a_section = cfg[cfg.index("backend be_detok_a"):]
    be_b_section = cfg[cfg.index("backend be_detok_b"):]
    assert "http-request lua.detokenize_query" in be_a_section
    assert "http-request lua.detokenize_query" not in be_b_section


def test_detokenize_query_multiple_prefixes_combined(db):
    """Multiple mask rules with detokenize_query=True produce a combined prefix regex."""
    backend = make_backend(db, name="be_multi_detok")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_ssn",
        backend_id=backend.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    make_response_transform(
        db,
        name="rt_cc",
        backend_id=backend.id,
        transform_type="mask",
        mask_mode="detector",
        detector="credit_card",
        token_mode="encrypt",
        token_prefix="ENC_",
        encrypt_key_env="RESP_TRANSFORM_KEY",
        detokenize_query=True,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "http-request lua.detokenize_query" in cfg
    # Both prefixes should appear in the ACL condition
    assert "SSN_" in cfg
    assert "ENC_" in cfg


def test_detokenize_query_not_emitted_when_module_disabled(db):
    """detokenize_query is not emitted when resp_transform module is disabled."""
    backend = make_backend(db, name="be_detok_disabled")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_detok_disabled",
        backend_id=backend.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    cfg = haproxy.generate_config(db, resp_transform_enabled_override=False)
    assert "http-request lua.detokenize_query" not in cfg


# ---------------------------------------------------------------------------
# Disk cache + resp_transform interaction
#
# When disk cache (Varnish) is active, the `del-header Accept-Encoding` must
# be guarded with `is_varnish_fetch` so it only strips on the Varnish→origin
# fetch path (where resp_transform needs uncompressed content). Client→Varnish
# requests keep Accept-Encoding so Varnish can vary on encoding and HAProxy's
# compression filter can negotiate on delivery.
# ---------------------------------------------------------------------------


def test_del_accept_encoding_guarded_when_disk_cache_active(db):
    """When disk cache is active, del-header Accept-Encoding is guarded with
    is_varnish_fetch so it only strips on Varnish→origin fetches."""
    from tests.factories import make_cache_config, make_cache_rule
    from app.services.settings import set_setting

    backend = make_backend(db, name="be_rt_disk")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_disk",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="disk")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform" in cfg
    # Should be guarded with is_varnish_fetch
    assert "http-request del-header Accept-Encoding if is_varnish_fetch" in cfg
    # Should NOT have the unguarded version
    assert "    http-request del-header Accept-Encoding\n" not in cfg


def test_del_accept_encoding_unguarded_when_disk_cache_inactive(db):
    """When disk cache is NOT active, del-header Accept-Encoding is unguarded
    (normal client→origin path always needs uncompressed content for transform)."""
    backend = make_backend(db, name="be_rt_no_disk")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_no_disk",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    db.commit()

    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform" in cfg
    # Should be unguarded (no is_varnish_fetch condition)
    assert "    http-request del-header Accept-Encoding\n" in cfg
    assert "http-request del-header Accept-Encoding if is_varnish_fetch" not in cfg


def test_del_accept_encoding_guarded_when_disk_cache_enabled_but_no_rules(db):
    """When disk cache is active but no cache rules match, the guard still
    applies (disk_cache_active is true, is_varnish_fetch ACL is emitted)."""
    from tests.factories import make_cache_config
    from app.services.settings import set_setting

    backend = make_backend(db, name="be_rt_disk_norule")
    make_server(db, backend.id)
    make_response_transform(
        db,
        name="rt_disk_norule",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db, resp_transform_enabled_override=True)
    assert "filter lua.resp_transform" in cfg
    assert "http-request del-header Accept-Encoding if is_varnish_fetch" in cfg
