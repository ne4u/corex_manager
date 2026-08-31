"""Tests for cache config generation in HAProxy config.

Memory cache (HAProxy native) emits `cache` sections and `cache-use`/`cache-store`
directives. Disk cache redirects server lines to the Varnish container and sets
the X-Cache-Backend routing header (only when the global disk_cache_enabled
toggle is on).
"""
from app.services import haproxy
from tests.factories import make_backend, make_server, make_cache_config, make_cache_rule


def test_no_cache_by_default(db):
    """A backend with no cache config emits no cache sections or directives."""
    backend = make_backend(db)
    make_server(db, backend.id)
    cfg = haproxy.generate_config(db)
    assert "cache " not in cfg  # no cache sections
    assert "cache-use" not in cfg
    assert "cache-store" not in cfg
    assert "X-Cache-Backend" not in cfg


def test_memory_cache_section_emitted(db):
    """A backend with haproxy_enabled emits a cache section with correct directives."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True, haproxy_total_max_size=200, haproxy_max_object_size=500000, haproxy_max_age=600)
    cfg = haproxy.generate_config(db)
    assert "cache cache_web" in cfg
    assert "total-max-size 200" in cfg
    assert "max-object-size 500000" in cfg
    assert "max-age 600" in cfg
    assert "process-vary on" in cfg


def test_memory_cache_directives_in_backend(db):
    """A backend with haproxy_enabled and a cache rule emits filter/cache-use/cache-store."""
    backend = make_backend(db, name="api")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True)
    # Cacheability rules gate cache-use; without one nothing is cached.
    make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    cfg = haproxy.generate_config(db)
    assert "filter cache cache_api" in cfg
    assert "http-request cache-use cache_api" in cfg
    assert "http-response cache-store cache_api" in cfg


def test_memory_cache_enabled_without_rules_caches_nothing(db):
    """Enabling a tier is not sufficient — cacheability rules decide what is stored.

    This is a deliberate behavior change: an empty ruleset caches nothing rather
    than everything, so caching is always explicit.
    """
    backend = make_backend(db, name="norule_api")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    cfg = haproxy.generate_config(db)
    assert "cache-use" not in cfg
    assert "cache-store" not in cfg


def test_memory_cache_with_condition(db):
    """The advanced ACL condition is ANDed onto the rule-generated cache-use line."""
    backend = make_backend(db, name="static")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, haproxy_cache_condition="{ path_beg /static/ }")
    make_cache_rule(db, cc.id, match_type="extension", pattern="css")
    cfg = haproxy.generate_config(db)
    assert "filter cache cache_static" in cfg
    assert "cache-use cache_static" in cfg
    # The condition should be in the cache-use line
    assert "path_beg /static/" in cfg


def test_memory_cache_strips_no_cache_headers_by_default(db):
    """RFC 7234 compliance disabled (default, CDN-style) strips Cache-Control/Pragma.

    Without this, a single browser hard-reload (which sends
    `Cache-Control: no-cache` / `Pragma: no-cache`) bypasses the shared memory
    cache for everyone. The del-header lines must appear before `filter cache`
    so HAProxy's cache filter never sees the headers.
    """
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    cfg = haproxy.generate_config(db)
    assert "http-request del-header Cache-Control" in cfg
    assert "http-request del-header Pragma" in cfg
    # The del-header lines must come before the filter/cache-use lines so the
    # cache filter evaluates against a header-stripped request.
    del_cc = cfg.index("http-request del-header Cache-Control")
    filter_idx = cfg.index("filter cache cache_web")
    assert del_cc < filter_idx, "del-header must precede filter cache"


def test_memory_cache_rfc7234_compliance_keeps_no_cache_headers(db):
    """RFC 7234 compliance enabled honors request-side no-cache headers.

    When enabled, HAProxy's cache filter follows RFC 7234 and bypasses the
    cache lookup for requests carrying `Cache-Control: no-cache` / `Pragma:
    no-cache`. No del-header lines are emitted.
    """
    backend = make_backend(db, name="strict")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, haproxy_rfc7234_compliance=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    cfg = haproxy.generate_config(db)
    assert "http-request del-header Cache-Control" not in cfg
    assert "http-request del-header Pragma" not in cfg
    # The cache directives themselves are still emitted.
    assert "filter cache cache_strict" in cfg
    assert "http-request cache-use cache_strict" in cfg


def test_memory_cache_no_strip_when_nothing_cacheable(db):
    """The del-header lines are not emitted when no rule can cache anything.

    Emitting them would only add overhead since no cache lookup happens.
    """
    backend = make_backend(db, name="empty")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    cfg = haproxy.generate_config(db)
    assert "http-request del-header Cache-Control" not in cfg
    assert "http-request del-header Pragma" not in cfg


def test_disk_cache_redirects_servers(db):
    """When disk cache is enabled, the Varnish server is emitted as a backup.

    Marking it as backup keeps it out of normal round-robin selection, so
    Varnish's own backend fetches are not routed back to Varnish. Cache-eligible
    client requests still reach Varnish via the explicit `use-server` directives.
    Origin servers remain active and are used for all other traffic.
    """
    backend = make_backend(db, name="cached")
    make_server(db, backend.id, address="10.0.0.1", port=8080)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Add a cache rule so use-server directives are emitted
    from app.models.models import CacheRule
    rule = CacheRule(cache_config_id=cc.id, match_type="path", pattern="/static/", action="cache", tier="disk", priority=0)
    db.add(rule)
    db.commit()
    
    # Enable the global disk cache toggle
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "true")
    cfg = haproxy.generate_config(db)
    
    # Varnish server is emitted as a backup (not a round-robin peer) to avoid
    # routing Varnish's own fetches back into Varnish.
    assert "server disk_cache varnish:6081" in cfg
    disk_cache_line = [l for l in cfg.split("\n") if "server disk_cache" in l and l.strip().startswith("server")]
    assert len(disk_cache_line) == 1
    assert " backup" in disk_cache_line[0], f"Varnish cache server should be backup: {disk_cache_line[0]}"
    # Origin server is still present (not forced as backup)
    assert "10.0.0.1:8080" in cfg
    # Origin should NOT have backup flag (unless Server.backup=True)
    # Since we created a server with default backup=False, check the server line
    # The server line should not contain "backup" after the address/port
    lines = cfg.split("\n")
    origin_line = [l for l in lines if "10.0.0.1:8080" in l and l.strip().startswith("server")]
    assert len(origin_line) == 1
    # Backup would be added as a flag, so if the line doesn't end with "backup" we're good
    # But let's be more precise: the line should not contain " backup" as a standalone word
    import re
    assert not re.search(r'\sbackup(\s|$)', origin_line[0]), f"Origin server should not be backup: {origin_line[0]}"
    
    # Redispatch + retry-on ensure fallback on Varnish errors (503/502/504)
    assert "option redispatch" in cfg
    assert "retry-on 503 502 504" in cfg
    
    # Check for use-server directive
    assert "use-server disk_cache" in cfg


def test_disk_cache_header_set(db):
    """When disk cache is enabled with cache rules, the X-Cache-Backend header is set conditionally."""
    backend = make_backend(db, name="mybackend")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Add a cache rule so the header is set
    from app.models.models import CacheRule
    rule = CacheRule(cache_config_id=cc.id, match_type="extension", pattern="jpg", action="cache", tier="disk", priority=0)
    db.add(rule)
    db.commit()
    
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "true")
    cfg = haproxy.generate_config(db)
    
    # Header is set conditionally (with "if" clause for cache rules or PURGE)
    assert "http-request set-header X-Cache-Backend mybackend if" in cfg


def test_disk_cache_globally_disabled(db):
    """When the global toggle is off, disk cache config is ignored (origin servers used)."""
    backend = make_backend(db, name="test_be")
    make_server(db, backend.id, address="10.0.0.5", port=80)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Global toggle is off by default
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "false")
    cfg = haproxy.generate_config(db)
    # Should fall back to origin servers
    assert "10.0.0.5:80" in cfg
    assert "server disk_cache varnish:6081" not in cfg
    # Should emit a comment about the disabled disk cache
    assert "disk cache requested but not enabled" in cfg


def test_both_tiers_simultaneous(db):
    """Both memory cache and disk cache can be enabled simultaneously.
    When disk cache is active, the memory cache filter is NOT emitted (it
    would buffer Varnish responses and cause 500 errors on large responses).
    Varnish handles all caching in that case."""
    backend = make_backend(db, name="dual")
    make_server(db, backend.id, address="10.0.0.10", port=9090)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "true")
    cfg = haproxy.generate_config(db)
    # Memory cache section is still declared (used by other backends potentially)
    assert "cache cache_dual" in cfg
    # But the filter cache directive is NOT emitted (disk cache is active)
    assert not any(l.strip().startswith("filter cache cache_dual") for l in cfg.split("\n"))
    assert "cache-use" not in cfg  # memory cache skipped
    assert "cache-store" not in cfg  # memory cache skipped
    # Disk cache routing — Varnish primary, origin as backup fallback
    assert "http-request set-header X-Cache-Backend dual" in cfg
    assert "server disk_cache varnish:6081" in cfg
    assert "10.0.0.10:9090" in cfg  # origin server still present as backup
    assert "option redispatch" in cfg  # fallback on Varnish errors


def test_tcp_backend_no_cache(db):
    """Cache directives are not emitted for TCP-mode backends."""
    backend = make_backend(db, name="tcp_be", protocol="tcp", mode="tcp")
    make_server(db, backend.id, address="10.0.0.2", port=3306)
    make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "true")
    cfg = haproxy.generate_config(db)
    # No cache section for TCP backends
    assert "cache cache_tcp_be" not in cfg
    assert "cache-use" not in cfg
    assert "X-Cache-Backend" not in cfg


def test_disk_cache_header_condition_uses_named_acls(db):
    """The X-Cache-Backend set-header condition must reference named ACLs.

    HAProxy parses `{ cacherule_... }` as an anonymous ACL whose fetch method is the
    ACL name, and `(cacherule_...)` as an ACL name including the parentheses, both
    of which fail validation. Named ACL references must appear bare and be combined
    with OR; AND (for bypass negations) is implicit in HAProxy.
    """
    backend = make_backend(db, name="ne4u.com-nginx")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    from app.models.models import CacheRule
    # Bypass rule then cache rule so the condition includes a negation.
    bypass = CacheRule(cache_config_id=cc.id, match_type="path", pattern="/api/", action="bypass", tier="disk", priority=0)
    rule = CacheRule(cache_config_id=cc.id, match_type="path", pattern="/static/", action="cache", tier="disk", priority=1)
    db.add(bypass)
    db.add(rule)
    db.commit()

    from app.services.settings import set_setting
    set_setting(db, "disk_cache_enabled", "true")
    cfg = haproxy.generate_config(db)

    header_line = next((l for l in cfg.split("\n") if "http-request set-header X-Cache-Backend" in l), "")
    assert header_line
    condition = header_line.split("if", 1)[1]
    # PURGE/BAN routes plus cache rule ACL(s)
    assert "is_cache_purge ||" in condition
    # Bypass rule must be negated inside the grouped condition
    assert "!cacherule_" in condition
    # Must not use `{ cacherule_... }` inline ACL syntax, or parenthesized names
    assert "{ cacherule_" not in header_line
    assert "}" not in condition
    assert "(cacherule_" not in condition
    assert "cacherule_" in condition
