"""Tests for Varnish VCL generation.

The VCL is auto-generated from the Backend/Server/CacheConfig models.
Varnish fetches through HAProxy (not directly from origin servers) so that
HAProxy's response filters run before Varnish caches the response. The Varnish
implementation detail is not exposed in the GUI — all user-facing text refers
to "Disk Cache".
"""
from app.services import varnish
from tests.factories import make_backend, make_server, make_cache_config, make_listener


def test_vcl_no_backends(db):
    """When no backends have disk cache enabled, a minimal valid VCL is generated."""
    backend = make_backend(db)
    make_server(db, backend.id)
    vcl = varnish.generate_vcl(db)
    assert "vcl 4.1" in vcl
    assert "backend default none" in vcl


def test_vcl_generation_single_backend(db):
    """VCL has a single HAProxy backend, routing validation, and TTL config."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id, address="10.0.0.1", port=8080)
    make_cache_config(db, backend.id, disk_cache_enabled=True, disk_cache_ttl=300, disk_cache_grace=1200)
    vcl = varnish.generate_vcl(db)
    assert "vcl 4.1" in vcl
    # Single HAProxy backend (not per-origin-server backends)
    assert "backend haproxy {" in vcl
    assert '"10.0.0.1"' not in vcl  # origin server address not in VCL
    # X-Cache-Backend routing validation
    assert 'req.http.X-Cache-Backend == "web"' in vcl
    assert "set beresp.ttl = 300s" in vcl
    assert "set beresp.grace = 1200s" in vcl


def test_vcl_generation_multiple_backends(db):
    """Multiple backends produce routing validation but still a single HAProxy backend."""
    b1 = make_backend(db, name="api")
    make_server(db, b1.id, address="10.0.0.1", port=80)
    make_cache_config(db, b1.id, disk_cache_enabled=True)

    b2 = make_backend(db, name="static")
    make_server(db, b2.id, address="10.0.0.2", port=80)
    make_cache_config(db, b2.id, disk_cache_enabled=True)

    vcl = varnish.generate_vcl(db)
    # Still a single HAProxy backend
    assert "backend haproxy {" in vcl
    assert vcl.count("backend haproxy {") == 1
    # Routing validation for both backends
    assert 'req.http.X-Cache-Backend == "api"' in vcl
    assert 'req.http.X-Cache-Backend == "static"' in vcl
    assert "} else if" in vcl


def test_vcl_purge_acl(db):
    """Purge ACL and handler are present when purge is enabled."""
    backend = make_backend(db, name="purge_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True, disk_cache_purge_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "acl purge {" in vcl
    assert 'req.method == "PURGE"' in vcl
    assert 'req.method == "BAN"' in vcl
    assert "return(purge)" in vcl


def test_vcl_no_purge_when_disabled(db):
    """No purge handler when purge is disabled."""
    backend = make_backend(db, name="no_purge")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True, disk_cache_purge_enabled=False)
    vcl = varnish.generate_vcl(db)
    assert "acl purge {" not in vcl
    assert 'req.method == "PURGE"' not in vcl


def test_vcl_sets_varnish_fetch_header(db):
    """X-Varnish-Fetch is set so HAProxy doesn't route back to Varnish (loop prevention)."""
    backend = make_backend(db, name="fetch_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert 'set req.http.X-Varnish-Fetch = "1"' in vcl
    assert "set req.backend_hint = haproxy;" in vcl


def test_vcl_strips_routing_header_in_deliver(db):
    """X-Cache-Backend is stripped in vcl_deliver so it doesn't leak to clients."""
    backend = make_backend(db, name="strip_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # X-Cache-Backend is NOT unset in vcl_recv (needed for vcl_backend_response)
    assert "unset req.http.X-Cache-Backend" not in vcl
    # X-Cache-Backend IS stripped in vcl_deliver
    assert "unset resp.http.X-Cache-Backend;" in vcl


def test_vcl_stores_cache_backend_for_purging(db):
    """X-Cache-Backend is copied to beresp in vcl_backend_response for per-backend purging."""
    backend = make_backend(db, name="purge_store")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "set beresp.http.X-Cache-Backend = bereq.http.X-Cache-Backend" in vcl


def test_vcl_strips_set_cookie_and_cache_control(db):
    """Set-Cookie and Cache-Control are stripped so origin headers don't prevent caching.

    PHP/nginx origins often send Set-Cookie or Cache-Control: private on every
    response. HAProxy's cache rules already determine which requests are
    cacheable, so Varnish can safely strip these headers before caching.
    """
    backend = make_backend(db, name="strip_headers")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "unset beresp.http.Set-Cookie;" in vcl
    assert "unset beresp.http.Cache-Control;" in vcl
    # The old uncacheable-on-Set-Cookie/private check should be gone
    assert "beresp.uncacheable = true" in vcl  # still used for non-2xx/3xx
    assert 'Cache-Control ~ "private"' not in vcl


def test_vcl_strips_via_header(db):
    """The Varnish Via header is removed in vcl_deliver so the proxy hop is hidden."""
    backend = make_backend(db, name="via_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "unset resp.http.Via;" in vcl


def test_vcl_renames_xvarnish_to_xvcache(db):
    """X-Varnish is renamed to X-VCache so the cache software is not advertised."""
    backend = make_backend(db, name="xvarnish_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "set resp.http.X-VCache = resp.http.X-Varnish;" in vcl
    assert "unset resp.http.X-Varnish;" in vcl


def test_vcl_matches_haproxy_backend_name_with_dots_and_dashes(db):
    """The routing header is matched against the HAProxy name, not the VCL identifier.

    HAProxy identifiers allow dots/colons/dashes but VCL identifiers do not, so a
    backend named "ne4u.com-nginx" is declared in VCL as `ne4u_com_nginx` while
    HAProxy still sends `X-Cache-Backend: ne4u.com-nginx`. Comparing against the
    sanitized identifier would never match and every request would fall through.
    """
    from app.services import haproxy
    from app.services.settings import set_setting

    backend = make_backend(db, name="ne4u.com-nginx")
    make_server(db, backend.id, address="10.0.0.1", port=8080)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    set_setting(db, "disk_cache_enabled", "true")

    vcl = varnish.generate_vcl(db)
    # Routing validation uses the unsanitized HAProxy section name.
    assert 'req.http.X-Cache-Backend == "ne4u.com-nginx"' in vcl
    assert 'req.http.X-Cache-Backend == "ne4u_com_nginx"' not in vcl

    # The value HAProxy actually sends must be exactly what the VCL compares.
    cfg = haproxy.generate_config(db)
    assert "http-request set-header X-Cache-Backend ne4u.com-nginx" in cfg


def test_vcl_health_check_returns_200(db):
    """Requests without the routing header (HAProxy health checks) get a 200."""
    backend = make_backend(db, name="hc")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "if (!req.http.X-Cache-Backend) {" in vcl
    assert 'return(synth(200, "OK"));' in vcl
    # A header that matches no backend is still a real error.
    assert 'return(synth(503, "Unknown cache backend"));' in vcl


def test_vcl_no_origin_server_backends(db):
    """Varnish fetches through HAProxy, not directly from origin servers."""
    backend = make_backend(db, name="origin_check")
    make_server(db, backend.id, name="s1", address="10.0.0.99", port=9999)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # Origin server address/port should NOT appear in VCL
    assert '"10.0.0.99"' not in vcl
    assert '"9999"' not in vcl
    # Only the HAProxy backend should be present
    assert "backend haproxy {" in vcl
    assert "import directors" not in vcl


def test_vcl_hash_varies_on_accept(db):
    """vcl_hash normalizes Accept to create separate entries for WebP vs non-WebP."""
    backend = make_backend(db, name="vary_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert "sub vcl_hash {" in vcl
    assert 'hash_data("webp")' in vcl
    assert 'req.http.Accept ~ "(?i)image/webp"' in vcl


def test_vcl_multiple_servers_no_directors(db):
    """Multiple origin servers don't create VCL directors — HAProxy handles load balancing."""
    backend = make_backend(db, name="multi")
    make_server(db, backend.id, name="s1", address="10.0.0.1", port=80)
    make_server(db, backend.id, name="s2", address="10.0.0.2", port=80)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # No directors — HAProxy handles origin server selection
    assert "import directors" not in vcl
    assert "directors.round_robin()" not in vcl
    assert "multi_s0" not in vcl
    assert "multi_s1" not in vcl
    # Still a single HAProxy backend
    assert "backend haproxy {" in vcl


def test_vcl_haproxy_host_from_container_name(db):
    """The VCL backend host is the HAProxy container name (Docker internal DNS)."""
    backend = make_backend(db, name="host_test")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # Default HAPROXY_CONTAINER_NAME is "corex"
    assert '.host = "corex";' in vcl


def test_vcl_haproxy_port_from_listener(db):
    """The VCL backend port is derived from the first enabled HTTP listener."""
    backend = make_backend(db, name="port_test")
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="http", bind_port=8080)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert '.port = "8080";' in vcl


def test_vcl_haproxy_port_falls_back_to_80(db):
    """When no HTTP listeners exist, the port falls back to 80."""
    backend = make_backend(db, name="fallback_port")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert '.port = "80";' in vcl


def test_vcl_haproxy_port_ignores_tcp_listeners(db):
    """TCP-mode listeners are not used for the HAProxy fetch port."""
    backend = make_backend(db, name="tcp_only")
    make_server(db, backend.id)
    # TCP listener should be ignored
    listener = make_listener(db, backend=backend, name="tcp_in", bind_port=3306, mode="tcp")
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # Falls back to 80 since no HTTP listener exists
    assert '.port = "80";' in vcl
    assert '.port = "3306";' not in vcl


def test_vcl_haproxy_port_picks_first_http_listener(db):
    """When multiple HTTP listeners exist, the first (by id) is used."""
    backend = make_backend(db, name="multi_listener")
    make_server(db, backend.id)
    make_listener(db, backend=backend, name="first", bind_port=8080)
    make_listener(db, backend=backend, name="second", bind_port=8443)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert '.port = "8080";' in vcl
    assert '.port = "8443";' not in vcl


def test_vcl_haproxy_port_ignores_ssl_listeners(db):
    """SSL listeners are not used for the Varnish fetch port — Varnish speaks plain HTTP."""
    backend = make_backend(db, name="ssl_skip")
    make_server(db, backend.id)
    # Only an SSL listener exists — should fall back to 80, not use 443
    make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert '.port = "80";' in vcl
    assert '.port = "443";' not in vcl


def test_vcl_haproxy_port_prefers_non_ssl_over_ssl(db):
    """When both SSL and non-SSL HTTP listeners exist, the non-SSL one is used."""
    backend = make_backend(db, name="mixed_ssl")
    make_server(db, backend.id)
    # SSL listener created first (lower id) — non-SSL should still be picked
    make_listener(db, backend=backend, name="https_first", bind_port=8443, ssl_enabled=True)
    make_listener(db, backend=backend, name="http_second", bind_port=8080, ssl_enabled=False)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    assert '.port = "8080";' in vcl
    assert '.port = "8443";' not in vcl


def test_vcl_strips_haproxy_managed_response_headers(db):
    """VCL vcl_backend_response strips HAProxy-managed response headers from
    cached objects so they're not baked into cache and duplicated on delivery."""
    from app.models.models import ResponseHeader
    backend = make_backend(db, name="web")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    # User-configured response headers
    db.add(ResponseHeader(name="h1", header="X-Custom-Header", value="val1", action="set", listener_ids=[]))
    db.add(ResponseHeader(name="h2", header="X-Another", value="val2", action="add", listener_ids=[]))
    # del-action headers should NOT be stripped (they don't add anything)
    db.add(ResponseHeader(name="h3", header="X-Delete-Me", value="unused", action="del", listener_ids=[]))
    db.commit()
    vcl = varnish.generate_vcl(db)
    # set/add headers should be stripped from cached objects
    assert "unset beresp.http.X-Custom-Header;" in vcl
    assert "unset beresp.http.X-Another;" in vcl
    # del-action header should not be stripped
    assert "unset beresp.http.X-Delete-Me;" not in vcl


def test_vcl_strips_csp_headers_when_page_protect_enabled(db):
    """VCL strips Content-Security-Policy headers from cached objects when
    Page Protect policies are enabled."""
    from tests.factories import make_page_protect_policy
    backend = make_backend(db, name="protected")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_page_protect_policy(db, backend_ids=[backend.id], mode="enforce", directives={"default-src": ["'self'"]})
    db.commit()
    vcl = varnish.generate_vcl(db)
    assert "unset beresp.http.Content-Security-Policy;" in vcl


def test_vcl_strips_alt_svc_when_quic_enabled(db):
    """VCL strips Alt-Svc from cached objects when any listener has QUIC enabled."""
    backend = make_backend(db, name="quic_be")
    make_server(db, backend.id)
    listener = make_listener(db, backend=backend, name="quic_in", bind_port=443, ssl_enabled=True)
    # Enable QUIC on the listener
    listener.quic = True
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    db.commit()
    vcl = varnish.generate_vcl(db)
    assert "unset beresp.http.Alt-Svc;" in vcl


def test_vcl_no_header_stripping_when_no_managed_headers(db):
    """When no ResponseHeaders or Page Protect policies are configured, no
    header stripping lines are emitted (beyond Set-Cookie/Cache-Control)."""
    backend = make_backend(db, name="plain")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # Standard strips are always present
    assert "unset beresp.http.Set-Cookie;" in vcl
    assert "unset beresp.http.Cache-Control;" in vcl
    # No HAProxy-managed header stripping comment
    assert "HAProxy-managed response headers" not in vcl
