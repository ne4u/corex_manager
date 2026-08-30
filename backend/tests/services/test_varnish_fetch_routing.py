"""Tests for Varnish fetch routing on force_https listeners.

When a listener has force_https=True and ssl_enabled=False, it exists solely
to redirect HTTP traffic to HTTPS. But Varnish fetches (which skip the
redirect via !is_varnish_fetch) still need to be routed to the correct
backend based on the Host header. This listener has no BackendRules of its
own, so the generator queries BackendRules from all other enabled HTTP-mode
listeners and emits their ACLs + use_backend rules conditioned on
is_varnish_fetch.
"""
from app.services import haproxy
from app.models.models import BackendRule, CacheRule
from app.services.settings import set_setting
from tests.factories import make_backend, make_server, make_cache_config, make_listener


def _make_backend_rule(db, listener_id, backend_id, condition_type="host", operator="reg", value="example\\.com", priority=100):
    rule = BackendRule(
        listener_id=listener_id,
        backend_id=backend_id,
        name=f"rule_{backend_id}",
        priority=priority,
        condition_type=condition_type,
        operator=operator,
        value=value,
        enabled=True,
    )
    db.add(rule)
    db.flush()
    return rule


def test_force_https_listener_emits_varnish_fetch_routing(db):
    """force_https listener emits use_backend rules from other listeners for Varnish fetches."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id, address="10.0.0.1", port=8080)

    # SSL listener (port 443) with a BackendRule routing by host
    ssl_listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    _make_backend_rule(db, ssl_listener.id, backend.id, value="example\\.com")

    # HTTP listener (port 80) with force_https — no BackendRules of its own
    http_listener = make_listener(db, name="http_in", bind_port=80, ssl_enabled=False)
    http_listener.force_https = True

    # Enable disk cache
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True, haproxy_enabled=False)
    rule = CacheRule(cache_config_id=cc.id, tier="disk", match_type="path", pattern="/static", action="cache", priority=1, enabled=True)
    db.add(rule)
    db.commit()
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)

    # The force_tls (http_in) frontend should have:
    # 1. ACL declarations with vfetch_ prefix
    # 2. use_backend rules conditioned on is_varnish_fetch
    # Split on \nfrontend (not just "frontend") because the log-format
    # string contains "frontend":"%f" which would break a naive split.
    http_section = cfg.split("frontend http_in")[1].split("\nfrontend ")[0] if "frontend http_in" in cfg else ""
    assert "acl vfetch_rule_" in http_section, "Varnish fetch ACL not emitted on force_https listener"
    assert "use_backend web if is_varnish_fetch" in http_section, "Varnish fetch use_backend not emitted"


def test_force_https_listener_no_varnish_routing_without_disk_cache(db):
    """force_https listener does NOT emit Varnish fetch routing when disk cache is off."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)

    ssl_listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    _make_backend_rule(db, ssl_listener.id, backend.id)

    http_listener = make_listener(db, name="http_in", bind_port=80, ssl_enabled=False)
    http_listener.force_https = True

    db.commit()
    # disk_cache_enabled defaults to false
    cfg = haproxy.generate_config(db)

    http_section = cfg.split("frontend http_in")[1].split("\nfrontend ")[0] if "frontend http_in" in cfg else ""
    assert "vfetch_rule_" not in http_section, "Varnish fetch routing emitted even without disk cache"


def test_ssl_listener_not_affected_by_varnish_fetch_routing(db):
    """SSL listener with its own BackendRules doesn't get vfetch_ prefixed rules."""
    backend = make_backend(db, name="web")
    make_server(db, backend.id)

    ssl_listener = make_listener(db, backend=backend, name="https_in", bind_port=443, ssl_enabled=True)
    _make_backend_rule(db, ssl_listener.id, backend.id)

    http_listener = make_listener(db, name="http_in", bind_port=80, ssl_enabled=False)
    http_listener.force_https = True

    cc = make_cache_config(db, backend.id, disk_cache_enabled=True, haproxy_enabled=False)
    rule = CacheRule(cache_config_id=cc.id, tier="disk", match_type="path", pattern="/static", action="cache", priority=1, enabled=True)
    db.add(rule)
    db.commit()
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)

    # The SSL listener should use its own be_rule_ prefixed ACLs, not vfetch_
    ssl_section = cfg.split("frontend https_in")[1].split("\nfrontend ")[0] if "frontend https_in" in cfg else ""
    assert "be_rule_" in ssl_section, "SSL listener should have its own BackendRule ACLs"
    assert "vfetch_rule_" not in ssl_section, "SSL listener should not have vfetch_ prefixed ACLs"
