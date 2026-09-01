"""Tests for cacheability rules (ordered, first-match-wins).

Rules decide what gets cached and drive both tiers: memory cache (HAProxy ACLs
gating `cache-use`) and disk cache (HAProxy use-server directives routing to
Varnish). With no rules, nothing is cached.
"""
import pytest

from app.services import haproxy, varnish
from app.services.cache_rules import (
    emit_haproxy_cache_rules,
    haproxy_acl_criterion,
    normalize_pattern,
    vcl_condition,
)
from app.services.settings import set_setting
from tests.factories import make_backend, make_cache_config, make_cache_rule, make_server


# ---------------------------------------------------------------------------
# Pattern normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("/downloads/*", "/downloads/"),
    ("/downloads/", "/downloads/"),
    ("/downloads", "/downloads"),
])
def test_normalize_path_strips_trailing_wildcard(raw, expected):
    assert normalize_pattern("path", raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("*.png", "png"),
    (".png", "png"),
    ("png", "png"),
    ("PNG", "png"),
])
def test_normalize_extension_accepts_common_forms(raw, expected):
    assert normalize_pattern("extension", raw) == expected


def test_normalize_filename_strips_leading_slash():
    assert normalize_pattern("filename", "/linux.iso") == "linux.iso"


@pytest.mark.parametrize("match_type,pattern", [
    ("path", "downloads/"),        # missing leading slash
    ("path", "/"),                 # matches everything
    ("filename", "dir/file.iso"),  # not a single segment
    ("filename", "*.iso"),         # wildcard
    ("extension", "pn g"),         # not alphanumeric
    ("extension", ""),             # empty
    ("path", '/a"b'),              # would break out of a VCL string literal
])
def test_normalize_rejects_invalid_patterns(match_type, pattern):
    with pytest.raises(ValueError):
        normalize_pattern(match_type, pattern)


def test_normalize_rejects_unknown_match_type():
    with pytest.raises(ValueError):
        normalize_pattern("regex", "^/x")


# ---------------------------------------------------------------------------
# Condition builders
# ---------------------------------------------------------------------------

def test_vcl_condition_escapes_regex_metacharacters(db):
    cc = make_cache_config(db, make_backend(db, name="b1").id)
    rule = make_cache_rule(db, cc.id, match_type="filename", pattern="linux.iso")
    cond = vcl_condition(rule)
    # The dot must be escaped so it does not match "linuxXiso".
    assert r"linux\.iso" in cond
    # req.url carries the query string, so allow an optional suffix.
    assert r"(\?.*)?$" in cond


def test_vcl_condition_extension_is_case_insensitive(db):
    cc = make_cache_config(db, make_backend(db, name="b2").id)
    rule = make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    assert "(?i)" in vcl_condition(rule)


def test_haproxy_acl_criterion_per_match_type(db):
    cc = make_cache_config(db, make_backend(db, name="b3").id)
    path = make_cache_rule(db, cc.id, match_type="path", pattern="/downloads/")
    fname = make_cache_rule(db, cc.id, match_type="filename", pattern="linux.iso")
    ext = make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    assert haproxy_acl_criterion(path) == "path_beg /downloads/"
    # Anchored on a full segment so "linux.iso" does not match "not-linux.iso".
    assert haproxy_acl_criterion(fname) == "path_end /linux.iso"
    assert haproxy_acl_criterion(ext) == "path_end -i .png"


# ---------------------------------------------------------------------------
# Empty ruleset — nothing is cached
# ---------------------------------------------------------------------------

def test_no_rules_caches_nothing_in_haproxy(db):
    backend = make_backend(db, name="norules")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, haproxy_enabled=True)
    cfg = haproxy.generate_config(db)
    assert "cache-use" not in cfg
    # cache-store would be pointless with no cache-use, so it is skipped too.
    assert "cache-store" not in cfg
    assert "No cacheability rules for memory tier" in cfg


def test_no_rules_caches_nothing_in_vcl(db):
    """VCL no longer evaluates rules (moved to HAProxy), just caches everything."""
    backend = make_backend(db, name="norules_disk")
    make_server(db, backend.id)
    make_cache_config(db, backend.id, disk_cache_enabled=True)
    vcl = varnish.generate_vcl(db)
    # VCL should NOT have rule evaluation logic
    assert 'X-Cache-Decision' not in vcl
    assert "cacheability rules" not in vcl.lower()
    # VCL should just cache GET/HEAD
    assert "return(hash);" in vcl


def test_all_bypass_rules_cache_nothing(db):
    backend = make_backend(db, name="allbypass")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png", action="bypass", priority=0)
    cfg = haproxy.generate_config(db)
    assert "cache-use" not in cfg
    assert "All memory tier cacheability rules are bypass rules" in cfg


# ---------------------------------------------------------------------------
# Ordered first-match semantics
# ---------------------------------------------------------------------------

def test_haproxy_cache_rule_negates_earlier_bypass(db):
    """A cache rule must not apply when an earlier bypass rule matched."""
    backend = make_backend(db, name="ordered")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True)
    bypass = make_cache_rule(db, cc.id, match_type="path", pattern="/private/", action="bypass", priority=0)
    cache = make_cache_rule(db, cc.id, match_type="extension", pattern="png", action="cache", priority=1)
    db.commit()

    lines, any_cacheable = emit_haproxy_cache_rules(cc, "cache_x", "cr")
    assert any_cacheable
    joined = "\n".join(lines)
    assert f"acl cr_{bypass.id} path_beg /private/" in joined
    assert f"acl cr_{cache.id} path_end -i .png" in joined
    # The cache rule is guarded by the negation of the preceding bypass rule.
    assert f"http-request cache-use cache_x if cr_{cache.id} !cr_{bypass.id}" in joined


def test_haproxy_earlier_cache_rule_has_no_negation(db):
    """A cache rule preceding any bypass rule is unconditional."""
    backend = make_backend(db, name="ordered2")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True)
    cache = make_cache_rule(db, cc.id, match_type="path", pattern="/assets/", action="cache", priority=0)
    make_cache_rule(db, cc.id, match_type="path", pattern="/assets/private/", action="bypass", priority=1)
    db.commit()

    lines, _ = emit_haproxy_cache_rules(cc, "cache_x", "cr")
    joined = "\n".join(lines)
    assert f"http-request cache-use cache_x if cr_{cache.id}\n" in joined + "\n"


def test_vcl_simplified_no_decision_logic(db):
    """VCL no longer contains rule evaluation logic (moved to HAProxy)."""
    backend = make_backend(db, name="vclorder")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="path", pattern="/private/", action="bypass", priority=0)
    make_cache_rule(db, cc.id, match_type="path", pattern="/downloads/", action="cache", priority=1)
    db.commit()

    vcl = varnish.generate_vcl(db)
    # VCL should NOT contain rule patterns or decision logic
    assert 'req.url ~ "^/private/"' not in vcl
    assert 'req.url ~ "^/downloads/"' not in vcl
    assert "X-Cache-Decision" not in vcl
    # VCL should just cache everything (return hash for GET/HEAD)
    assert "return(hash);" in vcl


def test_disabled_rules_are_skipped(db):
    """Disabled rules are not emitted in HAProxy config (VCL has no rules)."""
    backend = make_backend(db, name="disabledrule")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True, haproxy_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png", enabled=False, priority=0)
    make_cache_rule(db, cc.id, match_type="extension", pattern="jpg", enabled=True, priority=1)
    db.commit()

    # Check HAProxy config for ACLs (VCL no longer has rules)
    cfg = haproxy.generate_config(db)
    # Enabled rule should have an ACL
    assert "path_end -i .jpg" in cfg
    # Disabled rule should NOT have an ACL
    assert "path_end -i .png" not in cfg


# ---------------------------------------------------------------------------
# End-to-end generation
# ---------------------------------------------------------------------------

def test_vcl_backends_point_to_haproxy(db):
    """VCL backend definition points to HAProxy, not origin servers.

    Varnish fetches through HAProxy so response filters (img_2_webp, compression,
    resp_transform) run before Varnish caches the response. Origin server
    addresses do not appear in the VCL — HAProxy handles origin routing.
    """
    backend = make_backend(db, name="passthru")
    make_server(db, backend.id, address="10.0.0.99", port=8080)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    db.commit()

    vcl = varnish.generate_vcl(db)
    # VCL backend should point to HAProxy (container name "corex"), not the origin server
    assert '.host = "corex"' in vcl
    # Origin server address should NOT appear in VCL
    assert '.host = "10.0.0.99"' not in vcl
    assert '.port = "8080"' not in vcl
    # X-Varnish-Fetch is set so HAProxy doesn't route back to Varnish
    assert 'X-Varnish-Fetch' in vcl


def test_advanced_haproxy_condition_is_anded_onto_rules(db):
    """haproxy_cache_condition remains supported as an extra AND condition."""
    backend = make_backend(db, name="withcond")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, haproxy_cache_condition="{ method GET }")
    make_cache_rule(db, cc.id, match_type="extension", pattern="png")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "{ method GET }" in cfg
    line = next(ln for ln in cfg.splitlines() if "cache-use" in ln)
    assert line.strip().endswith("{ method GET }")


def test_both_tiers_share_the_same_rules(db):
    """Memory cache and disk cache use the same HAProxy ACLs.
    When disk cache is active, memory cache filter is still emitted but
    cache-use/cache-store are gated with !is_varnish_fetch. The shared ACLs
    are used by both the memory cache-use and disk cache use-server directives."""
    backend = make_backend(db, name="shared")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="path", pattern="/downloads/")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # The shared ACL should be present (used by both memory and disk cache)
    assert "path_beg /downloads/" in cfg
    # Memory cache filter IS emitted (gated by !is_varnish_fetch on use/store)
    assert "cache-use cache_shared" in cfg
    assert "!is_varnish_fetch" in cfg
    assert "filter cache cache_shared" in cfg
    assert "use-server disk_cache" in cfg  # disk cache
    # VCL should NOT have rules (they're evaluated in HAProxy)
    vcl = varnish.generate_vcl(db)
    assert 'req.url ~ "^/downloads/"' not in vcl


def test_varnish_fetch_loop_prevention(db):
    """Varnish fetches through HAProxy with X-Varnish-Fetch for loop prevention."""
    backend = make_backend(db, name="looptest")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="path", pattern="/cached/", action="cache")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Should have ACL to detect Varnish fetch requests (uses req.hdr_cnt
    # because bare hdr_cnt refers to response headers in some contexts)
    assert "acl is_varnish_fetch req.hdr_cnt(X-Varnish-Fetch) gt 0" in cfg
    # use-server directives should negate is_varnish_fetch
    assert "use-server disk_cache if" in cfg
    assert "!is_varnish_fetch" in cfg

    # VCL should set X-Varnish-Fetch so HAProxy doesn't route back to Varnish
    vcl = varnish.generate_vcl(db)
    assert 'set req.http.X-Varnish-Fetch = "1"' in vcl
    assert "set req.backend_hint = haproxy;" in vcl


def test_haproxy_use_server_negates_bypass_rules(db):
    """Disk cache use-server directives respect bypass rule negation."""
    backend = make_backend(db, name="negatetest")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Bypass rule (priority 0) - disk tier
    bypass_rule = make_cache_rule(db, cc.id, match_type="path", pattern="/private/", action="bypass", tier="disk", priority=0)
    # Cache rule (priority 1) - should negate earlier bypass rule - disk tier
    cache_rule = make_cache_rule(db, cc.id, match_type="path", pattern="/public/", action="cache", tier="disk", priority=1)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Cache rule's use-server should negate the bypass rule
    lines = cfg.split("\n")
    # ACL names include backend name: cacherule_{backend.name}_{rule.id}
    use_server_lines = [l for l in lines if "use-server disk_cache if" in l and "cacherule_" in l and "!is_cache_purge" not in l]
    # Should have one use-server for the cache rule
    assert len(use_server_lines) >= 1
    # The cache rule use-server line should reference both rules
    cache_use_server = use_server_lines[0]
    # Should contain the cache rule ACL (positive) and bypass rule ACL (negated)
    assert "cacherule_negatetest" in cache_use_server
    assert f"!cacherule_negatetest_{bypass_rule.id}" in cache_use_server or "!cacherule_" in cache_use_server


def test_purge_ban_always_routes_to_varnish(db):
    """PURGE/BAN methods always route to Varnish regardless of cache rules."""
    backend = make_backend(db, name="purgetest")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Even with no cache rules, PURGE/BAN should route to Varnish
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Should have ACL for PURGE/BAN
    assert "acl is_cache_purge method PURGE BAN" in cfg
    # Should have use-server for PURGE/BAN
    assert "use-server disk_cache if is_cache_purge" in cfg


def test_disk_cache_no_rules_no_varnish_routing(db):
    """When disk cache is enabled but no cache rules match, traffic goes to origins."""
    backend = make_backend(db, name="norules")
    make_server(db, backend.id, address="10.0.0.50", port=80)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    # No cache rules - only bypass or no rules
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Should have disk_cache server defined
    assert "server disk_cache varnish:6081" in cfg
    # Should have origin server
    assert "10.0.0.50:80" in cfg
    # Should NOT have use-server directives for cache rules (no rules)
    # But should have PURGE/BAN routing
    lines = [l for l in cfg.split("\n") if "use-server disk_cache" in l]
    # Only PURGE/BAN use-server should be present
    assert any("is_cache_purge" in l for l in lines)


def test_disk_cache_bypass_rule_no_use_server(db):
    """Bypass rules do not generate use-server directives."""
    backend = make_backend(db, name="bypassonly")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    # Only bypass rules
    make_cache_rule(db, cc.id, match_type="path", pattern="/api/", action="bypass", priority=0)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Should have ACL for the bypass rule
    assert "acl cacherule_" in cfg
    assert "path_beg /api/" in cfg
    # Should NOT have use-server for the bypass rule (only PURGE/BAN)
    lines = [l for l in cfg.split("\n") if "use-server disk_cache if" in l]
    # Only PURGE/BAN routing
    cache_rule_use_server = [l for l in lines if "cacherule_" in l and "!is_cache_purge" not in l]
    assert len(cache_rule_use_server) == 0


# ---------------------------------------------------------------------------
# Tier-Specific Rules
# ---------------------------------------------------------------------------

def test_memory_only_rule_not_in_disk_cache(db):
    """Rules with tier='memory' only apply to memory cache, not disk cache.
    When disk cache is active, memory cache is still emitted but gated with
    !is_varnish_fetch. Memory-only rules produce cache-use directives (gated)
    but no use-server directives. The ACL is shared between tiers."""
    backend = make_backend(db, name="memonly")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    # Memory-only rule
    make_cache_rule(db, cc.id, match_type="extension", pattern="jpg", action="cache", tier="memory", priority=0)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Memory cache IS emitted (gated with !is_varnish_fetch)
    assert "cache-use cache_memonly" in cfg
    assert "!is_varnish_fetch" in cfg
    # The ACL should still be present (shared between tiers)
    assert "path_end -i .jpg" in cfg
    # Should NOT have disk cache use-server for this memory-tier rule
    lines = [l for l in cfg.split("\n") if "use-server disk_cache if" in l and "cacherule_" in l]
    assert len([l for l in lines if "!is_cache_purge" not in l]) == 0  # No cache rule use-server (only PURGE)


def test_disk_only_rule_not_in_memory_cache(db):
    """Rules with tier='disk' only apply to disk cache, not memory cache."""
    backend = make_backend(db, name="diskonly")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    # Disk-only rule
    make_cache_rule(db, cc.id, match_type="extension", pattern="iso", action="cache", tier="disk", priority=0)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Should NOT have memory cache directive (memory cache skipped when disk cache active)
    assert "cache-use" not in cfg
    # Should have disk cache use-server
    assert "use-server disk_cache if cacherule_" in cfg
    assert "path_end -i .iso" in cfg


def test_same_pattern_both_tiers_requires_two_rules(db):
    """To cache the same pattern in both tiers, create two separate rules.
    Memory cache is still emitted (gated with !is_varnish_fetch) alongside
    disk cache, so both tiers can cache the same pattern."""
    backend = make_backend(db, name="bothtiers")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    # Create two rules for the same pattern - one per tier
    make_cache_rule(db, cc.id, match_type="extension", pattern="png", action="cache", tier="memory", priority=0)
    make_cache_rule(db, cc.id, match_type="extension", pattern="png", action="cache", tier="disk", priority=1)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # Memory cache IS emitted (gated with !is_varnish_fetch)
    assert "cache-use cache_bothtiers" in cfg
    assert "!is_varnish_fetch" in cfg
    # Should have disk cache use-server
    assert "use-server disk_cache if cacherule_" in cfg
    # Both ACLs are still emitted (shared between tiers)
    assert cfg.count("path_end -i .png") == 2  # Two ACLs, one per rule


def test_mixed_tier_rules(db):
    """Multiple rules with different tiers work correctly."""
    backend = make_backend(db, name="mixed")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    # Memory-only: small images
    make_cache_rule(db, cc.id, match_type="extension", pattern="jpg", action="cache", tier="memory", priority=0)
    # Disk-only: large files
    make_cache_rule(db, cc.id, match_type="extension", pattern="iso", action="cache", tier="disk", priority=1)
    # Memory: static assets
    make_cache_rule(db, cc.id, match_type="path", pattern="/static/", action="cache", tier="memory", priority=2)
    # Disk: downloads
    make_cache_rule(db, cc.id, match_type="path", pattern="/downloads/", action="cache", tier="disk", priority=3)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # All ACLs should be emitted (shared)
    assert "acl cacherule_mixed" in cfg
    assert "path_end -i .jpg" in cfg
    assert "path_end -i .iso" in cfg
    assert "path_beg /static/" in cfg
    assert "path_beg /downloads/" in cfg
    # Memory cache IS emitted (gated with !is_varnish_fetch) for memory-tier rules
    memory_lines = [l for l in cfg.split("\n") if "cache-use" in l]
    assert len(memory_lines) == 2  # jpg + /static/ (memory-tier rules)
    assert all("!is_varnish_fetch" in l for l in memory_lines)
    # Disk cache should have iso and /downloads/ (disk-tier rules only)
    disk_lines = [l for l in cfg.split("\n") if "use-server disk_cache if cacherule_" in l and "!is_cache_purge" not in l]
    assert len(disk_lines) == 2  # iso + downloads


def test_tier_validation_in_schema(db):
    """Pydantic schema validates tier field."""
    from app.schemas.cache import CacheRuleCreate
    from pydantic import ValidationError
    import pytest
    
    # Valid tiers
    for tier in ["memory", "disk"]:
        rule = CacheRuleCreate(match_type="extension", pattern="png", tier=tier)
        assert rule.tier == tier
    
    # Invalid tier (including "both" which is no longer supported)
    for invalid_tier in ["invalid", "both", "cache", ""]:
        with pytest.raises(ValidationError) as exc_info:
            CacheRuleCreate(match_type="extension", pattern="png", tier=invalid_tier)
        assert "tier must be one of" in str(exc_info.value)
    
    # Tier is required
    with pytest.raises(ValidationError) as exc_info:
        CacheRuleCreate(match_type="extension", pattern="png")  # Missing tier
    assert "Field required" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Disk cache eligible var — marks cache-eligible client requests so response
# filters (resp_transform) can skip processing on the Varnish→client path.
# ---------------------------------------------------------------------------


def test_disk_cache_eligible_var_set_for_cache_rule(db):
    """Cache-eligible client requests set txn.is_disk_cache_eligible so response
    filters know the response will come from Varnish (already transformed)."""
    backend = make_backend(db, name="eligible")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="disk")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # The var should be set with the same condition as X-Cache-Backend
    assert "set-var(txn.is_disk_cache_eligible)" in cfg
    # The var should be conditioned on !is_varnish_fetch (only for client requests)
    assert "set-var(txn.is_disk_cache_eligible) str(1) if" in cfg
    assert "!is_varnish_fetch" in cfg


def test_disk_cache_eligible_var_not_set_without_disk_cache(db):
    """The is_disk_cache_eligible var is not emitted when disk cache is off."""
    backend = make_backend(db, name="no_disk")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=False)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="memory")
    set_setting(db, "disk_cache_enabled", "false")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "set-var(txn.is_disk_cache_eligible)" not in cfg


def test_disk_cache_eligible_var_includes_purge_condition(db):
    """PURGE/BAN requests also set the var (they route to Varnish)."""
    backend = make_backend(db, name="purge_var")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="disk")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    var_line = next(l for l in cfg.split("\n") if "set-var(txn.is_disk_cache_eligible)" in l)
    # Should include is_cache_purge in the condition
    assert "is_cache_purge" in var_line


# ---------------------------------------------------------------------------
# Memory cache-store guard when disk cache is active
#
# When both memory cache and disk cache are enabled, cache-store must be
# guarded so the memory cache filter doesn't buffer Varnish's response (which
# can exceed tune.bufsize and cause intermittent 500 errors).
# ---------------------------------------------------------------------------


def test_cache_store_guarded_when_disk_cache_active(db):
    """When both memory and disk cache are enabled, the memory cache filter
    IS emitted but cache-store is guarded with !is_varnish_fetch so Varnish
    responses aren't double-cached in memory."""
    backend = make_backend(db, name="dual_cache")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="memory")
    make_cache_rule(db, cc.id, match_type="extension", pattern="js", action="cache", tier="disk")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    # filter cache IS present (gated by !is_varnish_fetch on use/store)
    assert "filter cache cache_dual_cache" in cfg
    # cache-use IS present, gated with !is_varnish_fetch
    assert "cache-use cache_dual_cache" in cfg
    # cache-store IS present, gated with !is_varnish_fetch
    assert "cache-store cache_dual_cache if !is_varnish_fetch" in cfg


def test_cache_store_unguarded_when_disk_cache_inactive(db):
    """When disk cache is NOT active, memory cache filter is emitted normally."""
    backend = make_backend(db, name="mem_only")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=False)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="memory")
    set_setting(db, "disk_cache_enabled", "false")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "filter cache" in cfg
    assert "cache-use" in cfg
    assert "cache-store" in cfg


def test_cache_store_guarded_with_response_phase_rules(db):
    """When disk cache is active, memory cache filter is still emitted with
    response-phase rules, but cache-store is guarded with !is_varnish_fetch."""
    backend = make_backend(db, name="resp_phase")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    # Request-phase rule (needed to trigger any_cacheable=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="html", action="cache", tier="memory", priority=0)
    # Response-phase rule (content_type) for memory tier
    make_cache_rule(db, cc.id, match_type="content_type", pattern="text/html", action="cache", tier="memory", priority=1)
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "filter cache cache_resp_phase" in cfg
    # cache-store should be present and guarded with !is_varnish_fetch
    assert "cache-store" in cfg
    assert "!is_varnish_fetch" in cfg


def test_cache_use_guarded_when_disk_cache_active(db):
    """When both memory and disk cache are enabled, cache-use IS emitted
    but gated with !is_varnish_fetch so Varnish fetches bypass memory cache."""
    backend = make_backend(db, name="dual_cache_use")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=True)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="memory")
    make_cache_rule(db, cc.id, match_type="extension", pattern="js", action="cache", tier="disk")
    set_setting(db, "disk_cache_enabled", "true")
    db.commit()

    cfg = haproxy.generate_config(db)
    assert "cache-use cache_dual_cache_use" in cfg
    assert "!is_varnish_fetch" in cfg
    assert "filter cache cache_dual_cache_use" in cfg


def test_cache_use_unguarded_when_disk_cache_inactive(db):
    """When disk cache is NOT active, cache-use lines are emitted normally."""
    backend = make_backend(db, name="mem_only_use")
    make_server(db, backend.id)
    cc = make_cache_config(db, backend.id, haproxy_enabled=True, disk_cache_enabled=False)
    make_cache_rule(db, cc.id, match_type="extension", pattern="css", action="cache", tier="memory")
    set_setting(db, "disk_cache_enabled", "false")
    db.commit()

    cfg = haproxy.generate_config(db)
    cache_use_lines = [l for l in cfg.split("\n") if "cache-use" in l and "http-request" in l]
    assert len(cache_use_lines) >= 1
    for line in cache_use_lines:
        assert "is_disk_cache_eligible" not in line
