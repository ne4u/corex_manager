"""Comprehensive tests for the Terraform export service.

Covers:
  - Collection completeness (every model exported)
  - FK resolution (cross-module, same-module, list FKs)
  - Secret flag behavior (4 flags × all secret field types)
  - Sensitive settings handling
  - Runtime state exclusion
  - Non-name-keyed models
  - External file generation
  - Root main.tf / variables.tf wiring consistency
  - HCL structural validity
"""
import io
import re
import zipfile

import pytest
from sqlalchemy import inspect as sa_inspect

from app.services.terraform_export import (
    generate_terraform_export,
    SKIP_FIELDS,
    SKIP_SETTING_KEYS,
    SENSITIVE_SETTING_KEYS,
    EXCLUDED_TABLES,
)
from app.models.models import (
    AsnList, Backend, BackendRule, CacheConfig, CacheRule, Certificate, CipherSuite,
    CustomErrorPage, DynamicFeed, FcgiApp, GeoList, Ja4List, Listener,
    LogDestination, LoggedField, NetworkList, NetworkListEntry, OpenApiSpec,
    PageProtectPolicy, PatternList, RateLimit, Redirect, RequestHeader,
    ResponseHeader, ResponseTransform, Rewrite, RiskRule, RiskRuleset,
    SecurityRule, Server, Setting, User, WafException, WafRule,
    WafSiemIntegration,
)
from app.models.api_armor import ApiKeyList, ApiKeyListEntry, ApiSchema, AuthPolicy
from app.models.mcp import (
    McpDlpRule, McpGuardrail, McpIdentity, McpPolicy, McpServer,
    McpServerReplica, McpSkill, McpSkillVersion, Team, UserTeam,
)
from tests.factories import (
    make_backend, make_listener, make_server, make_waf_rule,
    make_waf_exception, make_siem_integration, make_rate_limit,
    make_security_rule, make_rewrite, make_request_header,
    make_page_protect_policy, make_cache_config, make_cache_rule,
    make_response_transform,
)


# ─── Helpers ────────────────────────────────────────────────────────────────

def _export(db, **kwargs):
    """Run generate_terraform_export and return a ZipFile."""
    zb = generate_terraform_export(db, **kwargs)
    return zipfile.ZipFile(io.BytesIO(zb))


def _read(zf, path):
    """Read a file from the export ZIP."""
    return zf.read(path).decode("utf-8")


def _tfvars(zf):
    return _read(zf, "environments/dev.tfvars")


def _module_tf(zf, mod_name):
    return _read(zf, f"modules/{mod_name}/main.tf")


def _module_var_tf(zf, mod_name):
    """Read a module's variables.tf from the export ZIP."""
    return _read(zf, f"modules/{mod_name}/variables.tf")


def _module_locals_tf(zf, mod_name):
    """Read a module's locals.tf from the export ZIP."""
    return _read(zf, f"modules/{mod_name}/locals.tf")


def _has_module(zf, mod_name):
    try:
        zf.read(f"modules/{mod_name}/main.tf")
        return True
    except KeyError:
        return False


def _collection_keys(tfvars_text):
    """Extract top-level collection names from tfvars (lines like 'name = {')."""
    return set(re.findall(r'^([a-z_]+) = \{', tfvars_text, re.MULTILINE))


def _collection_entries(tfvars_text, col_name):
    """Extract the entry keys for a collection from tfvars."""
    m = re.search(rf'^{col_name} = \{{(.*?)\n\}}', tfvars_text, re.MULTILINE | re.DOTALL)
    if not m:
        return set()
    return set(re.findall(r'"([^"]+)" = \{', m.group(1)))


def _entry_fields(tfvars_text, col_name, entry_key):
    """Extract field names for a specific entry in a tfvars collection."""
    m = re.search(rf'^{col_name} = \{{(.*?)\n\}}', tfvars_text, re.MULTILINE | re.DOTALL)
    if not m:
        return set()
    entry_m = re.search(rf'"{re.escape(entry_key)}" = \{{([^}}]*)\}}', m.group(1))
    if not entry_m:
        return set()
    return set(re.findall(r'"(\w+)" = ', entry_m.group(1)))


def _populate_full_config(db):
    """Populate the DB with a comprehensive set of configuration data."""
    be = make_backend(db, name="web")
    ln = make_listener(db, backend=be, name="https", bind_port=443, ssl_enabled=True)
    make_server(db, be.id, name="web1")
    db.add(BackendRule(name="api", listener_id=ln.id, backend_id=be.id, priority=100,
                       condition_type="path", condition_name="path", operator="beg", value="/api"))
    db.flush()

    # Traffic
    db.add(CustomErrorPage(code=503, content="<h1>503</h1>", content_type="text/html"))
    db.add(FcgiApp(name="php", docroot="/var/www"))
    make_rate_limit(db, listener_id=ln.id, name="api_limit")
    db.add(ResponseHeader(name="hsts", listener_id=ln.id,
                          header="Strict-Transport-Security", value="max-age=31536000"))
    make_request_header(db, backend_id=be.id, name="xfwd")
    db.add(Redirect(name="www", listener_id=ln.id, source="/old", target="/new", code=301))
    make_rewrite(db, listener_id=ln.id, name="api_rw")
    make_response_transform(db, backend_id=be.id, name="gzip")

    # Security lists
    nl = NetworkList(name="blocked", description="Bad IPs")
    db.add(nl); db.flush()
    db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.0/8", note="internal"))
    db.add(NetworkListEntry(list_id=nl.id, value="192.168.0.0/16"))
    db.add(GeoList(name="geo_block"))
    db.add(PatternList(name="sqli"))
    db.add(DynamicFeed(name="feed1", list_type="network", target_list_id=nl.id,
                       url="https://example.com/feed", update_interval_hours=3600))

    # Security rules
    make_security_rule(db, name="block_bots", listener_ids=[ln.id], action="deny",
                       expression='hdr(user-agent) -m sub bot')

    # WAF
    siem = make_siem_integration(db, name="splunk")
    wr = make_waf_rule(db, name="sqli_rule", listener_id=ln.id, backend_id=be.id,
                       siem_integration_id=siem.id)
    make_waf_exception(db, waf_rule_id=wr.id, name="allow_admin", rule_id="942100")

    # Cache
    cc = make_cache_config(db, backend_id=be.id)
    make_cache_rule(db, cache_config_id=cc.id)

    # Observability
    db.add(LogDestination(name="syslog", listener_id=ln.id, target="127.0.0.1:514"))
    db.add(LoggedField(name="custom", listener_id=ln.id, field="X-Custom"))

    # Page protect
    make_page_protect_policy(db, backend_ids=[be.id])

    # API Armor
    db.add(AuthPolicy(name="bearer", listener_ids=[ln.id], backend_ids=[be.id], auth_type="bearer"))
    akl = ApiKeyList(name="keys", description="API keys")
    db.add(akl); db.flush()
    db.add(ApiKeyListEntry(list_id=akl.id, value="key123", note="test key"))
    db.add(OpenApiSpec(name="api_v1", listener_ids=[ln.id], backend_ids=[be.id], spec="openapi: 3.0.0"))
    db.add(ApiSchema(name="schema1", method="GET", path="/api",
                     schema='{"type":"object"}', source="manual", enabled=True))

    # Risk scoring
    rs = RiskRuleset(name="default_rs", slug="default_rs", enabled=True)
    db.add(rs); db.flush()
    db.add(RiskRule(name="high", ruleset_id=rs.id, expression="score > 80", points=100))

    # Management
    db.add(User(username="admin", email="admin@ex.com", role="admin",
               hashed_password="$2b$12$abc", is_admin=True))
    db.add(Setting(key="site_name", value="coreX"))
    db.add(Setting(key="session_timeout_minutes", value="30"))

    # MCP Gateway
    team = Team(name="Eng", slug="eng")
    db.add(team); db.flush()
    srv = McpServer(name="tools", team_id=team.id, namespace="eng", transport_type="stdio")
    db.add(srv); db.flush()
    db.add(McpServerReplica(server_id=srv.id, url="http://localhost:8080"))
    db.add(McpIdentity(name="bot", team_id=team.id, kind="pat"))
    db.add(McpPolicy(name="pol", team_id=team.id, expression="true", action="allow"))
    db.add(McpDlpRule(name="dlp1", team_id=team.id, detector="regex", find_regex="key", action="redact"))
    db.add(McpGuardrail(name="jb", team_id=team.id, pack="jailbreak", action="block"))
    skill = McpSkill(name="helper", team_id=team.id)
    db.add(skill); db.flush()
    db.add(McpSkillVersion(skill_id=skill.id, version="1.0.0", body="# Helper",
                          frontmatter={"v": "1.0.0"}))

    db.commit()


# ─── Completeness: every model collection is exported ───────────────────────

class TestCollectionCompleteness:

    def test_all_modules_generated_with_data(self, db):
        """All 13 modules should be generated when data exists for them."""
        _populate_full_config(db)
        zf = _export(db)
        for mod in ['routing', 'traffic', 'security-lists', 'security-rules',
                    'waf', 'cache', 'observability', 'page-protect', 'api-armor',
                    'risk-scoring', 'management', 'mcp-gateway']:
            assert _has_module(zf, mod), f"Module '{mod}' not generated"

    def test_ssl_module_generated_with_certs(self, db):
        db.add(Certificate(name="wildcard", domain="*.example.com"))
        db.commit()
        zf = _export(db)
        assert _has_module(zf, 'ssl')

    def test_empty_db_produces_valid_zip(self, db):
        """An empty DB should still produce a valid ZIP with root files."""
        zf = _export(db)
        for f in ['backend.tf', 'versions.tf', 'providers.tf', 'main.tf',
                  'variables.tf', 'outputs.tf', '.gitignore', 'README.md']:
            assert f in zf.namelist(), f"Root file '{f}' missing"

    def test_all_expected_collections_in_tfvars(self, db):
        """All configuration collections should appear in tfvars when populated."""
        _populate_full_config(db)
        zf = _export(db)
        tv = _tfvars(zf)
        cols = _collection_keys(tv)
        expected = {
            'backends', 'servers', 'listeners', 'backend_rules',
            'fcgi_apps', 'error_pages', 'rate_limits', 'response_headers',
            'request_headers', 'redirects', 'rewrites', 'response_transforms',
            'network_lists', 'dynamic_feeds',
            'security_rules',
            'waf_rules', 'waf_exceptions',
            'cache_configs',  # cache_rules are nested under cache_configs
            'log_destinations', 'logged_fields',
            'page_protect_policies',
            'auth_policies', 'api_key_lists', 'openapi_specs', 'api_schemas',
            'risk_rulesets', 'risk_rules',
            'users', 'settings',
            'mcp_teams', 'mcp_servers', 'mcp_server_replicas',
            'mcp_identities', 'mcp_policies', 'mcp_dlp_rules', 'mcp_guardrails',
            'mcp_skills', 'mcp_skill_versions',
        }
        missing = expected - cols
        assert not missing, f"Missing collections in tfvars: {missing}"

    def test_excluded_tables_not_in_export(self, db):
        """Runtime/metrics tables should never appear in the export."""
        _populate_full_config(db)
        zf = _export(db)
        tv = _tfvars(zf)
        cols = _collection_keys(tv)
        for table in EXCLUDED_TABLES:
            # Convert table name to likely collection name
            col_name = table.rstrip('s') if not table.endswith('ies') else table[:-3] + 'y'
            # Check both singular and plural
            assert table not in cols, f"Excluded table '{table}' found in tfvars"
            assert col_name not in cols, f"Excluded table '{col_name}' found in tfvars"


# ─── FK resolution ──────────────────────────────────────────────────────────

class TestFKResolution:

    def test_cross_module_fk_resolved_in_tfvars(self, db):
        """FK IDs should be resolved to logical names in tfvars."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # Listener's default_backend_id should be resolved to "web"
        m = re.search(r'listeners = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None
        assert '"https"' in m.group(1)
        assert '"web"' in m.group(1)
        # Should NOT contain raw ID
        assert f'"default_backend_id" = {be.id}' not in m.group(1)

    def test_same_module_fk_resolved_in_tfvars(self, db):
        """Same-module FKs should be resolved to logical names in tfvars."""
        be = make_backend(db, name="web")
        make_server(db, be.id, name="web1")
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        m = re.search(r'servers = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None
        assert '"web1"' in m.group(1)
        assert '"backend_id" = "web"' in m.group(1)

    def test_cross_module_fk_in_module_main_tf(self, db):
        """Module main.tf should reference cross-module FKs via var.xxx_ids.

        FCGI apps were moved from traffic to routing to break a circular
        dependency (routing ↔ traffic). fcgi_app_id is NOT in the provider's
        backend schema, so it's skipped via PROVIDER_FIELD_OVERRIDES.
        """
        from app.models.models import FcgiApp
        fcgi = FcgiApp(name="php", docroot="/var/www")
        db.add(fcgi); db.flush()
        be = Backend(name="web", mode="http", algorithm="roundrobin", fcgi_app_id=fcgi.id)
        db.add(be); db.commit()
        zf = _export(db)
        routing_tf = _module_tf(zf, 'routing')
        # fcgi_app_id is not in the provider schema — it should be skipped
        assert 'fcgi_app_id' not in routing_tf, \
            "fcgi_app_id should be skipped (not in provider backend schema)"
        # Verify no circular dependency: routing should NOT reference module.traffic
        assert 'module.traffic' not in routing_tf

    def test_same_module_fk_in_module_main_tf(self, db):
        """Module main.tf should reference same-module FKs via corex_xxx.this[...].id.

        WAF exception's waf_rule_id is nullable (the DB allows null), so it
        should use try() to produce null when the exception has no rule.
        """
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        wr = make_waf_rule(db, name="rule", listener_id=ln.id, backend_id=be.id)
        make_waf_exception(db, waf_rule_id=wr.id, name="ex")
        db.commit()
        zf = _export(db)
        waf_tf = _module_tf(zf, 'waf')
        # waf_rule_id is nullable — use try() to produce null when absent
        assert 'waf_rule_id = try(corex_waf_rule.this[each.value.waf_rule_id].id, null)' in waf_tf

    def test_polymorphic_fk_uses_coalesce_not_key(self, db):
        """Dynamic feed target_list_id should use coalesce() with try() per type.

        The FK value in tfvars is a string (the list name), not an object with
        .key. Each type should be wrapped in its own try() so that undeclared
        resource types don't cause parse errors.
        """
        nl = NetworkList(name="allowed")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="feed1", list_type="network", target_list_id=nl.id,
                          url="https://example.com/feed", update_interval_hours=3600))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        # Should use coalesce() with individual try() calls
        assert 'coalesce(' in sec_tf, "Polymorphic FK should use coalesce()"
        # Should NOT use .key (the FK value is a string, not an object)
        feed_block = sec_tf[sec_tf.find('corex_dynamic_feed'):]
        feed_block = feed_block[:feed_block.find('}')]
        assert '.key]' not in feed_block, \
            "Polymorphic FK should not use .key (value is a string)"
        # Should reference each.value.target_list_id directly
        assert 'each.value.target_list_id' in sec_tf
        # Should NOT reference pattern_list (no pattern lists in DB)
        assert 'corex_pattern_list' not in feed_block, \
            "Should not reference undeclared resource type corex_pattern_list"

    def test_polymorphic_fk_resolves_correct_list_type(self, db):
        """Dynamic feed target_list_id should resolve to the correct list name
        based on list_type, not just the first matching ID across tables.
        """
        nl = NetworkList(name="net_list")
        db.add(nl); db.flush()
        al = AsnList(name="asn_list")
        db.add(al); db.flush()
        # Both lists have id=1 in their respective tables
        db.add(DynamicFeed(name="net_feed", list_type="network", target_list_id=nl.id,
                          url="https://example.com/feed", update_interval_hours=3600))
        db.add(DynamicFeed(name="asn_feed", list_type="asn", target_list_id=al.id,
                          url="https://example.com/feed2", update_interval_hours=3600))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # Extract the dynamic_feeds block and check target_list_id values
        m = re.search(r'dynamic_feeds = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None, "dynamic_feeds not found in tfvars"
        block = m.group(1)
        # net_feed should resolve to "net_list"
        net_m = re.search(r'"net_feed" = \{([^}]*)\}', block)
        assert net_m is not None, "net_feed not found"
        assert '"target_list_id" = "net_list"' in net_m.group(1), \
            f"net_feed should resolve to 'net_list', got: {net_m.group(1)}"
        # asn_feed should resolve to "asn_list" (not "net_list")
        asn_m = re.search(r'"asn_feed" = \{([^}]*)\}', block)
        assert asn_m is not None, "asn_feed not found"
        assert '"target_list_id" = "asn_list"' in asn_m.group(1), \
            f"asn_feed should resolve to 'asn_list', got: {asn_m.group(1)}"

    def test_polymorphic_fk_multiple_asn_feeds(self, db):
        """Multiple ASN feeds with overlapping IDs should all resolve to ASN lists.

        Each list type table has its own auto-increment, so network_lists
        and asn_lists can both have IDs 1-4. Feeds with list_type="asn"
        must resolve against asn_lists, not network_lists.
        """
        # Network lists (IDs 1-4)
        for name in ['allowed', 'tor', 'cloudflare_v4', 'cloudflare_v6']:
            db.add(NetworkList(name=name))
        # ASN lists (IDs 1-4 — separate auto-increment)
        asn_names = ['asn_clawler', 'asn_hosting', 'asn_scanner', 'asn_vpn']
        for name in asn_names:
            db.add(AsnList(name=name))
        db.flush()
        # ASN feeds targeting ASN lists 1-4
        for i, name in enumerate(asn_names, 1):
            db.add(DynamicFeed(name=f'feed_{name.replace("asn_", "")}',
                             list_type='asn', target_list_id=i,
                             url=f'https://example.com/{i}',
                             update_interval_hours=3600))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        m = re.search(r'dynamic_feeds = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None, "dynamic_feeds not found in tfvars"
        block = m.group(1)
        # Every ASN feed should resolve to the matching ASN list name
        for asn_name in asn_names:
            assert f'"target_list_id" = "{asn_name}"' in block, \
                f"ASN feed should resolve to '{asn_name}', not a network list name"
        # No network list names should appear as target_list_id values
        for net_name in ['allowed', 'tor', 'cloudflare_v4', 'cloudflare_v6']:
            assert f'"target_list_id" = "{net_name}"' not in block, \
                f"Network list name '{net_name}' leaked into ASN feed target_list_id"

    def test_list_fk_resolved_in_tfvars(self, db):
        """List-valued FKs should be resolved to lists of logical names."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        make_security_rule(db, name="rule1", listener_ids=[ln.id])
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        m = re.search(r'security_rules = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None
        assert '"https"' in m.group(1)

    def test_waf_siem_integration_id_is_raw_int(self, db):
        """WAF rule's siem_integration_id is a raw int (no waf_siem_integration resource)."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        siem = make_siem_integration(db, name="splunk")
        make_waf_rule(db, name="rule", listener_id=ln.id, backend_id=be.id,
                      siem_integration_id=siem.id)
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        m = re.search(r'waf_rules = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None
        # siem_integration_id is a raw int, not resolved to a name
        assert '"siem_integration_id" = 1' in m.group(1)
        waf_tf = _module_tf(zf, 'waf')
        # The resource block should emit it as a raw int, not a FK reference
        assert 'siem_integration_id = try(each.value.siem_integration_id, null)' in waf_tf
        # No waf_siem_integration resource should be emitted
        assert 'corex_waf_siem_integration' not in waf_tf


# ─── Secret flag behavior ──────────────────────────────────────────────────

class TestSecretFlags:

    def _populate_with_secrets(self, db):
        """Populate DB with known secret values for all secret categories."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        db.add(User(username="admin", email="admin@ex.com", role="admin",
                   hashed_password="SECRET_HASHED_PASSWORD", is_admin=True,
                   totp_secret="SECRET_TOTP"))
        db.add(Certificate(name="wildcard", domain="*.example.com",
                         dns_credentials="SECRET_DNS_CREDENTIALS"))
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, namespace="eng",
                       transport_type="stdio", auth_secret_enc="SECRET_AUTH_TOKEN")
        db.add(srv); db.flush()
        db.add(McpIdentity(name="bot", team_id=team.id, kind="pat",
                          pat_hash="SECRET_PAT_HASH",
                          idp_user_info={"sub": "secret"}))
        db.add(Setting(key="maxmind_license_key", value="SECRET_MAXMIND_KEY"))
        db.add(Setting(key="cap_secret", value="SECRET_CAP_SECRET"))
        db.add(Setting(key="keepalived_auth_password", value="SECRET_HA_PASSWORD"))
        db.commit()

    # Note: hashed_password, totp_secret, and pat_hash are not in the provider
    # schema, so they're skipped entirely and never appear in tfvars.
    SECRET_VALUES = [
        "SECRET_AUTH_TOKEN",
        "SECRET_DNS_CREDENTIALS", "SECRET_MAXMIND_KEY",
        "SECRET_CAP_SECRET", "SECRET_HA_PASSWORD",
    ]

    def test_all_flags_off_no_secrets_leaked(self, db):
        """With all flags off, no secret values should appear in tfvars."""
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=False, include_system_secrets=False)
        tv = _tfvars(zf)
        for s in self.SECRET_VALUES:
            assert s not in tv, f"Secret '{s}' leaked in tfvars with all flags off"

    def test_all_flags_off_secret_placeholders_in_modules(self, db):
        """With all flags off, modules should have var.xxx placeholders for secrets.

        Note: hashed_password, totp_secret, and pat_hash are not in the provider
        schema, so they're skipped entirely (not emitted as placeholders).
        """
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=False, include_system_secrets=False)
        mgmt_tf = _module_tf(zf, 'management')
        # hashed_password and totp_secret are not in the provider schema — skipped
        assert 'hashed_password' not in mgmt_tf
        assert 'totp_secret' not in mgmt_tf
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        assert 'var.mcp_servers_auth_secrets' in mcp_tf
        # pat_hash is not in the provider schema — skipped
        assert 'pat_hash' not in mcp_tf
        ssl_tf = _module_tf(zf, 'ssl')
        assert 'var.certificates_dns_credentials' in ssl_tf

    def test_include_secrets_master_override(self, db):
        """include_secrets=True should inline ALL secrets in tfvars."""
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=True, include_certs=False,
                     include_users_identities=False, include_system_secrets=False)
        tv = _tfvars(zf)
        for s in self.SECRET_VALUES:
            assert s in tv, f"Secret '{s}' missing with include_secrets=True"

    def test_include_certs_only(self, db):
        """include_certs=True should include dns_credentials but not other secrets."""
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=False, include_certs=True,
                     include_users_identities=False, include_system_secrets=False)
        tv = _tfvars(zf)
        assert "SECRET_DNS_CREDENTIALS" in tv, "dns_credentials should be present with include_certs=True"
        others = [s for s in self.SECRET_VALUES if s != "SECRET_DNS_CREDENTIALS"]
        for s in others:
            assert s not in tv, f"Secret '{s}' leaked with include_certs=True only"

    def test_include_users_identities_only(self, db):
        """include_users_identities=True should include user/identity secrets only.

        Note: hashed_password, totp_secret, and pat_hash are not in the provider
        schema, so they're skipped entirely even with include_users_identities=True.
        """
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=True, include_system_secrets=False)
        tv = _tfvars(zf)
        # hashed_password, totp_secret, pat_hash are not in the provider schema — skipped
        assert "SECRET_HASHED_PASSWORD" not in tv
        assert "SECRET_TOTP" not in tv
        assert "SECRET_PAT_HASH" not in tv
        non_user = ["SECRET_AUTH_TOKEN", "SECRET_DNS_CREDENTIALS",
                    "SECRET_MAXMIND_KEY", "SECRET_CAP_SECRET", "SECRET_HA_PASSWORD"]
        for s in non_user:
            assert s not in tv, f"Non-user secret '{s}' leaked with include_users_identities=True"

    def test_include_system_secrets_only(self, db):
        """include_system_secrets=True should include system secrets only."""
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=False, include_system_secrets=True)
        tv = _tfvars(zf)
        assert "SECRET_AUTH_TOKEN" in tv
        assert "SECRET_MAXMIND_KEY" in tv
        assert "SECRET_CAP_SECRET" in tv
        assert "SECRET_HA_PASSWORD" in tv
        non_sys = ["SECRET_HASHED_PASSWORD", "SECRET_TOTP", "SECRET_PAT_HASH",
                   "SECRET_DNS_CREDENTIALS"]
        for s in non_sys:
            assert s not in tv, f"Non-system secret '{s}' leaked with include_system_secrets=True"

    def test_secret_variables_declared_in_variables_tf(self, db):
        """Secret var placeholders should be declared in root variables.tf."""
        self._populate_with_secrets(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=False, include_system_secrets=False)
        var_tf = _read(zf, "variables.tf")
        # users_hashed_passwords and users_totp_secrets are no longer exported
        # (the user provider has write-only password, not hashed_password/totp_secret).
        # mcp_identities_pat_hashes is no longer exported (provider has pat_prefix, not pat_hash).
        # The test data only has auth_secret_enc for MCP servers, so only
        # mcp_servers_auth_secrets is declared.
        for var_name in ['mcp_servers_auth_secrets',
                         'certificates_dns_credentials']:
            assert f'variable "{var_name}"' in var_tf, f"Secret variable '{var_name}' not declared in variables.tf"
            assert 'sensitive   = true' in var_tf.split(f'variable "{var_name}"')[1].split('}')[0]


# ─── Secret placeholder format & type correctness ──────────────────────────

class TestSecretPlaceholderFormat:
    """Verify that secret placeholders are correctly typed and formatted
    in root variables.tf, environments/dev.tfvars, and terraform.tfvars.example.

    Map secrets (per-resource) must be declared as map(string) with empty map
    placeholders. Singleton secrets must be declared as string with scalar
    placeholders. No secret value may leak when its flag is off.
    """

    def _populate_all_secret_categories(self, db):
        """Populate DB with one secret per category, using recognizable values."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        db.add(User(username="admin", email="admin@ex.com", role="admin",
                   hashed_password="SECRET_HASHED_PASSWORD", is_admin=True,
                   totp_secret="SECRET_TOTP"))
        db.add(Certificate(name="wildcard", domain="*.example.com",
                         dns_credentials="SECRET_DNS_CREDENTIALS"))
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, namespace="eng",
                      transport_type="stdio",
                      auth_secret_enc="SECRET_AUTH_TOKEN",
                      oauth_client_secret_enc="SECRET_OAUTH_TOKEN",
                      env_vars_json='{"KEY":"SECRET_ENV_VAR"}')
        db.add(srv); db.flush()
        db.add(McpIdentity(name="bot", team_id=team.id, kind="pat",
                          pat_hash="SECRET_PAT_HASH",
                          idp_user_info={"sub": "secret"}))
        db.add(Setting(key="maxmind_license_key", value="SECRET_MAXMIND_KEY"))
        db.add(Setting(key="cap_secret", value="SECRET_CAP_SECRET"))
        db.add(Setting(key="recaptcha_secret", value="SECRET_RECAPTCHA_SECRET"))
        db.add(Setting(key="turnstile_secret", value="SECRET_TURNSTILE_SECRET"))
        db.add(Setting(key="keepalived_auth_password", value="SECRET_HA_PASSWORD"))
        db.commit()

    # Note: hashed_password, totp_secret, and pat_hash are not in the provider
    # schema, so they're skipped entirely and never appear in tfvars.
    ALL_SECRET_VALUES = [
        "SECRET_AUTH_TOKEN",
        "SECRET_OAUTH_TOKEN", "SECRET_ENV_VAR",
        "SECRET_DNS_CREDENTIALS", "SECRET_MAXMIND_KEY",
        "SECRET_CAP_SECRET", "SECRET_RECAPTCHA_SECRET", "SECRET_TURNSTILE_SECRET",
        "SECRET_HA_PASSWORD",
    ]

    # Per-resource map secrets → must be map(string) in variables.tf
    MAP_SECRET_VARS = [
        # users_hashed_passwords and users_totp_secrets are no longer exported
        # (provider has write-only password, not hashed_password/totp_secret).
        # mcp_identities_pat_hashes is no longer exported (provider has pat_prefix, not pat_hash).
        # mcp_identities_idp_info is not a secret (provider has idp_user_info as regular field).
        'mcp_servers_auth_secrets', 'mcp_servers_oauth_secrets',
        'mcp_servers_env_vars',
        'certificates_dns_credentials',
    ]

    # Singleton string secrets → must be string in variables.tf
    STRING_SECRET_VARS = ['maxmind_license_key']

    # ── Type correctness in root variables.tf ──

    def test_map_secrets_declared_as_map_string(self, db):
        """Per-resource secret vars must be type = map(string) in root variables.tf."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        var_tf = _read(zf, "variables.tf")
        for var_name in self.MAP_SECRET_VARS:
            assert f'variable "{var_name}"' in var_tf, f"{var_name} not declared"
            section = var_tf.split(f'variable "{var_name}"')[1].split('}')[0]
            assert 'map(string)' in section, \
                f"{var_name} should be map(string), got: {section.strip()}"

    def test_string_secrets_declared_as_string(self, db):
        """Singleton secret vars must be type = string in root variables.tf."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        var_tf = _read(zf, "variables.tf")
        for var_name in self.STRING_SECRET_VARS:
            assert f'variable "{var_name}"' in var_tf, f"{var_name} not declared"
            section = var_tf.split(f'variable "{var_name}"')[1].split('}')[0]
            assert 'type        = string' in section, \
                f"{var_name} should be string, got: {section.strip()}"
            assert 'map(string)' not in section, \
                f"{var_name} should NOT be map(string), got: {section.strip()}"

    def test_all_secret_vars_marked_sensitive(self, db):
        """Every secret var in root variables.tf must have sensitive = true."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        var_tf = _read(zf, "variables.tf")
        all_vars = self.MAP_SECRET_VARS + self.STRING_SECRET_VARS
        for var_name in all_vars:
            section = var_tf.split(f'variable "{var_name}"')[1].split('}')[0]
            assert 'sensitive   = true' in section, \
                f"{var_name} missing sensitive = true"

    # ── Placeholder format in dev.secrets.tfvars ──

    def test_map_secret_placeholders_in_secrets_tfvars(self, db):
        """Map secrets should have per-resource placeholders in dev.secrets.tfvars."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # Each map secret var should have a map block
        for var_name in self.MAP_SECRET_VARS:
            assert f'{var_name} = {{' in secrets, \
                f"{var_name} should have map placeholder in dev.secrets.tfvars"
        # Verify actual resource names are pre-populated (not just generic comment)
        # users_hashed_passwords is no longer exported (dead secret).
        # mcp_identities_pat_hashes is no longer exported (dead secret).
        # dns_credentials is map(map(string)) — placeholder is an empty map, not "change-me"
        assert '"wildcard" = {}' in secrets, \
            "certificates_dns_credentials should have 'wildcard' key pre-populated with empty map"
        assert '"tools" = "change-me"' in secrets, \
            "mcp_servers_auth_secrets should have 'tools' key pre-populated"

    def test_string_secret_placeholders_in_secrets_tfvars(self, db):
        """String secrets should have scalar placeholders in dev.secrets.tfvars."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        for var_name in self.STRING_SECRET_VARS:
            assert f'{var_name} = "change-me"' in secrets, \
                f"{var_name} should have string placeholder in dev.secrets.tfvars"

    def test_no_secret_values_in_dev_tfvars_all_off(self, db):
        """No secret values should appear in dev.tfvars when all flags are off."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        for s in self.ALL_SECRET_VALUES:
            assert s not in tv, f"Secret '{s}' leaked in dev.tfvars"

    def test_no_secret_map_vars_in_dev_tfvars(self, db):
        """Standalone secret map vars should NOT be in dev.tfvars (only in secrets.tfvars)."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        for var_name in self.MAP_SECRET_VARS:
            assert f'{var_name} = {{' not in tv, \
                f"{var_name} should not be in dev.tfvars (belongs in secrets.tfvars)"

    def test_no_secret_string_vars_in_dev_tfvars(self, db):
        """Standalone secret string vars should NOT be in dev.tfvars."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        for var_name in self.STRING_SECRET_VARS:
            assert f'{var_name} = "change-me"' not in tv, \
                f"{var_name} should not be in dev.tfvars (belongs in secrets.tfvars)"

    def test_corex_password_in_secrets_tfvars_not_dev_tfvars(self, db):
        """corex_password should be assigned in dev.secrets.tfvars, not dev.tfvars."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # Check for actual assignment, not just the string (which appears in comments)
        assert '\ncorex_password =' not in tv, \
            "corex_password should not be assigned in dev.tfvars"
        assert 'corex_password = "change-me"' in secrets, \
            "corex_password should be assigned in dev.secrets.tfvars"

    def test_secrets_tfvars_file_exists(self, db):
        """dev.secrets.tfvars should exist in the export zip."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        assert 'environments/dev.secrets.tfvars' in zf.namelist()

    def test_secrets_tfvars_gitignored(self, db):
        """*.secrets.tfvars should be in .gitignore."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        gitignore = _read(zf, '.gitignore')
        assert '*.secrets.tfvars' in gitignore

    # ── terraform.tfvars.example ──

    def test_tfvars_example_exists_in_zip(self, db):
        """terraform.tfvars.example should be present in the export zip."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        assert 'terraform.tfvars.example' in zf.namelist()

    def test_tfvars_example_has_map_placeholders(self, db):
        """terraform.tfvars.example should have per-resource map placeholders."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        example = _read(zf, 'terraform.tfvars.example')
        for var_name in self.MAP_SECRET_VARS:
            assert f'{var_name} = {{' in example, \
                f"{var_name} missing map placeholder in tfvars.example"
        # Verify actual resource names are pre-populated
        # users_hashed_passwords and mcp_identities_pat_hashes are no longer exported.
        assert '"wildcard" = "change-me"' in example, \
            "tfvars.example should have 'wildcard' key in certificates_dns_credentials"
        assert '"tools" = "change-me"' in example, \
            "tfvars.example should have 'tools' key in mcp_servers secrets"

    def test_tfvars_example_has_string_placeholders(self, db):
        """terraform.tfvars.example should have string placeholders for singleton secrets."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        example = _read(zf, 'terraform.tfvars.example')
        for var_name in self.STRING_SECRET_VARS:
            assert f'{var_name} = "change-me"' in example, \
                f"{var_name} missing string placeholder in tfvars.example"

    def test_tfvars_example_no_secret_values_all_off(self, db):
        """terraform.tfvars.example should not contain real secret values."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        example = _read(zf, 'terraform.tfvars.example')
        for s in self.ALL_SECRET_VALUES:
            assert s not in example, f"Secret '{s}' leaked in tfvars.example"

    def test_tfvars_example_absent_when_master_on(self, db):
        """terraform.tfvars.example should have no secret placeholders when include_secrets=True."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=True)
        example = _read(zf, 'terraform.tfvars.example')
        all_vars = self.MAP_SECRET_VARS + self.STRING_SECRET_VARS
        for var_name in all_vars:
            assert f'{var_name} =' not in example or 'change-me' not in example.split(f'{var_name}')[1].split('\n')[0] if var_name in example else True, \
                f"{var_name} should not have placeholder when include_secrets=True"

    # ── No duplicate declarations in module variables.tf ──

    def test_no_duplicate_secret_vars_in_module(self, db):
        """Secret vars should not be declared twice in a module's variables.tf."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        for mod_name in ['management', 'mcp-gateway', 'ssl']:
            var_tf = _module_var_tf(zf, mod_name)
            for var_name in self.MAP_SECRET_VARS + self.STRING_SECRET_VARS:
                count = len(re.findall(f'variable "{var_name}"', var_tf))
                assert count <= 1, \
                    f"{var_name} declared {count} times in {mod_name}/variables.tf"

    # ── All 5 flag combinations: comprehensive matrix ──

    def test_all_flags_off_placeholders_for_all_secrets(self, db):
        """All flags off: all secret vars get placeholders, no values leak."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=False, include_system_secrets=False)
        tv = _tfvars(zf)
        var_tf = _read(zf, "variables.tf")
        # All secret vars declared
        for v in self.MAP_SECRET_VARS + self.STRING_SECRET_VARS:
            assert f'variable "{v}"' in var_tf, f"{v} not declared in variables.tf"
        # No secret values leaked
        for s in self.ALL_SECRET_VALUES:
            assert s not in tv, f"Secret '{s}' leaked"

    def test_master_on_all_secrets_inlined(self, db):
        """include_secrets=True: all secrets inlined, no placeholders."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=True, include_certs=False,
                     include_users_identities=False, include_system_secrets=False)
        tv = _tfvars(zf)
        for s in self.ALL_SECRET_VALUES:
            assert s in tv, f"Secret '{s}' missing with master override"

    def test_certs_only_dns_credentials_inlined(self, db):
        """include_certs=True: only DNS credentials inlined, rest are placeholders."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=False, include_certs=True,
                     include_users_identities=False, include_system_secrets=False)
        tv = _tfvars(zf)
        assert "SECRET_DNS_CREDENTIALS" in tv
        others = [s for s in self.ALL_SECRET_VALUES if s != "SECRET_DNS_CREDENTIALS"]
        for s in others:
            assert s not in tv, f"Secret '{s}' leaked with certs-only flag"

    def test_users_identities_only_user_secrets_inlined(self, db):
        """include_users_identities=True: only user/identity secrets inlined.

        Note: hashed_password, totp_secret, and pat_hash are not in the provider
        schema, so they're skipped entirely even with include_users_identities=True.
        """
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=True, include_system_secrets=False)
        tv = _tfvars(zf)
        # hashed_password, totp_secret, pat_hash are not in the provider schema — skipped
        assert "SECRET_HASHED_PASSWORD" not in tv
        assert "SECRET_TOTP" not in tv
        assert "SECRET_PAT_HASH" not in tv
        non_user = ["SECRET_AUTH_TOKEN", "SECRET_OAUTH_TOKEN", "SECRET_ENV_VAR",
                    "SECRET_DNS_CREDENTIALS", "SECRET_MAXMIND_KEY",
                    "SECRET_CAP_SECRET", "SECRET_HA_PASSWORD"]
        for s in non_user:
            assert s not in tv, f"Non-user secret '{s}' leaked with users_identities flag"

    def test_system_secrets_only_system_inlined(self, db):
        """include_system_secrets=True: only system secrets inlined."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=False, include_certs=False,
                     include_users_identities=False, include_system_secrets=True)
        tv = _tfvars(zf)
        assert "SECRET_AUTH_TOKEN" in tv
        assert "SECRET_OAUTH_TOKEN" in tv
        assert "SECRET_ENV_VAR" in tv
        assert "SECRET_MAXMIND_KEY" in tv
        assert "SECRET_CAP_SECRET" in tv
        assert "SECRET_RECAPTCHA_SECRET" in tv
        assert "SECRET_TURNSTILE_SECRET" in tv
        assert "SECRET_HA_PASSWORD" in tv
        non_sys = ["SECRET_HASHED_PASSWORD", "SECRET_TOTP", "SECRET_PAT_HASH",
                   "SECRET_DNS_CREDENTIALS"]
        for s in non_sys:
            assert s not in tv, f"Non-system secret '{s}' leaked with system_secrets flag"

    # ── Captcha and HA secret placeholders ──

    def test_captcha_secrets_have_placeholders_when_off(self, db):
        """Captcha secrets should show 'change-me' placeholders in secrets.tfvars when system secrets off."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # The sensitive captcha keys should be in captcha_secrets in secrets.tfvars
        assert 'captcha_secrets' in secrets, \
            "captcha_secrets map should be in dev.secrets.tfvars"
        assert '"cap_secret" = "change-me"' in secrets, \
            "cap_secret should have 'change-me' placeholder in captcha_secrets"
        assert '"recaptcha_secret" = "change-me"' in secrets, \
            "recaptcha_secret should have 'change-me' placeholder in captcha_secrets"
        assert '"turnstile_secret" = "change-me"' in secrets, \
            "turnstile_secret should have 'change-me' placeholder in captcha_secrets"
        # Real values must not leak
        assert "SECRET_CAP_SECRET" not in tv
        assert "SECRET_RECAPTCHA_SECRET" not in tv
        assert "SECRET_TURNSTILE_SECRET" not in tv
        # Captcha secrets should NOT be in dev.tfvars
        assert '"cap_secret"' not in tv, \
            "cap_secret should not be in dev.tfvars (it's in secrets.tfvars)"
        assert '"recaptcha_secret"' not in tv, \
            "recaptcha_secret should not be in dev.tfvars"
        assert '"turnstile_secret"' not in tv, \
            "turnstile_secret should not be in dev.tfvars"

    def test_ha_password_has_placeholder_when_off(self, db):
        """keepalived auth_password should show 'change-me' placeholder when system secrets off."""
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        # keepalived fields are nested under keepalived, so key is auth_password
        assert '"auth_password" = "change-me"' in tv, \
            "keepalived auth_password should have 'change-me' placeholder in ha_config"
        assert "SECRET_HA_PASSWORD" not in tv

    def test_captcha_secrets_inlined_with_system_flag(self, db):
        """Captcha secrets should be inlined when include_system_secrets=True."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_system_secrets=True)
        tv = _tfvars(zf)
        assert "SECRET_CAP_SECRET" in tv
        assert "SECRET_RECAPTCHA_SECRET" in tv
        assert "SECRET_TURNSTILE_SECRET" in tv
        assert "SECRET_HA_PASSWORD" in tv
        # No change-me placeholders for captcha/HA secrets
        assert '"cap_secret" = "change-me"' not in tv
        assert '"recaptcha_secret" = "change-me"' not in tv
        assert '"turnstile_secret" = "change-me"' not in tv
        assert '"keepalived_auth_password" = "change-me"' not in tv

    def test_captcha_secrets_inlined_with_master_flag(self, db):
        """Captcha secrets should be inlined when include_secrets=True."""
        self._populate_all_secret_categories(db)
        zf = _export(db, include_secrets=True)
        tv = _tfvars(zf)
        assert "SECRET_CAP_SECRET" in tv
        assert "SECRET_RECAPTCHA_SECRET" in tv
        assert "SECRET_TURNSTILE_SECRET" in tv
        assert "SECRET_HA_PASSWORD" in tv

    # ── Completeness: every sensitive field/setting has a placeholder ──

    def test_every_sensitive_field_has_secret_var(self, db):
        """Every field in SENSITIVE_FIELDS should have a corresponding secret var
        declared in root variables.tf when secrets are off."""
        from app.services.terraform_export import SENSITIVE_FIELDS
        # Map of table → expected secret var names for each sensitive field
        expected_vars = {
            'certificates': {'dns_credentials': 'certificates_dns_credentials'},
            'users': {
                'hashed_password': 'users_hashed_passwords',
                'totp_secret': 'users_totp_secrets',
            },
            'mcp_servers': {
                'auth_secret_enc': 'mcp_servers_auth_secrets',
                'oauth_client_secret_enc': 'mcp_servers_oauth_secrets',
                'env_vars_json': 'mcp_servers_env_vars',
            },
            'mcp_identities': {
                'pat_hash': 'mcp_identities_pat_hashes',
                'idp_user_info': 'mcp_identities_idp_info',
            },
        }
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        var_tf = _read(zf, "variables.tf")
        for table, fields in SENSITIVE_FIELDS.items():
            for field in fields:
                var_name = expected_vars.get(table, {}).get(field)
                assert var_name, f"No expected var mapping for {table}.{field}"
                assert f'variable "{var_name}"' in var_tf, \
                    f"Secret var '{var_name}' for {table}.{field} not declared in variables.tf"

    def test_every_sensitive_setting_has_placeholder(self, db):
        """Every key in SENSITIVE_SETTING_KEYS should get a 'change-me' placeholder
        when system secrets are off.

        Sensitive keys embedded in map variables (captcha_settings, ha_config)
        appear as 'change-me' in dev.tfvars. Singleton secret string vars
        (maxmind_license_key) appear in dev.secrets.tfvars.
        """
        from app.services.terraform_export import SENSITIVE_SETTING_KEYS
        self._populate_all_secret_categories(db)
        zf = _export(db)  # all flags off
        tv = _tfvars(zf)
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        combined = tv + '\n' + secrets
        for key in SENSITIVE_SETTING_KEYS:
            # maxmind_license_key is a singleton string var: key = "change-me"
            # captcha/HA secrets are inside maps: "key" = "change-me"
            # keepalived_auth_password is nested under keepalived: "auth_password" = "change-me"
            nested_key = key.replace('keepalived_', '') if key.startswith('keepalived_') else key
            assert (f'{key} = "change-me"' in combined or f'"{key}" = "change-me"' in combined
                    or f'"{nested_key}" = "change-me"' in combined), \
                f"Sensitive setting '{key}' missing 'change-me' placeholder"

    def test_no_dead_sensitive_setting_keys(self):
        """Every key in SENSITIVE_SETTING_KEYS should be used by the application
        (i.e., it should appear in a captcha_keys or ha_config_keys list in the exporter)."""
        from app.services.terraform_export import SENSITIVE_SETTING_KEYS
        # These are the keys the exporter actually queries and exports
        exported_keys = set()
        # Captcha keys (from the exporter source)
        exported_keys.update([
            'captcha_provider', 'captcha_valid_seconds',
            'cap_site_key', 'cap_secret',
            'recaptcha_site_key', 'recaptcha_secret', 'recaptcha_version', 'recaptcha_min_score',
            'turnstile_site_key', 'turnstile_secret',
        ])
        # HA config keys
        exported_keys.update([
            'ha_enabled', 'ha_topology', 'haproxy_ha_replicas', 'valkey_ha_replicas',
            'coraza_ha_replicas', 'haproxy_instances', 'haproxy_peer_port',
            'keepalived_vip', 'keepalived_virtual_router_id', 'keepalived_priority',
            'keepalived_interface', 'keepalived_auth_password', 'keepalived_peer_addresses',
            'keepalived_advert_int', 'keepalived_preempt', 'keepalived_track_script',
            'valkey_sentinel_enabled', 'valkey_sentinel_hosts', 'valkey_sentinel_service',
        ])
        # MaxMind is handled separately but still a sensitive setting
        exported_keys.add('maxmind_license_key')
        for key in SENSITIVE_SETTING_KEYS:
            assert key in exported_keys, \
                f"Sensitive setting '{key}' is in SENSITIVE_SETTING_KEYS but not exported by the exporter (dead key)"


# ─── Sensitive settings ─────────────────────────────────────────────────────

class TestSensitiveSettings:

    def test_sensitive_settings_excluded_by_default(self, db):
        """Sensitive settings should be excluded from tfvars by default."""
        for key in SENSITIVE_SETTING_KEYS:
            db.add(Setting(key=key, value=f"secret_value_for_{key}"))
        db.commit()
        zf = _export(db, include_secrets=False, include_system_secrets=False)
        tv = _tfvars(zf)
        for key in SENSITIVE_SETTING_KEYS:
            assert f"secret_value_for_{key}" not in tv, f"Sensitive setting '{key}' leaked"

    def test_sensitive_settings_included_with_system_secrets(self, db):
        """Sensitive settings should be included with include_system_secrets=True."""
        for key in SENSITIVE_SETTING_KEYS:
            db.add(Setting(key=key, value=f"secret_value_for_{key}"))
        db.commit()
        zf = _export(db, include_secrets=False, include_system_secrets=True)
        tv = _tfvars(zf)
        for key in SENSITIVE_SETTING_KEYS:
            assert f"secret_value_for_{key}" in tv, f"Sensitive setting '{key}' missing with system_secrets=True"

    def test_sensitive_settings_included_with_master_flag(self, db):
        """Sensitive settings should be included with include_secrets=True."""
        for key in SENSITIVE_SETTING_KEYS:
            db.add(Setting(key=key, value=f"secret_value_for_{key}"))
        db.commit()
        zf = _export(db, include_secrets=True)
        tv = _tfvars(zf)
        for key in SENSITIVE_SETTING_KEYS:
            assert f"secret_value_for_{key}" in tv, f"Sensitive setting '{key}' missing with include_secrets=True"


# ─── Runtime state exclusion ────────────────────────────────────────────────

class TestRuntimeStateExclusion:

    @pytest.mark.parametrize("key", [
        "last_applied_at", "geoip_download_last_run_at",
        "rule_set_download_poll_last_run_at", "auto_renew_last_run_at",
        "security_list_feeds_poll_last_run_at",
        "captcha_cookie_secret", "pp_hasher_bypass_token",
        "ja4_auto_disabled_rule_ids", "ja4_risk_auto_disabled_rule_ids",
        "risk_auto_disabled_rule_ids",
        "api_armor_profiler_interval", "api_armor_schema_learn_interval",
        "crs_active_version",
    ])
    def test_runtime_state_excluded(self, db, key):
        """Runtime state settings should never appear in the export."""
        db.add(Setting(key=key, value=f"runtime_value_for_{key}"))
        db.commit()
        zf = _export(db, include_secrets=True, include_certs=True,
                     include_users_identities=True, include_system_secrets=True)
        tv = _tfvars(zf)
        assert f"runtime_value_for_{key}" not in tv, f"Runtime state '{key}' leaked even with all flags on"
        assert key not in tv, f"Runtime state key '{key}' found in tfvars"


# ─── Singleton settings ─────────────────────────────────────────────────────

class TestSingletonSettings:

    def test_captcha_settings_exported(self, db):
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="recaptcha_site_key", value="my-site-key"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        tv = _tfvars(zf)
        assert "captcha_settings" in tv
        assert "recaptcha" in tv
        assert "my-site-key" in tv

    def test_ha_config_exported(self, db):
        db.add(Setting(key="ha_enabled", value="true"))
        db.add(Setting(key="keepalived_vip", value="10.0.0.100"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        tv = _tfvars(zf)
        assert "ha_config" in tv
        assert "10.0.0.100" in tv

    def test_api_armor_settings_exported(self, db):
        db.add(Setting(key="api_armor_enabled", value="true"))
        db.add(Setting(key="api_armor_max_body_bytes", value="1048576"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert "api_armor_settings" in tv
        assert "1048576" in tv

    def test_haproxy_global_options_exported(self, db):
        db.add(Setting(key="haproxy_global_options", value='{"log":{"stdout":true}}'))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert "haproxy_global_options" in tv

    def test_maxmind_key_excluded_by_default(self, db):
        db.add(Setting(key="maxmind_license_key", value="SECRET_KEY"))
        db.commit()
        zf = _export(db, include_secrets=False, include_system_secrets=False)
        tv = _tfvars(zf)
        assert "SECRET_KEY" not in tv

    def test_maxmind_key_included_with_system_secrets(self, db):
        db.add(Setting(key="maxmind_license_key", value="SECRET_KEY"))
        db.commit()
        zf = _export(db, include_secrets=False, include_system_secrets=True)
        tv = _tfvars(zf)
        assert "SECRET_KEY" in tv

    def test_singleton_resources_in_management_module(self, db):
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="ha_enabled", value="false"))
        db.add(Setting(key="api_armor_enabled", value="true"))
        db.add(Setting(key="haproxy_global_options", value="{}"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        mgmt_tf = _module_tf(zf, 'management')
        for res in ['corex_global_options', 'corex_captcha_settings',
                    'corex_ha_config']:
            assert res in mgmt_tf, f"Singleton resource '{res}' missing from management module"
        # api_armor_settings now lives in the api-armor module, not management
        aa_tf = _module_tf(zf, 'api-armor')
        assert 'corex_api_armor_settings' in aa_tf, \
            "Singleton resource 'corex_api_armor_settings' should be in api-armor module"


# ─── Non-name-keyed models ──────────────────────────────────────────────────

class TestNonNameKeyedModels:

    def test_error_pages_keyed_by_code(self, db):
        """Error pages should be keyed by HTTP code (raw, not sanitized).

        Keys are "403" not "_403" so file paths match: error_403.html
        """
        db.add(CustomErrorPage(code=503, content="<h1>503</h1>", content_type="text/html"))
        db.add(CustomErrorPage(code=404, content="<h1>404</h1>", content_type="text/html"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        entries = _collection_entries(tv, 'error_pages')
        assert '503' in entries, f"Error page key should be '503', got: {entries}"
        assert '404' in entries, f"Error page key should be '404', got: {entries}"
        traffic_tf = _module_tf(zf, 'traffic')
        # Use try(each.value.code, each.key) to preserve original integer code
        assert 'code = try(each.value.code, each.key)' in traffic_tf
        # Verify file names match keys (no double underscore)
        files = [n for n in zf.namelist() if 'files/traffic/' in n]
        assert any('error_503.html' in f for f in files), f"File should be error_503.html, got: {files}"
        assert not any('error__503' in f for f in files), "File should not have double underscore"

    def test_cache_configs_keyed_by_backend(self, db):
        """Cache configs should be keyed by cache_<backend_name>."""
        be = make_backend(db, name="web")
        make_cache_config(db, backend_id=be.id)
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        entries = _collection_entries(tv, 'cache_configs')
        assert 'cache_web' in entries

    def test_mcp_server_replicas_keyed_by_server_and_id(self, db):
        """MCP server replicas should have a synthetic key."""
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, namespace="eng", transport_type="stdio")
        db.add(srv); db.flush()
        db.add(McpServerReplica(server_id=srv.id, url="http://localhost:8080"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        entries = _collection_entries(tv, 'mcp_server_replicas')
        assert any(k.startswith('replica_tools_') for k in entries), f"Replica key not found in {entries}"


# ─── External file generation ──────────────────────────────────────────────

class TestExternalFiles:

    def test_cert_pem_files_generated(self, db):
        """Certificate PEM placeholder files should be generated for custom-provider
        certs when include_certs=False. Let's Encrypt certs are provider-managed
        and don't need PEM files.
        """
        db.add(Certificate(name="wildcard", domain="*.example.com", provider="custom"))
        # LE cert should NOT get PEM files
        db.add(Certificate(name="le-cert", domain="example.com", provider="letsencrypt"))
        db.commit()
        zf = _export(db, include_certs=False)
        names = zf.namelist()
        # Custom cert should have PEM files
        assert any('environments/dev/files/ssl/' in n and 'wildcard_fullchain.pem' in n for n in names), \
            "Custom cert should have fullchain PEM file"
        assert any('environments/dev/files/ssl/' in n and 'wildcard_key.pem' in n for n in names), \
            "Custom cert should have key PEM file"
        # LE cert should NOT have PEM files
        assert not any('le_cert' in n and '.pem' in n for n in names), \
            "Let's Encrypt cert should NOT have PEM files"

    def test_security_list_entry_files_generated(self, db):
        """Security list entries should be exported as JSON files in environments/dev/files/."""
        nl = NetworkList(name="blocked")
        db.add(nl); db.flush()
        db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.0/8", note="internal"))
        db.commit()
        zf = _export(db)
        names = zf.namelist()
        assert any('environments/dev/files/security-lists/network_' in n and n.endswith('.json') for n in names), \
            f"Network list JSON file not found in {names}"

    def test_mcp_skill_version_files_generated(self, db):
        """MCP skill version body and frontmatter should be exported as files in environments/dev/files/."""
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        skill = McpSkill(name="helper", team_id=team.id)
        db.add(skill); db.flush()
        db.add(McpSkillVersion(skill_id=skill.id, version="1.0.0", body="# Helper",
                              frontmatter={"v": "1.0.0"}))
        db.commit()
        zf = _export(db)
        names = zf.namelist()
        assert any('environments/dev/files/mcp-gateway/skills/' in n and n.endswith('.md') for n in names), \
            f"Skill body file not found in {names}"
        assert any('environments/dev/files/mcp-gateway/skills/' in n and n.endswith('.json') for n in names), \
            f"Skill frontmatter file not found in {names}"

    def test_empty_security_list_generates_file(self, db):
        """Security lists with no entries should still generate an empty JSON file.

        Without this, root main.tf's file() would fail on the missing file.
        """
        nl = NetworkList(name="empty_list")
        db.add(nl)
        db.commit()
        zf = _export(db)
        names = zf.namelist()
        assert any('environments/dev/files/security-lists/network_empty_list.json' in n for n in names), \
            f"Empty list should still generate a JSON file, got: {[n for n in names if 'security-lists' in n]}"
        # Verify the file contains an empty JSON array
        content = zf.read('environments/dev/files/security-lists/network_empty_list.json').decode()
        assert content.strip() == '[]', f"Empty list file should contain [], got: {content}"

    def test_file_expressions_use_try(self, db):
        """All file() expressions in root locals.tf should be wrapped in try().

        This prevents Terraform from failing when a file doesn't exist
        (e.g. lists with no entries, skills without body content).
        """
        _populate_full_config(db)
        zf = _export(db)
        locals_tf = _read(zf, "locals.tf")
        # Find all file() calls
        import re
        file_lines = [line.strip() for line in locals_tf.split('\n') if 'file(' in line]
        for line in file_lines:
            if line.startswith('#'):
                continue
            assert 'try(' in line, \
                f"file() expression not wrapped in try(): {line}"

    def test_error_page_file_name_matches_key(self, db):
        """Error page file names should match their map keys.

        Key "403" -> file error_403.html (not error__403.html with double underscore)
        """
        db.add(CustomErrorPage(code=403, content="<h1>403</h1>", content_type="text/html"))
        db.commit()
        zf = _export(db)
        names = zf.namelist()
        assert any('error_403.html' in n for n in names), \
            f"File should be error_403.html, got: {[n for n in names if 'traffic' in n]}"
        assert not any('error__403' in n for n in names), \
            "File should not have double underscore"
        # Verify the root locals.tf expression uses ${k} which matches the key
        locals_tf = _read(zf, "locals.tf")
        assert 'error_${k}.html' in locals_tf, \
            "Root locals.tf should use error_${k}.html (matching the raw code key)"


# ─── Root main.tf / variables.tf wiring ─────────────────────────────────────

class TestRootWiring:

    def _check_no_unexpected_args(self, zf):
        """Check that root main.tf doesn't pass arguments that modules don't declare.

        Returns a dict of {module_name: set(unexpected_args)} for any mismatches.
        """
        main_tf = _read(zf, "main.tf")
        all_modules = re.findall(r'module "([^"]+)"', main_tf)
        mismatches = {}
        for mod_name in all_modules:
            mod_dir = mod_name.replace('_', '-')
            pattern = r'module "' + mod_name + r'" \{'
            m = re.search(pattern, main_tf)
            if not m:
                continue
            start = m.start()
            depth = 0
            end = start
            for i, c in enumerate(main_tf[start:], start):
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            block = main_tf[start:end]
            passed = set()
            for line in block.split('\n'):
                line = line.strip()
                if '=' in line and not line.startswith('#') and not line.startswith('source'):
                    arg = line.split('=')[0].strip()
                    if arg and not arg.startswith('#'):
                        passed.add(arg)
            try:
                var_tf = zf.read(f"modules/{mod_dir}/variables.tf").decode()
            except KeyError:
                try:
                    var_tf = zf.read(f"modules/{mod_name}/variables.tf").decode()
                except KeyError:
                    continue
            declared = set(re.findall(r'variable "([^"]+)"', var_tf))
            unexpected = passed - declared
            if unexpected:
                mismatches[mod_name] = unexpected
        return mismatches

    def test_no_unexpected_args_empty_db(self, db):
        """Root main.tf should not pass arguments that modules don't declare (empty DB)."""
        zf = _export(db)
        mismatches = self._check_no_unexpected_args(zf)
        assert not mismatches, \
            f"Root passes arguments that modules don't declare: {mismatches}"

    def test_no_unexpected_args_full_db(self, db):
        """Root main.tf should not pass arguments that modules don't declare (full DB)."""
        _populate_full_config(db)
        zf = _export(db)
        mismatches = self._check_no_unexpected_args(zf)
        assert not mismatches, \
            f"Root passes arguments that modules don't declare: {mismatches}"

    def test_no_circular_module_dependency(self, db):
        """Routing and traffic modules must not have a circular dependency.

        FCGI apps were moved from traffic to routing to break the cycle.
        Routing should NOT reference module.traffic, and traffic should
        reference module.routing one-way only.
        """
        _populate_full_config(db)
        zf = _export(db)
        main_tf = _read(zf, "main.tf")
        # Extract the routing module block
        routing_block = main_tf.split('module "routing" {')[1].split('module "')[0]
        # Routing must NOT depend on traffic
        assert 'module.traffic' not in routing_block, \
            "Routing module depends on traffic — circular dependency not resolved"
        # Traffic SHOULD depend on routing (one-way)
        traffic_block = main_tf.split('module "traffic" {')[1].split('module "')[0]
        assert 'module.routing' in traffic_block, \
            "Traffic module should depend on routing (one-way)"

    def test_all_main_tf_vars_declared_in_variables_tf(self, db):
        """Every var.xxx referenced in main.tf must be declared in variables.tf."""
        _populate_full_config(db)
        zf = _export(db)
        main_tf = _read(zf, "main.tf")
        var_tf = _read(zf, "variables.tf")
        var_refs = set(re.findall(r'var\.([a-z_0-9]+)', main_tf))
        declared = set(re.findall(r'variable "([a-z_0-9]+)"', var_tf))
        missing = var_refs - declared
        assert not missing, f"Variables referenced in main.tf but not declared: {missing}"

    def test_all_module_vars_have_root_wiring(self, db):
        """Every collection variable in a module should be wired in root main.tf."""
        _populate_full_config(db)
        zf = _export(db)
        main_tf = _read(zf, "main.tf")
        # File content vars are wired with expressions (e.g. { for k, v in ... })
        # not simple var.xxx references, so we check by variable name presence
        for mod in ['routing', 'traffic', 'waf', 'cache', 'management', 'mcp-gateway']:
            mod_tf = _module_tf(zf, mod)
            mod_vars = set(re.findall(r'var\.([a-z_0-9]+)', mod_tf))
            # Filter out cross-module dependency vars (listener_ids, backend_ids, etc.)
            # and secret map vars - those are wired separately
            for v in mod_vars:
                if v.endswith('_ids') or v.endswith('_passwords') or v.endswith('_secrets') or v.endswith('_info'):
                    continue
                # File content vars are wired with for-expressions, not var.xxx
                if v in ('cert_fullchains', 'cert_keys', 'error_page_contents',
                         'network_list_entries', 'asn_list_entries', 'geo_list_entries',
                         'ja4_list_entries', 'pattern_list_entries',
                         'mcp_skill_bodies', 'mcp_skill_frontmatters'):
                    assert f'{v} = ' in main_tf, \
                        f"Module '{mod}' var '{v}' not wired in root main.tf"
                else:
                    assert f'{v} = var.{v}' in main_tf, \
                        f"Module '{mod}' var '{v}' not wired in root main.tf"

    def test_cross_module_dependencies_wired(self, db):
        """Cross-module dependency maps should be wired in root main.tf."""
        _populate_full_config(db)
        zf = _export(db)
        main_tf = _read(zf, "main.tf")
        # WAF module depends on routing's listener_ids and backend_ids
        assert 'listener_ids = module.routing.listener_ids' in main_tf
        assert 'backend_ids = module.routing.backend_ids' in main_tf
        # MCP gateway depends on management's user_ids
        assert 'user_ids = module.management.user_ids' in main_tf


# ─── HCL structural validity ────────────────────────────────────────────────

class TestHCLValidity:

    def test_resource_blocks_have_for_each(self, db):
        """Every resource block in module main.tf should have for_each."""
        _populate_full_config(db)
        zf = _export(db)
        for name in zf.namelist():
            if not name.startswith('modules/') or not name.endswith('/main.tf'):
                continue
            content = _read(zf, name)
            # Find all resource blocks
            resources = re.findall(r'resource "corex_\w+" "this" \{', content)
            # Singleton resources (captcha_settings, ha_config, api_armor_settings,
            # global_options, maxmind_license_key, page_protect_settings,
            # mcp_alert_config) don't use for_each
            singleton_types = {
                'corex_captcha_settings', 'corex_ha_config',
                'corex_api_armor_settings', 'corex_global_options',
                'corex_maxmind_license_key',
                'corex_page_protect_settings', 'corex_mcp_alert_config',
            }
            for_each_resources = 0
            for match in re.finditer(r'resource "(corex_\w+)" "this" \{', content):
                if match.group(1) not in singleton_types:
                    for_each_resources += 1
            # Each non-singleton resource block should have for_each (var.xxx, merge([...]), or { for ... })
            for_each_count = len(re.findall(r'for_each = (var\.|merge|\{)', content))
            if for_each_resources > 0:
                assert for_each_count >= for_each_resources, \
                    f"{name}: {for_each_resources} for_each resources but only {for_each_count} for_each"

    def test_no_duplicate_resource_types_in_module(self, db):
        """Each module should not have duplicate resource type definitions."""
        _populate_full_config(db)
        zf = _export(db)
        for name in zf.namelist():
            if not name.startswith('modules/') or not name.endswith('/main.tf'):
                continue
            content = _read(zf, name)
            types = re.findall(r'resource "(corex_\w+)" "this"', content)
            assert len(types) == len(set(types)), \
                f"{name}: duplicate resource types: {types}"

    def test_tfvars_balanced_braces(self, db):
        """tfvars should have balanced braces."""
        _populate_full_config(db)
        zf = _export(db)
        tv = _tfvars(zf)
        assert tv.count('{') == tv.count('}'), "Unbalanced braces in tfvars"

    def test_module_tf_balanced_braces(self, db):
        """Each module main.tf should have balanced braces."""
        _populate_full_config(db)
        zf = _export(db)
        for name in zf.namelist():
            if not name.startswith('modules/') or not name.endswith('/main.tf'):
                continue
            content = _read(zf, name)
            assert content.count('{') == content.count('}'), \
                f"Unbalanced braces in {name}"


# ─── Model field preservation ───────────────────────────────────────────────

class TestFieldPreservation:

    def test_backend_all_fields_preserved(self, db):
        """Backend model fields should be preserved in the export.

        Only fields in the provider schema are exported; fields like
        timeout_queue, http_reuse, fullconn are skipped (not in provider).
        """
        be = Backend(name="web", mode="http", protocol="http", algorithm="roundrobin",
                     health_check_enabled=True, retries=3, redispatch=True,
                     timeout_queue=10000, timeout_check=5000, timeout_tunnel=60000,
                     http_reuse="safe", fullconn=1000, host_header="example.com",
                     restore_client_ip=True, client_ip_header="X-Forwarded-For")
        db.add(be); db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        fields = _entry_fields(tv, 'backends', 'web')
        # Check that provider-supported fields are preserved
        for expected_field in ['mode', 'protocol', 'algorithm', 'health_check_enabled',
                               'retries', 'redispatch', 'host_header',
                               'restore_client_ip', 'client_ip_header']:
            assert expected_field in fields, f"Backend field '{expected_field}' missing from tfvars"
        # Fields not in the provider schema should be skipped
        for skipped_field in ['timeout_queue', 'timeout_check', 'timeout_tunnel',
                              'http_reuse', 'fullconn']:
            assert skipped_field not in fields, f"Backend field '{skipped_field}' should be skipped (not in provider schema)"

    def test_waf_rule_all_fields_preserved(self, db):
        """WAF rule model fields should be preserved in the module main.tf.

        Only fields in the provider schema are exported; content_types,
        sec_rules, rate_* are skipped (not in provider schema).
        """
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        make_waf_rule(db, name="rule", listener_id=ln.id, backend_id=be.id,
                      redirect_url="/blocked", status_code=403,
                      path_pattern="/api/*", http_methods="GET,POST",
                      content_types="application/json")
        db.commit()
        zf = _export(db)
        waf_tf = _module_tf(zf, 'waf')
        # These provider-supported fields should be referenced in the resource block
        for field in ['redirect_url', 'status_code', 'path_pattern',
                      'http_methods',
                      'rule_set_version', 'rule_set_url', 'rule_set_sha256',
                      'siem_integration_id']:
            assert f'{field} = ' in waf_tf, f"WAF rule field '{field}' missing from module main.tf"
        # Fields not in the provider schema should be skipped
        for skipped in ['content_types', 'sec_rules', 'rate_header',
                        'rate_enabled', 'rate_events', 'rate_window_seconds']:
            assert f'{skipped} = ' not in waf_tf, f"WAF rule field '{skipped}' should be skipped (not in provider schema)"

    def test_none_values_omitted_from_tfvars(self, db):
        """None/null values should be omitted from tfvars entries."""
        be = Backend(name="web", mode="http", algorithm="roundrobin")
        # Many fields are None
        db.add(be); db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        fields = _entry_fields(tv, 'backends', 'web')
        # None fields should not appear
        assert 'cookie_name' not in fields  # None by default
        assert 'host_header' not in fields  # None by default
        # Non-None fields should appear
        assert 'mode' in fields
        assert 'algorithm' in fields

    def test_name_included_in_tfvars(self, db):
        """The name field should be included in tfvars so resource blocks can
        use the original (unsanitized) name via try(each.value.name, each.key).
        """
        be = make_backend(db, name="web-server")
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # The sanitized key is "web_server" but the name field preserves "web-server"
        m = re.search(r'backends = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None
        assert '"name" = "web-server"' in m.group(1), \
            "name field should preserve original hyphenated name"

    def test_resource_block_uses_try_name_not_each_key(self, db):
        """Resource blocks should use name = try(each.value.name, each.key)
        to preserve the original name from tfvars.
        """
        db.add(NetworkList(name="asn-hosting"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        assert 'name = try(each.value.name, each.key)' in sec_tf, \
            "Resource blocks should use try(each.value.name, each.key)"

    def test_ssl_le_cert_no_pem_content(self, db):
        """Let's Encrypt certs should not pass fullchain/key PEM content.
        Only custom-provider certs should get PEM content.
        """
        db.add(Certificate(name="le-cert", domain="example.com", provider="letsencrypt"))
        db.add(Certificate(name="custom-cert", domain="example.com", provider="custom"))
        db.commit()
        zf = _export(db)
        ssl_tf = _module_tf(zf, 'ssl')
        # Should conditionally pass PEM only for custom provider
        assert 'each.value.provider_name == "custom" ? var.cert_fullchains[each.key] : null' in ssl_tf
        assert 'each.value.provider_name == "custom" ? var.cert_keys[each.key] : null' in ssl_tf
        # Should NOT unconditionally pass PEM
        assert 'fullchain = var.cert_fullchains[each.key]' not in ssl_tf

    def test_gitignore_no_pem_key(self, db):
        """.gitignore should not globally ignore *.pem and *.key so placeholder
        PEM files under environments/*/files/ssl/ can be committed.
        """
        db.add(Certificate(name="custom-cert", domain="example.com", provider="custom"))
        db.commit()
        zf = _export(db)
        gi = zf.read('.gitignore').decode()
        # Should NOT have global *.pem or *.key ignores
        assert '*.pem\n' not in gi, ".gitignore should not globally ignore *.pem"
        assert '*.key\n' not in gi, ".gitignore should not globally ignore *.key"

    def test_non_nullable_same_module_fk_fails_loud(self, db):
        """Non-nullable same-module FKs should NOT use try() — they should
        fail loud if the key doesn't match, instead of silently producing null.
        """
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        db.add(BackendRule(listener_id=ln.id, backend_id=be.id, name="rule1"))
        db.commit()
        zf = _export(db)
        routing_tf = _module_tf(zf, 'routing')
        # BackendRule's listener_id and backend_id are non-nullable same-module FKs
        # They should NOT be wrapped in try()
        assert 'listener_id = corex_listener.this[each.value.listener_id].id' in routing_tf, \
            "Non-nullable same-module FK should fail loud (no try())"
        assert 'backend_id = corex_backend.this[each.value.backend_id].id' in routing_tf, \
            "Non-nullable same-module FK should fail loud (no try())"
        # Make sure they're NOT wrapped in try()
        assert 'try(corex_listener.this[each.value.listener_id].id, null)' not in routing_tf, \
            "Non-nullable same-module FK should NOT use try()"
        assert 'try(corex_backend.this[each.value.backend_id].id, null)' not in routing_tf, \
            "Non-nullable same-module FK should NOT use try()"

    def test_nullable_cross_module_fk_uses_try(self, db):
        """Nullable cross-module FKs should use try() to handle null values."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        # RateLimit.listener_id is nullable=True
        db.add(RateLimit(name="rl1", listener_id=ln.id, events=100, window_seconds=60))
        db.add(RateLimit(name="rl2", listener_id=None, events=100, window_seconds=60))
        db.commit()
        zf = _export(db)
        traffic_tf = _module_tf(zf, 'traffic')
        # Nullable cross-module FK should use try()
        assert 'listener_id = try(var.listener_ids[each.value.listener_id], null)' in traffic_tf, \
            "Nullable cross-module FK should use try()"

    def test_optional_fields_use_try_all_modules(self, db):
        """Module resource blocks should use try() for all each.value references.

        Fields that are None in the database are omitted from tfvars, so
        each.value.{field} would fail without try().
        """
        _populate_full_config(db)
        zf = _export(db)
        import re
        for mod_name in ['ssl', 'routing', 'traffic', 'security-lists', 'security-rules',
                        'waf', 'cache', 'observability', 'page-protect', 'api-armor',
                        'risk-scoring', 'management', 'mcp-gateway']:
            try:
                mod_tf = _module_tf(zf, mod_name)
            except KeyError:
                continue
            bare_refs = re.findall(r'= each\.value\.\w+\s*$', mod_tf)
            assert not bare_refs, \
                f"Found bare each.value references (no try()) in {mod_name} module: {bare_refs}"


# ─── Typed variables, state separation, nested cache rules ────────────────

class TestTypedVariables:

    def test_collection_vars_use_typed_objects(self, db):
        """Collection variables should use map(object({...})) instead of type=any."""
        _populate_full_config(db)
        zf = _export(db)
        # Check module-level variables
        for mod_name in ['routing', 'security-lists', 'cache']:
            try:
                mod_vars = zf.read(f'modules/{mod_name}/variables.tf').decode()
            except KeyError:
                continue
            assert 'map(object({' in mod_vars, \
                f"{mod_name} variables.tf should use map(object(...)) types"
        # Check root variables.tf
        root_vars = zf.read('variables.tf').decode()
        assert 'map(object({' in root_vars, \
            "Root variables.tf should use map(object(...)) types"

    def test_typed_vars_use_optional(self, db):
        """Object fields should use optional() so missing fields become null."""
        db.add(NetworkList(name="test"))
        db.commit()
        zf = _export(db)
        sec_vars = zf.read('modules/security-lists/variables.tf').decode()
        assert 'optional(string)' in sec_vars, \
            "Typed fields should use optional()"

    def test_typed_vars_no_any_for_collections(self, db):
        """Collection variables should not use type=any (except for file content vars and singletons)."""
        _populate_full_config(db)
        zf = _export(db)
        root_vars = zf.read('variables.tf').decode()
        # Find all variable blocks with type = any
        import re
        any_vars = re.findall(r'variable "(\w+)" \{\n  type\s+= any', root_vars)
        # Filter out file content variables (entries, frontmatters) which stay as any
        file_content_vars = {
            'network_list_entries', 'asn_list_entries', 'geo_list_entries',
            'ja4_list_entries', 'pattern_list_entries',
            'mcp_skill_bodies', 'mcp_skill_frontmatters',
        }
        # Filter out singleton variables (not map collections)
        singleton_vars = {
            'settings', 'captcha_settings', 'ha_config',
            'haproxy_global_options', 'api_armor_settings',
            'maxmind_license_key',
            'page_protect_settings', 'mcp_alert_config',
            'ssl_labs_settings',
        }
        excluded = file_content_vars | singleton_vars
        collection_any_vars = [v for v in any_vars if v not in excluded]
        assert not collection_any_vars, \
            f"Collection variables should not use type=any: {collection_any_vars}"


class TestStateSeparation:

    def test_backend_tf_has_no_hardcoded_key(self, db):
        """backend.tf should not have a hardcoded state key — it's per-environment."""
        db.add(Backend(name="web", mode="http", protocol="http", algorithm="roundrobin"))
        db.commit()
        zf = _export(db)
        backend_tf = zf.read('backend.tf').decode()
        # Should NOT have a hardcoded key in the backend block
        assert 'key = "corex/terraform.tfstate"' not in backend_tf, \
            "backend.tf should not hardcode a single state key"
        # Should mention per-environment backend config
        assert 'backend-config=environments' in backend_tf, \
            "backend.tf should reference per-environment backend config"

    def test_env_backend_tfvars_has_state_key(self, db):
        """Per-environment backend.tfvars should have a state key with env name."""
        db.add(Backend(name="web", mode="http", protocol="http", algorithm="roundrobin"))
        db.commit()
        zf = _export(db)
        env_backend = zf.read('environments/dev.backend.tfvars').decode()
        assert 'key = "corex/dev/terraform.tfstate"' in env_backend, \
            "dev.backend.tfvars should have key = corex/dev/terraform.tfstate"


class TestNestedCacheRules:

    def test_cache_rules_nested_under_configs(self, db):
        """Cache rules should be nested under cache_configs, not a separate collection."""
        be = make_backend(db, name="web")
        db.flush()
        cc = CacheConfig(backend_id=be.id, haproxy_enabled=True)
        db.add(cc); db.flush()
        db.add(CacheRule(cache_config_id=cc.id, priority=0, match_type="path",
                        pattern="/static/*", action="cache", tier="memory"))
        db.add(CacheRule(cache_config_id=cc.id, priority=1, match_type="path",
                        pattern="/api/*", action="bypass", tier="memory"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # cache_rules should NOT be a separate collection
        assert 'cache_rules = {' not in tv, \
            "cache_rules should not be a separate collection in tfvars"
        # cache_configs should have nested rules
        m = re.search(r'cache_configs = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None, "cache_configs not found in tfvars"
        assert '"rules"' in m.group(1), \
            "cache_configs should have nested rules"
        assert '"pattern" = "/static/*"' in m.group(1), \
            "First rule pattern should be in nested rules"
        assert '"pattern" = "/api/*"' in m.group(1), \
            "Second rule pattern should be in nested rules"

    def test_cache_module_flattens_nested_rules(self, db):
        """Cache module should flatten nested rules into corex_cache_rule resources."""
        be = make_backend(db, name="web")
        db.flush()
        cc = CacheConfig(backend_id=be.id, haproxy_enabled=True)
        db.add(cc); db.flush()
        db.add(CacheRule(cache_config_id=cc.id, priority=0, match_type="path",
                        pattern="/static/*", action="cache", tier="memory"))
        db.commit()
        zf = _export(db)
        cache_tf = _module_tf(zf, 'cache')
        # Should have a corex_cache_rule resource
        assert 'resource "corex_cache_rule" "this"' in cache_tf, \
            "Cache module should have corex_cache_rule resource"
        # Should use merge() to flatten nested rules
        assert 'merge([' in cache_tf, \
            "Cache rules should use merge() to flatten nested rules"
        # Should resolve cache_config_id from parent config
        assert 'cache_config_id = corex_cache_config.this[each.value.config_key].id' in cache_tf, \
            "Cache rule should resolve config_id from parent config"

    def test_cache_configs_typed_with_rules(self, db):
        """Cache configs variable should have typed rules field."""
        be = make_backend(db, name="web")
        db.flush()
        db.add(CacheConfig(backend_id=be.id, haproxy_enabled=True))
        db.commit()
        zf = _export(db)
        cache_vars = zf.read('modules/cache/variables.tf').decode()
        assert 'rules = optional(list(object({' in cache_vars, \
            "cache_configs type should include optional(list(object(...))) for rules"
        assert 'priority' in cache_vars and 'match_type' in cache_vars, \
            "Cache rule object type should include priority and match_type"


# ─── MCP Gateway self-registered resources ─────────────────────────────────

class TestMcpSelfRegisteredExclusion:

    def test_platform_team_included(self, db):
        """The 'platform' team should be included — user-created servers may live in it.

        Only the self-registered server (namespace 'corex-manager') and skill
        (name 'corex-manager') are filtered individually, not the whole team.
        """
        db.add(Team(name="Platform", slug="platform"))
        db.add(Team(name="Eng", slug="eng"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        entries = _collection_entries(tv, 'mcp_teams')
        assert 'eng' in entries
        assert 'platform' in entries, \
            "Platform team should be included (user-created resources may live in it)"

    def test_corex_manager_server_excluded(self, db):
        """Self-registered 'corex-manager' namespace servers should be excluded."""
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpServer(name="tools", team_id=team.id, namespace="eng", transport_type="stdio"))
        db.add(McpServer(name="corex-manager", team_id=team.id, namespace="corex-manager",
                        transport_type="stdio"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        entries = _collection_entries(tv, 'mcp_servers')
        assert 'tools' in entries
        assert 'corex-manager' not in entries


# ─── Singleton resource schema correctness ──────────────────────────────────

class TestSingletonSchema:
    """Singleton resources must NOT use for_each — they have flat attributes."""

    def test_captcha_no_for_each(self, db):
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        mgmt = _module_tf(zf, 'management')
        # Find the captcha resource block
        m = re.search(r'resource "corex_captcha_settings" "this" \{(.*?)\n\}',
                      mgmt, re.DOTALL)
        assert m, "corex_captcha_settings resource not found"
        block = m.group(1)
        assert 'for_each' not in block, "Singleton should not use for_each"
        assert 'captcha_provider' in block

    def test_ha_config_no_for_each(self, db):
        db.add(Setting(key="ha_enabled", value="true"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        mgmt = _module_tf(zf, 'management')
        m = re.search(r'resource "corex_ha_config" "this" \{(.*?)\n\}',
                      mgmt, re.DOTALL)
        assert m, "corex_ha_config resource not found"
        block = m.group(1)
        assert 'for_each' not in block, "Singleton should not use for_each"

    def test_api_armor_no_for_each(self, db):
        db.add(Setting(key="api_armor_enabled", value="true"))
        db.commit()
        zf = _export(db)
        # api_armor_settings now lives in the api-armor module
        aa = _module_tf(zf, 'api-armor')
        m = re.search(r'resource "corex_api_armor_settings" "this" \{(.*?)\n\}',
                      aa, re.DOTALL)
        assert m, "corex_api_armor_settings resource not found in api-armor module"
        block = m.group(1)
        assert 'for_each' not in block, "Singleton should not use for_each"

    def test_global_options_uses_list_object(self, db):
        """haproxy_global_options is a list of objects; provider expects list, not JSON string."""
        db.add(Setting(key="haproxy_global_options",
                       value='[{"target":"global","directive":"log","value":"","enabled":true}]'))
        db.commit()
        zf = _export(db)
        mgmt = _module_tf(zf, 'management')
        m = re.search(r'resource "corex_global_options" "this" \{(.*?)\n\}',
                      mgmt, re.DOTALL)
        assert m, "corex_global_options resource not found"
        block = m.group(1)
        # Should pass the list variable directly, not jsondecode() a string
        assert 'options = var.haproxy_global_options' in block, \
            "Should pass the list variable directly (no jsondecode())"
        assert 'jsondecode(' not in block, \
            "Should not use jsondecode() — the tfvars already has a list"
        assert 'for_each' not in block
        # Variable type should be list(object({...})), not string
        var_tf = _read(zf, 'variables.tf')
        assert 'list(object({' in var_tf and 'target = optional(string)' in var_tf, \
            "Root variable should be list(object({...}))"


# ─── Feed-managed lists ──────────────────────────────────────────────────────

class TestFeedManagedLists:

    def test_feed_managed_list_marked_in_tfvars(self, db):
        """Lists with a dynamic feed should have feed_managed = true in tfvars."""
        nl = NetworkList(name="tor-exit-nodes", description="Tor exit nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        # Also add a non-feed-managed list
        nl2 = NetworkList(name="trusted", description="Trusted IPs")
        db.add(nl2); db.flush()
        db.add(NetworkListEntry(list_id=nl2.id, value="10.0.0.1"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # The feed-managed list should have feed_managed = true
        tor_fields = _entry_fields(tv, 'network_lists', 'tor_exit_nodes')
        assert 'feed_managed' in tor_fields, \
            "Feed-managed list should have feed_managed field in tfvars"
        # Parse the actual value
        m = re.search(r'"tor_exit_nodes" = \{([^}]*)\}', tv)
        assert m, "tor_exit_nodes entry not found"
        assert '"feed_managed" = true' in m.group(1)
        # The owned list should NOT have feed_managed = true
        trusted_m = re.search(r'"trusted" = \{([^}]*)\}', tv)
        if trusted_m:
            assert 'feed_managed = true' not in trusted_m.group(1)

    def test_feed_managed_list_no_snapshot_file(self, db):
        """Feed-managed lists should NOT ship entry snapshot JSON files."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(NetworkListEntry(list_id=nl.id, value="1.2.3.4"))
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        # Also add an owned list with entries
        nl2 = NetworkList(name="owned-list")
        db.add(nl2); db.flush()
        db.add(NetworkListEntry(list_id=nl2.id, value="10.0.0.1"))
        db.commit()
        zf = _export(db)
        # The feed-managed list should NOT have a JSON file
        tor_file = 'environments/dev/files/security-lists/network_tor_exit_nodes.json'
        assert tor_file not in zf.namelist(), \
            "Feed-managed list should not ship a snapshot file"
        # The owned list SHOULD have a JSON file
        owned_file = 'environments/dev/files/security-lists/network_owned_list.json'
        assert owned_file in zf.namelist(), \
            "Owned list should ship a snapshot file"

    def test_feed_managed_list_has_ignore_changes(self, db):
        """Feed-managed lists should be in a separate block with ignore_changes."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        # Should have a feed_managed resource block
        assert 'corex_network_list" "feed_managed"' in sec_tf, \
            "Should have a feed_managed resource block"
        # That block should have ignore_changes = [entries]
        m = re.search(r'resource "corex_network_list" "feed_managed" \{(.*?)\n\}',
                      sec_tf, re.DOTALL)
        assert m, "feed_managed block not found"
        assert 'ignore_changes = [entries]' in m.group(1)

    def test_owned_list_not_in_feed_managed_block(self, db):
        """Owned lists should be in the main block (.this), not feed_managed."""
        nl = NetworkList(name="trusted")
        db.add(nl); db.flush()
        db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        # The .feed_managed resource block is always emitted (empty for_each
        # when no feed-managed lists exist), but the owned list should be
        # in .this, not .feed_managed.
        assert 'resource "corex_network_list" "this"' in sec_tf, \
            "Owned list should be in .this resource block"
        assert 'resource "corex_network_list" "feed_managed"' in sec_tf, \
            "feed_managed block should always be emitted (empty for_each is valid)"

    def test_root_entries_skip_feed_managed(self, db):
        """Root locals.tf entries expression should skip feed-managed lists."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        locals_tf = _read(zf, 'locals.tf')
        # The entries expression should check feed_managed
        assert 'feed_managed' in locals_tf, \
            "Root locals.tf should reference feed_managed in entries expression"


# ─── Import blocks ───────────────────────────────────────────────────────────

class TestImportBlocks:

    def test_imports_tf_generated(self, db):
        """imports.tf should be generated in the ZIP."""
        _populate_full_config(db)
        zf = _export(db)
        assert 'imports.tf' in zf.namelist()

    def test_import_blocks_use_module_address(self, db):
        """Import blocks should reference module.corex_resource.this[key]."""
        be = make_backend(db, name="web-backend")
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'import {' in imports
        assert 'module.routing.corex_backend.this' in imports
        assert '"web_backend"' in imports

    def test_import_id_is_original_name(self, db):
        """Import ID should be the original API name, not the sanitized key."""
        be = make_backend(db, name="web-backend")
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        # Should import by the original name "web-backend"
        assert 'id = "web-backend"' in imports

    def test_import_blocks_for_certificates(self, db):
        """Certificates should have import blocks."""
        from app.models.models import Certificate
        db.add(Certificate(name="ne4u.com", domain="ne4u.com", provider="custom"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'module.ssl.corex_certificate.this' in imports
        assert 'id = "ne4u.com"' in imports

    def test_import_feed_managed_targets_feed_managed_block(self, db):
        """Feed-managed lists should get import blocks targeting .feed_managed, not .this."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        # Should import the feed-managed list targeting .feed_managed
        assert 'corex_network_list.feed_managed["tor_exit_nodes"]' in imports, \
            "Feed-managed list should have an import block targeting .feed_managed"
        assert 'id = "tor-exit-nodes"' in imports, \
            "Feed-managed import ID should be the original API name"
        # Should NOT have a .this import for the feed-managed list
        assert 'corex_network_list.this["tor_exit_nodes"]' not in imports, \
            "Feed-managed list should not get a .this import block"

    def test_import_count_line(self, db):
        """imports.tf should end with a count line."""
        _populate_full_config(db)
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'Total:' in imports

    def test_import_full_config_covers_all_collections(self, db):
        """Full config should produce import blocks for all major resource types."""
        _populate_full_config(db)
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        # Every major resource type present in the full config fixture
        # should have at least one import block
        expected = [
            'corex_backend.this',
            'corex_server.this',
            'corex_listener.this',
            'corex_backend_rule.this',
            'corex_fcgi_app.this',
            'corex_network_list.feed_managed',
            'corex_geo_list.this',
            'corex_pattern_list.this',
            'corex_dynamic_feed.this',
            'corex_security_rule.this',
            'corex_waf_rule.this',
            'corex_waf_exception.this',
            'corex_cache_config.this',
            'corex_rate_limit.this',
            'corex_response_header.this',
            'corex_request_header.this',
            'corex_redirect.this',
            'corex_rewrite.this',
            'corex_response_transform.this',
            'corex_error_page.this',
            'corex_log_destination.this',
            'corex_logged_field.this',
            'corex_page_protect_policy.this',
            'corex_api_armor_auth_policy.this',
            'corex_api_armor_api_key_list.this',
            'corex_api_armor_openapi_spec.this',
            'corex_risk_ruleset.this',
            'corex_risk_rule.this',
            'corex_user.this',
            'corex_setting.this',
            'corex_mcp_team.this',
            'corex_mcp_server.this',
            'corex_mcp_server_replica.this',
            'corex_mcp_identity.this',
            'corex_mcp_policy.this',
            'corex_mcp_dlp_rule.this',
            'corex_mcp_guardrail.this',
            'corex_mcp_skill.this',
            'corex_mcp_skill_version.this',
        ]
        missing = [r for r in expected if r not in imports]
        assert not missing, f"Missing import blocks for: {missing}"

    def test_import_server_uses_numeric_id(self, db):
        """Server import ID should be the numeric row ID (provider requires numeric)."""
        be = make_backend(db, name="web")
        srv = make_server(db, be.id, name="web1")
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        # Server should be imported by numeric ID, not by name
        assert f'id = "{srv.id}"' in imports, \
            "Server should be imported by numeric row ID"
        assert 'corex_server.this["web1"]' in imports

    def test_import_backend_rule_uses_numeric_id(self, db):
        """BackendRule import ID should be the numeric row ID."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        br = BackendRule(name="api", listener_id=ln.id, backend_id=be.id,
                         priority=100, condition_type="path", condition_name="path",
                         operator="beg", value="/api")
        db.add(br); db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert f'id = "{br.id}"' in imports, \
            "BackendRule should be imported by numeric row ID"

    def test_import_cache_config_uses_backend_name(self, db):
        """CacheConfig import ID should be the backend name (portable across instances)."""
        be = make_backend(db, name="web")
        cc = CacheConfig(backend_id=be.id, haproxy_enabled=True)
        db.add(cc); db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'id = "web"' in imports, \
            "CacheConfig should be imported by backend name, not numeric backend_id"

    def test_import_user_uses_username(self, db):
        """User import ID should be the username string."""
        db.add(User(username="admin", email="admin@ex.com", role="admin",
                    hashed_password="$2b$12$abc", is_admin=True))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'id = "admin"' in imports, \
            "User should be imported by username"

    def test_import_setting_uses_key(self, db):
        """Setting import ID should be the setting key string."""
        db.add(Setting(key="site_name", value="coreX"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'id = "site_name"' in imports, \
            "Setting should be imported by its key"

    def test_import_mcp_team_member_uses_composite_names(self, db):
        """McpTeamMember import ID should be "{team_name}:{user_username}" (portable)."""
        team = Team(name="Eng", slug="eng")
        user = User(username="admin", email="admin@ex.com", role="admin",
                    hashed_password="$2b$12$abc", is_admin=True)
        db.add_all([team, user]); db.flush()
        ut = UserTeam(team_id=team.id, user_id=user.id)
        db.add(ut); db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        composite = 'Eng:admin'
        assert f'id = "{composite}"' in imports, \
            "McpTeamMember should be imported by composite team_name:user_username"

    def test_import_waf_exception_uses_numeric_id(self, db):
        """WafException import ID should be the numeric row ID."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        wr = make_waf_rule(db, name="sqli_rule", listener_id=ln.id, backend_id=be.id)
        we = make_waf_exception(db, waf_rule_id=wr.id, name="allow_admin", rule_id="942100")
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert f'id = "{we.id}"' in imports, \
            "WafException should be imported by numeric row ID"

    def test_import_logged_field_uses_numeric_id(self, db):
        """LoggedField import ID should be the numeric row ID."""
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        lf = LoggedField(listener_id=ln.id, name="custom", field="X-Custom")
        db.add(lf); db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert f'id = "{lf.id}"' in imports, \
            "LoggedField should be imported by numeric row ID"

    def test_import_mcp_server_replica_uses_numeric_id(self, db):
        """McpServerReplica import ID should be the numeric row ID."""
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, namespace="eng", transport_type="stdio")
        db.add(srv); db.flush()
        rep = McpServerReplica(server_id=srv.id, url="http://localhost:8080")
        db.add(rep); db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert f'id = "{rep.id}"' in imports, \
            "McpServerReplica should be imported by numeric row ID"

    def test_import_readme_uses_module_prefix(self, db):
        """README import examples should use the module.<name>. prefix."""
        be = make_backend(db, name="web-backend")
        db.commit()
        zf = _export(db)
        readme = _read(zf, 'README.md')
        assert 'module.routing.corex_backend.this' in readme, \
            "README should show module-prefixed import addresses"
        assert 'module.ssl.corex_certificate.this' in readme, \
            "README should show module-prefixed import addresses"
        # Should not show bare (unprefixed) resource addresses
        assert 'terraform import corex_backend.this' not in readme, \
            "README should not show bare (unprefixed) import addresses"


# ─── Production safety ──────────────────────────────────────────────────────

class TestModuleCompleteness:
    """Tests that modules always emit resource blocks for declared variables,
    so the module is environment-independent and adding data to tfvars creates
    resources without regenerating the module."""

    def test_empty_db_emits_all_resource_blocks(self, db):
        """Empty DB should still emit resource blocks for all collections."""
        zf = _export(db)
        # Traffic module should have redirect, rewrite, response_transform blocks
        traffic_tf = _module_tf(zf, 'traffic')
        assert 'resource "corex_redirect" "this"' in traffic_tf, \
            "Traffic module should emit redirect resource block even when empty"
        assert 'resource "corex_rewrite" "this"' in traffic_tf, \
            "Traffic module should emit rewrite resource block even when empty"
        assert 'resource "corex_response_transform" "this"' in traffic_tf, \
            "Traffic module should emit response_transform resource block even when empty"
        # SSL module should have cipher_suite block
        ssl_tf = _module_tf(zf, 'ssl')
        assert 'resource "corex_cipher_suite" "this"' in ssl_tf, \
            "SSL module should emit cipher_suite resource block even when empty"
        # MCP module should have dlp, guardrail, skill, server_replica blocks
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        assert 'resource "corex_mcp_dlp_rule" "this"' in mcp_tf, \
            "MCP module should emit dlp_rule resource block even when empty"
        assert 'resource "corex_mcp_guardrail" "this"' in mcp_tf, \
            "MCP module should emit guardrail resource block even when empty"
        assert 'resource "corex_mcp_skill" "this"' in mcp_tf, \
            "MCP module should emit skill resource block even when empty"
        assert 'resource "corex_mcp_server_replica" "this"' in mcp_tf, \
            "MCP module should emit server_replica resource block even when empty"

    def test_empty_db_no_unexpected_args(self, db):
        """Empty DB: root main.tf should not pass args that modules don't declare."""
        zf = _export(db)
        # Check all modules for unexpected args
        for mod_name in ['routing', 'traffic', 'ssl', 'security-lists', 'security-rules',
                        'waf', 'cache', 'observability', 'page-protect', 'api-armor',
                        'risk-scoring', 'management', 'mcp-gateway']:
            if not _has_module(zf, mod_name):
                continue
            mod_tf = _module_tf(zf, mod_name)
            mod_var_tf = _module_var_tf(zf, mod_name)
            # Extract declared variable names from variables.tf
            import re
            declared = set(re.findall(r'variable "(\w+)"', mod_var_tf))
            # Extract passed arguments from root main.tf
            root_main = _read(zf, 'main.tf')
            mod_block_pattern = rf'module "{mod_name.replace("-", "_")}" \{{.*?\n\}}'
            mod_block_match = re.search(mod_block_pattern, root_main, re.DOTALL)
            if mod_block_match:
                passed = set(re.findall(r'^\s+(\w+)\s*=', mod_block_match.group(), re.MULTILINE))
                # Remove source (it's not a variable)
                passed.discard('source')
                unexpected = passed - declared
                assert not unexpected, \
                    f"Module {mod_name} gets unexpected args: {unexpected}"


class TestEnvironmentVariable:
    """Tests that environment is set in every tfvars file."""

    def test_environment_in_dev_tfvars(self, db):
        """dev.tfvars should set environment = "dev"."""
        zf = _export(db)
        tv = _tfvars(zf)
        assert 'environment = "dev"' in tv, \
            "dev.tfvars should set environment = 'dev'"

    def test_environment_comment_explains_copying(self, db):
        """dev.tfvars should have a comment explaining to update environment when copying."""
        zf = _export(db)
        tv = _tfvars(zf)
        assert 'prod' in tv.lower(), \
            "dev.tfvars should mention prod in the environment comment"


class TestHaproxyGlobalOptionsType:
    """Tests that haproxy_global_options is typed as list(object({...}))."""

    def test_root_variable_typed_as_list_object(self, db):
        """Root variables.tf should declare haproxy_global_options as list(object({...}))."""
        db.add(Setting(key="haproxy_global_options", value="[]"))
        db.commit()
        zf = _export(db)
        var_tf = _read(zf, 'variables.tf')
        # Find the haproxy_global_options variable block
        import re
        m = re.search(r'variable "haproxy_global_options" \{(.*?)\n\}', var_tf, re.DOTALL)
        assert m, "haproxy_global_options variable not found in root variables.tf"
        block = m.group(1)
        assert 'list(object({' in block, \
            "haproxy_global_options should be typed as list(object({...})) at root"
        assert 'target = optional(string)' in block
        assert 'directive = optional(string)' in block
        assert 'value = optional(string)' in block
        assert 'enabled = optional(bool)' in block
        assert 'default     = []' in block, \
            "haproxy_global_options should default to [] at root"

    def test_module_variable_typed_as_list_object(self, db):
        """Management module variables.tf should declare haproxy_global_options as list(object({...}))."""
        db.add(Setting(key="haproxy_global_options", value="[]"))
        db.commit()
        zf = _export(db)
        mod_var_tf = _module_var_tf(zf, 'management')
        import re
        m = re.search(r'variable "haproxy_global_options" \{(.*?)\n\}', mod_var_tf, re.DOTALL)
        assert m, "haproxy_global_options variable not found in management module"
        block = m.group(1)
        assert 'list(object({' in block, \
            "haproxy_global_options should be typed as list(object({...})) in management module"
        assert 'target = optional(string)' in block


class TestCaptchaSecretsSplit:
    """Tests that captcha secrets are split into captcha_secrets in secrets.tfvars."""

    def test_captcha_secrets_in_secrets_tfvars(self, db):
        """captcha_secrets should be in dev.secrets.tfvars, not dev.tfvars."""
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="cap_secret", value="real-secret"))
        db.add(Setting(key="recaptcha_secret", value="real-recaptcha-secret"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # Non-secret keys should be in dev.tfvars
        assert '"captcha_provider" = "recaptcha"' in tv, \
            "Non-secret captcha key should be in dev.tfvars"
        # Secret keys should be in secrets.tfvars, not dev.tfvars
        assert 'captcha_secrets' in secrets, \
            "captcha_secrets map should be in dev.secrets.tfvars"
        assert '"cap_secret"' in secrets, \
            "cap_secret should be in dev.secrets.tfvars"
        assert '"recaptcha_secret"' in secrets, \
            "recaptcha_secret should be in dev.secrets.tfvars"
        # Secret keys should NOT be in dev.tfvars
        assert '"cap_secret"' not in tv, \
            "cap_secret should not be in dev.tfvars"
        assert '"recaptcha_secret"' not in tv, \
            "recaptcha_secret should not be in dev.tfvars"

    def test_captcha_module_references_captcha_secrets(self, db):
        """Management module should reference var.captcha_secrets for secret keys."""
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="cap_secret", value="real-secret"))
        db.commit()
        zf = _export(db)
        mgmt_tf = _module_tf(zf, 'management')
        assert 'var.captcha_secrets' in mgmt_tf, \
            "Module should reference var.captcha_secrets for secret keys"
        assert 'var.captcha_settings' in mgmt_tf, \
            "Module should reference var.captcha_settings for non-secret keys"

    def test_captcha_secrets_inlined_with_include_secrets(self, db):
        """When include_secrets=True, all captcha keys should be in captcha_settings."""
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="cap_secret", value="real-secret"))
        db.commit()
        zf = _export(db, include_secrets=True)
        tv = _tfvars(zf)
        assert '"cap_secret" = "real-secret"' in tv, \
            "cap_secret should be inlined in captcha_settings when include_secrets=True"
        # captcha_secrets should NOT be in tfvars or secrets.tfvars
        assert 'captcha_secrets' not in tv, \
            "captcha_secrets should not exist when include_secrets=True"


class TestUsersUsernameField:
    """Tests that users use 'username' field explicitly, not 'name'."""

    def test_user_resource_uses_username_field(self, db):
        """User resource block should set username = try(each.value.username, each.key)."""
        db.add(User(username="admin", email="admin@ex.com", role="admin",
                    hashed_password="$2b$12$abc", is_admin=True))
        db.commit()
        zf = _export(db)
        mgmt_tf = _module_tf(zf, 'management')
        assert 'username = try(each.value.username, each.key)' in mgmt_tf, \
            "User resource should set username explicitly"
        # Should NOT use name = try(each.value.name, each.key) for users
        import re
        user_block = re.search(r'resource "corex_user" "this" \{(.*?)\n\}', mgmt_tf, re.DOTALL)
        assert user_block, "User resource block not found"
        assert 'name = try(each.value.name' not in user_block.group(1), \
            "User resource should NOT use name = try(each.value.name, ...)"

    def test_user_tfvars_includes_username(self, db):
        """User tfvars should include the username field explicitly."""
        db.add(User(username="admin", email="admin@ex.com", role="admin",
                    hashed_password="$2b$12$abc", is_admin=True))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert '"username" = "admin"' in tv, \
            "User tfvars should include username field explicitly"


class TestProductionSafety:

    def test_certificates_do_not_have_prevent_destroy(self, db):
        """Certificates should NOT have prevent_destroy — it blocks replacing bad certs."""
        from app.models.models import Certificate
        db.add(Certificate(name="cert1", domain="example.com", provider="custom"))
        db.commit()
        zf = _export(db)
        ssl_tf = _module_tf(zf, 'ssl')
        assert 'prevent_destroy = true' not in ssl_tf, \
            "Certificates should NOT have prevent_destroy (blocks replacing bad certs)"

    def test_listeners_have_prevent_destroy(self, db):
        """Listeners should have lifecycle { prevent_destroy = true }."""
        be = make_backend(db, name="web")
        make_listener(db, backend=be, name="https", bind_port=443, ssl_enabled=True)
        db.commit()
        zf = _export(db)
        routing_tf = _module_tf(zf, 'routing')
        assert 'prevent_destroy = true' in routing_tf, \
            "Listeners should have prevent_destroy"

    def test_backend_tf_has_encryption_note(self, db):
        """backend.tf should mention encryption for remote state."""
        zf = _export(db)
        backend_tf = _read(zf, 'backend.tf')
        assert 'encrypt' in backend_tf.lower() or 'encryption' in backend_tf.lower()

    def test_imports_tf_explains_adoption_not_config_generation(self, db):
        """imports.tf header should explain that import blocks adopt existing
        objects into state, not generate config."""
        _populate_full_config(db)
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'adopt' in imports.lower(), \
            "imports.tf should explain that blocks adopt existing objects"
        assert 'no-op' in imports.lower() or 'no-op' in imports, \
            "imports.tf should mention that imported resources become no-ops"

    def test_readme_import_section_mentions_imports_tf(self, db):
        """README import section should mention the generated imports.tf file."""
        zf = _export(db)
        readme = _read(zf, 'README.md')
        assert 'imports.tf' in readme, \
            "README should mention the generated imports.tf file"


# ─── .gitignore correctness ───────────────────────────────────────────────────

class TestGitignore:

    def test_lockfile_not_ignored(self, db):
        """.terraform.lock.hcl should NOT be ignored (commit it for reproducible builds)."""
        zf = _export(db)
        gi = _read(zf, '.gitignore')
        # Should not have a line that ignores .terraform.lock.hcl
        for line in gi.strip().split('\n'):
            line = line.strip()
            if line.startswith('#'):
                continue
            assert '.terraform.lock.hcl' not in line, \
                f".terraform.lock.hcl should not be ignored: {line}"

    def test_tfstate_ignored(self, db):
        """*.tfstate should be ignored."""
        zf = _export(db)
        gi = _read(zf, '.gitignore')
        assert '*.tfstate' in gi

    def test_secrets_tfvars_ignored(self, db):
        """*.secrets.tfvars should be ignored."""
        zf = _export(db)
        gi = _read(zf, '.gitignore')
        assert '*.secrets.tfvars' in gi


# ─── README correctness ──────────────────────────────────────────────────────

class TestReadme:

    def test_readme_has_import_section(self, db):
        """README should mention terraform import."""
        _populate_full_config(db)
        zf = _export(db)
        readme = _read(zf, 'README.md')
        assert 'import' in readme.lower()

    def test_readme_tree_built_from_modules(self, db):
        """README tree should list actual modules, not hardcoded ones."""
        # Add a certificate so the ssl module is generated
        from app.models.models import Certificate
        db.add(Certificate(name="cert1", domain="example.com", provider="custom"))
        _populate_full_config(db)
        zf = _export(db)
        readme = _read(zf, 'README.md')
        # Should mention modules that actually exist
        for mod_name in ['routing', 'ssl', 'traffic', 'security-lists']:
            assert mod_name in readme, f"Module {mod_name} should be in README tree"

    def test_readme_no_phantom_modules(self, db):
        """README should not list modules that don't exist."""
        zf = _export(db)
        readme = _read(zf, 'README.md')
        # These were listed in the old README but may not exist as modules
        # The tree should be built from actual modules
        # Check that the tree section exists
        assert 'modules/' in readme


# ─── Dynamic feed target_list_id typing ──────────────────────────────────────

class TestDynamicFeedTargetListId:
    """target_list_id in dynamic_feeds must be typed as string, not number."""

    def test_target_list_id_typed_as_string(self, db):
        """target_list_id holds a logical key (string), not an integer ID."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        # Check module variables.tf
        mod_vars = _module_var_tf(zf, 'security-lists')
        # Find the dynamic_feeds variable type
        m = re.search(r'variable "dynamic_feeds" \{(.*?)\n\}', mod_vars, re.DOTALL)
        assert m, "dynamic_feeds variable not found in module variables.tf"
        block = m.group(1)
        assert 'target_list_id = optional(string)' in block, \
            "target_list_id should be optional(string), not optional(number)"

    def test_target_list_id_typed_as_string_root(self, db):
        """Same type in root variables.tf."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        root_vars = _read(zf, 'variables.tf')
        m = re.search(r'variable "dynamic_feeds" \{(.*?)\n\}', root_vars, re.DOTALL)
        assert m, "dynamic_feeds variable not found in root variables.tf"
        block = m.group(1)
        assert 'target_list_id = optional(string)' in block, \
            "target_list_id should be optional(string) in root variables.tf"

    def test_target_list_id_is_string_in_tfvars(self, db):
        """tfvars should pass a string (sanitized name), not a number."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # The target_list_id should be a string key like "tor_exit_nodes"
        assert '"tor_exit_nodes"' in tv, \
            "target_list_id should be a string key in tfvars"


# ─── Feed-managed list lookup via locals ─────────────────────────────────────

class TestFeedManagedLookup:
    """Feeds must find feed-managed lists via merged locals, not just .this."""

    def test_feed_uses_local_not_direct_reference(self, db):
        """Polymorphic FK should use local.xxx_list_ids, not corex_xxx.this."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        # Should use local.network_list_ids, not corex_network_list.this
        assert 'local.network_list_ids' in sec_tf, \
            "Polymorphic FK should use local.network_list_ids"
        # Should NOT use corex_network_list.this in the coalesce
        assert 'coalesce(' in sec_tf
        coalesce_m = re.search(r'coalesce\((.*?)\)', sec_tf, re.DOTALL)
        if coalesce_m:
            assert 'local.' in coalesce_m.group(1), \
                "coalesce() should reference locals, not direct resource refs"

    def test_locals_merge_this_and_feed_managed(self, db):
        """Locals should merge .this and .feed_managed for types with feeds."""
        nl = NetworkList(name="tor-exit-nodes")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="tor-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com/tor",
                          update_interval_hours=1))
        db.commit()
        zf = _export(db)
        sec_locals = _module_locals_tf(zf, 'security-lists')
        # Should have a locals block
        assert 'locals {' in sec_locals
        # Should merge .this and .feed_managed for network lists
        m = re.search(r'locals \{(.*?)\n\}', sec_locals, re.DOTALL)
        assert m, "locals block not found"
        locals_block = m.group(1)
        assert 'corex_network_list.this' in locals_block
        assert 'corex_network_list.feed_managed' in locals_block
        assert 'merge(' in locals_block

    def test_locals_no_feed_managed_for_owned_types(self, db):
        """Types without feed-managed lists should just use .this in locals."""
        nl = NetworkList(name="trusted")
        db.add(nl); db.flush()
        db.add(NetworkListEntry(list_id=nl.id, value="10.0.0.1"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        m = re.search(r'locals \{(.*?)\n\}', sec_tf, re.DOTALL)
        if m:
            locals_block = m.group(1)
            # network_list_ids should just be .this (no feed_managed)
            network_m = re.search(r'network_list_ids = (.*)', locals_block)
            if network_m:
                assert 'merge(' not in network_m.group(1), \
                    "Should not merge when no feed-managed lists"

    def test_merged_ids_exported_as_output(self, db):
        """Merged ID maps should be exported as module outputs."""
        nl = NetworkList(name="trusted")
        db.add(nl); db.flush()
        db.commit()
        zf = _export(db)
        outputs_tf = _read(zf, 'modules/security-lists/outputs.tf')
        assert 'network_list_ids' in outputs_tf, \
            "Merged ID map should be exported as output"


# ─── MCP skill versions declaration ──────────────────────────────────────────

class TestMcpSkillVersions:
    """mcp_skill_versions must always be declared in the module."""

    def test_variable_always_declared(self, db):
        """mcp_skill_versions should be declared even when there are no skill versions."""
        # No skill versions in DB
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpServer(name="tools", team_id=team.id, namespace="eng", transport_type="stdio"))
        db.commit()
        zf = _export(db)
        mod_vars = _module_var_tf(zf, 'mcp-gateway')
        assert 'variable "mcp_skill_versions"' in mod_vars, \
            "mcp_skill_versions should always be declared in the module"

    def test_self_registered_skill_versions_filtered_from_tfvars(self, db):
        """Self-registered skill versions should not appear in tfvars."""
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        # Add a self-registered skill
        reg_skill = McpSkill(name="corex-manager", team_id=team.id)
        db.add(reg_skill); db.flush()
        # Add a user skill
        user_skill = McpSkill(name="my-tool", team_id=team.id)
        db.add(user_skill); db.flush()
        # Add versions for both
        db.add(McpSkillVersion(skill_id=reg_skill.id, version="1", body="reg body"))
        db.add(McpSkillVersion(skill_id=user_skill.id, version="1", body="user body"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # The self-registered skill version should NOT be in tfvars
        assert 'version_corex_manager_v1' not in tv, \
            "Self-registered skill version should be filtered from tfvars"
        # The user skill version SHOULD be in tfvars
        assert 'version_my_tool_v1' in tv, \
            "User skill version should be in tfvars"

    def test_self_registered_skill_version_no_import_block(self, db):
        """Self-registered skill versions should not get import blocks.

        The import target must exist in the generated config (tfvars), otherwise
        Terraform errors with 'configuration for import target does not exist'.
        """
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        reg_skill = McpSkill(name="corex-manager", team_id=team.id)
        db.add(reg_skill); db.flush()
        user_skill = McpSkill(name="my-tool", team_id=team.id)
        db.add(user_skill); db.flush()
        db.add(McpSkillVersion(skill_id=reg_skill.id, version="1", body="reg body"))
        db.add(McpSkillVersion(skill_id=user_skill.id, version="1", body="user body"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        # Should NOT have an import for the self-registered skill version
        assert 'version_unknown' not in imports, \
            "Self-registered skill version should not get an import block"
        assert 'version_corex_manager' not in imports, \
            "Self-registered skill version should not get an import block"
        # Should have an import for the user skill version
        assert 'version_my_tool_v1' in imports, \
            "User skill version should get an import block"


class TestWafExceptionFiltering:
    """WAF exceptions with null waf_rule_id are now included (provider accepts null)."""

    def test_waf_exception_without_rule_id_included(self, db):
        """WAF exceptions with null waf_rule_id should be included in tfvars.

        The provider's waf_rule_id is now optional (nullable), so exceptions
        without a rule association can be exported. The waf_rule_id field will
        be omitted from tfvars (defaults to null in the module).
        """
        be = make_backend(db, name="web")
        ln = make_listener(db, backend=be, name="https")
        wr = make_waf_rule(db, name="rule", listener_id=ln.id, backend_id=be.id)
        # Exception WITH waf_rule_id — should be exported with the rule ref
        make_waf_exception(db, waf_rule_id=wr.id, name="with_rule", rule_id="942100")
        # Exception WITHOUT waf_rule_id — should also be exported (null waf_rule_id)
        make_waf_exception(db, waf_rule_id=None, name="orphan", rule_id="942200")
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        imports = _read(zf, 'imports.tf')
        # Both exceptions should be in tfvars
        assert '"with_rule"' in tv, \
            "WAF exception with waf_rule_id should be in tfvars"
        assert '"orphan"' in tv, \
            "WAF exception without waf_rule_id should be in tfvars (nullable)"
        # Both should have import blocks
        assert 'orphan' in imports, \
            "WAF exception without waf_rule_id should get an import block"


class TestNoDuplicateModuleArgs:
    """Root main.tf should not pass duplicate arguments to modules."""

    def test_no_duplicate_captcha_secrets_on_management(self, db):
        """captcha_secrets should appear exactly once in the management module block."""
        import re
        from app.models.models import Setting
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="cap_secret", value="secret"))
        db.commit()
        zf = _export(db)
        main_tf = _read(zf, 'main.tf')
        m = re.search(r'module "management" \{(.*?)\n\}', main_tf, re.DOTALL)
        assert m, "management module block not found in main.tf"
        block = m.group(1)
        count = len(re.findall(r'captcha_secrets\s*=\s*var\.captcha_secrets', block))
        assert count == 1, \
            f"captcha_secrets should appear once in management block, found {count}"


class TestCacheRuleImports:
    """Cache rules must get import blocks with composite keys matching the module."""

    def test_cache_rule_imports_use_composite_keys(self, db):
        """Cache rule imports should use '{config_key}_{priority}' as the address key."""
        from app.models.cache import CacheConfig, CacheRule
        be = make_backend(db, name="ne4u_com")
        cc = CacheConfig(backend_id=be.id, haproxy_enabled=True)
        db.add(cc); db.flush()
        db.add(CacheRule(cache_config_id=cc.id, priority=0, enabled=True,
                        match_type="path", pattern="/api", action="cache", tier="memory"))
        db.add(CacheRule(cache_config_id=cc.id, priority=1, enabled=True,
                        match_type="path", pattern="/static", action="cache", tier="disk"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        # Should have imports for both cache rules with composite keys
        assert 'corex_cache_rule.this["cache_ne4u_com_0"]' in imports, \
            "Cache rule import should use '{config_key}_{priority}' key"
        assert 'corex_cache_rule.this["cache_ne4u_com_1"]' in imports, \
            "Cache rule import should use '{config_key}_{priority}' key"
        # The import ID should be the numeric row ID
        assert 'id = "1"' in imports or 'id = "2"' in imports, \
            "Cache rule import ID should be the numeric row ID"

    def test_cache_rule_imports_absent_when_no_configs(self, db):
        """No cache rule imports when there are no cache configs."""
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'corex_cache_rule' not in imports, \
            "No cache rule imports when there are no cache configs"

    def test_cache_rule_import_matches_module_key_format(self, db):
        """Cache rule import keys must match the module's for_each key format."""
        from app.models.cache import CacheConfig, CacheRule
        be = make_backend(db, name="web")
        cc = CacheConfig(backend_id=be.id, haproxy_enabled=True)
        db.add(cc); db.flush()
        db.add(CacheRule(cache_config_id=cc.id, priority=5, enabled=True,
                        match_type="path", pattern="/img", action="cache", tier="memory"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        cache_tf = _module_tf(zf, 'cache')
        # The module uses "${config_key}_${rule.priority}" as the key
        # The import should use the same format
        assert 'corex_cache_rule.this["cache_web_5"]' in imports, \
            "Cache rule import key must match module's for_each key format"
        # Verify the module also uses this key format
        assert '${config_key}_${rule.priority}' in cache_tf, \
            "Module should use ${config_key}_${rule.priority} as the key"


# ─── MCP team_id filtering ───────────────────────────────────────────────────

class TestMcpTeamIdFiltering:
    """Resources in all teams (including platform) should be exported.

    Only the self-registered server (namespace 'corex-manager') and skill
    (name 'corex-manager') are filtered individually.
    """

    def test_platform_server_included_in_tfvars(self, db):
        """Server on the platform team should appear in tfvars (user-created)."""
        platform = Team(name="Platform", slug="platform")
        eng = Team(name="CoreX Engineering", slug="eng")
        db.add_all([platform, eng]); db.flush()
        db.add(McpServer(name="opensearch", team_id=platform.id, namespace="eng", transport_type="stdio"))
        db.add(McpServer(name="tools", team_id=eng.id, namespace="eng", transport_type="stdio"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        servers = _collection_entries(tv, 'mcp_servers')
        assert 'opensearch' in servers, \
            "Server on platform team should be included (user-created)"
        assert 'tools' in servers, \
            "Server on eng team should be present"

    def test_platform_identity_included_in_tfvars(self, db):
        """Identity on the platform team should appear in tfvars."""
        platform = Team(name="Platform", slug="platform")
        eng = Team(name="CoreX Engineering", slug="eng")
        db.add_all([platform, eng]); db.flush()
        db.add(McpIdentity(name="platform_bot", team_id=platform.id, kind="pat"))
        db.add(McpIdentity(name="eng_bot", team_id=eng.id, kind="pat"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        identities = _collection_entries(tv, 'mcp_identities')
        assert 'platform_bot' in identities, \
            "Identity on platform team should be included"
        assert 'eng_bot' in identities, \
            "Identity on eng team should be present"

    def test_platform_policy_included_in_tfvars(self, db):
        """Policy on the platform team should appear in tfvars."""
        platform = Team(name="Platform", slug="platform")
        eng = Team(name="CoreX Engineering", slug="eng")
        db.add_all([platform, eng]); db.flush()
        db.add(McpPolicy(name="platform_pol", team_id=platform.id, action="allow", expression="true"))
        db.add(McpPolicy(name="eng_pol", team_id=eng.id, action="allow", expression="true"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        policies = _collection_entries(tv, 'mcp_policies')
        assert 'platform_pol' in policies, \
            "Policy on platform team should be included"
        assert 'eng_pol' in policies, \
            "Policy on eng team should be present"

    def test_platform_server_included_in_module(self, db):
        """Server on the platform team should appear in the module resource block."""
        platform = Team(name="Platform", slug="platform")
        eng = Team(name="CoreX Engineering", slug="eng")
        db.add_all([platform, eng]); db.flush()
        db.add(McpServer(name="opensearch", team_id=platform.id, namespace="eng", transport_type="stdio"))
        db.add(McpServer(name="tools", team_id=eng.id, namespace="eng", transport_type="stdio"))
        db.commit()
        zf = _export(db)
        mod_tf = _module_tf(zf, 'mcp-gateway')
        # The module should have the resource block (for_each = var.mcp_servers)
        assert 'resource "corex_mcp_server" "this"' in mod_tf, \
            "MCP server resource block should exist"

    def test_platform_server_replica_included(self, db):
        """Replica of a platform-team server should be included."""
        platform = Team(name="Platform", slug="platform")
        eng = Team(name="CoreX Engineering", slug="eng")
        db.add_all([platform, eng]); db.flush()
        plat_srv = McpServer(name="plat-srv", team_id=platform.id, namespace="eng", transport_type="stdio")
        eng_srv = McpServer(name="eng-srv", team_id=eng.id, namespace="eng", transport_type="stdio")
        db.add_all([plat_srv, eng_srv]); db.flush()
        db.add(McpServerReplica(server_id=plat_srv.id, url="http://plat:8080"))
        db.add(McpServerReplica(server_id=eng_srv.id, url="http://eng:8080"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        replicas = _collection_entries(tv, 'mcp_server_replicas')
        # Both replicas should be in tfvars
        assert any('plat' in k for k in replicas), \
            "Replica of platform-team server should be included"
        assert any('eng' in k for k in replicas), \
            "Replica of eng-team server should be present"

    def test_eng_server_has_team_id(self, db):
        """Server on a non-filtered team should have team_id set in tfvars."""
        eng = Team(name="CoreX Engineering", slug="eng")
        db.add(eng); db.flush()
        db.add(McpServer(name="opensearch", team_id=eng.id, namespace="eng", transport_type="stdio"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        servers = _collection_entries(tv, 'mcp_servers')
        assert 'opensearch' in servers
        fields = _entry_fields(tv, 'mcp_servers', 'opensearch')
        assert 'team_id' in fields, \
            "Server should have team_id field in tfvars"
        # Verify the team_id value is the sanitized team name
        import re as _re
        m = _re.search(r'"opensearch" = \{([^}]*)\}', tv)
        assert '"team_id" = "corex_engineering"' in m.group(1), \
            "team_id should be the sanitized team name"


# ─── Structural recommendations ─────────────────────────────────────────────

class TestStructuralRecommendations:
    """Tests for structural cleanup of generated Terraform."""

    def test_api_armor_settings_in_api_armor_module(self, db):
        """api_armor_settings singleton should live in api-armor, not management."""
        from app.models.models import Setting
        db.add(Setting(key="api_armor_enabled", value="true"))
        db.commit()
        zf = _export(db)
        mgmt = _module_tf(zf, 'management')
        aa = _module_tf(zf, 'api-armor')
        assert 'corex_api_armor_settings' not in mgmt, \
            "api_armor_settings should NOT be in management module"
        assert 'corex_api_armor_settings' in aa, \
            "api_armor_settings should be in api-armor module"

    def test_pattern_list_resource_always_emitted(self, db):
        """corex_pattern_list resource should be emitted even when empty."""
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        assert 'resource "corex_pattern_list" "this"' in sec_tf, \
            "Pattern list resource block should always be emitted"

    def test_skill_version_always_has_body_frontmatter(self, db):
        """Skill version resource should always reference body/frontmatter vars."""
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        # Find the skill_version resource block
        m = re.search(r'resource "corex_mcp_skill_version" "this" \{(.*?)\n\}',
                      mcp_tf, re.DOTALL)
        assert m, "skill_version resource block not found"
        block = m.group(1)
        assert 'var.mcp_skill_bodies' in block, \
            "skill_version should reference var.mcp_skill_bodies"
        assert 'var.mcp_skill_frontmatters' in block, \
            "skill_version should reference var.mcp_skill_frontmatters"

    def test_locals_in_separate_file(self, db):
        """Locals should be in locals.tf, not jammed onto main.tf."""
        nl = NetworkList(name="test-list")
        db.add(nl)
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        sec_locals = _module_locals_tf(zf, 'security-lists')
        # Locals should NOT be in main.tf
        assert 'locals {' not in sec_tf, \
            "Locals should not be in main.tf — use locals.tf"
        # Locals SHOULD be in locals.tf
        assert 'locals {' in sec_locals, \
            "Locals should be in locals.tf"

    def test_root_outputs_include_list_ids(self, db):
        """Root outputs should surface merged list IDs from security-lists."""
        nl = NetworkList(name="test-list")
        db.add(nl)
        db.commit()
        zf = _export(db)
        outputs = _read(zf, 'outputs.tf')
        assert 'security_lists_network_list_ids' in outputs, \
            "Root outputs should include network_list_ids when network lists exist"

    def test_root_outputs_include_waf_rule_ids(self, db):
        """Root outputs should surface WAF rule IDs."""
        from app.models.waf import WafRule
        db.add(WafRule(name="test-rule", enabled=True))
        db.commit()
        zf = _export(db)
        outputs = _read(zf, 'outputs.tf')
        assert 'waf_waf_rule_ids' in outputs, \
            "Root outputs should include waf_rule_ids"

    def test_root_outputs_include_mcp_team_ids(self, db):
        """Root outputs should surface MCP team IDs."""
        db.add(Team(name="Eng", slug="eng"))
        db.commit()
        zf = _export(db)
        outputs = _read(zf, 'outputs.tf')
        assert 'mcp_gateway_mcp_team_ids' in outputs, \
            "Root outputs should include mcp_team_ids"

    def test_api_key_list_id_uses_string_key(self, db):
        """Auth policy api_key_list_id should be a string key, not numeric ID."""
        from app.models.api_armor import AuthPolicy, ApiKeyList
        akl = ApiKeyList(name="test-keys")
        db.add(akl); db.flush()
        db.add(AuthPolicy(name="test-policy", auth_type="api_key",
                         api_key_list_id=akl.id, enabled=True))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # The tfvars should have the string key, not the numeric ID.
        # The key is sanitized: "test-policy" -> "test_policy"
        m = re.search(r'"test_policy" = \{([^}]*)\}', tv)
        assert m, "test_policy not found in tfvars"
        block = m.group(1)
        assert '"api_key_list_id" = "test_keys"' in block, \
            "api_key_list_id should be the sanitized string key, not numeric ID"
        # The module should resolve it via corex_api_armor_api_key_list.this
        aa_tf = _module_tf(zf, 'api-armor')
        assert 'corex_api_armor_api_key_list.this' in aa_tf, \
            "Module should resolve api_key_list_id via resource lookup"

    def test_singleton_imports_generated(self, db):
        """Singleton resources should get import blocks now that the provider
        has ImportState for them."""
        from app.models.models import Setting
        db.add(Setting(key="haproxy_global_options",
                       value='[{"target":"global","directive":"log-requests","value":"","enabled":true}]'))
        db.add(Setting(key="api_armor_enabled", value="true"))
        db.add(Setting(key="captcha_provider", value="recaptcha"))
        db.add(Setting(key="ha_enabled", value="false"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        imports = _read(zf, 'imports.tf')
        # All four singletons should have import blocks
        assert 'module.management.corex_global_options.this' in imports, \
            "global_options singleton should have an import block"
        assert 'module.management.corex_captcha_settings.this' in imports, \
            "captcha_settings singleton should have an import block"
        assert 'module.management.corex_ha_config.this' in imports, \
            "ha_config singleton should have an import block"
        assert 'module.api_armor.corex_api_armor_settings.this' in imports, \
            "api_armor_settings singleton should have an import block"
        # The old "cannot be imported" comment should be gone
        assert 'cannot be imported' not in imports, \
            "The 'cannot be imported' comment should be removed"


class TestGeneratorHygiene:
    """Tests for generator hygiene: empty files, stub READMEs, file locals."""

    def test_no_empty_locals_tf(self, db):
        """Modules without real locals should not get a locals.tf file."""
        zf = _export(db)
        # Only security-lists should have a locals.tf (when it has active lists)
        for name in zf.namelist():
            if name.endswith('locals.tf') and 'modules/' in name:
                mod_name = name.split('/')[1]
                # security-lists may have locals; others should not
                if mod_name != 'security-lists':
                    content = _read(zf, name)
                    assert content.strip() != '', \
                        f"{mod_name}/locals.tf should not be emitted empty"

    def test_no_stub_readme(self, db):
        """Modules should not get stub README.md files."""
        zf = _export(db)
        for name in zf.namelist():
            if name.endswith('README.md') and 'modules/' in name:
                content = _read(zf, name)
                # Stub READMEs say "See `main.tf`" — real ones have more content
                assert 'See `main.tf`' not in content, \
                    f"{name} is a stub README and should not be emitted"

    def test_root_file_locals_block(self, db):
        """Root locals.tf should have a locals block for file() expressions."""
        from app.models.models import NetworkList
        db.add(NetworkList(name="test-list"))
        db.commit()
        zf = _export(db)
        root_locals = _read(zf, 'locals.tf')
        assert 'locals {' in root_locals, \
            "Root locals.tf should have a locals block for file content"
        root_main = _read(zf, 'main.tf')
        assert 'local.network_list_entries' in root_main, \
            "Module arguments should reference local.xxx, not inline file()"

    def test_no_inline_file_in_module_args(self, db):
        """Module arguments should not have inline file() expressions."""
        from app.models.models import NetworkList
        db.add(NetworkList(name="test-list"))
        db.commit()
        zf = _export(db)
        root_main = _read(zf, 'main.tf')
        # The inline file() expressions should be in locals.tf, not
        # on module arguments
        # Find module blocks and check they use local.xxx for file content
        idx = root_main.find('module "security_lists"')
        if idx >= 0:
            mod_block = root_main[idx:root_main.find('}', idx) + 1]
            assert 'file(' not in mod_block, \
                "Module arguments should use local.xxx, not inline file()"


class TestFeedManagedAllTypes:
    """Tests for feed_managed split on all list types, not just network/asn."""

    def test_geo_list_always_has_feed_managed_block(self, db):
        """Geo lists should always have a .feed_managed resource block."""
        from app.models.models import GeoList
        db.add(GeoList(name="blocked-countries"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        assert 'resource "corex_geo_list" "this"' in sec_tf, \
            "Geo list should have .this resource block"
        assert 'resource "corex_geo_list" "feed_managed"' in sec_tf, \
            "Geo list should always have .feed_managed block (even if empty)"

    def test_ja4_list_always_has_feed_managed_block(self, db):
        """JA4 lists should always have a .feed_managed resource block."""
        from app.models.models import Ja4List
        db.add(Ja4List(name="bad-fingerprints"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        assert 'resource "corex_ja4_list" "this"' in sec_tf, \
            "JA4 list should have .this resource block"
        assert 'resource "corex_ja4_list" "feed_managed"' in sec_tf, \
            "JA4 list should always have .feed_managed block (even if empty)"

    def test_pattern_list_always_has_feed_managed_block(self, db):
        """Pattern lists should always have a .feed_managed resource block."""
        from app.models.models import PatternList
        db.add(PatternList(name="suspicious"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        assert 'resource "corex_pattern_list" "this"' in sec_tf, \
            "Pattern list should have .this resource block"
        assert 'resource "corex_pattern_list" "feed_managed"' in sec_tf, \
            "Pattern list should always have .feed_managed block (even if empty)"

    def test_all_list_types_use_merge_in_locals(self, db):
        """All 5 list types should always use merge() in locals, even if empty."""
        from app.models.models import NetworkList, GeoList
        db.add(NetworkList(name="net1"))
        db.add(GeoList(name="geo1"))
        db.commit()
        zf = _export(db)
        sec_locals = _module_locals_tf(zf, 'security-lists')
        # All 5 types should use merge() — not .this-only
        for type_key in ['network', 'asn', 'geo', 'ja4', 'pattern']:
            assert f'{type_key}_list_ids = merge(' in sec_locals, \
                f"{type_key}_list_ids should use merge() even when no {type_key} lists exist"
            assert f'corex_{type_key}_list.feed_managed' in sec_locals, \
                f"{type_key} merge should include .feed_managed"

    def test_feed_coalesce_includes_all_list_types(self, db):
        """The coalesce() should include all 5 list types, not just active ones."""
        from app.models.models import NetworkList, DynamicFeed
        nl = NetworkList(name="target-list")
        db.add(nl); db.flush()
        db.add(DynamicFeed(name="test-feed", list_type="network",
                          target_list_id=nl.id, url="https://example.com"))
        db.commit()
        zf = _export(db)
        sec_tf = _module_tf(zf, 'security-lists')
        # All 5 list types should be in the coalesce
        assert 'local.network_list_ids[each.value.target_list_id]' in sec_tf, \
            "coalesce should include network_list_ids"
        assert 'local.asn_list_ids[each.value.target_list_id]' in sec_tf, \
            "coalesce should include asn_list_ids"
        assert 'local.geo_list_ids[each.value.target_list_id]' in sec_tf, \
            "coalesce should include geo_list_ids"
        assert 'local.ja4_list_ids[each.value.target_list_id]' in sec_tf, \
            "coalesce should include ja4_list_ids"
        assert 'local.pattern_list_ids[each.value.target_list_id]' in sec_tf, \
            "coalesce should include pattern_list_ids"
        # The tobool() trick should be gone
        assert 'tobool(' not in sec_tf, \
            "tobool() trick should be removed — use plain coalesce()"


class TestApiKeyListType:
    """Tests for api_key_lists variable type completeness."""

    def test_api_key_lists_has_name_and_entries(self, db):
        """api_key_lists variable should include name and entries fields."""
        from app.models.api_armor import ApiKeyList
        db.add(ApiKeyList(name="test-keys", description="test"))
        db.commit()
        zf = _export(db)
        var_tf = _read(zf, 'modules/api-armor/variables.tf')
        # Find the api_key_lists variable block (search for a larger window)
        idx = var_tf.find('variable "api_key_lists"')
        assert idx >= 0, "api_key_lists variable not found"
        # Take a generous slice to capture the full variable block
        block = var_tf[idx:idx + 600]
        assert 'name' in block, \
            "api_key_lists type should include name field"
        assert 'entries' in block, \
            "api_key_lists type should include entries field"
        assert 'value' in block, \
            "entries type should include value field"


# ─── Provider Schema Compatibility (round 2) ──────────────────────────────

class TestProviderSchemaCompatibility2:
    """Tests for the second round of provider schema compatibility fixes."""

    def test_cache_config_provider_field_names(self, db):
        """Cache config should use provider field names, not DB column names."""
        be = Backend(name="web", mode="http")
        db.add(be); db.flush()
        cc = CacheConfig(backend_id=be.id, haproxy_enabled=True,
                        haproxy_total_max_size=1024, haproxy_max_age=3600,
                        haproxy_rfc7234_compliance=True,
                        disk_cache_ttl=86400)
        db.add(cc); db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # Find the cache_configs block and get the first entry key
        m = re.search(r'cache_configs = \{(.*?)\n\}', tv, re.DOTALL)
        assert m is not None, "cache_configs not found in tfvars"
        # Get the first key name
        key_m = re.search(r'"([^"]+)"', m.group(1))
        assert key_m is not None
        entry_key = key_m.group(1)
        fields = _entry_fields(tv, 'cache_configs', entry_key)
        # Provider uses haproxy_cache_size, not haproxy_total_max_size
        assert 'haproxy_cache_size' in fields, "haproxy_total_max_size should be renamed to haproxy_cache_size"
        assert 'haproxy_total_max_size' not in fields, "haproxy_total_max_size should be renamed"
        assert 'haproxy_cache_max_age' in fields, "haproxy_max_age should be renamed to haproxy_cache_max_age"
        assert 'haproxy_max_age' not in fields
        assert 'rfc7234_compliance' in fields, "haproxy_rfc7234_compliance should be renamed"
        assert 'haproxy_rfc7234_compliance' not in fields
        assert 'disk_cache_max_age' in fields, "disk_cache_ttl should be renamed to disk_cache_max_age"
        assert 'disk_cache_ttl' not in fields
        # Unsupported fields should be skipped
        assert 'haproxy_max_object_size' not in fields
        assert 'haproxy_process_vary' not in fields
        assert 'disk_cache_grace' not in fields

    def test_listener_no_options_field(self, db):
        """Listener should not have options or haproxy_options (not in provider)."""
        be = Backend(name="web", mode="http")
        db.add(be); db.flush()
        ln = Listener(name="https", bind_address="0.0.0.0", bind_port=443,
                     mode="http", default_backend_id=be.id)
        db.add(ln); db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        fields = _entry_fields(tv, 'listeners', 'https')
        assert 'options' not in fields, "listener should not have options (not in provider)"
        assert 'haproxy_options' not in fields

    def test_server_no_options_or_cert_ids(self, db):
        """Server should not have options, ca_certificate_id, client_certificate_id."""
        be = Backend(name="web", mode="http")
        db.add(be); db.flush()
        from app.models.models import Server
        srv = Server(name="srv1", address="10.0.0.1", port=80, backend_id=be.id)
        db.add(srv); db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        fields = _entry_fields(tv, 'servers', 'srv1')
        assert 'options' not in fields, "server should not have options (not in provider)"
        assert 'ca_certificate_id' not in fields
        assert 'client_certificate_id' not in fields

    def test_mcp_server_renamed_fields(self, db):
        """MCP server should use provider field names (auth_secret, args, env_vars).

        The attribute name in the resource block uses the provider name.
        The each.value reference may still use the DB field name (that's the
        tfvars key), which is correct — the rename is on the provider side.
        """
        team = Team(name="dev", slug="dev")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, url="http://localhost",
                       namespace="eng",
                       auth_type="bearer", auth_secret_enc="SECRET",
                       args_json='["--port", "8080"]',
                       env_vars_json='{"FOO": "bar"}',
                       oauth_client_secret_enc="OAUTH_SECRET")
        db.add(srv); db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        # Provider uses auth_secret, not auth_secret_enc — check the attribute name
        assert '  auth_secret = ' in mcp_tf, "auth_secret_enc should be renamed to auth_secret"
        # The attribute should be args, not args_json
        assert '  args = ' in mcp_tf, "args_json should be renamed to args"
        # The attribute should be env_vars, not env_vars_json
        assert '  env_vars = ' in mcp_tf, "env_vars_json should be renamed to env_vars"
        # The attribute should be oauth_client_secret, not oauth_client_secret_enc
        assert '  oauth_client_secret = ' in mcp_tf
        # The old attribute names should NOT appear as attribute names
        assert '  auth_secret_enc = ' not in mcp_tf
        assert '  args_json = ' not in mcp_tf
        assert '  env_vars_json = ' not in mcp_tf
        assert '  oauth_client_secret_enc = ' not in mcp_tf

    def test_mcp_server_args_env_vars_type_overrides(self, db):
        """MCP server args should be list(string), env_vars should be map(string).

        args_json is not a secret field, so it appears in the variable type as 'args'.
        env_vars_json IS a secret field (when secrets are off), so it's handled
        via a separate var and appears in the resource block as 'env_vars'.
        """
        team = Team(name="dev", slug="dev")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, url="http://localhost",
                       namespace="eng",
                       args_json='["--port", "8080"]',
                       env_vars_json='{"FOO": "bar"}')
        db.add(srv); db.commit()
        zf = _export(db)
        var_tf = _read(zf, 'modules/mcp-gateway/variables.tf')
        # Find the mcp_servers variable block
        idx = var_tf.find('variable "mcp_servers"')
        assert idx >= 0
        block = var_tf[idx:idx + 2000]
        # args_json is not a secret, so it should be in the variable type as 'args'
        assert 'args' in block, "mcp_servers type should include args (renamed from args_json)"
        # env_vars_json is a secret, so it's not in the variable type
        # but it should be in the resource block
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        assert '  env_vars = ' in mcp_tf, "resource block should have env_vars"

    def test_mcp_team_member_no_name(self, db):
        """MCP team member should not have name (not in provider)."""
        from app.models.auth import User
        team = Team(name="dev", slug="dev")
        db.add(team); db.flush()
        user = User(username="admin", role="admin", email="a@b.com",
                   hashed_password="dummy")
        db.add(user); db.flush()
        ut = UserTeam(team_id=team.id, user_id=user.id)
        db.add(ut); db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        # The resource block should have team_id and user_id, but not name
        assert 'team_id = ' in mcp_tf
        assert 'user_id = ' in mcp_tf
        # name should not appear in the team_member resource block
        member_idx = mcp_tf.find('corex_mcp_team_member')
        if member_idx >= 0:
            block = mcp_tf[member_idx:member_idx + 300]
            assert '  name = ' not in block, "team_member should not have name (not in provider)"

    def test_mcp_skill_version_no_name_no_version(self, db):
        """MCP skill version should not have name or version (computed-only)."""
        team = Team(name="dev", slug="dev")
        db.add(team); db.flush()
        skill = McpSkill(name="my-skill", team_id=team.id)
        db.add(skill); db.flush()
        sv = McpSkillVersion(skill_id=skill.id, version=1,
                            created_by="admin", body="content")
        db.add(sv); db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        # version is computed-only — should not be set in config
        assert 'version = try(each.value.version' not in mcp_tf, \
            "version is computed-only, should not be set"
        # name and created_by are not in the provider schema
        assert 'created_by' not in mcp_tf

    def test_mcp_policy_no_priority(self, db):
        """MCP policy should not have priority (computed-only in provider)."""
        team = Team(name="dev", slug="dev")
        db.add(team); db.flush()
        pol = McpPolicy(name="allow-all", team_id=team.id, priority=5,
                       expression="true", action="allow")
        db.add(pol); db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        # Find the mcp_policy resource block specifically
        idx = mcp_tf.find('corex_mcp_policy')
        assert idx >= 0, "mcp_policy resource block not found"
        block = mcp_tf[idx:idx + 500]
        # priority is computed-only — should not be set in config
        assert 'priority = ' not in block, \
            "priority is computed-only, should not be set in mcp_policy"

    def test_maxmind_license_key_uses_value(self, db):
        """MaxMind license key resource should use 'value', not 'license_key'."""
        from app.services.terraform_export import get_maxmind_license_key
        from app.models.models import Setting
        db.add(Setting(key="maxmind_license_key", value="SECRET_MAXMIND"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        mgmt_tf = _module_tf(zf, 'management')
        assert 'value = var.maxmind_license_key' in mgmt_tf, \
            "maxmind_license_key resource should use 'value', not 'license_key'"
        assert 'license_key = ' not in mgmt_tf

    def test_ha_config_keepalived_nested(self, db):
        """HA config should nest keepalived fields under a keepalived attribute."""
        from app.models.models import Setting
        db.add(Setting(key="ha_enabled", value="true"))
        db.add(Setting(key="keepalived_vip", value="10.0.0.100"))
        db.add(Setting(key="keepalived_virtual_router_id", value="51"))
        db.add(Setting(key="keepalived_priority", value="100"))
        db.commit()
        zf = _export(db)
        mgmt_tf = _module_tf(zf, 'management')
        # keepalived is a SingleNestedAttribute — use assignment, not a block
        assert 'keepalived = try(var.ha_config["keepalived"], null)' in mgmt_tf, \
            "HA config should use keepalived = assignment (SingleNestedAttribute)"
        # Should NOT have top-level keepalived_* fields
        assert 'keepalived_vip = ' not in mgmt_tf
        assert 'keepalived_virtual_router_id = ' not in mgmt_tf

    def test_ha_config_tfvars_keepalived_nested(self, db):
        """HA config tfvars should nest keepalived under 'keepalived' key."""
        from app.models.models import Setting
        db.add(Setting(key="ha_enabled", value="true"))
        db.add(Setting(key="keepalived_vip", value="10.0.0.100"))
        db.add(Setting(key="keepalived_virtual_router_id", value="51"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # ha_config should have a nested keepalived map
        assert '"keepalived" = {' in tv, "tfvars should nest keepalived fields"
        assert '"vip" = "10.0.0.100"' in tv
        assert '"virtual_router_id" = 51' in tv  # int, not string
        # Should NOT have top-level keepalived_* keys
        assert '"keepalived_vip"' not in tv
        assert '"keepalived_virtual_router_id"' not in tv

    def test_singleton_bool_coercion(self, db):
        """Singleton bool settings should be coerced to bool, not string."""
        from app.models.models import Setting
        db.add(Setting(key="ha_enabled", value="true"))
        db.add(Setting(key="api_armor_enabled", value="true"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        tv = _tfvars(zf)
        # Should be native bool (no quotes), not string "true"
        assert '"ha_enabled" = true' in tv, "ha_enabled should be bool true, not string 'true'"
        assert '"api_armor_enabled" = true' in tv

    def test_singleton_int_coercion(self, db):
        """Singleton int settings should be coerced to int, not string."""
        from app.models.models import Setting
        db.add(Setting(key="haproxy_ha_replicas", value="3"))
        db.add(Setting(key="api_armor_max_body_bytes", value="1048576"))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        tv = _tfvars(zf)
        assert '"haproxy_ha_replicas" = 3' in tv, "haproxy_ha_replicas should be int 3, not string '3'"
        assert '"api_armor_max_body_bytes" = 1048576' in tv

    def test_singleton_list_coercion(self, db):
        """Singleton list settings should be coerced to list, not string."""
        from app.models.models import Setting
        db.add(Setting(key="api_armor_backend_ids", value="[1, 2, 3]"))
        db.add(Setting(key="valkey_sentinel_hosts", value='["host1", "host2"]'))
        db.commit()
        zf = _export(db, include_system_secrets=True)
        tv = _tfvars(zf)
        # Should be a list, not a string
        assert '"api_armor_backend_ids" = [' in tv
        assert '"valkey_sentinel_hosts" = [' in tv

    def test_dns_credentials_secret_var_is_map_of_maps(self, db):
        """certificates_dns_credentials should be map(map(string)), not map(string)."""
        from app.models.models import Certificate
        cert = Certificate(name="wildcard", provider="letsencrypt",
                          dns_credentials='{"api_key": "secret"}')
        db.add(cert); db.commit()
        zf = _export(db)  # secrets off
        var_tf = _read(zf, 'modules/ssl/variables.tf')
        # Find the certificates_dns_credentials variable
        idx = var_tf.find('variable "certificates_dns_credentials"')
        assert idx >= 0
        block = var_tf[idx:idx + 200]
        assert 'map(map(string))' in block, \
            "certificates_dns_credentials should be map(map(string))"

    def test_dns_credentials_secret_placeholder_is_empty_map(self, db):
        """certificates_dns_credentials placeholder should be empty map, not 'change-me'."""
        from app.models.models import Certificate
        cert = Certificate(name="wildcard", provider="letsencrypt")
        db.add(cert); db.commit()
        zf = _export(db)  # secrets off
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # Should have "wildcard" = {} (empty map), not "wildcard" = "change-me"
        assert '"wildcard" = {}' in secrets, \
            "dns_credentials placeholder should be empty map, not 'change-me'"

    def test_mcp_skill_frontmatter_is_string_not_object(self, db):
        """MCP skill frontmatter should be a JSON string (file()), not jsondecode()."""
        team = Team(name="dev", slug="dev")
        db.add(team); db.flush()
        skill = McpSkill(name="my-skill", team_id=team.id)
        db.add(skill); db.flush()
        sv = McpSkillVersion(skill_id=skill.id, version=1, body="content",
                            frontmatter='{"name": "test"}')
        db.add(sv); db.commit()
        zf = _export(db)
        locals_tf = _read(zf, 'locals.tf')
        # Should use file() (returns string), not jsondecode() (returns object)
        assert 'mcp_skill_frontmatters' in locals_tf
        assert 'jsondecode' not in locals_tf.split('mcp_skill_frontmatters')[1].split('\n')[0], \
            "frontmatter should use file() (string), not jsondecode() (object)"


# ─── New resources & dead secret removal (round 3) ───────────────────────

class TestNewResourcesAndDeadSecrets:
    """Tests for newly exported resources and removed dead secrets."""

    def test_page_protect_settings_exported(self, db):
        """corex_page_protect_settings should be exported as a singleton."""
        from app.models.models import Setting
        db.add(Setting(key="page_protect_monitoring_enabled", value="true"))
        db.add(Setting(key="page_protect_beacon_path", value="/_cx-assets"))
        db.add(Setting(key="page_protect_beacon_content_types", value="text/html,application/json"))
        db.add(Setting(key="page_protect_beacon_backend_ids", value="[1, 2, 3]"))
        db.commit()
        zf = _export(db)
        pp_tf = _module_tf(zf, 'page-protect')
        assert 'resource "corex_page_protect_settings" "this"' in pp_tf, \
            "page_protect_settings should be exported"
        # Should use provider field names
        assert 'monitoring_enabled = ' in pp_tf
        assert 'beacon_paths = ' in pp_tf, "beacon_path should be renamed to beacon_paths"
        assert 'beacon_content_types = ' in pp_tf
        assert 'backend_ids = ' in pp_tf, "beacon_backend_ids should be renamed to backend_ids"

    def test_page_protect_settings_tfvars(self, db):
        """page_protect_settings tfvars should have coerced types."""
        from app.models.models import Setting
        db.add(Setting(key="page_protect_monitoring_enabled", value="true"))
        db.add(Setting(key="page_protect_beacon_path", value="/_cx-assets"))
        db.add(Setting(key="page_protect_beacon_content_types", value="text/html,application/json"))
        db.add(Setting(key="page_protect_beacon_backend_ids", value="[1, 2, 3]"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # monitoring_enabled should be bool, not string
        assert '"monitoring_enabled" = true' in tv
        # beacon_paths should be a list (from string)
        assert '"beacon_paths" = [' in tv
        # beacon_content_types should be a list (from comma-separated string)
        assert '"beacon_content_types" = [' in tv
        # backend_ids should be a list of ints
        assert '"backend_ids" = [' in tv

    def test_page_protect_script_exported(self, db):
        """corex_page_protect_script should be exported as a for_each collection."""
        from app.models.page_protect import PageProtectScript
        db.add(PageProtectScript(url="https://example.com/script.js",
                                resource_type="script", ignored=False,
                                source="manual"))
        db.commit()
        zf = _export(db)
        pp_tf = _module_tf(zf, 'page-protect')
        assert 'resource "corex_page_protect_script" "this"' in pp_tf, \
            "page_protect_script should be exported"
        # Should have url, resource_type, ignored (provider fields)
        assert 'url = ' in pp_tf
        assert 'resource_type = ' in pp_tf
        assert 'ignored = ' in pp_tf
        # Should NOT have runtime fields
        assert 'first_seen' not in pp_tf
        assert 'last_seen' not in pp_tf
        assert 'occurrence_count' not in pp_tf
        assert 'first_hash' not in pp_tf
        assert 'content = ' not in pp_tf.split('corex_page_protect_script')[1].split('}')[0]

    def test_page_protect_script_only_manual_exported(self, db):
        """Only manually-added scripts (source='manual') should be exported."""
        from app.models.page_protect import PageProtectScript
        db.add(PageProtectScript(url="https://example.com/manual.js", source="manual"))
        db.add(PageProtectScript(url="https://example.com/csp.js", source="csp"))
        db.add(PageProtectScript(url="https://example.com/beacon.js", source="beacon"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert 'manual.js' in tv, "manual script should be in tfvars"
        assert 'csp.js' not in tv, "csp-detected script should NOT be in tfvars"
        assert 'beacon.js' not in tv, "beacon-detected script should NOT be in tfvars"

    def test_ssl_labs_settings_exported(self, db):
        """corex_ssl_labs_settings should be exported per certificate."""
        from app.models.models import Certificate
        cert = Certificate(name="wildcard", provider="letsencrypt")
        db.add(cert); db.commit()
        zf = _export(db)
        ssl_tf = _module_tf(zf, 'ssl')
        assert 'resource "corex_ssl_labs_settings" "this"' in ssl_tf, \
            "ssl_labs_settings should be exported"
        assert 'cert_id' in ssl_tf
        assert 'max_scans_per_host' in ssl_tf

    def test_ssl_labs_settings_tfvars(self, db):
        """ssl_labs_settings tfvars should have max_scans_per_host (cert_id is wired in module)."""
        from app.models.models import Certificate
        cert = Certificate(name="wildcard", provider="letsencrypt")
        db.add(cert); db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert 'ssl_labs_settings' in tv
        # cert_id is NOT in tfvars — it's wired to corex_certificate.this[each.key].id
        assert '"cert_id"' not in tv
        assert '"max_scans_per_host" = ' in tv

    def test_mcp_alert_config_exported(self, db):
        """corex_mcp_alert_config should be exported as a singleton."""
        from app.models.models import Setting
        db.add(Setting(key="mcp_alert_thresholds", value='{"failed_auth": 5, "rate_limit": 10}'))
        db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        assert 'resource "corex_mcp_alert_config" "this"' in mcp_tf, \
            "mcp_alert_config should be exported"
        assert 'webhook_url' in mcp_tf
        assert 'thresholds' in mcp_tf

    def test_mcp_alert_config_tfvars(self, db):
        """mcp_alert_config tfvars should have webhook_url and thresholds."""
        from app.models.models import Setting
        db.add(Setting(key="mcp_alert_thresholds", value='{"failed_auth": 5}'))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert 'mcp_alert_config' in tv
        assert '"webhook_url"' in tv
        assert '"thresholds"' in tv

    def test_no_dead_user_secret_vars(self, db):
        """users_hashed_passwords and users_totp_secrets should NOT be declared."""
        from app.models.auth import User
        db.add(User(username="admin", email="a@b.com", role="admin",
                   hashed_password="dummy"))
        db.commit()
        zf = _export(db)  # all flags off
        var_tf = _read(zf, 'variables.tf')
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # These are dead secrets — the provider user resource has write-only password,
        # not hashed_password or totp_secret.
        assert 'variable "users_hashed_passwords"' not in var_tf, \
            "users_hashed_passwords should not be declared (dead secret)"
        assert 'variable "users_totp_secrets"' not in var_tf, \
            "users_totp_secrets should not be declared (dead secret)"
        assert 'users_hashed_passwords' not in secrets, \
            "users_hashed_passwords should not be in secrets tfvars"
        assert 'users_totp_secrets' not in secrets, \
            "users_totp_secrets should not be in secrets tfvars"

    def test_no_dead_mcp_identity_pat_hash_secret_var(self, db):
        """mcp_identities_pat_hashes should NOT be declared (dead secret)."""
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpIdentity(name="bot", team_id=team.id, kind="pat",
                          pat_hash="SECRET_PAT"))
        db.commit()
        zf = _export(db)  # all flags off
        var_tf = _read(zf, 'variables.tf')
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        # pat_hash is not in the provider schema (provider has pat_prefix, computed)
        assert 'variable "mcp_identities_pat_hashes"' not in var_tf, \
            "mcp_identities_pat_hashes should not be declared (dead secret)"
        assert 'mcp_identities_pat_hashes' not in secrets, \
            "mcp_identities_pat_hashes should not be in secrets tfvars"

    def test_user_resource_has_no_hashed_password_or_totp(self, db):
        """User resource block should not have hashed_password or totp_secret."""
        from app.models.auth import User
        db.add(User(username="admin", email="a@b.com", role="admin",
                   hashed_password="dummy", totp_secret="secret"))
        db.commit()
        zf = _export(db)
        mgmt_tf = _module_tf(zf, 'management')
        # Find the user resource block
        idx = mgmt_tf.find('corex_user')
        assert idx >= 0
        block = mgmt_tf[idx:idx + 500]
        assert 'hashed_password' not in block, \
            "user resource should not have hashed_password (not in provider)"
        assert 'totp_secret' not in block, \
            "user resource should not have totp_secret (not in provider)"

    def test_page_protect_settings_in_imports(self, db):
        """page_protect_settings should have an import block."""
        from app.models.models import Setting
        db.add(Setting(key="page_protect_monitoring_enabled", value="true"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'corex_page_protect_settings' in imports, \
            "page_protect_settings should have import block"

    def test_mcp_alert_config_in_imports(self, db):
        """mcp_alert_config should have an import block."""
        from app.models.models import Setting
        db.add(Setting(key="mcp_alert_thresholds", value='{"failed_auth": 5}'))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'corex_mcp_alert_config' in imports, \
            "mcp_alert_config should have import block"

    def test_ssl_labs_settings_in_imports(self, db):
        """ssl_labs_settings should have import blocks per cert."""
        from app.models.models import Certificate
        cert = Certificate(name="wildcard", provider="letsencrypt")
        db.add(cert); db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'corex_ssl_labs_settings' in imports, \
            "ssl_labs_settings should have import block"

    def test_page_protect_script_in_imports(self, db):
        """page_protect_script should have import blocks by URL."""
        from app.models.page_protect import PageProtectScript
        db.add(PageProtectScript(url="https://example.com/script.js", source="manual"))
        db.commit()
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'corex_page_protect_script' in imports, \
            "page_protect_script should have import block"
        assert 'https://example.com/script.js' in imports, \
            "page_protect_script import should use URL as ID"

    def test_no_page_protect_settings_skip_comment(self, db):
        """imports.tf should not have the old 'not yet exported' comment."""
        zf = _export(db)
        imports = _read(zf, 'imports.tf')
        assert 'not yet exported' not in imports, \
            "imports.tf should not say page_protect_settings is not yet exported"


# ─── Schema mismatch fixes (round 4) ─────────────────────────────────────

class TestSchemaMismatchFixes:
    """Tests for the schema mismatch fixes: cache module, keepalived, ssl_labs
    cert_id, MCP server types, replica name, computed attrs, cipher tls_options."""

    def test_cache_module_uses_provider_names(self, db):
        """Cache module main.tf should use provider-facing field names on both sides."""
        from app.models.cache import CacheConfig
        from app.models.proxy import Backend
        be = Backend(name='web')
        db.add(be); db.flush()
        db.add(CacheConfig(backend_id=be.id, haproxy_enabled=True,
                          haproxy_total_max_size=100, haproxy_max_age=300,
                          haproxy_rfc7234_compliance=True, disk_cache_ttl=120))
        db.commit()
        zf = _export(db)
        cache_tf = _module_tf(zf, 'cache')
        # Provider-facing names on the left (attribute)
        assert 'haproxy_cache_size = ' in cache_tf
        assert 'haproxy_cache_max_age = ' in cache_tf
        assert 'rfc7234_compliance = ' in cache_tf
        assert 'disk_cache_max_age = ' in cache_tf
        # Provider-facing names on the right (each.value)
        assert 'each.value.haproxy_cache_size' in cache_tf
        assert 'each.value.haproxy_cache_max_age' in cache_tf
        assert 'each.value.rfc7234_compliance' in cache_tf
        assert 'each.value.disk_cache_max_age' in cache_tf
        # Old DB names should NOT appear on the right
        assert 'each.value.haproxy_total_max_size' not in cache_tf
        assert 'each.value.haproxy_max_age' not in cache_tf
        assert 'each.value.haproxy_rfc7234_compliance' not in cache_tf
        assert 'each.value.disk_cache_ttl' not in cache_tf

    def test_cache_module_variable_type_uses_provider_names(self, db):
        """Cache module variables.tf should use provider-facing field names."""
        from app.models.cache import CacheConfig
        from app.models.proxy import Backend
        be = Backend(name='web')
        db.add(be); db.flush()
        db.add(CacheConfig(backend_id=be.id))
        db.commit()
        zf = _export(db)
        cache_vars = _read(zf, 'modules/cache/variables.tf')
        assert 'haproxy_cache_size = optional(number)' in cache_vars
        assert 'haproxy_cache_max_age = optional(number)' in cache_vars
        assert 'rfc7234_compliance = optional(bool)' in cache_vars
        assert 'disk_cache_max_age = optional(number)' in cache_vars
        # Old DB names should NOT be in the type
        assert 'haproxy_total_max_size' not in cache_vars
        assert 'haproxy_max_age' not in cache_vars
        assert 'haproxy_rfc7234_compliance' not in cache_vars
        assert 'disk_cache_ttl' not in cache_vars

    def test_cache_config_no_name_attribute(self, db):
        """Cache config resource should not have a name attribute (not in provider)."""
        from app.models.cache import CacheConfig
        from app.models.proxy import Backend
        be = Backend(name='web')
        db.add(be); db.flush()
        db.add(CacheConfig(backend_id=be.id))
        db.commit()
        zf = _export(db)
        cache_tf = _module_tf(zf, 'cache')
        # Find the cache_config resource block
        idx = cache_tf.find('corex_cache_config')
        block = cache_tf[idx:idx + 500]
        assert 'name = ' not in block, \
            "cache_config should not have name attribute (not in provider schema)"

    def test_cache_config_has_provider_only_fields(self, db):
        """Cache config should include haproxy_cache_vary and disk_cache_max_size (provider-only)."""
        from app.models.cache import CacheConfig
        from app.models.proxy import Backend
        be = Backend(name='web')
        db.add(be); db.flush()
        db.add(CacheConfig(backend_id=be.id))
        db.commit()
        zf = _export(db)
        cache_tf = _module_tf(zf, 'cache')
        cache_vars = _read(zf, 'modules/cache/variables.tf')
        # Variable type should have these optional fields
        assert 'haproxy_cache_vary = optional(list(string))' in cache_vars
        assert 'disk_cache_max_size = optional(number)' in cache_vars
        # Resource block should emit them (null when unset)
        idx = cache_tf.find('corex_cache_config')
        block = cache_tf[idx:idx + 800]
        assert 'haproxy_cache_vary = try(each.value.haproxy_cache_vary, null)' in block
        assert 'disk_cache_max_size = try(each.value.disk_cache_max_size, null)' in block

    def test_ssl_labs_settings_typed_as_map_object(self, db):
        """ssl_labs_settings should be typed as map(object({...})), not any."""
        from app.models.models import Certificate
        db.add(Certificate(name="wildcard", provider="letsencrypt"))
        db.commit()
        zf = _export(db)
        # Module variable
        sv = _read(zf, 'modules/ssl/variables.tf')
        assert 'map(object({' in sv and 'max_scans_per_host = optional(number)' in sv, \
            "ssl_labs_settings module variable should be map(object({...}))"
        # Root variable
        rv = _read(zf, 'variables.tf')
        assert 'map(object({' in rv, \
            "ssl_labs_settings root variable should be map(object({...}))"
        # cert_id should NOT be in the type
        assert 'cert_id' not in sv.split('ssl_labs_settings')[1].split('}')[0]

    def test_ssl_labs_tfvars_no_cert_id(self, db):
        """ssl_labs_settings tfvars should NOT contain cert_id (wired in module)."""
        from app.models.models import Certificate
        db.add(Certificate(name="wildcard", provider="letsencrypt"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        assert 'ssl_labs_settings' in tv
        assert '"cert_id"' not in tv, \
            "cert_id should not be in tfvars (wired to local cert resource)"

    def test_keepalived_uses_assignment_not_block(self, db):
        """keepalived should use assignment syntax (SingleNestedAttribute), not block."""
        from app.models.models import Setting
        db.add(Setting(key="ha_enabled", value="true"))
        db.add(Setting(key="keepalived_vip", value="10.0.0.100"))
        db.commit()
        zf = _export(db)
        mgmt_tf = _module_tf(zf, 'management')
        # SingleNestedAttribute uses assignment
        assert 'keepalived = try(var.ha_config["keepalived"], null)' in mgmt_tf
        # Should NOT use block syntax
        assert 'keepalived {' not in mgmt_tf

    def test_ssl_labs_cert_id_wired_to_local_ref(self, db):
        """ssl_labs_settings cert_id should reference local certificate resource, not snapshot int."""
        from app.models.models import Certificate
        db.add(Certificate(name="wildcard", provider="letsencrypt"))
        db.commit()
        zf = _export(db)
        ssl_tf = _module_tf(zf, 'ssl')
        assert 'corex_certificate.this[each.key].id' in ssl_tf, \
            "cert_id should be wired to local certificate resource ID"
        # Should NOT use a snapshot integer from tfvars
        assert 'each.value.cert_id' not in ssl_tf

    def test_mcp_server_env_vars_secret_is_map(self, db):
        """mcp_servers_env_vars secret var should be map(map(string)), not map(string)."""
        from app.models.mcp import McpServer, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpServer(name="tools", team_id=team.id, namespace="eng",
                        transport_type="stdio", env_vars_json='{"FOO": "bar"}'))
        db.commit()
        zf = _export(db, include_secrets=False, include_system_secrets=False)
        var_tf = _read(zf, 'variables.tf')
        # Should be map(map(string)) — each server has a map of env vars
        assert 'map(map(string))' in var_tf, \
            "mcp_servers_env_vars should be map(map(string))"
        # Placeholder should be an empty map, not "change-me"
        secrets = _read(zf, 'environments/dev.secrets.tfvars')
        assert '"tools" = {}' in secrets, \
            "env_vars placeholder should be empty map, not string"

    def test_mcp_server_args_is_list_in_tfvars(self, db):
        """MCP server args should be a list in tfvars, not a JSON string."""
        from app.models.mcp import McpServer, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpServer(name="tools", team_id=team.id, namespace="eng",
                        transport_type="stdio", args_json='["--port", "8080"]'))
        db.commit()
        zf = _export(db, include_secrets=True)
        tv = _tfvars(zf)
        assert '"args" = ["--port", "8080"]' in tv, \
            "args should be a list in tfvars, not a JSON string"

    def test_mcp_server_env_vars_is_map_in_tfvars(self, db):
        """MCP server env_vars should be a map in tfvars, not a JSON string."""
        from app.models.mcp import McpServer, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpServer(name="tools", team_id=team.id, namespace="eng",
                        transport_type="stdio", env_vars_json='{"FOO": "bar"}'))
        db.commit()
        zf = _export(db, include_secrets=True)
        tv = _tfvars(zf)
        assert '"env_vars" = {"FOO" = "bar"}' in tv, \
            "env_vars should be a map in tfvars, not a JSON string"

    def test_mcp_server_replica_no_name(self, db):
        """MCP server replica resource should not have a name attribute."""
        from app.models.mcp import McpServer, McpServerReplica, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        srv = McpServer(name="tools", team_id=team.id, namespace="eng",
                       transport_type="stdio")
        db.add(srv); db.flush()
        db.add(McpServerReplica(server_id=srv.id, url="http://replica:8080"))
        db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        idx = mcp_tf.find('corex_mcp_server_replica')
        block = mcp_tf[idx:idx + 400]
        assert 'name = ' not in block, \
            "mcp_server_replica should not have name (provider only has server_id, url, enabled, verify_tls)"

    def test_mcp_dlp_rule_no_priority(self, db):
        """MCP DLP rule should not have priority (computed-only in provider)."""
        from app.models.mcp import McpDlpRule, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpDlpRule(team_id=team.id, name="rule1", direction="request",
                        detector="regex", find_regex="test", action="block"))
        db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        idx = mcp_tf.find('corex_mcp_dlp_rule')
        block = mcp_tf[idx:idx + 500]
        assert 'priority = ' not in block, \
            "mcp_dlp_rule should not have priority (computed-only)"

    def test_mcp_guardrail_no_priority(self, db):
        """MCP guardrail should not have priority (computed-only in provider)."""
        from app.models.mcp import McpGuardrail, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpGuardrail(team_id=team.id, name="g1", direction="both",
                          find_regex="test", action="block"))
        db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        idx = mcp_tf.find('corex_mcp_guardrail')
        block = mcp_tf[idx:idx + 500]
        assert 'priority = ' not in block, \
            "mcp_guardrail should not have priority (computed-only)"

    def test_mcp_skill_no_enable_when_ast(self, db):
        """MCP skill should not have enable_when_ast (computed-only in provider)."""
        from app.models.mcp import McpSkill, Team
        team = Team(name="Eng", slug="eng")
        db.add(team); db.flush()
        db.add(McpSkill(team_id=team.id, name="skill1"))
        db.commit()
        zf = _export(db)
        mcp_tf = _module_tf(zf, 'mcp-gateway')
        idx = mcp_tf.find('corex_mcp_skill"')
        block = mcp_tf[idx:idx + 500]
        assert 'enable_when_ast = ' not in block, \
            "mcp_skill should not have enable_when_ast (computed-only)"

    def test_cipher_suite_tls_options_is_list(self, db):
        """Cipher suite tls_options should be a list in tfvars, not a string."""
        from app.models.proxy import CipherSuite
        db.add(CipherSuite(name="modern", baseline="modern", ciphers="ECDHE",
                          tls_options="no-sslv3 no-tlsv10"))
        db.commit()
        zf = _export(db)
        tv = _tfvars(zf)
        # Should be a list, not a string
        assert '"tls_options" = ["no-sslv3", "no-tlsv10"]' in tv, \
            "tls_options should be a list in tfvars"

    def test_cipher_suite_tls_options_variable_type(self, db):
        """Cipher suite variable type should have tls_options as list(string)."""
        from app.models.proxy import CipherSuite
        db.add(CipherSuite(name="modern", baseline="modern", ciphers="ECDHE"))
        db.commit()
        zf = _export(db)
        ssl_vars = _read(zf, 'modules/ssl/variables.tf')
        assert 'tls_options = optional(list(string))' in ssl_vars, \
            "tls_options should be list(string) in variable type"


# ─── Schema-driven overrides ────────────────────────────────────────────────

class TestSchemaDrivenOverrides:
    """Tests that the exporter derives field skips from the provider schema JSON,
    not just from manual PROVIDER_FIELD_OVERRIDES. This prevents drift when the
    provider schema changes."""

    def test_schema_computed_fields_are_skipped(self):
        """The provider schema JSON should mark computed-only fields, and the
        exporter should skip them even if PROVIDER_FIELD_OVERRIDES doesn't list them."""
        from app.services.provider_schema import get_computed_fields
        # These are computed-only in the provider schema (not optional+computed)
        assert 'priority' in get_computed_fields('mcp_dlp_rule')
        assert 'priority' in get_computed_fields('mcp_guardrail')
        assert 'enable_when_ast' in get_computed_fields('mcp_skill')
        assert 'published_version_id' in get_computed_fields('mcp_skill')

    def test_resolve_provider_overrides_merges_schema_and_manual(self):
        """_resolve_provider_overrides should merge manual overrides with schema-derived skips."""
        from app.services.terraform_export import _resolve_provider_overrides
        from app.models.mcp import McpDlpRule, McpServerReplica
        from app.models.cache import CacheConfig

        # mcp_dlp_rule: manual override doesn't list 'priority', but schema says it's computed
        dlp = _resolve_provider_overrides('mcp_dlp_rule', McpDlpRule)
        assert 'priority' in dlp['skip'], "schema-derived computed fields should be in skip"

        # mcp_server_replica: manual override lists 'name', schema adds 'id'
        rep = _resolve_provider_overrides('mcp_server_replica', McpServerReplica)
        assert 'name' in rep['skip'], "manual skip should be preserved"
        assert 'id' in rep['skip'], "schema-derived computed 'id' should be in skip"

        # cache_config: manual override has renames, schema adds computed 'id'
        cc = _resolve_provider_overrides('cache_config', CacheConfig)
        assert 'name' in cc['skip'], "manual skip should be preserved"
        assert 'id' in cc['skip'], "schema-derived computed 'id' should be in skip"
        assert cc['rename']['haproxy_total_max_size'] == 'haproxy_cache_size'

    def test_schema_unsupported_fields_are_skipped(self):
        """DB fields not in the provider schema should be skipped."""
        from app.services.terraform_export import _resolve_provider_overrides
        from app.models.cache import CacheConfig
        cc = _resolve_provider_overrides('cache_config', CacheConfig)
        # These DB columns don't exist in the provider schema
        assert 'haproxy_max_object_size' in cc['skip']
        assert 'haproxy_max_secondary_entries' in cc['skip']
        assert 'disk_cache_grace' in cc['skip']
        assert 'disk_cache_purge_enabled' in cc['skip']

    def test_schema_file_exists(self):
        """The provider schema JSON file should exist and be loadable."""
        import os
        from app.services.provider_schema import _SCHEMA_PATH
        assert os.path.exists(_SCHEMA_PATH), "corex_provider_schema.json should exist"
        from app.services.provider_schema import _resource_schemas
        schemas = _resource_schemas()
        assert 'cache_config' in schemas
        assert 'mcp_server' in schemas
        assert len(schemas) >= 50, "Should have 50+ resource schemas"
