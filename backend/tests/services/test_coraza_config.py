import os
import pytest

from app.services import coraza_config
from tests.factories import (
    make_backend,
    make_listener,
    make_server,
    make_waf_exception,
    make_waf_rule,
)


def test_rules_for_listener_empty(db):
    listener = make_listener(db)
    assert coraza_config.rules_for_listener(db, listener.id) == []


def test_rules_for_listener_global_no_backend(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="global", listener_id=None, backend_id=None)
    rules = coraza_config.rules_for_listener(db, listener.id)
    assert len(rules) == 1
    assert rules[0].name == "global"


def test_rules_for_listener_global_with_matching_backend(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    other_backend = make_backend(db, name="other")
    make_waf_rule(db, name="global-match", listener_id=None, backend_id=backend.id)
    make_waf_rule(db, name="global-no-match", listener_id=None, backend_id=other_backend.id)
    rules = coraza_config.rules_for_listener(db, listener.id)
    assert len(rules) == 1
    assert rules[0].name == "global-match"


def test_rules_for_listener_specific(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    other_listener = make_listener(db, backend=backend, name="other_listener")
    rule = make_waf_rule(db, name="specific", listener_id=listener.id)
    make_waf_rule(db, name="other", listener_id=other_listener.id)
    rules = coraza_config.rules_for_listener(db, listener.id)
    assert len(rules) == 1
    assert rules[0].id == rule.id


def test_rules_for_listener_merges_specific_and_global(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    specific = make_waf_rule(db, name="specific", listener_id=listener.id)
    global_rule = make_waf_rule(db, name="global", listener_id=None)
    rules = coraza_config.rules_for_listener(db, listener.id)
    assert [r.name for r in rules] == ["specific", "global"]
    assert rules[0].id == specific.id


def test_rules_for_listener_disabled_excluded(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="disabled", listener_id=None, enabled=False)
    assert coraza_config.rules_for_listener(db, listener.id) == []


def test_coraza_app_for_listener_specific(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="specific", listener_id=listener.id)
    assert coraza_config.coraza_app_for_listener(listener.id, db) == f"haproxy-waf-listener-{listener.id}"


def test_coraza_app_for_listener_global(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="global", listener_id=None)
    assert coraza_config.coraza_app_for_listener(listener.id, db) == f"haproxy-waf-listener-{listener.id}"


def test_coraza_app_for_listener_no_rules(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    assert coraza_config.coraza_app_for_listener(listener.id, db) == "haproxy-waf"


def test_generate_coraza_spoa_config_no_rules(db):
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "default_application: haproxy-waf" in cfg
    assert "- name: haproxy-waf" in cfg
    assert "SecRuleEngine Off" in cfg


def test_generate_coraza_spoa_config_per_listener_app(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_server(db, backend.id)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert f"- name: haproxy-waf-listener-{listener.id}" in cfg
    assert "Include @owasp_crs/*.conf" in cfg
    assert "Include @coraza.conf-recommended" in cfg


def test_generate_coraza_spoa_config_rate_limit(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        rate_enabled=True,
        rate_events=10,
        rate_window_seconds=60,
        rate_action="block",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    # Coraza's setvar only supports the TX collection, so IP-based rate rules
    # are intentionally not emitted from the Coraza config.
    assert "initcol:ip" not in cfg
    assert "IP:RATE_COUNT" not in cfg
    assert "setvar:ip" not in cfg


def test_generate_coraza_spoa_config_scope_checks(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        path_pattern="/api",
        http_methods="GET,POST",
        content_types="application/json",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert '!@beginsWith /api' in cfg
    assert '!@within GET,POST' in cfg
    assert '!@beginsWith application/json' in cfg
    assert "SecMarker HAPROXY-WAF-SCOPE-END" in cfg


def test_generate_coraza_spoa_config_exceptions(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(db, waf_rule_id=rule.id, rule_id="123", action="remove")
    make_waf_exception(db, waf_rule_id=rule.id, rule_tag="sqli", action="remove")
    make_waf_exception(db, waf_rule_id=rule.id, rule_msg="xss", action="remove")
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_id="456",
        action="allow",
        zone="ARGS",
        variable="foo",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "SecRuleRemoveById 123" in cfg
    assert "SecRuleRemoveByTag sqli" in cfg
    assert "SecRuleRemoveByMsg xss" in cfg
    assert "SecRuleUpdateTargetById 456 !ARGS:foo" in cfg


def test_exception_conditional_remove_by_id(db):
    """Conditional exception: only remove rule when REMOTE_ADDR equals a value."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_id="942100",
        action="remove",
        condition_variable="REMOTE_ADDR",
        condition_operator="equals",
        condition_value="10.0.0.1",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert 'ctl:ruleRemoveById=942100' in cfg
    assert 'REMOTE_ADDR "@streq 10.0.0.1"' in cfg
    # Should NOT emit the unconditional SecRuleRemoveById
    assert "SecRuleRemoveById 942100" not in cfg


def test_exception_conditional_allow_by_id(db):
    """Conditional allow: exclude a target only when a condition matches."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_id="942100",
        action="allow",
        zone="ARGS",
        variable="foo",
        condition_variable="REMOTE_ADDR",
        condition_operator="regex",
        condition_value="^192.168.",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert 'ctl:ruleRemoveTargetById=942100;ARGS:foo' in cfg
    assert 'REMOTE_ADDR "@rx ^192.168."' in cfg


def test_exception_conditional_remove_by_tag(db):
    """Conditional exception by tag with condition."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_tag="sqli",
        action="remove",
        condition_variable="REQUEST_METHOD",
        condition_operator="equals",
        condition_value="GET",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert 'ctl:ruleRemoveByTag=sqli' in cfg
    assert 'REQUEST_METHOD "@streq GET"' in cfg


def test_exception_matcher_only(db):
    """Matcher-only exception: exclude a variable when its content matches."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_id="942100",
        action="allow",
        zone="ARGS",
        variable="foo",
        matcher="contains",
        value="bar",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert 'ctl:ruleRemoveTargetById=942100;ARGS:foo' in cfg
    assert 'ARGS:foo "@contains bar"' in cfg


def test_exception_conditional_with_matcher(db):
    """Both condition and matcher: chained SecRule."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_id="942100",
        action="allow",
        zone="ARGS",
        variable="foo",
        matcher="contains",
        value="bar",
        condition_variable="REMOTE_ADDR",
        condition_operator="equals",
        condition_value="10.0.0.1",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "chain" in cfg
    assert 'REMOTE_ADDR "@streq 10.0.0.1"' in cfg
    assert 'ARGS:foo "@contains bar"' in cfg
    assert 'ctl:ruleRemoveTargetById=942100;ARGS:foo' in cfg


def test_exception_global_appears_in_config(db):
    """A global exception (waf_rule_id=None) is included in the generated config.

    Regression: previously _exceptions_for_rules filtered on
    `e.waf_rule_id in rule_ids`, and `None in {1,2}` is False, so global
    exceptions were silently dropped and the on-disk config never changed
    (so the "unapplied changes" banner never appeared after creating one).
    """
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=None,
        rule_tag="OWASP_CRS",
        action="remove",
        condition_variable="REQUEST_URI",
        condition_operator="regex",
        condition_value=r"^\/upload\?n\=.+$",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "ctl:ruleRemoveByTag=OWASP_CRS" in cfg
    # _escape_pattern doubles backslashes, so the emitted regex has literal \\.
    assert r'REQUEST_URI "@rx ^\\/upload\\?n\\=.+$"' in cfg


def test_exception_conditional_remove_all_rules(db):
    """Conditional "remove" with no rule_id/tag/msg disables the whole engine.

    This is the "bypass all security rules when <condition>" case. The correct
    Coraza directive is ``ctl:ruleEngine=Off``, which skips every rule for the
    remainder of the transaction. Previously this configuration was silently
    dropped because _exception_ctl_action returned None when no specific rule
    target was supplied.
    """
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        action="remove",
        condition_variable="REQUEST_URI",
        condition_operator="contains",
        condition_value="/upload?n=",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert 'ctl:ruleEngine=Off' in cfg
    assert 'REQUEST_URI "@contains /upload?n="' in cfg
    # Must precede CRS includes so it takes effect before any CRS rule fires.
    ctl_pos = cfg.find("ctl:ruleEngine=Off")
    include_pos = cfg.find("Include @owasp_crs")
    assert ctl_pos != -1
    assert include_pos == -1 or ctl_pos < include_pos


def test_exception_global_appears_in_every_app_block(db):
    """A global exception is applied to every listener app block, not just one."""
    backend = make_backend(db)
    listener_a = make_listener(db, backend=backend, name="a")
    listener_b = make_listener(db, backend=backend, name="b")
    make_waf_rule(db, name="waf-a", listener_id=listener_a.id)
    make_waf_rule(db, name="waf-b", listener_id=listener_b.id)
    make_waf_exception(
        db,
        waf_rule_id=None,
        rule_id="942100",
        action="remove",
        condition_variable="REMOTE_ADDR",
        condition_operator="equals",
        condition_value="10.0.0.1",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    # The conditional ctl: directive should appear once per listener app block.
    assert cfg.count("ctl:ruleRemoveById=942100") == 2


def test_conditional_exception_precedes_crs_includes(db):
    """Conditional exceptions (ctl:) must appear before CRS Include directives.

    ctl:ruleRemoveByTag is a runtime action that only affects rules evaluated
    AFTER it in the transaction. If the SecRule containing the ctl action is
    emitted after the CRS ``Include`` directives, the CRS rules (and the
    blocking meta-rules 949110/959100) have already fired by the time the ctl
    takes effect, so the exception silently does nothing and the request is
    still blocked (403).
    """
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id, rule_set="owasp-crs")
    make_waf_exception(
        db,
        waf_rule_id=None,
        rule_tag="OWASP_CRS",
        action="remove",
        condition_variable="REQUEST_URI",
        condition_operator="regex",
        condition_value=r"^\/upload\?n\=.+$",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    ctl_pos = cfg.find("ctl:ruleRemoveByTag=OWASP_CRS")
    include_pos = cfg.find("Include @owasp_crs")
    assert ctl_pos != -1, "conditional ctl: directive not found in config"
    assert include_pos != -1, "CRS Include directive not found in config"
    assert ctl_pos < include_pos, (
        "conditional exception must precede CRS includes — "
        f"ctl at {ctl_pos}, Include at {include_pos}"
    )


def test_unconditional_exception_after_crs_includes(db):
    """Unconditional exceptions (SecRuleRemoveById etc.) appear after includes.

    These are config-time directives that work regardless of position, but
    keeping them after the includes matches the CRS convention and avoids
    polluting the pre-include section reserved for runtime ctl: actions.
    """
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="waf", listener_id=listener.id, rule_set="owasp-crs")
    make_waf_exception(db, waf_rule_id=None, rule_id="942100", action="remove")
    cfg = coraza_config.generate_coraza_spoa_config(db)
    remove_pos = cfg.find("SecRuleRemoveById 942100")
    include_pos = cfg.find("Include @owasp_crs")
    assert remove_pos != -1
    assert include_pos != -1
    assert remove_pos > include_pos


def test_exception_unconditional_unchanged(db):
    """Unconditional exceptions (no condition/matcher) still work as before."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(db, name="waf", listener_id=listener.id)
    make_waf_exception(db, waf_rule_id=rule.id, rule_id="123", action="remove")
    make_waf_exception(
        db,
        waf_rule_id=rule.id,
        rule_id="456",
        action="allow",
        zone="ARGS",
        variable="foo",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "SecRuleRemoveById 123" in cfg
    assert "SecRuleUpdateTargetById 456 !ARGS:foo" in cfg
    # No ctl: directives for unconditional exceptions
    assert "ctl:ruleRemoveById" not in cfg


def test_generate_coraza_spoa_config_custom_rules(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(
        db,
        name="waf",
        listener_id=listener.id,
        sec_rules='SecRule REQUEST_URI "@rx ." "id:1,phase:1,deny"',
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "id:1,phase:1,deny" in cfg


def _in_application_block(cfg: str, app_name: str, needle: str) -> bool:
    in_app = False
    saw = False
    for line in cfg.splitlines():
        if line.startswith(f"{app_name}:"):
            in_app = True
        elif line.strip().endswith(":") and not line.startswith(" "):
            in_app = False
        if in_app and needle in line:
            saw = True
    return saw


def test_generate_coraza_spoa_config_rule_sets(db):
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="coraza-rule", listener_id=listener.id, rule_set="coraza")
    make_waf_rule(db, name="owasp-rule", listener_id=listener.id, rule_set="owasp-crs")
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "Include @coraza.conf-recommended" in cfg
    assert "Include @owasp_crs/*.conf" in cfg

    listener2 = make_listener(db, backend=backend, name="l2")
    make_waf_rule(db, name="custom", listener_id=listener2.id, rule_set="custom")
    cfg2 = coraza_config.generate_coraza_spoa_config(db)
    # custom-only app should not include CRS
    app_name = f"haproxy-waf-listener-{listener2.id}"
    assert not _in_application_block(cfg2, app_name, "@owasp_crs")


def test_generate_coraza_spoa_config_crs_rule_set(db):
    """The 'crs' rule set value triggers CRS includes (same as coraza/owasp-crs)."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="crs-waf", listener_id=listener.id, rule_set="crs")
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "Include @coraza.conf-recommended" in cfg
    assert "Include @owasp_crs/*.conf" in cfg


def test_generate_coraza_spoa_config_crs_filesystem_includes(db, tmp_path, monkeypatch):
    """When a CRS version is downloaded, use filesystem includes instead of embedded."""
    from app.services import crs_downloader
    from app.services.settings import set_setting

    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    # Simulate a downloaded CRS version
    crs_dir = os.path.join(str(tmp_path), "4.0.0")
    os.makedirs(os.path.join(crs_dir, "rules"))
    with open(os.path.join(crs_dir, "crs-setup.conf.example"), "w") as f:
        f.write("# CRS setup\n")
    with open(os.path.join(crs_dir, "rules", "REQUEST-901.conf"), "w") as f:
        f.write("# rule\n")
    set_setting(db, "crs_active_version", "4.0.0")

    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="crs-waf", listener_id=listener.id, rule_set="crs")
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "Include @coraza.conf-recommended" in cfg
    assert "Include /app/data/crs/4.0.0/crs-setup.conf.example" in cfg
    assert "Include /app/data/crs/4.0.0/rules/*.conf" in cfg
    # Should NOT use embedded includes
    assert "Include @owasp_crs" not in cfg
    assert "Include @crs-setup.conf.example" not in cfg


def test_generate_coraza_spoa_config_crs_falls_back_to_embedded(db, tmp_path, monkeypatch):
    """When active version dir is missing, fall back to embedded includes."""
    from app.services import crs_downloader
    from app.services.settings import set_setting

    monkeypatch.setattr(crs_downloader.settings, "CRS_DIR", str(tmp_path))
    set_setting(db, "crs_active_version", "4.0.0")
    # Don't create the directory — simulate files deleted

    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="crs-waf", listener_id=listener.id, rule_set="crs")
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "Include @coraza.conf-recommended" in cfg
    assert "Include @crs-setup.conf.example" in cfg
    assert "Include @owasp_crs/*.conf" in cfg


def test_generate_coraza_spoa_config_crs_no_active_version_uses_embedded(db):
    """When no active CRS version is set, use embedded includes."""
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(db, name="crs-waf", listener_id=listener.id, rule_set="crs")
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "Include @coraza.conf-recommended" in cfg
    assert "Include @owasp_crs/*.conf" in cfg


def test_generate_coraza_spoa_config_remote_rule_set_not_downloaded(db, tmp_path, monkeypatch):
    """Remote rule set that hasn't been downloaded emits a comment."""
    from app.services import rule_set_downloader
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
    )
    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "not yet downloaded" in cfg
    assert "Include /app/data/custom-rules/remote-waf.conf" not in cfg


def test_generate_coraza_spoa_config_remote_rule_set_downloaded(db, tmp_path, monkeypatch):
    """Remote rule set that has been downloaded emits an Include."""
    from app.services import rule_set_downloader
    monkeypatch.setattr(rule_set_downloader.settings, "CUSTOM_RULES_DIR", str(tmp_path))
    backend = make_backend(db)
    listener = make_listener(db, backend=backend)
    rule = make_waf_rule(
        db, name="remote-waf", listener_id=listener.id,
        rule_set="remote", rule_set_url="https://example.com/rules.conf",
    )
    # Simulate a downloaded file
    path = rule_set_downloader._rule_file_path(rule.name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('SecRule REQUEST_URI "@rx ." "id:1,phase:1,deny"')

    cfg = coraza_config.generate_coraza_spoa_config(db)
    assert "Include /app/data/custom-rules/remote-waf.conf" in cfg
