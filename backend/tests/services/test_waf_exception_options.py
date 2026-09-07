import json

from app.services import waf_exception_options as opts
from tests.factories import (
    make_waf_exception,
    make_waf_metric,
    make_waf_rule,
)


def _options(db):
    # Call the undecorated function so a live Valkey (if present) can't serve
    # stale results between tests.
    return opts.get_exception_options.__wrapped__(db)


def test_defaults_present(db):
    """Static lists are returned even with no rules, metrics, or logs."""
    out = _options(db)
    assert "ARGS" in out["zones"]
    assert "REQUEST_HEADERS" in out["zones"]
    assert "REQUEST_URI" in out["condition_variables"]
    assert "OWASP_CRS" in out["tags"]
    assert out["rules"] == []


def test_metrics_supply_rule_ids_and_msgs(db):
    make_waf_metric(db, rule_id="942100", msg="SQL Injection Attack")
    make_waf_metric(db, rule_id="942100", msg="SQL Injection Attack")
    make_waf_metric(db, rule_id="930100", msg="Path Traversal Attack")

    out = _options(db)
    by_id = {r["id"]: r for r in out["rules"]}
    assert by_id["942100"]["hits"] == 2
    assert by_id["942100"]["msg"] == "SQL Injection Attack"
    assert by_id["930100"]["hits"] == 1
    # Sorted by hit count, most frequent first.
    assert out["rules"][0]["id"] == "942100"
    msgs = {m["msg"]: m for m in out["msgs"]}
    assert msgs["SQL Injection Attack"]["rule_id"] == "942100"


def test_sec_rules_text_parsed(db):
    """Rule ids/tags/msgs are extracted from a WafRule's inline sec_rules."""
    make_waf_rule(
        db,
        name="waf",
        sec_rules='SecRule ARGS "@rx foo" "id:100001,phase:2,deny,tag:\'attack-custom\',msg:\'My custom rule\'"',
    )
    out = _options(db)
    by_id = {r["id"]: r for r in out["rules"]}
    assert "100001" in by_id
    assert by_id["100001"]["msg"] == "My custom rule"
    assert by_id["100001"]["tags"] == ["attack-custom"]
    assert "attack-custom" in out["tags"]
    assert any(m["msg"] == "My custom rule" for m in out["msgs"])


def test_custom_rules_dir_parsed(db, tmp_path, monkeypatch):
    rules_dir = tmp_path / "custom-rules"
    rules_dir.mkdir()
    (rules_dir / "remote.conf").write_text(
        'SecRule REQUEST_HEADERS:User-Agent "@contains bad" "id:200001,phase:1,deny,tag:\'attack-scanner\'"'
    )
    monkeypatch.setattr(opts.settings, "CUSTOM_RULES_DIR", str(rules_dir))
    out = _options(db)
    assert any(r["id"] == "200001" for r in out["rules"])
    assert "attack-scanner" in out["tags"]


def test_log_tail_parsed(db, tmp_path, monkeypatch):
    log = tmp_path / "coraza-spoa.log"
    lines = [
        '[client "1.2.3.4"] Coraza: Warning. x [id "920350"] [msg "Host header is a numeric IP address"] '
        '[data "Matched Data: 1.2.3.4 found within REMOTE_ADDR: 1.2.3.4"] [tag "application-multi"] [tag "OWASP_CRS"]',
        json.dumps({"match": {"rule_id": 942100, "msg": "SQLi", "tags": ["attack-sqli"], "data": "found within ARGS:q: x"}}),
    ]
    log.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(opts.settings, "CORAZA_SPOA_LOG_PATH", str(log))

    out = _options(db)
    ids = {r["id"] for r in out["rules"]}
    assert {"920350", "942100"} <= ids
    assert {"application-multi", "attack-sqli"} <= set(out["tags"])
    assert any(m["msg"] == "Host header is a numeric IP address" for m in out["msgs"])
    zones = {v["zone"] for v in out["variables"]}
    assert "REMOTE_ADDR" in zones
    assert {"zone": "ARGS", "key": "q"} in out["variables"]


def test_existing_exception_values_merged(db):
    make_waf_exception(
        db,
        rule_id="941100,941160",
        rule_tag="attack-xss",
        zone="ARGS,REQUEST_HEADERS",
        variable="token",
        condition_variable="REQUEST_HEADERS:X-Custom",
    )
    out = _options(db)
    ids = {r["id"] for r in out["rules"]}
    assert {"941100", "941160"} <= ids
    assert "attack-xss" in out["tags"]
    assert "ARGS" in out["zones"]
    assert "REQUEST_HEADERS:X-Custom" in out["condition_variables"]
    assert {"zone": "REQUEST_HEADERS", "key": "token"} in out["variables"]


def test_parse_rule_line():
    parsed = opts._parse_rule_line(
        'SecRule ARGS "@rx ." "id:942100,phase:2,block,msg:\'SQL Injection\',tag:\'attack-sqli\',tag:\'OWASP_CRS\'"'
    )
    assert parsed == {"id": "942100", "msg": "SQL Injection", "tags": ["attack-sqli", "OWASP_CRS"]}
    assert opts._parse_rule_line("# a comment") is None
    assert opts._parse_rule_line("SecRuleEngine On") is None


def test_collect_within():
    variables = {}
    opts._collect_within("Matched Data: x found within ARGS:foo: bar", variables)
    opts._collect_within("found within REMOTE_ADDR: 1.2.3.4", variables)
    opts._collect_within(None, variables)
    assert ("ARGS", "foo") in variables
    assert ("REMOTE_ADDR", "") in variables


def test_split_field():
    assert opts._split_field("a,b c") == ["a", "b", "c"]
    assert opts._split_field("a b,c", comma_only=True) == ["a b", "c"]
    assert opts._split_field(None) == []
    assert opts._split_field("") == []
