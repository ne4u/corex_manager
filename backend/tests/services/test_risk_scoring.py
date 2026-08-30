"""Tests for the risk_scoring service (expression validation, category
derivation, score budget enforcement, emission, data file generation,
baseline seeding idempotency).
"""
import os
import pytest

from app.models.models import (
    RiskRule, RiskRuleset, NetworkList, NetworkListEntry, AsnList, AsnListEntry,
    GeoList, GeoListEntry, Ja4List, Ja4ListEntry,
)
from app.services import risk_scoring


class TestCategoryDerivation:
    def test_protocol_field(self):
        ast = risk_scoring.parse_expression("http.request.version_numeric < 11")
        assert risk_scoring.derive_category(ast, 4) == "protocol"

    def test_headers_field(self):
        ast = risk_scoring.parse_expression('not http.request.headers["accept-language"] exists')
        assert risk_scoring.derive_category(ast, 3) == "headers"

    def test_geo_field(self):
        ast = risk_scoring.parse_expression("http.request.geo_lang_mismatch")
        assert risk_scoring.derive_category(ast, 4) == "geo"

    def test_behavioral_field(self):
        ast = risk_scoring.parse_expression("http.request.uri_length > 1024")
        assert risk_scoring.derive_category(ast, 2) == "behavioral"

    def test_list_in_list(self):
        ast = risk_scoring.parse_expression("ip.src in $network:mylist")
        assert risk_scoring.derive_category(ast, 12) == "list"

    def test_trust_negative_points(self):
        ast = risk_scoring.parse_expression("http.request.version_numeric >= 20")
        # Negative points → trust override regardless of field
        assert risk_scoring.derive_category(ast, -5) == "trust"

    def test_first_field_wins(self):
        # Expression with protocol field first, then headers field
        ast = risk_scoring.parse_expression(
            'http.request.version_numeric >= 20 and not http.request.headers["priority"] exists'
        )
        assert risk_scoring.derive_category(ast, 3) == "protocol"

    def test_in_list_overrides_first_field(self):
        # Even if geo field is first, in_list → list
        ast = risk_scoring.parse_expression("ip.geoip.country in $geo:high_risk_countries")
        assert risk_scoring.derive_category(ast, 5) == "list"

    def test_no_match_custom(self):
        ast = risk_scoring.parse_expression("http.request.method = \"GET\"")
        assert risk_scoring.derive_category(ast, 5) == "custom"

    def test_none_ast(self):
        assert risk_scoring.derive_category(None, 0) == "custom"


class TestExpressionValidation:
    def test_valid_expression(self, db):
        ok, ast, error = risk_scoring.validate_expression("http.request.version_numeric < 11", db)
        assert ok is True
        assert error is None
        assert ast is not None

    def test_empty_expression(self, db):
        ok, ast, error = risk_scoring.validate_expression("", db)
        assert ok is True

    def test_invalid_expression(self, db):
        ok, ast, error = risk_scoring.validate_expression("http.host @", db)
        assert ok is False
        assert error is not None

    def test_response_phase_rejected(self, db):
        ok, ast, error = risk_scoring.validate_expression("http.response.status_code = 200", db)
        assert ok is False
        assert "request-phase" in (error or "")


class TestEmission:
    def test_emit_no_rules(self, db):
        listener = type("Listener", (), {"id": 1})()
        lines = []
        risk_scoring.emit_risk_scoring(listener, db, lines)
        # Should still emit risk_capture and risk_compute
        assert any("lua.risk_capture" in l for l in lines)
        assert any("lua.risk_compute" in l for l in lines)

    def test_emit_with_rules(self, db):
        rule = RiskRule(name="test", expression='http.host = "a"', points=10, enabled=True, priority=0, ruleset_id=1)
        db.add(rule)
        db.commit()
        listener = type("Listener", (), {"id": 1})()
        lines = []
        risk_scoring.emit_risk_scoring(listener, db, lines)
        assert any("lua.risk_capture" in l for l in lines)
        assert any(f"set-var(txn.risk.match_{rule.id})" in l for l in lines)
        assert any("lua.risk_compute" in l for l in lines)

    def test_emit_no_double_braces(self, db):
        """Regression: translate() already wraps each leaf in { ... }, so
        emit_risk_scoring must NOT add another layer of braces.
        `{ { ... } }` is rejected by HAProxy with "missing fetch method in
        ACL expression '{'".
        """
        rule = RiskRule(name="test", expression='http.request.version_numeric < 11',
                        points=4, enabled=True, priority=0, ruleset_id=1)
        db.add(rule)
        db.commit()
        listener = type("Listener", (), {"id": 1})()
        lines = []
        risk_scoring.emit_risk_scoring(listener, db, lines)
        match_lines = [l for l in lines if f"set-var(txn.risk.match_{rule.id})" in l]
        assert len(match_lines) == 1
        line = match_lines[0]
        # The condition after "if " must not start with "{ {" (double brace)
        assert "if { {" not in line
        # And must not contain "} }" at the end (double close)
        assert not line.rstrip().endswith("} }")


class TestDataFile:
    def test_write_data_file(self, db, tmp_path, monkeypatch):
        monkeypatch.setattr(risk_scoring.settings, "SECURITY_LISTS_DIR", str(tmp_path / "lists"))
        rule = RiskRule(name="test rule", expression='http.host = "a"', points=15, enabled=True, priority=0, log=True, ruleset_id=1)
        db.add(rule)
        db.commit()
        path = risk_scoring.write_risk_rules_data_file(db)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "return {" in content
        assert f"id = {rule.id}" in content
        assert "points = 15" in content
        assert "test rule" in content
        # New format: ruleset field per rule + rulesets list
        assert "rulesets" in content
        assert '"default"' in content
        assert "ruleset = " in content

    def test_write_data_file_empty(self, db, tmp_path, monkeypatch):
        monkeypatch.setattr(risk_scoring.settings, "SECURITY_LISTS_DIR", str(tmp_path / "lists"))
        path = risk_scoring.write_risk_rules_data_file(db)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "return {" in content


class TestBaselineSeeding:
    def test_seed_creates_rules_and_lists(self, db):
        created_rules, created_lists, created_rulesets, skipped = risk_scoring.seed_baseline_rules(db)
        # default ruleset was created by the db fixture, so 0 new rulesets
        assert created_rulesets == 0
        assert created_lists == 4
        # default ruleset is skipped (already exists from fixture)
        assert skipped == 1
        assert created_rules > 0
        # Check rulesets exist
        rulesets = db.query(RiskRuleset).all()
        slugs = {rs.slug for rs in rulesets}
        assert "default" in slugs
        # Check lists exist
        assert db.query(GeoList).filter(GeoList.name == "high_risk_countries").first() is not None
        assert db.query(AsnList).filter(AsnList.name == "datacenter_asns").first() is not None
        assert db.query(Ja4List).filter(Ja4List.name == "known_bot_ja4").first() is not None
        assert db.query(NetworkList).filter(NetworkList.name == "ip_blocklist").first() is not None

    def test_seed_idempotent(self, db):
        risk_scoring.seed_baseline_rules(db)
        created_rules, created_lists, created_rulesets, skipped = risk_scoring.seed_baseline_rules(db)
        assert created_rules == 0
        assert created_lists == 0
        assert created_rulesets == 0
        # All rulesets (1) + lists (4) + rules are skipped
        assert skipped > 0

    def test_seed_positive_points_per_ruleset(self, db):
        risk_scoring.seed_baseline_rules(db)
        # Each ruleset should have positive-point rules (exact sum is not
        # meaningful since there's no budget — the Lua script clamps to 99)
        for slug in ("default",):
            rs = db.query(RiskRuleset).filter(RiskRuleset.slug == slug).first()
            assert rs is not None, f"Ruleset {slug} not found"
            rules = db.query(RiskRule).filter(
                RiskRule.ruleset_id == rs.id,
                RiskRule.enabled == True,
                RiskRule.points > 0,
            ).all()
            assert len(rules) > 0, f"Ruleset {slug} has no positive-point rules"
            total = sum(r.points for r in rules)
            assert total > 0, f"Ruleset {slug} has {total} positive points"

    def test_seed_categories_set(self, db):
        risk_scoring.seed_baseline_rules(db)
        rules = db.query(RiskRule).all()
        for rule in rules:
            assert rule.category is not None
            assert rule.category in risk_scoring.VALID_CATEGORIES

    def test_seed_trust_rules_negative(self, db):
        risk_scoring.seed_baseline_rules(db)
        trust_rules = db.query(RiskRule).filter(RiskRule.category == "trust").all()
        assert len(trust_rules) > 0
        for rule in trust_rules:
            assert rule.points < 0

    def test_seed_rules_have_ruleset_id(self, db):
        risk_scoring.seed_baseline_rules(db)
        rules = db.query(RiskRule).all()
        for rule in rules:
            assert rule.ruleset_id is not None
            rs = db.get(RiskRuleset, rule.ruleset_id)
            assert rs is not None


class TestSlugGeneration:
    def test_basic_slug(self):
        assert risk_scoring.slugify_ruleset_name("Human") == "human"

    def test_multi_word_slug(self):
        assert risk_scoring.slugify_ruleset_name("Human Score") == "human_score"

    def test_special_chars(self):
        assert risk_scoring.slugify_ruleset_name("API v2.0!") == "api_v2_0"

    def test_leading_digit(self):
        assert risk_scoring.slugify_ruleset_name("3rd Party") == "rs_3rd_party"

    def test_empty_name(self):
        assert risk_scoring.slugify_ruleset_name("") == "ruleset"

    def test_only_special_chars(self):
        assert risk_scoring.slugify_ruleset_name("!@#$%") == "ruleset"

    def test_validate_slug_valid(self):
        assert risk_scoring.validate_slug("default") is True
        assert risk_scoring.validate_slug("human_score") is True
        assert risk_scoring.validate_slug("api_v2") is True

    def test_validate_slug_invalid(self):
        assert risk_scoring.validate_slug("2api") is False
        assert risk_scoring.validate_slug("api-score") is False
        assert risk_scoring.validate_slug("") is False


class TestRulesetCRUD:
    def test_create_ruleset(self, db):
        rs = risk_scoring.create_ruleset(db, name="Human Score", description="Browser traffic")
        assert rs.id is not None
        assert rs.slug == "human_score"
        assert rs.name == "Human Score"
        assert rs.description == "Browser traffic"
        assert rs.enabled is True

    def test_create_ruleset_unique_slug(self, db):
        rs1 = risk_scoring.create_ruleset(db, name="Human", description="")
        assert rs1.slug == "human"
        rs2 = risk_scoring.create_ruleset(db, name="Human", description="")
        assert rs2.slug == "human_2"
        assert rs2.id != rs1.id

    def test_update_ruleset_name(self, db):
        rs = risk_scoring.create_ruleset(db, name="Test RS", description="")
        updated = risk_scoring.update_ruleset(db, rs.id, name="Renamed RS")
        assert updated.name == "Renamed RS"
        assert updated.slug == "renamed_rs"

    def test_update_default_slug_locked(self, db):
        # The default ruleset (id=1, slug="default") should not have its slug changed
        updated = risk_scoring.update_ruleset(db, 1, name="New Default Name")
        assert updated.slug == "default"  # slug unchanged
        assert updated.name == "New Default Name"

    def test_delete_ruleset(self, db):
        rs = risk_scoring.create_ruleset(db, name="ToDelete", description="")
        risk_scoring.delete_ruleset(db, rs.id)
        assert db.get(RiskRuleset, rs.id) is None

    def test_delete_default_ruleset_prevented(self, db):
        with pytest.raises(ValueError, match="default"):
            risk_scoring.delete_ruleset(db, 1)

    def test_delete_ruleset_cascades_rules(self, db):
        rs = risk_scoring.create_ruleset(db, name="ToDelete", description="")
        rule = RiskRule(name="test", expression="http.host = \"a\"", points=10,
                        enabled=True, priority=0, ruleset_id=rs.id)
        db.add(rule)
        db.commit()
        rule_id = rule.id
        risk_scoring.delete_ruleset(db, rs.id)
        assert db.get(RiskRule, rule_id) is None
