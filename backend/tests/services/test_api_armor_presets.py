"""Tests for API Armor preset security rules."""
from app.services.api_armor_presets import get_preset_rules, apply_preset_rules
from app.models.models import SecurityRule


def test_get_preset_rules():
    """get_preset_rules returns a list of preset rule dicts."""
    presets = get_preset_rules()
    assert len(presets) > 0
    for p in presets:
        assert "name" in p
        assert "expression" in p
        assert "action" in p
    # Should include GraphQL depth rule
    names = [p["name"] for p in presets]
    assert any("depth" in n.lower() for n in names)
    # Should include auth validation rule
    assert any("auth" in n.lower() for n in names)


def test_apply_preset_rules_creates_rules(db):
    """apply_preset_rules creates SecurityRule rows for each preset."""
    existing = db.query(SecurityRule).count()
    created = apply_preset_rules(db)
    assert len(created) > 0
    assert db.query(SecurityRule).count() == existing + len(created)


def test_apply_preset_rules_idempotent(db):
    """apply_preset_rules doesn't create duplicates on second call."""
    first = apply_preset_rules(db)
    assert len(first) > 0
    second = apply_preset_rules(db)
    assert len(second) == 0


def test_apply_preset_rules_with_listener_ids(db):
    """apply_preset_rules scopes rules to specified listeners."""
    created = apply_preset_rules(db, listener_ids=[1, 2])
    assert len(created) > 0
    for rule in created:
        assert rule.listener_ids == [1, 2]


def test_apply_preset_rules_priority(db):
    """apply_preset_rules assigns incrementing priorities."""
    created = apply_preset_rules(db)
    assert len(created) > 1
    priorities = [r.priority for r in created]
    assert priorities == sorted(priorities)
    assert priorities[-1] > priorities[0]


def test_preset_graphql_depth_rule_expression(db):
    """The GraphQL depth preset uses the graphql.depth field."""
    created = apply_preset_rules(db)
    depth_rule = next(r for r in created if "depth" in r.name.lower())
    assert "graphql.depth" in depth_rule.expression
    assert depth_rule.action == "block"


def test_preset_auth_rule_expression(db):
    """The auth preset uses the auth.valid field."""
    created = apply_preset_rules(db)
    auth_rule = next(r for r in created if "auth" in r.name.lower())
    assert "auth.valid" in auth_rule.expression
    assert auth_rule.action == "block"
    assert auth_rule.status_code == 401
