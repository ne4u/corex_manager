"""API Armor preset security rules.

Provides ready-to-use security rules for common API/GraphQL protection patterns.
Users can apply these presets from the API Armor page (Phase 7) or via the API.
"""
from typing import List, Optional

from sqlalchemy.orm import Session

from ..models.models import SecurityRule


PRESET_RULES: List[dict] = [
    {
        "name": "API Armor: Block invalid GraphQL queries",
        "description": "Blocks requests where GraphQL parsing fails (invalid syntax).",
        "expression": "graphql.valid = false",
        "action": "block",
        "log": True,
        "status_code": 400,
    },
    {
        "name": "API Armor: Block GraphQL query depth > 10",
        "description": "Blocks deeply nested GraphQL queries that could cause DoS.",
        "expression": "graphql.depth > 10",
        "action": "block",
        "log": True,
        "status_code": 400,
    },
    {
        "name": "API Armor: Block GraphQL complexity > 1000",
        "description": "Blocks high-complexity GraphQL queries that could cause DoS.",
        "expression": "graphql.complexity > 1000",
        "action": "block",
        "log": True,
        "status_code": 400,
    },
    {
        "name": "API Armor: Block GraphQL alias abuse > 10",
        "description": "Blocks queries with excessive aliases (batching/batching attacks).",
        "expression": "graphql.alias_count > 10",
        "action": "block",
        "log": True,
        "status_code": 400,
    },
    {
        "name": "API Armor: Block GraphQL fragment abuse > 5",
        "description": "Blocks queries with excessive fragments (DoS vector).",
        "expression": "graphql.fragment_count > 5",
        "action": "block",
        "log": True,
        "status_code": 400,
    },
    {
        "name": "API Armor: Block schema validation failures",
        "description": "Blocks requests that fail JSON schema validation.",
        "expression": "api.schema_valid = false",
        "action": "block",
        "log": True,
        "status_code": 400,
    },
    {
        "name": "API Armor: Block invalid auth tokens",
        "description": "Blocks requests with invalid JWT or API key authentication.",
        "expression": "auth.valid = false",
        "action": "block",
        "log": True,
        "status_code": 401,
    },
    {
        "name": "API Armor: Flag profile anomalies",
        "description": "Flags requests that deviate from learned behavioral profiles.",
        "expression": "api.profile_anomaly = true",
        "action": "log",
        "log": True,
        "status_code": None,
    },
]


def get_preset_rules() -> List[dict]:
    """Return the list of preset API Armor security rules."""
    return [r.copy() for r in PRESET_RULES]


def apply_preset_rules(db: Session, listener_ids: Optional[List[int]] = None) -> List[SecurityRule]:
    """Apply all preset API Armor security rules that don't already exist.

    Args:
        db: Database session.
        listener_ids: Optional list of listener IDs to scope the rules to.
            If None, rules apply to all listeners (empty list).

    Returns:
        List of newly created SecurityRule objects.
    """
    created = []
    existing_names = {r.name for r in db.query(SecurityRule).all()}

    # Get the max priority to append after existing rules
    max_priority = db.query(SecurityRule).order_by(SecurityRule.priority.desc()).first()
    next_priority = (max_priority.priority + 1 if max_priority else 0)

    for preset in PRESET_RULES:
        if preset["name"] in existing_names:
            continue

        rule = SecurityRule(
            name=preset["name"],
            enabled=True,
            priority=next_priority,
            listener_ids=listener_ids or [],
            expression=preset["expression"],
            action=preset["action"],
            log=preset.get("log", True),
            status_code=preset.get("status_code"),
        )
        db.add(rule)
        created.append(rule)
        next_priority += 1

    if created:
        db.commit()
        for rule in created:
            db.refresh(rule)

    return created
