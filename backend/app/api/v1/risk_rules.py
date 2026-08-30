"""Risk Rules REST API router.

Mirrors the Security Rules router pattern. Provides CRUD, reorder, validate,
and seed-baseline endpoints. Rules are scoped to a ruleset via ruleset_id.
The total of matched rule points is clamped to [0, 99] at runtime by the
Lua risk_compute action.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..deps import get_current_user, get_db, require_write, rate_limit
from ...models.models import RiskRule, RiskRuleset
from ...schemas.security_rules import (
    RiskRuleCreate,
    RiskRuleReorder,
    RiskRuleResponse,
    RiskRuleUpdate,
    RiskRuleValidateRequest,
    RiskRuleValidateResponse,
    RiskSeedBaselineResponse,
)
from ...services.risk_scoring import (
    derive_category,
    parse_expression,
    reorder_rules,
    seed_baseline_rules,
    validate_expression,
)

router = APIRouter()


@router.get("/risk-rules", response_model=List[RiskRuleResponse])
def list_risk_rules(
    ruleset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    query = db.query(RiskRule)
    if ruleset_id is not None:
        query = query.filter(RiskRule.ruleset_id == ruleset_id)
    return query.order_by(RiskRule.priority).all()


@router.post("/risk-rules", response_model=RiskRuleResponse)
def create_risk_rule(
    r: RiskRuleCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    # Validate ruleset exists
    ruleset = db.get(RiskRuleset, r.ruleset_id)
    if not ruleset:
        raise HTTPException(status_code=400, detail=f"Ruleset {r.ruleset_id} not found")

    # Validate expression
    ok, ast, error = validate_expression(r.expression, db)
    if not ok:
        raise HTTPException(status_code=400, detail=error)

    # Auto-derive category if not provided
    category = r.category
    if not category:
        category = derive_category(ast, r.points)

    max_priority = db.query(RiskRule).filter(
        RiskRule.ruleset_id == r.ruleset_id
    ).order_by(RiskRule.priority.desc()).first()
    priority = (max_priority.priority + 1) if max_priority else 0
    obj = RiskRule(
        name=r.name,
        enabled=r.enabled,
        listener_ids=r.listener_ids,
        expression=r.expression,
        expression_ast=ast,
        points=r.points,
        category=category,
        log=r.log,
        priority=priority,
        ruleset_id=r.ruleset_id,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/risk-rules/reorder")
def reorder_risk_rules(
    payload: RiskRuleReorder,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    reorder_rules(db, payload.ordered_ids)
    return {"ok": True}


@router.post("/risk-rules/validate", response_model=RiskRuleValidateResponse)
def validate_risk_rule(
    payload: RiskRuleValidateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    ok, ast, error = validate_expression(payload.expression, db)
    suggested_category = None
    if ok and ast:
        suggested_category = derive_category(ast, 0)
    return RiskRuleValidateResponse(
        ok=ok, ast=ast, error=error, suggested_category=suggested_category
    )


@router.post("/risk-rules/seed-baseline", response_model=RiskSeedBaselineResponse)
def seed_baseline(
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Seed 4 baseline rulesets (default, human, api, mobile) + rules + seed lists.

    Idempotent: checks ruleset slugs, rule names, and list names before creating; skips existing.
    """
    created_rules, created_lists, created_rulesets, skipped = seed_baseline_rules(db)
    return RiskSeedBaselineResponse(
        created_rules=created_rules,
        created_lists=created_lists,
        created_rulesets=created_rulesets,
        skipped=skipped,
    )


@router.put("/risk-rules/{rid}", response_model=RiskRuleResponse)
def update_risk_rule(
    rid: int,
    r_in: RiskRuleUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(RiskRule, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="Risk rule not found")

    data = r_in.model_dump(exclude_unset=True)

    # Validate ruleset if changed
    ruleset_id = data.get("ruleset_id", obj.ruleset_id)
    if "ruleset_id" in data:
        ruleset = db.get(RiskRuleset, ruleset_id)
        if not ruleset:
            raise HTTPException(status_code=400, detail=f"Ruleset {ruleset_id} not found")

    # Re-parse expression if changed
    new_ast = obj.expression_ast
    if "expression" in data and data["expression"] is not None:
        ok, ast, error = validate_expression(data["expression"], db)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        data["expression_ast"] = ast
        new_ast = ast

    # Current points (for category derivation)
    new_points = data.get("points", obj.points)

    # Auto-derive category if expression changed and category not explicitly provided
    if "expression" in data and "category" not in data:
        data["category"] = derive_category(new_ast, new_points)
    elif "points" in data and "category" not in data:
        # Re-derive if points changed (negative → trust override)
        data["category"] = derive_category(new_ast, new_points)

    for k, v in data.items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/risk-rules/{rid}")
def delete_risk_rule(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(RiskRule, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="Risk rule not found")
    db.delete(obj)
    db.commit()
    return {"ok": True}
