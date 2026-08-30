from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_current_user, get_db, require_write, rate_limit
from ...models.models import SecurityRule
from ...schemas.security_rules import (
    SecurityRuleCreate,
    SecurityRuleReorder,
    SecurityRuleResponse,
    SecurityRuleUpdate,
    SecurityRuleValidateRequest,
    SecurityRuleValidateResponse,
)
from ...services.security_rules import parse_expression, reorder_rules, translate, validate_expression

router = APIRouter()


@router.get("/security-rules", response_model=List[SecurityRuleResponse])
def list_security_rules(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return db.query(SecurityRule).order_by(SecurityRule.priority).all()


@router.post("/security-rules", response_model=SecurityRuleResponse)
def create_security_rule(
    r: SecurityRuleCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    try:
        ast = parse_expression(r.expression)
        translate(ast, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    max_priority = db.query(SecurityRule).order_by(SecurityRule.priority.desc()).first()
    priority = (max_priority.priority + 1) if max_priority else 0
    obj = SecurityRule(**r.model_dump(), priority=priority, expression_ast=ast)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/security-rules/reorder")
def reorder_security_rules(
    payload: SecurityRuleReorder,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    reorder_rules(db, payload.ordered_ids)
    return {"ok": True}


@router.post("/security-rules/validate", response_model=SecurityRuleValidateResponse)
def validate_security_rule(
    payload: SecurityRuleValidateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    ok, ast, error = validate_expression(payload.expression, db)
    return SecurityRuleValidateResponse(ok=ok, ast=ast, error=error)


@router.put("/security-rules/{rid}", response_model=SecurityRuleResponse)
def update_security_rule(
    rid: int,
    r_in: SecurityRuleUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(SecurityRule, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="Security rule not found")
    data = r_in.model_dump(exclude_unset=True)
    if "expression" in data and data["expression"] is not None:
        try:
            ast = parse_expression(data["expression"])
            translate(ast, db)
            data["expression_ast"] = ast
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    for k, v in data.items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/security-rules/{rid}")
def delete_security_rule(
    rid: int,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(SecurityRule, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="Security rule not found")
    db.delete(obj)
    db.commit()
    return {"ok": True}
