"""Risk Rulesets REST API router.

Provides CRUD for risk rulesets. Each ruleset has its own independent
score variable (risk.<slug>.score), clamped to [0, 99] at runtime.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..deps import get_current_user, get_db, require_write, rate_limit
from ...models.models import RiskRule, RiskRuleset
from ...schemas.security_rules import (
    RiskRulesetCreate,
    RiskRulesetResponse,
    RiskRulesetUpdate,
)
from ...services.risk_scoring import (
    create_ruleset,
    delete_ruleset,
    slugify_ruleset_name,
    update_ruleset,
    validate_slug,
)

router = APIRouter()


def _ruleset_to_response(rs: RiskRuleset, db: Session) -> RiskRulesetResponse:
    """Build a RiskRulesetResponse with rule_count."""
    rule_count = db.query(RiskRule).filter(RiskRule.ruleset_id == rs.id).count()
    return RiskRulesetResponse(
        id=rs.id,
        name=rs.name,
        slug=rs.slug,
        description=rs.description,
        enabled=rs.enabled,
        priority=rs.priority,
        rule_count=rule_count,
        created_at=rs.created_at,
        updated_at=rs.updated_at,
    )


@router.get("/risk-rulesets", response_model=List[RiskRulesetResponse])
def list_rulesets(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    rulesets = db.query(RiskRuleset).order_by(RiskRuleset.priority).all()
    return [_ruleset_to_response(rs, db) for rs in rulesets]


@router.post("/risk-rulesets", response_model=RiskRulesetResponse)
def create_ruleset_endpoint(
    r: RiskRulesetCreate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    # Validate slug preview
    slug = slugify_ruleset_name(r.name)
    if not validate_slug(slug):
        raise HTTPException(
            status_code=400,
            detail=f"Ruleset name '{r.name}' produces invalid slug '{slug}'. Use a name with alphanumeric characters.",
        )
    rs = create_ruleset(
        db,
        name=r.name,
        description=r.description,
    )
    return _ruleset_to_response(rs, db)


@router.put("/risk-rulesets/{rsid}", response_model=RiskRulesetResponse)
def update_ruleset_endpoint(
    rsid: int,
    r_in: RiskRulesetUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    try:
        rs = update_ruleset(
            db,
            ruleset_id=rsid,
            name=r_in.name,
            description=r_in.description,
            enabled=r_in.enabled,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _ruleset_to_response(rs, db)


@router.delete("/risk-rulesets/{rsid}")
def delete_ruleset_endpoint(
    rsid: int,
    force: bool = False,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    try:
        delete_ruleset(db, ruleset_id=rsid, force=force)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}
