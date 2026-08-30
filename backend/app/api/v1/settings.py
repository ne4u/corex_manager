import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..deps import get_db, require_admin, rate_limit
from ...models.models import Setting, NetworkList
from ...models.security import SecurityRule
from ...schemas.settings import SettingCreate, SettingResponse
from ...services.security_rules import rules_referencing_ja4
from ...services.settings import get_setting, list_settings, set_setting

router = APIRouter()


@router.get("/settings", response_model=List[SettingResponse])
def list_settings_endpoint(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    return list_settings(db)


@router.get("/settings/{key}", response_model=SettingResponse)
def get_setting_endpoint(
    key: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    value = get_setting(db, key)
    row = db.query(Setting).filter(Setting.key == key).first()
    if not row:
        row = Setting(key=key, value=value)
    return row


@router.put("/settings/{key}", response_model=SettingResponse)
def update_setting_endpoint(
    key: str,
    s_in: SettingCreate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    if key == "session_timeout_minutes":
        try:
            val = int(s_in.value)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be an integer")
        if val <= 4 or val >= 1441:
            raise HTTPException(status_code=400, detail="session_timeout_minutes must be between 5 and 1440")
    if key == "session_warning_seconds":
        try:
            val = int(s_in.value)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="session_warning_seconds must be an integer")
        if val <= 4 or val >= 121:
            raise HTTPException(status_code=400, detail="session_warning_seconds must be between 5 and 120")

    if key == "ja4_enabled":
        enabling = (s_in.value or "").lower() in ("true", "1", "yes")
        if enabling:
            stored = get_setting(db, "ja4_auto_disabled_rule_ids", "[]") or "[]"
            try:
                ids = json.loads(stored) if isinstance(stored, str) else []
            except (json.JSONDecodeError, TypeError):
                ids = []
            for rid in ids:
                rule = db.get(SecurityRule, rid)
                if rule:
                    rule.enabled = True
            # Re-enable risk rules that were auto-disabled when ja4 was turned off.
            risk_stored = get_setting(db, "ja4_risk_auto_disabled_rule_ids", "[]") or "[]"
            try:
                risk_ids = json.loads(risk_stored) if isinstance(risk_stored, str) else []
            except (json.JSONDecodeError, TypeError):
                risk_ids = []
            from ...models.models import RiskRule
            for rid in risk_ids:
                rule = db.get(RiskRule, rid)
                if rule:
                    rule.enabled = True
            set_setting(db, "ja4_risk_auto_disabled_rule_ids", "[]")
            set_setting(db, "ja4_auto_disabled_rule_ids", "[]")
            db.commit()
        else:
            rules = rules_referencing_ja4(db)
            ids = []
            for rule in rules:
                rule.enabled = False
                ids.append(rule.id)
            set_setting(db, "ja4_auto_disabled_rule_ids", json.dumps(ids))
            # Also auto-disable risk rules referencing JA4-derived fields.
            from ...services.risk_scoring import rules_referencing_ja4_fields
            risk_rules = rules_referencing_ja4_fields(db)
            risk_ids = []
            for rule in risk_rules:
                rule.enabled = False
                risk_ids.append(rule.id)
            set_setting(db, "ja4_risk_auto_disabled_rule_ids", json.dumps(risk_ids))
            db.commit()

    if key == "req_fp_enabled":
        enabling = (s_in.value or "").lower() in ("true", "1", "yes")
        if not enabling:
            # API Armor depends on req_fp subfields at runtime. Reject
            # disabling req_fp while API Armor is enabled.
            from ...core.config import get_settings
            _settings = get_settings()
            api_armor_on = get_setting(db, "api_armor_enabled", str(_settings.API_ARMOR_ENABLED)).lower() in ("true", "1", "yes")
            if api_armor_on:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot disable HTTP Request Fingerprinting while API Armor is enabled. "
                           "Disable API Armor first.",
                )
            # Auto-disable risk rules that reference txn.risk_fp.* / req_fp-derived fields.
            from ...services.risk_scoring import rules_referencing_req_fp
            risk_rules = rules_referencing_req_fp(db)
            risk_ids = []
            for rule in risk_rules:
                rule.enabled = False
                risk_ids.append(rule.id)
            set_setting(db, "risk_auto_disabled_rule_ids", json.dumps(risk_ids))
            db.commit()
        else:
            # Re-enable risk rules that were auto-disabled when req_fp was turned off.
            stored = get_setting(db, "risk_auto_disabled_rule_ids", "[]") or "[]"
            try:
                risk_ids = json.loads(stored) if isinstance(stored, str) else []
            except (json.JSONDecodeError, TypeError):
                risk_ids = []
            from ...models.models import RiskRule
            for rid in risk_ids:
                rule = db.get(RiskRule, rid)
                if rule:
                    rule.enabled = True
            set_setting(db, "risk_auto_disabled_rule_ids", "[]")
            db.commit()

    if key == "restore_client_ip_trusted_network_list":
        # Empty value clears the setting (restore becomes ungated).
        # Multiple list names are stored as a comma-separated string.
        val = (s_in.value or "").strip()
        if val:
            names = [n.strip() for n in val.split(",") if n.strip()]
            for n in names:
                if not db.query(NetworkList).filter(NetworkList.name == n).first():
                    raise HTTPException(
                        status_code=400,
                        detail=f"trusted network list not found: {n}",
                    )

    return set_setting(db, key, s_in.value)
