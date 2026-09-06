"""High Availability (HA) API routes.

Provides endpoints for viewing/updating HA configuration and monitoring
the health of all HA instances (HAProxy, Valkey, Coraza).
"""
from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..deps import get_current_user, get_db, require_admin, rate_limit
from ...schemas.ha import (
    HaConfigResponse,
    HaConfigUpdate,
    HaHealthSummary,
    HaApplyResponse,
)
from ...services import ha as ha_service
from ...core.valkey_client import cache_get, cache_set

router = APIRouter(prefix="/ha", tags=["ha"])


@router.get("/config", response_model=HaConfigResponse)
def get_ha_config(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Return the current HA configuration.

    Available to any authenticated user. Includes HA enabled state, topology,
    replica counts, HAProxy instance inventory, keepalived settings, and
    Valkey Sentinel settings.
    """
    return ha_service.get_ha_config(db)


@router.put("/config", response_model=HaConfigResponse)
def update_ha_config(
    update: HaConfigUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Update HA configuration (admin only).

    Accepts a partial update — only the provided fields are written to the
    DB settings table. After updating, regenerates keepalived configs and
    returns the new full config.
    """
    ha_service.update_ha_config(db, update.model_dump(exclude_unset=True))
    # Regenerate keepalived configs with the new settings
    ha_service.write_keepalived_configs(db)
    return ha_service.get_ha_config(db)


@router.get("/health", response_model=HaHealthSummary)
def get_ha_health(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Return aggregated health across all HA instances.

    Available to any authenticated user. Cached in Valkey for 5 seconds
    (key ``ha:health``) to avoid hammering the Data Plane API on rapid
    auto-refresh polls.
    """
    cached = cache_get("ha:health")
    if cached is not None:
        return cached
    result = ha_service.get_ha_health(db)
    cache_set("ha:health", result, ttl=5)
    return result


@router.post("/apply", response_model=HaApplyResponse)
def apply_ha_config(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _=Depends(rate_limit),
):
    """Push the current configuration to all HAProxy instances (admin only).

    Triggers ``write_config`` which generates the config, validates it,
    writes files to disk, and pushes to every instance's Data Plane API.
    Returns per-instance push results.
    """
    from ...services.haproxy import write_config
    try:
        config = write_config(db, created_by=getattr(user, "username", None))
        # write_config already pushed to all instances; collect results
        from ...services import ha as _ha
        push_results = _ha.push_config_to_all_instances(db, config)
        return HaApplyResponse(
            status="ok",
            results=push_results,
        )
    except Exception as e:
        return HaApplyResponse(
            status="error",
            error=str(e),
        )
