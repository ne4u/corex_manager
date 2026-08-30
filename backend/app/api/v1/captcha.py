"""CAPTCHA configuration, stats, and Cap admin API proxy endpoints."""
import asyncio
import base64
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ..deps import get_current_user, get_db, rate_limit, require_write
from ...models.waf import ChallengeEvent
from ...services.settings import get_setting, set_setting

router = APIRouter()
settings = get_settings()
logger = logging.getLogger(__name__)

# Retention window for challenge event stats (days). All stats endpoints
# clamp their queries to this window and the table is pruned on startup.
_RETENTION_DAYS = settings.CAPTCHA_CHALLENGE_RETENTION_DAYS


def prune_challenge_events(db: Session) -> int:
    """Delete challenge events older than the retention window.

    Called on startup to keep the ``challenge_events`` table bounded.
    Returns the number of rows deleted.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)).replace(tzinfo=None)
    result = db.query(ChallengeEvent).filter(ChallengeEvent.created_at < cutoff).delete()
    db.commit()
    return result


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CaptchaSettings(BaseModel):
    captcha_provider: str = "cap"  # "cap", "recaptcha", "turnstile"
    captcha_valid_seconds: int = Field(default=3600, ge=0)
    # Cap (labeled "Native" in the UI — the built-in provider)
    cap_site_key: Optional[str] = None
    cap_secret_configured: bool = False
    cap_service_url: str = ""
    cap_widget_cdn_url: str = ""
    # reCAPTCHA
    recaptcha_site_key: Optional[str] = None
    recaptcha_secret_configured: bool = False
    recaptcha_version: str = "v2"
    recaptcha_min_score: float = 0.5
    # Turnstile
    turnstile_site_key: Optional[str] = None
    turnstile_secret_configured: bool = False
    # Shared
    challenge_url: str = ""
    proxy_path: str = ""


class CaptchaSettingsUpdate(BaseModel):
    captcha_provider: Optional[str] = None
    captcha_valid_seconds: Optional[int] = Field(default=None, ge=0)
    # Cap (Native)
    cap_site_key: Optional[str] = None
    cap_secret: Optional[str] = None  # write-only
    # reCAPTCHA
    recaptcha_site_key: Optional[str] = None
    recaptcha_secret: Optional[str] = None  # write-only
    recaptcha_version: Optional[str] = None
    recaptcha_min_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Turnstile
    turnstile_site_key: Optional[str] = None
    turnstile_secret: Optional[str] = None  # write-only


class CapKeyCreate(BaseModel):
    name: Optional[str] = None
    instrumentation: Optional[bool] = None
    blockAutomatedBrowsers: Optional[bool] = None
    corsOrigins: Optional[List[str]] = None
    rsw: Optional[bool] = None
    rswT: Optional[int] = Field(default=None, ge=10000, le=300000)


class CapKeyConfigUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=600)
    difficulty: Optional[int] = Field(default=None, ge=1, le=8)
    challengeCount: Optional[int] = Field(default=None, ge=1, le=500)
    instrumentation: Optional[bool] = None
    obfuscationLevel: Optional[int] = Field(default=None, ge=1, le=10)
    blockAutomatedBrowsers: Optional[bool] = None
    ratelimitMax: Optional[int] = Field(default=None, ge=1, le=10000)
    ratelimitDuration: Optional[int] = Field(default=None, ge=1000, le=3600000)
    corsOrigins: Optional[Any] = None
    blockNonBrowserUA: Optional[bool] = None
    requiredHeaders: Optional[List[str]] = None
    rsw: Optional[bool] = None
    rswT: Optional[int] = Field(default=None, ge=10000, le=300000)


class ChallengeStatRow(BaseModel):
    rule_type: str
    rule_id: Optional[int] = None
    rule_name: Optional[str] = None
    issued: int = 0
    solved: int = 0
    failed: int = 0
    solve_rate: float = 0.0


class ChallengeTimeSeriesPoint(BaseModel):
    bucket: int
    issued: int = 0
    solved: int = 0
    failed: int = 0


class ChallengeEventRow(BaseModel):
    id: int
    created_at: str
    rule_type: str
    rule_id: Optional[int] = None
    rule_name: Optional[str] = None
    event_type: str
    request_id: Optional[str] = None
    client_ip: Optional[str] = None


# ---------------------------------------------------------------------------
# Cap session management
# ---------------------------------------------------------------------------

_cap_session_cache: Dict[str, Any] = {}


async def _get_cap_session() -> str:
    """Login to the Cap service with ADMIN_KEY and cache the bearer value.

    Cap's protected endpoints expect an ``Authorization: Bearer <X>`` header
    where ``<X>`` is base64(JSON({"token": <session_token>, "hash":
    <hashed_token>})). The login response returns both ``session_token`` and
    ``hashed_token``; we build the envelope here and cache the full bearer
    string so callers can use it directly.
    """
    global _cap_session_cache
    admin_key = settings.CAPTCHA_ADMIN_KEY if hasattr(settings, "CAPTCHA_ADMIN_KEY") else None
    # Fallback: check env for CAP_ADMIN_KEY
    if not admin_key:
        import os
        admin_key = os.environ.get("CAP_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(status_code=503, detail="CAP_ADMIN_KEY not configured")
    # Check cache
    cached = _cap_session_cache.get("token")
    cached_expires = _cap_session_cache.get("expires", 0)
    if cached and datetime.now(timezone.utc).timestamp() < cached_expires - 60:
        return cached
    # Login
    base_url = settings.CAPTCHA_SERVICE_URL.rstrip("/")
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{base_url}/auth/login",
            json={"admin_key": admin_key},
            timeout=10,
        )
    if res.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Cap auth failed: {res.status_code}")
    data = res.json()
    session_token = data.get("session_token") or data.get("token")
    hashed_token = data.get("hashed_token") or data.get("hash")
    if not session_token or not hashed_token:
        raise HTTPException(status_code=502, detail="Cap auth returned no session token")
    # Cap expects Bearer base64(JSON({"token": ..., "hash": ...}))
    envelope = json.dumps({"token": session_token, "hash": hashed_token})
    bearer_value = base64.b64encode(envelope.encode()).decode()
    # Cache for 29 days (Cap sessions last 30 days)
    _cap_session_cache["token"] = bearer_value
    _cap_session_cache["expires"] = (datetime.now(timezone.utc) + timedelta(days=29)).timestamp()
    return bearer_value


async def _cap_api_call(method: str, path: str, json_body: Any = None) -> Any:
    """Make an authenticated API call to the Cap service."""
    token = await _get_cap_session()
    base_url = settings.CAPTCHA_SERVICE_URL.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        res = await client.request(
            method,
            f"{base_url}{path}",
            json=json_body,
            headers=headers,
            timeout=15,
        )
    if res.status_code == 401:
        # Session expired — clear cache and retry once
        global _cap_session_cache
        _cap_session_cache.clear()
        token = await _get_cap_session()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            res = await client.request(
                method,
                f"{base_url}{path}",
                json=json_body,
                headers=headers,
                timeout=15,
            )
    return res


def _cap_error(status_code: int, detail: str) -> HTTPException:
    """Map an upstream Cap service error to an HTTPException.

    Upstream auth failures (401/403) are rewritten to 502 Bad Gateway so the
    frontend's global 401 interceptor (which logs the user out) is not
    triggered. A 401/403 here means the Cap service rejected our admin session,
    not that the coreX Manager user's session is invalid.
    """
    if status_code in (401, 403):
        return HTTPException(
            status_code=502,
            detail=f"Cap service auth failed ({status_code}): {detail}",
        )
    return HTTPException(status_code=status_code, detail=detail)


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------

def _build_captcha_settings(db: Session) -> CaptchaSettings:
    """Build a CaptchaSettings response from DB settings + env fallbacks."""
    provider = get_setting(db, "captcha_provider", "cap") or "cap"
    ttl = int(get_setting(db, "captcha_valid_seconds", "3600") or 3600)
    # Cap (Native)
    cap_site_key = get_setting(db, "cap_site_key") or settings.CAPTCHA_SITE_KEY
    cap_secret = get_setting(db, "cap_secret") or settings.CAPTCHA_SECRET
    # reCAPTCHA
    recaptcha_site_key = get_setting(db, "recaptcha_site_key") or settings.RECAPTCHA_SITE_KEY
    recaptcha_secret = get_setting(db, "recaptcha_secret") or settings.RECAPTCHA_SECRET
    recaptcha_version = get_setting(db, "recaptcha_version") or settings.RECAPTCHA_VERSION or "v2"
    recaptcha_min_score = float(get_setting(db, "recaptcha_min_score") or settings.RECAPTCHA_MIN_SCORE or 0.5)
    # Turnstile
    turnstile_site_key = get_setting(db, "turnstile_site_key") or settings.TURNSTILE_SITE_KEY
    turnstile_secret = get_setting(db, "turnstile_secret") or settings.TURNSTILE_SECRET
    return CaptchaSettings(
        captcha_provider=provider,
        captcha_valid_seconds=ttl,
        cap_site_key=cap_site_key,
        cap_secret_configured=bool(cap_secret),
        cap_service_url=settings.CAPTCHA_SERVICE_URL,
        cap_widget_cdn_url=settings.CAPTCHA_WIDGET_CDN_URL,
        recaptcha_site_key=recaptcha_site_key,
        recaptcha_secret_configured=bool(recaptcha_secret),
        recaptcha_version=recaptcha_version,
        recaptcha_min_score=recaptcha_min_score,
        turnstile_site_key=turnstile_site_key,
        turnstile_secret_configured=bool(turnstile_secret),
        challenge_url=settings.CAPTCHA_CHALLENGE_URL,
        proxy_path=settings.CAPTCHA_PROXY_PATH,
    )


@router.get("/captcha/settings", response_model=CaptchaSettings)
def get_captcha_settings_route(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    return _build_captcha_settings(db)


@router.put("/captcha/settings", response_model=CaptchaSettings)
def update_captcha_settings_route(
    s_in: CaptchaSettingsUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    if s_in.captcha_provider is not None:
        if s_in.captcha_provider not in ("cap", "recaptcha", "turnstile"):
            raise HTTPException(status_code=400, detail="Invalid captcha_provider")
        set_setting(db, "captcha_provider", s_in.captcha_provider)
    if s_in.captcha_valid_seconds is not None:
        set_setting(db, "captcha_valid_seconds", str(s_in.captcha_valid_seconds))
    # Cap (Native)
    if s_in.cap_site_key is not None:
        set_setting(db, "cap_site_key", s_in.cap_site_key)
    if s_in.cap_secret is not None:
        set_setting(db, "cap_secret", s_in.cap_secret)
    # reCAPTCHA
    if s_in.recaptcha_site_key is not None:
        set_setting(db, "recaptcha_site_key", s_in.recaptcha_site_key)
    if s_in.recaptcha_secret is not None:
        set_setting(db, "recaptcha_secret", s_in.recaptcha_secret)
    if s_in.recaptcha_version is not None:
        set_setting(db, "recaptcha_version", s_in.recaptcha_version)
    if s_in.recaptcha_min_score is not None:
        set_setting(db, "recaptcha_min_score", str(s_in.recaptcha_min_score))
    # Turnstile
    if s_in.turnstile_site_key is not None:
        set_setting(db, "turnstile_site_key", s_in.turnstile_site_key)
    if s_in.turnstile_secret is not None:
        set_setting(db, "turnstile_secret", s_in.turnstile_secret)
    return _build_captcha_settings(db)


# ---------------------------------------------------------------------------
# Challenge event stats endpoints
# ---------------------------------------------------------------------------

@router.get("/captcha/stats", response_model=List[ChallengeStatRow])
def get_challenge_stats_route(
    from_ts: Optional[int] = Query(None),
    to_ts: Optional[int] = Query(None),
    rule_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Aggregated challenge stats per rule (last 7 days max)."""
    # Clamp to retention window — stats are only kept for _RETENTION_DAYS.
    retention_start = (datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)).replace(tzinfo=None)
    q = db.query(
        ChallengeEvent.rule_type,
        ChallengeEvent.rule_id,
        ChallengeEvent.rule_name,
        ChallengeEvent.event_type,
        func.count().label("cnt"),
    )
    effective_from = datetime.fromtimestamp(from_ts, tz=timezone.utc).replace(tzinfo=None) if from_ts else retention_start
    if effective_from < retention_start:
        effective_from = retention_start
    q = q.filter(ChallengeEvent.created_at >= effective_from)
    if to_ts:
        q = q.filter(ChallengeEvent.created_at <= datetime.fromtimestamp(to_ts, tz=timezone.utc).replace(tzinfo=None))
    if rule_type:
        q = q.filter(ChallengeEvent.rule_type == rule_type)
    q = q.group_by(ChallengeEvent.rule_type, ChallengeEvent.rule_id, ChallengeEvent.rule_name, ChallengeEvent.event_type)
    rows = q.all()
    # Aggregate into per-rule rows
    agg: Dict[tuple, Dict[str, int]] = {}
    for r in rows:
        key = (r.rule_type, r.rule_id, r.rule_name)
        if key not in agg:
            agg[key] = {"issued": 0, "solved": 0, "failed": 0}
        agg[key][r.event_type] = r.cnt
    result = []
    for (rt, rid, rname), counts in agg.items():
        issued = counts["issued"]
        solved = counts["solved"]
        solve_rate = (solved / issued * 100) if issued > 0 else 0.0
        result.append(ChallengeStatRow(
            rule_type=rt,
            rule_id=rid,
            rule_name=rname,
            issued=issued,
            solved=solved,
            failed=counts["failed"],
            solve_rate=round(solve_rate, 1),
        ))
    return result


@router.get("/captcha/stats/{rule_type}/{rule_id}", response_model=List[ChallengeTimeSeriesPoint])
def get_challenge_timeseries_route(
    rule_type: str,
    rule_id: int,
    hours: int = Query(24, ge=1, le=168),  # capped at 7 days (retention window)
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Time series of challenge events for a specific rule (hourly buckets)."""
    start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    q = db.query(
        ChallengeEvent.event_type,
        ChallengeEvent.created_at,
    ).filter(
        ChallengeEvent.rule_type == rule_type,
        ChallengeEvent.rule_id == rule_id,
        ChallengeEvent.created_at >= start,
    )
    rows = q.all()
    # Bucket into hours
    buckets: Dict[int, Dict[str, int]] = {}
    for r in rows:
        bucket = int(r.created_at.replace(minute=0, second=0, microsecond=0).timestamp())
        if bucket not in buckets:
            buckets[bucket] = {"issued": 0, "solved": 0, "failed": 0}
        buckets[bucket][r.event_type] += 1
    # Fill in empty buckets
    now_hour = int(datetime.now(timezone.utc).replace(tzinfo=None, minute=0, second=0, microsecond=0).timestamp())
    result = []
    for i in range(hours):
        b = now_hour - (hours - 1 - i) * 3600
        counts = buckets.get(b, {"issued": 0, "solved": 0, "failed": 0})
        result.append(ChallengeTimeSeriesPoint(
            bucket=b,
            issued=counts["issued"],
            solved=counts["solved"],
            failed=counts["failed"],
        ))
    return result


@router.get("/captcha/events", response_model=List[ChallengeEventRow])
def get_challenge_events_route(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    rule_type: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List recent challenge events with request IDs for correlation (last 7 days)."""
    retention_start = (datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)).replace(tzinfo=None)
    q = db.query(ChallengeEvent).filter(ChallengeEvent.created_at >= retention_start)
    if rule_type:
        q = q.filter(ChallengeEvent.rule_type == rule_type)
    if event_type:
        q = q.filter(ChallengeEvent.event_type == event_type)
    if request_id:
        q = q.filter(ChallengeEvent.request_id == request_id)
    q = q.order_by(ChallengeEvent.created_at.desc()).limit(limit).offset(offset)
    rows = q.all()
    return [
        ChallengeEventRow(
            id=r.id,
            created_at=r.created_at.isoformat() if r.created_at else "",
            rule_type=r.rule_type,
            rule_id=r.rule_id,
            rule_name=r.rule_name,
            event_type=r.event_type,
            request_id=r.request_id,
            client_ip=r.client_ip,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Cap admin API proxy endpoints
# ---------------------------------------------------------------------------

@router.get("/captcha/keys")
async def list_cap_keys(
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List all Cap site keys."""
    try:
        res = await _cap_api_call("GET", "/server/keys")
        if res.status_code != 200:
            raise _cap_error(res.status_code, res.text)
        return res.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cap service unreachable: {e}")


@router.post("/captcha/keys")
async def create_cap_key(
    body: CapKeyCreate,
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Create a new Cap site key."""
    try:
        res = await _cap_api_call("POST", "/server/keys", json_body=body.model_dump(exclude_none=True))
        if res.status_code != 200:
            raise _cap_error(res.status_code, res.text)
        return res.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cap service unreachable: {e}")


@router.get("/captcha/keys/{site_key}")
async def get_cap_key(
    site_key: str,
    chart_duration: str = Query("today"),
    user=Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get Cap key details and stats."""
    try:
        res = await _cap_api_call("GET", f"/server/keys/{site_key}?chartDuration={chart_duration}")
        if res.status_code != 200:
            raise _cap_error(res.status_code, res.text)
        return res.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cap service unreachable: {e}")


@router.put("/captcha/keys/{site_key}/config")
async def update_cap_key_config(
    site_key: str,
    body: CapKeyConfigUpdate,
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Update Cap key configuration."""
    try:
        res = await _cap_api_call("PUT", f"/server/keys/{site_key}/config", json_body=body.model_dump(exclude_none=True))
        if res.status_code != 200:
            raise _cap_error(res.status_code, res.text)
        return res.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cap service unreachable: {e}")


@router.delete("/captcha/keys/{site_key}")
async def delete_cap_key(
    site_key: str,
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Delete a Cap site key."""
    try:
        res = await _cap_api_call("DELETE", f"/server/keys/{site_key}")
        if res.status_code != 200:
            raise _cap_error(res.status_code, res.text)
        return res.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cap service unreachable: {e}")


@router.post("/captcha/keys/{site_key}/rotate-secret")
async def rotate_cap_key_secret(
    site_key: str,
    user=Depends(require_write),
    _=Depends(rate_limit),
):
    """Rotate the secret key for a Cap site key. Returns the new secret once."""
    try:
        res = await _cap_api_call("POST", f"/server/keys/{site_key}/rotate-secret")
        if res.status_code != 200:
            raise _cap_error(res.status_code, res.text)
        return res.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cap service unreachable: {e}")
