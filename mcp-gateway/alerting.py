"""Alerting for MCP Gateway — threshold-based security event alerts.

Monitors security events (guardrail hits, DLP blocks, policy denials, auth
failures) and triggers alerts when thresholds are exceeded.

Alert delivery:
- Webhook (MCP_ALERT_WEBHOOK_URL env var)
- Log (always)

Thresholds are configurable via env vars with sane defaults.
"""
import json
import logging
import os
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_WEBHOOK_URL = os.environ.get("MCP_ALERT_WEBHOOK_URL", "")
_WEBHOOK_TIMEOUT = int(os.environ.get("MCP_ALERT_WEBHOOK_TIMEOUT", "5"))

# Thresholds: max events per window before alerting
_ALERT_THRESHOLDS = {
    "guardrail_blocked": int(os.environ.get("MCP_ALERT_GUARDRAIL_THRESHOLD", "10")),
    "dlp_blocked": int(os.environ.get("MCP_ALERT_DLP_THRESHOLD", "10")),
    "policy_denied": int(os.environ.get("MCP_ALERT_POLICY_DENY_THRESHOLD", "20")),
    "auth_failed": int(os.environ.get("MCP_ALERT_AUTH_FAIL_THRESHOLD", "10")),
    "rate_limited": int(os.environ.get("MCP_ALERT_RATELIMIT_THRESHOLD", "50")),
}
_ALERT_WINDOW = int(os.environ.get("MCP_ALERT_WINDOW_SECONDS", "60"))

# In-memory counters (per gateway instance)
_counters: dict[str, list[float]] = {}
_last_alert: dict[str, float] = {}
_ALERT_COOLDOWN = int(os.environ.get("MCP_ALERT_COOLDOWN_SECONDS", "300"))


def record_event(event_type: str) -> None:
    """Record a security event and check if alert threshold is exceeded."""
    threshold = _ALERT_THRESHOLDS.get(event_type, 0)
    if threshold <= 0:
        return

    now = time.time()
    cutoff = now - _ALERT_WINDOW

    timestamps = _counters.get(event_type, [])
    timestamps = [t for t in timestamps if t > cutoff]
    timestamps.append(now)
    _counters[event_type] = timestamps

    if len(timestamps) >= threshold:
        last = _last_alert.get(event_type, 0)
        if now - last > _ALERT_COOLDOWN:
            _send_alert(event_type, len(timestamps), threshold)
            _last_alert[event_type] = now


def _send_alert(event_type: str, count: int, threshold: int) -> None:
    """Send an alert via webhook and log."""
    message = (
        f"MCP Gateway Alert: {event_type} threshold exceeded — "
        f"{count} events in {_ALERT_WINDOW}s (threshold: {threshold})"
    )
    logger.warning(message)

    if not _WEBHOOK_URL:
        return

    payload = {
        "text": message,
        "event_type": event_type,
        "count": count,
        "threshold": threshold,
        "window_seconds": _ALERT_WINDOW,
        "timestamp": time.time(),
    }

    try:
        import asyncio
        loop = asyncio.get_running_loop()
        loop.create_task(_send_webhook(payload))
    except Exception as e:
        logger.warning("Failed to send alert webhook: %s", e)


async def _send_webhook(payload: dict) -> None:
    """Send alert payload to webhook URL."""
    try:
        async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT) as client:
            await client.post(_WEBHOOK_URL, json=payload)
    except Exception as e:
        logger.warning("Alert webhook delivery failed: %s", e)
