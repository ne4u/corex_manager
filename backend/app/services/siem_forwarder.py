"""SIEM forwarder for WAF events.

A background thread polls the WafMetric table for new events (by ID watermark)
and forwards them to configured SIEM integrations. Only SIEM integrations that
are referenced by at least one enabled WafRule (via siem_integration_id) receive
events. If a WafRule has no siem_integration_id, its events are not forwarded.
"""
import json
import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

import httpx
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.database import SessionLocal
from ..models.models import WafMetric, WafRule, WafSiemIntegration

logger = logging.getLogger(__name__)
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_event(integration: WafSiemIntegration, metric: WafMetric) -> str:
    """Format a WafMetric event per the integration's format setting."""
    fmt = integration.format or "json"
    ts = metric.captured_at.isoformat() if metric.captured_at else _utcnow().isoformat()

    if fmt == "json":
        payload = {
            "action": metric.action,
            "rule_id": metric.rule_id,
            "severity": metric.severity,
            "msg": metric.msg,
            "client": metric.client,
            "country": metric.country,
            "uri": metric.uri,
            "timestamp": ts,
        }
        return json.dumps(payload)

    if fmt == "syslog":
        # RFC 5424: <priority>version timestamp hostname app-name procid msgid - message
        payload = {
            "action": metric.action,
            "rule_id": metric.rule_id,
            "severity": metric.severity,
            "msg": metric.msg,
            "client": metric.client,
            "country": metric.country,
            "uri": metric.uri,
            "timestamp": ts,
        }
        hostname = socket.gethostname()
        return f"<134>1 {ts} {hostname} coraza-spoa {metric.id} - - {json.dumps(payload)}"

    if fmt == "cef":
        # CEF: Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
        severity_map = {"CRITICAL": 10, "ERROR": 8, "WARNING": 6, "NOTICE": 4, "INFO": 2}
        sev_num = severity_map.get((metric.severity or "").upper(), 6)
        extension = f"src={metric.client or ''} request={metric.uri or ''} act={metric.action or ''}"
        return (
            f"CEF:0|HAProxyManager|CorazaWAF|1.0|{metric.rule_id or 'unknown'}|"
            f"{metric.msg or 'WAF event'}|{sev_num}|{extension}"
        )

    # Fallback to JSON
    payload = {
        "action": metric.action,
        "rule_id": metric.rule_id,
        "severity": metric.severity,
        "msg": metric.msg,
        "client": metric.client,
        "country": metric.country,
        "uri": metric.uri,
        "timestamp": ts,
    }
    return json.dumps(payload)


def _send_webhook(integration: WafSiemIntegration, payload: str) -> bool:
    """Send event to a webhook endpoint via HTTP POST."""
    try:
        headers = {"Content-Type": "application/json"}
        if integration.auth_header:
            headers["Authorization"] = integration.auth_header
        with httpx.Client(timeout=10) as client:
            resp = client.post(integration.target, content=payload, headers=headers)
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("Webhook send to '%s' failed: %s", integration.target, exc)
        return False


def _send_syslog(integration: WafSiemIntegration, message: str) -> bool:
    """Send event to a syslog endpoint via UDP."""
    try:
        # Parse host:port from target
        target = integration.target
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target
            port = 514
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode("utf-8"), (host, port))
        finally:
            sock.close()
        return True
    except Exception as exc:
        logger.warning("Syslog send to '%s' failed: %s", integration.target, exc)
        return False


def _send_elastic(integration: WafSiemIntegration, payload: str) -> bool:
    """Send event to an Elasticsearch endpoint via HTTP POST."""
    try:
        headers = {"Content-Type": "application/json"}
        if integration.auth_header:
            headers["Authorization"] = integration.auth_header
        with httpx.Client(timeout=10) as client:
            resp = client.post(integration.target, content=payload, headers=headers)
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("Elastic send to '%s' failed: %s", integration.target, exc)
        return False


def _send_event(integration: WafSiemIntegration, metric: WafMetric) -> bool:
    """Format and send a single event to a single integration."""
    formatted = _format_event(integration, metric)
    itype = integration.integration_type or "webhook"
    if itype == "webhook":
        return _send_webhook(integration, formatted)
    elif itype == "syslog":
        return _send_syslog(integration, formatted)
    elif itype == "elastic":
        return _send_elastic(integration, formatted)
    logger.warning("Unknown integration type '%s' for SIEM '%s'", itype, integration.name)
    return False


class SiemForwarder:
    """Background thread that forwards WafMetric events to SIEM integrations."""

    def __init__(self, poll_interval_seconds: Optional[int] = None, batch_size: Optional[int] = None):
        self.poll_interval_seconds = (
            poll_interval_seconds
            if poll_interval_seconds is not None
            else settings.SIEM_FORWARDER_POLL_INTERVAL_SECONDS
        )
        self.batch_size = (
            batch_size
            if batch_size is not None
            else settings.SIEM_FORWARDER_BATCH_SIZE
        )
        self._last_id = 0
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)

    def _run(self):
        while not self._stop_event.wait(self.poll_interval_seconds):
            self._tick()

    def _tick(self):
        try:
            with SessionLocal() as db:
                self._forward_events(db)
        except Exception as exc:
            logger.exception("SIEM forwarder tick failed: %s", exc)

    def _forward_events(self, db: Session):
        # Find SIEM integrations referenced by enabled WafRules
        referenced_ids: Set[int] = set(
            rid[0]
            for rid in db.query(WafRule.siem_integration_id)
            .filter(
                WafRule.enabled == True,  # noqa: E712
                WafRule.siem_integration_id.isnot(None),
            )
            .distinct()
            .all()
        )
        if not referenced_ids:
            # No rules reference any SIEM — just advance the watermark
            latest = db.query(WafMetric).order_by(WafMetric.id.desc()).first()
            if latest:
                self._last_id = latest.id
            return

        integrations: Dict[int, WafSiemIntegration] = {
            s.id: s
            for s in db.query(WafSiemIntegration)
            .filter(
                WafSiemIntegration.id.in_(referenced_ids),
                WafSiemIntegration.enabled == True,  # noqa: E712
            )
            .all()
        }
        if not integrations:
            # Referenced integrations are all disabled — advance watermark
            latest = db.query(WafMetric).order_by(WafMetric.id.desc()).first()
            if latest:
                self._last_id = latest.id
            return

        # Fetch new events
        metrics: List[WafMetric] = (
            db.query(WafMetric)
            .filter(WafMetric.id > self._last_id)
            .order_by(WafMetric.id)
            .limit(self.batch_size)
            .all()
        )
        if not metrics:
            return

        for metric in metrics:
            for integration in integrations.values():
                _send_event(integration, metric)

        self._last_id = metrics[-1].id
