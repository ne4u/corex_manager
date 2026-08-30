"""Tests for the SIEM forwarder."""
import json
from unittest.mock import MagicMock, patch

import pytest

from tests.factories import make_waf_metric, make_waf_rule, make_siem_integration
from app.services import siem_forwarder
from app.services.siem_forwarder import SiemForwarder, _format_event, _send_event


def test_format_event_json(db):
    """JSON format produces a valid JSON string with event fields."""
    integration = make_siem_integration(db, name="siem1", format="json")
    metric = make_waf_metric(db, action="deny", rule_id="942100", msg="SQL injection", client="1.2.3.4")
    formatted = _format_event(integration, metric)
    data = json.loads(formatted)
    assert data["action"] == "deny"
    assert data["rule_id"] == "942100"
    assert data["msg"] == "SQL injection"
    assert data["client"] == "1.2.3.4"


def test_format_event_syslog(db):
    """Syslog format produces an RFC 5424 message."""
    integration = make_siem_integration(db, name="siem1", format="syslog")
    metric = make_waf_metric(db, action="deny", rule_id="942100")
    formatted = _format_event(integration, metric)
    assert formatted.startswith("<134>1 ")
    assert "coraza-spoa" in formatted


def test_format_event_cef(db):
    """CEF format produces a CEF string."""
    integration = make_siem_integration(db, name="siem1", format="cef")
    metric = make_waf_metric(db, action="deny", rule_id="942100", msg="xss", severity="CRITICAL", client="1.2.3.4", uri="/test")
    formatted = _format_event(integration, metric)
    assert formatted.startswith("CEF:0|HAProxyManager|CorazaWAF|1.0|942100|xss|10|")
    assert "src=1.2.3.4" in formatted
    assert "request=/test" in formatted


def test_send_event_webhook(db):
    """Webhook send calls httpx POST."""
    integration = make_siem_integration(db, name="siem1", integration_type="webhook", target="https://example.com/webhook")
    metric = make_waf_metric(db, action="deny")
    with patch("app.services.siem_forwarder.httpx.Client") as mock_client:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
        ok = _send_event(integration, metric)
    assert ok is True


def test_send_event_syslog(db):
    """Syslog send calls socket.sendto."""
    integration = make_siem_integration(db, name="siem1", integration_type="syslog", target="127.0.0.1:514")
    metric = make_waf_metric(db, action="deny")
    with patch("app.services.siem_forwarder.socket.socket") as mock_socket:
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        ok = _send_event(integration, metric)
    assert ok is True
    mock_sock.sendto.assert_called_once()


def test_send_event_elastic(db):
    """Elastic send calls httpx POST."""
    integration = make_siem_integration(db, name="siem1", integration_type="elastic", target="https://example.com/_doc")
    metric = make_waf_metric(db, action="deny")
    with patch("app.services.siem_forwarder.httpx.Client") as mock_client:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
        ok = _send_event(integration, metric)
    assert ok is True


def test_forwarder_filters_by_referenced_siem(db):
    """Only SIEM integrations referenced by enabled WafRules receive events."""
    siem1 = make_siem_integration(db, name="siem1", enabled=True)
    siem2 = make_siem_integration(db, name="siem2", enabled=True)
    # Rule references siem1
    make_waf_rule(db, name="waf1", siem_integration_id=siem1.id)
    # Rule references siem2
    make_waf_rule(db, name="waf2", siem_integration_id=siem2.id)
    # Rule with no SIEM
    make_waf_rule(db, name="waf3", siem_integration_id=None)
    # Metrics
    make_waf_metric(db, action="deny")

    forwarder = SiemForwarder()
    sent_integrations = []

    def mock_send(integration, metric):
        sent_integrations.append(integration.name)
        return True

    with patch("app.services.siem_forwarder._send_event", side_effect=mock_send):
        forwarder._forward_events(db)

    # Both siem1 and siem2 should receive events (both are referenced)
    assert "siem1" in sent_integrations
    assert "siem2" in sent_integrations


def test_forwarder_skips_unreferenced_siem(db):
    """SIEM integrations not referenced by any WafRule don't receive events."""
    siem1 = make_siem_integration(db, name="siem1", enabled=True)
    siem2 = make_siem_integration(db, name="siem2", enabled=True)
    # Only siem1 is referenced
    make_waf_rule(db, name="waf1", siem_integration_id=siem1.id)
    make_waf_metric(db, action="deny")

    forwarder = SiemForwarder()
    sent_integrations = []

    def mock_send(integration, metric):
        sent_integrations.append(integration.name)
        return True

    with patch("app.services.siem_forwarder._send_event", side_effect=mock_send):
        forwarder._forward_events(db)

    assert "siem1" in sent_integrations
    assert "siem2" not in sent_integrations


def test_forwarder_skips_disabled_siem(db):
    """Disabled SIEM integrations don't receive events even if referenced."""
    siem1 = make_siem_integration(db, name="siem1", enabled=False)
    make_waf_rule(db, name="waf1", siem_integration_id=siem1.id)
    make_waf_metric(db, action="deny")

    forwarder = SiemForwarder()
    sent_integrations = []

    def mock_send(integration, metric):
        sent_integrations.append(integration.name)
        return True

    with patch("app.services.siem_forwarder._send_event", side_effect=mock_send):
        forwarder._forward_events(db)

    assert sent_integrations == []


def test_forwarder_no_siem_referenced_advances_watermark(db):
    """When no WafRule references a SIEM, the watermark advances without sending."""
    make_siem_integration(db, name="siem1", enabled=True)
    make_waf_rule(db, name="waf1", siem_integration_id=None)
    metric = make_waf_metric(db, action="deny")

    forwarder = SiemForwarder()
    forwarder._last_id = 0

    sent = []
    with patch("app.services.siem_forwarder._send_event", side_effect=lambda i, m: sent.append(1)):
        forwarder._forward_events(db)

    assert sent == []
    assert forwarder._last_id == metric.id


def test_forwarder_watermark_advances(db):
    """The forwarder doesn't re-send old events."""
    siem1 = make_siem_integration(db, name="siem1", enabled=True)
    make_waf_rule(db, name="waf1", siem_integration_id=siem1.id)
    metric1 = make_waf_metric(db, action="deny")
    metric2 = make_waf_metric(db, action="deny")

    forwarder = SiemForwarder()
    forwarder._last_id = metric1.id  # Already processed metric1

    sent_ids = []
    def mock_send(integration, metric):
        sent_ids.append(metric.id)
        return True

    with patch("app.services.siem_forwarder._send_event", side_effect=mock_send):
        forwarder._forward_events(db)

    # Only metric2 should be sent
    assert sent_ids == [metric2.id]
    assert forwarder._last_id == metric2.id
