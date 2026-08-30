"""Integration tests for the /audit-events endpoints."""
import json

import pytest


def test_list_audit_events_empty(client, db):
    res = client.get("/api/v1/audit-events")
    assert res.status_code == 200
    assert res.json() == []


def test_list_audit_events_after_mutation(client, db):
    # Creating a backend should produce an audit event via middleware
    res = client.post("/api/v1/backends", json={"name": "test-backend", "protocol": "http"})
    assert res.status_code == 200

    res = client.get("/api/v1/audit-events")
    assert res.status_code == 200
    events = res.json()
    # At least one event should exist (the create_backend)
    audit_events = [e for e in events if e["action"] == "create_backend"]
    assert len(audit_events) >= 1

    event = audit_events[0]
    assert event["method"] == "POST"
    assert event["path"] == "/api/v1/backends"
    assert event["resource_type"] == "backend"
    assert event["snapshot_id"] is None  # not yet applied
    # Payload should be captured (JSON body)
    assert event["payload"] is not None
    assert event["payload"].get("name") == "test-backend"


def test_audit_event_payload_not_captured_for_auth(client, db):
    # Auth endpoints should not capture payload
    # We need to hit the token endpoint; it will fail but middleware still logs
    client.post("/api/v1/auth/token", data={"username": "x", "password": "y"})
    res = client.get("/api/v1/audit-events")
    events = res.json()
    auth_events = [e for e in events if e["action"] == "login"]
    if auth_events:
        assert auth_events[0]["payload"] is None


def test_audit_event_resource_id_from_response(client, db):
    res = client.post("/api/v1/backends", json={"name": "rid-test", "protocol": "http"})
    backend_id = res.json()["id"]

    res = client.get("/api/v1/audit-events")
    events = res.json()
    create_events = [e for e in events if e["action"] == "create_backend"]
    assert len(create_events) >= 1
    # The resource_id should be populated from the response body
    assert create_events[0]["resource_id"] == str(backend_id)


def test_audit_events_filter_by_action(client, db):
    client.post("/api/v1/backends", json={"name": "filter-test-1", "protocol": "http"})
    client.post("/api/v1/listeners", json={"name": "listener-1", "address": "*:8080", "protocol": "http"})

    res = client.get("/api/v1/audit-events", params={"action": "create_backend"})
    assert res.status_code == 200
    events = res.json()
    assert all("create_backend" in e["action"] for e in events)


def test_audit_events_has_snapshot_filter(client, db):
    """Pending/applied filter uses last_applied_at timestamp, not snapshot_id FK."""
    from app.services.settings import set_setting
    from datetime import datetime, timedelta, timezone

    # Create a backend (will be pending — no last_applied_at set yet)
    client.post("/api/v1/backends", json={"name": "snap-filter-test", "protocol": "http"})

    # With no last_applied_at, all config events are pending
    res = client.get("/api/v1/audit-events", params={"has_snapshot": "false"})
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    assert all(e["snapshot_id"] is None for e in events)

    # Set last_applied_at to now — the event was created before this, so it's applied
    now = datetime.now(timezone.utc)
    set_setting(db, "last_applied_at", now.isoformat())
    db.commit()

    # Filter for applied only — should include the backend event
    res = client.get("/api/v1/audit-events", params={"has_snapshot": "true"})
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    # Applied events have snapshot_created_at set (even if snapshot_id is null for pruned)
    assert all(e["snapshot_created_at"] is not None for e in events)

    # Filter for pending — should be empty (no events after last_applied_at)
    res = client.get("/api/v1/audit-events", params={"has_snapshot": "false"})
    assert res.status_code == 200
    events = res.json()
    assert len(events) == 0


def test_audit_events_pending_after_apply_then_new_event(client, db):
    """After last_applied_at is set, new events show as pending, old as applied."""
    from app.services.settings import set_setting
    from datetime import datetime, timedelta, timezone

    # Set last_applied_at to 10 minutes ago
    past = datetime.now(timezone.utc) - timedelta(minutes=10)
    set_setting(db, "last_applied_at", past.isoformat())
    db.commit()

    # Create a backend NOW (after last_applied_at) — should be pending
    client.post("/api/v1/backends", json={"name": "after-apply-test", "protocol": "http"})

    res = client.get("/api/v1/audit-events", params={"has_snapshot": "false"})
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    assert any(e["action"] == "create_backend" for e in events)


def test_audit_events_export_csv(client, db):
    client.post("/api/v1/backends", json={"name": "export-test", "protocol": "http"})

    res = client.get("/api/v1/audit-events/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
    assert "attachment" in res.headers.get("content-disposition", "")

    lines = res.text.strip().splitlines()
    # Header row
    header = lines[0].split(",")
    assert "action" in header
    assert "method" in header
    assert "payload" in header
    assert "snapshot_id" in header
    # At least one data row
    assert len(lines) >= 2


def test_get_request_not_audited(client, db):
    # GET requests should not produce audit events
    client.get("/api/v1/backends")
    res = client.get("/api/v1/audit-events")
    events = res.json()
    # No event should have method GET
    assert all(e["method"] != "GET" for e in events)


def test_audit_event_filter_options(client, db):
    # Create some events with known values
    client.post("/api/v1/backends", json={"name": "filter-opts-1", "protocol": "http"})
    client.post("/api/v1/listeners", json={"name": "listener-opts-1", "address": "*:8081", "protocol": "http"})

    res = client.get("/api/v1/audit-events/filters")
    assert res.status_code == 200
    data = res.json()
    assert "usernames" in data
    assert "actions" in data
    assert "resource_types" in data
    assert "ip_addresses" in data
    # Actions should include create_backend and create_listener
    assert "create_backend" in data["actions"]
    assert "create_listener" in data["actions"]
    # Resource types should include backend and listener
    assert "backend" in data["resource_types"]
    assert "listener" in data["resource_types"]


def test_audit_event_config_change_false_for_validate(client, db):
    """POST /security-rules/validate (validation-only) should create a config_change=False event."""
    client.post("/api/v1/security-rules/validate", json={"expression": "ip == '1.2.3.4'"})

    res = client.get("/api/v1/audit-events")
    events = res.json()
    validate_events = [e for e in events if e["action"] == "validate_security_rule"]
    assert len(validate_events) >= 1
    assert validate_events[0]["config_change"] is False


def test_audit_event_config_change_true_for_backend(client, db):
    """POST /backends should create a config_change=True event."""
    client.post("/api/v1/backends", json={"name": "cc-test", "protocol": "http"})

    res = client.get("/api/v1/audit-events")
    events = res.json()
    backend_events = [e for e in events if e["action"] == "create_backend"]
    assert len(backend_events) >= 1
    assert backend_events[0]["config_change"] is True


def test_audit_events_pending_filter_excludes_non_config(client, db):
    """has_snapshot=false should exclude config_change=False events."""
    # Create a non-config event (validation-only)
    client.post("/api/v1/security-rules/validate", json={"expression": "ip == '1.2.3.4'"})
    # Create a config-affecting event
    client.post("/api/v1/backends", json={"name": "pending-filter-test", "protocol": "http"})

    # Filter for pending only — should include backend but NOT validate
    res = client.get("/api/v1/audit-events", params={"has_snapshot": "false"})
    assert res.status_code == 200
    events = res.json()
    assert all(e["snapshot_id"] is None for e in events)
    # All pending events should be config_change=True
    assert all(e["config_change"] is True for e in events)
    # Should NOT include the validate event
    assert not any(e["action"] == "validate_security_rule" for e in events)
    # Should include the backend event
    assert any(e["action"] == "create_backend" for e in events)


def test_audit_events_all_includes_non_config(client, db):
    """has_snapshot unset (all) should include both config and non-config events."""
    client.post("/api/v1/security-rules/validate", json={"expression": "ip == '1.2.3.4'"})
    client.post("/api/v1/backends", json={"name": "all-filter-test", "protocol": "http"})

    res = client.get("/api/v1/audit-events")
    events = res.json()
    # Should include both types
    assert any(e["config_change"] is False for e in events)
    assert any(e["config_change"] is True for e in events)
