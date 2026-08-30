"""Unit tests for the audit service: action derivation, payload truncation, config-change classification."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.services.audit import (
    derive_action,
    is_config_change,
    should_capture_payload,
    truncate_payload,
)


# --- derive_action: special cases -----------------------------------------

def test_derive_action_login():
    action, rtype, rid = derive_action("POST", "/api/v1/auth/token")
    assert action == "login"
    assert rtype is None
    assert rid is None


def test_derive_action_logout():
    action, rtype, rid = derive_action("POST", "/api/v1/auth/logout")
    assert action == "logout"


def test_derive_action_refresh_token():
    action, _, _ = derive_action("POST", "/api/v1/auth/refresh")
    assert action == "refresh_token"


def test_derive_action_totp_setup():
    action, _, _ = derive_action("POST", "/api/v1/auth/totp/setup")
    assert action == "totp_setup"


def test_derive_action_apply_config():
    action, rtype, rid = derive_action("POST", "/api/v1/config/apply")
    assert action == "apply_config"
    assert rtype == "config"
    assert rid is None


def test_derive_action_revert_config():
    action, rtype, _ = derive_action("POST", "/api/v1/config/revert")
    assert action == "revert_config"
    assert rtype == "config"


def test_derive_action_rollback_snapshot():
    action, rtype, rid = derive_action("POST", "/api/v1/config/snapshots/42/rollback")
    assert action == "rollback_snapshot"
    assert rtype == "config_snapshot"
    assert rid == "42"


def test_derive_action_issue_certificate():
    action, rtype, rid = derive_action("POST", "/api/v1/certificates/5/issue")
    assert action == "issue_certificate"
    assert rtype == "certificate"
    assert rid == "5"


def test_derive_action_renew_certificates():
    action, rtype, _ = derive_action("POST", "/api/v1/certificates/renew")
    assert action == "renew_certificates"
    assert rtype == "certificate"


def test_derive_action_import_waf_rules():
    action, rtype, _ = derive_action("POST", "/api/v1/waf/rules/import")
    assert action == "import_waf_rules"
    assert rtype == "waf_rule"


def test_derive_action_snapshot_waf_rule():
    action, rtype, rid = derive_action("POST", "/api/v1/waf/rules/3/snapshot")
    assert action == "snapshot_waf_rule"
    assert rtype == "waf_rule"
    assert rid == "3"


def test_derive_action_restore_waf_rule():
    action, rtype, rid = derive_action("POST", "/api/v1/waf/rules/3/restore/7")
    assert action == "restore_waf_rule"
    assert rtype == "waf_rule"
    assert rid == "3"


def test_derive_action_refresh_feed():
    action, rtype, rid = derive_action("POST", "/api/v1/security-lists/feeds/9/refresh")
    assert action == "refresh_feed"
    assert rtype == "dynamic_feed"
    assert rid == "9"


# --- derive_action: generic REST fallback ---------------------------------

def test_derive_action_create_backend():
    action, rtype, rid = derive_action("POST", "/api/v1/backends")
    assert action == "create_backend"
    assert rtype == "backend"
    assert rid is None  # POST to collection, id filled from response later


def test_derive_action_update_backend():
    action, rtype, rid = derive_action("PUT", "/api/v1/backends/5")
    assert action == "update_backend"
    assert rtype == "backend"
    assert rid == "5"


def test_derive_action_delete_backend():
    action, rtype, rid = derive_action("DELETE", "/api/v1/backends/5")
    assert action == "delete_backend"
    assert rtype == "backend"
    assert rid == "5"


def test_derive_action_create_listener():
    action, rtype, _ = derive_action("POST", "/api/v1/listeners")
    assert action == "create_listener"
    assert rtype == "listener"


def test_derive_action_delete_server():
    action, rtype, rid = derive_action("DELETE", "/api/v1/servers/12")
    assert action == "delete_server"
    assert rtype == "server"
    assert rid == "12"


def test_derive_action_create_waf_exception():
    action, rtype, _ = derive_action("POST", "/api/v1/waf-exceptions")
    assert action == "create_waf_exception"
    assert rtype == "waf_exception"


def test_derive_action_create_security_list_network():
    action, rtype, _ = derive_action("POST", "/api/v1/security-lists/network")
    assert action == "create_network_list"
    assert rtype == "network_list"


def test_derive_action_update_security_list_asn_entry():
    action, rtype, rid = derive_action("PUT", "/api/v1/security-lists/asn/3/entries/7")
    assert action == "update_entry"
    assert rtype == "entry"
    assert rid == "7"


def test_derive_action_create_user():
    action, rtype, _ = derive_action("POST", "/api/v1/users")
    assert action == "create_user"
    assert rtype == "user"


# --- should_capture_payload ------------------------------------------------

def test_should_capture_payload_json():
    assert should_capture_payload("/api/v1/backends", "application/json") is True


def test_should_capture_payload_no_content_type():
    assert should_capture_payload("/api/v1/backends", None) is False


def test_should_capture_payload_multipart():
    assert should_capture_payload("/api/v1/certificates/1/upload", "multipart/form-data") is False


def test_should_capture_payload_auth_token():
    assert should_capture_payload("/api/v1/auth/token", "application/json") is False


def test_should_capture_payload_auth_totp():
    assert should_capture_payload("/api/v1/auth/totp/verify", "application/json") is False


def test_should_capture_payload_cert_create():
    assert should_capture_payload("/api/v1/certificates", "application/json") is False


def test_should_capture_payload_cert_update():
    # PUT /certificates/{id} doesn't contain key material, only metadata
    assert should_capture_payload("/api/v1/certificates/1", "application/json") is True


# --- truncate_payload ------------------------------------------------------

def test_truncate_payload_empty():
    assert truncate_payload(b"", 1024) is None


def test_truncate_payload_json_dict():
    body = b'{"name": "test", "port": 80}'
    result = truncate_payload(body, 1024)
    assert result == {"name": "test", "port": 80}


def test_truncate_payload_json_list():
    body = b'[1, 2, 3]'
    result = truncate_payload(body, 1024)
    assert result == {"_list": [1, 2, 3]}


def test_truncate_payload_truncated():
    big = json.dumps({"data": "x" * 1000}).encode()
    result = truncate_payload(big, 100)
    assert result is not None
    assert result.get("_truncated") is True
    assert result.get("_size") == len(big)
    assert "_preview" in result


def test_truncate_payload_non_json():
    body = b"not json at all"
    result = truncate_payload(body, 1024)
    assert result is not None
    assert result.get("_raw") == "not json at all"
    assert result.get("_truncated") is False


def test_truncate_payload_non_json_truncated():
    body = b"x" * 500
    result = truncate_payload(body, 100)
    assert result is not None
    assert result.get("_truncated") is True
    assert result.get("_size") == 500
    assert len(result.get("_raw", "")) == 100


# --- _get_last_applied_at --------------------------------------------------

def test_get_last_applied_at_from_setting(db):
    """last_applied_at setting is the primary source."""
    from app.services.settings import set_setting
    from app.services.audit_events import _get_last_applied_at
    ts = datetime(2026, 1, 15, 12, 0, 0)
    set_setting(db, "last_applied_at", ts.isoformat())
    result = _get_last_applied_at(db)
    assert result is not None
    # Should match (timezone stripped for DB comparison)
    assert result.replace(tzinfo=None) == ts


def test_get_last_applied_at_fallback_to_snapshot(db):
    """If setting is missing, fall back to latest ConfigSnapshot.created_at."""
    from app.models.tasks import ConfigSnapshot
    from app.services.audit_events import _get_last_applied_at
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    snap = ConfigSnapshot(snapshot_path="/tmp/test.json", created_at=now)
    db.add(snap)
    db.commit()
    result = _get_last_applied_at(db)
    assert result is not None
    assert result.replace(tzinfo=None) == now


def test_get_last_applied_at_none_when_no_data(db):
    """Returns None when no setting and no snapshots exist."""
    from app.services.audit_events import _get_last_applied_at
    result = _get_last_applied_at(db)
    assert result is None


# --- _compute_snapshot_for_events -----------------------------------------

def test_compute_snapshot_before_event(db):
    """Event before a snapshot maps to that snapshot."""
    from app.models.models import AuditEvent
    from app.models.tasks import ConfigSnapshot
    from app.services.audit_events import _compute_snapshot_for_events
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    event = AuditEvent(action="create_backend", method="POST", path="/api/v1/backends", created_at=now - timedelta(minutes=5))
    db.add(event)
    db.commit()
    snap = ConfigSnapshot(snapshot_path="/tmp/test.json", created_at=now)
    db.add(snap)
    db.commit()
    result = _compute_snapshot_for_events([event], db)
    assert result[event.id] is not None
    assert result[event.id].id == snap.id


def test_compute_snapshot_after_all_snapshots(db):
    """Event after all snapshots maps to None (pending)."""
    from app.models.models import AuditEvent
    from app.models.tasks import ConfigSnapshot
    from app.services.audit_events import _compute_snapshot_for_events
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    snap = ConfigSnapshot(snapshot_path="/tmp/test.json", created_at=now - timedelta(minutes=10))
    db.add(snap)
    db.commit()
    event = AuditEvent(action="create_backend", method="POST", path="/api/v1/backends", created_at=now)
    db.add(event)
    db.commit()
    result = _compute_snapshot_for_events([event], db)
    assert result[event.id] is None


def test_compute_snapshot_between_two_snapshots(db):
    """Event between two snapshots maps to the later one."""
    from app.models.models import AuditEvent
    from app.models.tasks import ConfigSnapshot
    from app.services.audit_events import _compute_snapshot_for_events
    base = datetime.now(timezone.utc).replace(tzinfo=None)
    snap1 = ConfigSnapshot(snapshot_path="/tmp/s1.json", created_at=base - timedelta(minutes=20))
    snap2 = ConfigSnapshot(snapshot_path="/tmp/s2.json", created_at=base - timedelta(minutes=5))
    db.add_all([snap1, snap2])
    db.commit()
    event = AuditEvent(action="create_backend", method="POST", path="/api/v1/backends", created_at=base - timedelta(minutes=10))
    db.add(event)
    db.commit()
    result = _compute_snapshot_for_events([event], db)
    assert result[event.id] is not None
    assert result[event.id].id == snap2.id


def test_compute_snapshot_no_snapshots(db):
    """No snapshots → all events map to None."""
    from app.models.models import AuditEvent
    from app.services.audit_events import _compute_snapshot_for_events
    event = AuditEvent(action="create_backend", method="POST", path="/api/v1/backends")
    db.add(event)
    db.commit()
    result = _compute_snapshot_for_events([event], db)
    assert result[event.id] is None


def test_compute_snapshot_empty_events(db):
    """Empty event list → empty map."""
    from app.services.audit_events import _compute_snapshot_for_events
    result = _compute_snapshot_for_events([], db)
    assert result == {}


# --- is_config_change ------------------------------------------------------

def test_is_config_change_auth_paths():
    """Auth events don't affect generated config."""
    assert is_config_change("POST", "/api/v1/auth/token") is False
    assert is_config_change("POST", "/api/v1/auth/logout") is False
    assert is_config_change("POST", "/api/v1/auth/refresh") is False
    assert is_config_change("POST", "/api/v1/auth/totp/setup") is False
    assert is_config_change("POST", "/api/v1/auth/totp/verify") is False
    assert is_config_change("POST", "/api/v1/auth/totp/disable") is False
    assert is_config_change("POST", "/api/v1/auth/change-password") is False


def test_is_config_change_user_preferences():
    """Theme / custom themes / language changes don't affect config."""
    assert is_config_change("PUT", "/api/v1/auth/preferences") is False


def test_is_config_change_user_management():
    """User CRUD doesn't affect generated config."""
    assert is_config_change("POST", "/api/v1/users") is False
    assert is_config_change("PUT", "/api/v1/users/5") is False
    assert is_config_change("DELETE", "/api/v1/users/5") is False


def test_is_config_change_task_cancel():
    """Task cancellation is operational, not config."""
    assert is_config_change("POST", "/api/v1/tasks/42/cancel") is False


def test_is_config_change_config_snapshots_max():
    """max_snapshots setting is not read by any generator."""
    assert is_config_change("PUT", "/api/v1/config/snapshots/max") is False


def test_is_config_change_config_lifecycle_actions():
    """apply/revert/rollback are lifecycle actions, not pending changes."""
    assert is_config_change("POST", "/api/v1/config/apply") is False
    assert is_config_change("POST", "/api/v1/config/revert") is False
    assert is_config_change("POST", "/api/v1/config/snapshots/42/rollback") is False


def test_is_config_change_captcha_keys():
    """Captcha key management proxies to external Cap service."""
    assert is_config_change("POST", "/api/v1/captcha/keys") is False
    assert is_config_change("PUT", "/api/v1/captcha/keys/abc-site-key/config") is False
    assert is_config_change("DELETE", "/api/v1/captcha/keys/abc-site-key") is False
    assert is_config_change("POST", "/api/v1/captcha/keys/abc-site-key/rotate-secret") is False


def test_is_config_change_waf_operational():
    """WAF operational endpoints (verify, SIEM, rule versions) don't affect config."""
    assert is_config_change("POST", "/api/v1/waf/verify-captcha") is False
    assert is_config_change("POST", "/api/v1/waf/siem-integrations") is False
    assert is_config_change("PUT", "/api/v1/waf/siem-integrations/3") is False
    assert is_config_change("DELETE", "/api/v1/waf/siem-integrations/3") is False
    assert is_config_change("POST", "/api/v1/waf/rules/5/snapshot") is False
    assert is_config_change("PUT", "/api/v1/waf/rule-versions/max") is False
    assert is_config_change("DELETE", "/api/v1/waf/rule-versions/7") is False


def test_is_config_change_validation_only():
    """Validation-only endpoints don't write to DB."""
    assert is_config_change("POST", "/api/v1/security-rules/validate") is False
    assert is_config_change("POST", "/api/v1/risk-rules/validate") is False
    assert is_config_change("POST", "/api/v1/resp-transforms/validate") is False


def test_is_config_change_cache_flush():
    """Cache flush is operational, not a config change."""
    assert is_config_change("POST", "/api/v1/cache/5/clear") is False
    assert is_config_change("POST", "/api/v1/cache/clear-all") is False


def test_is_config_change_api_armor_runtime():
    """API Armor runtime/observational data is not consumed by generators."""
    assert is_config_change("POST", "/api/v1/api-armor/specs") is False
    assert is_config_change("DELETE", "/api/v1/api-armor/specs/3") is False
    assert is_config_change("PUT", "/api/v1/api-armor/schemas/3") is False
    assert is_config_change("POST", "/api/v1/api-armor/auth-policies") is False
    assert is_config_change("PUT", "/api/v1/api-armor/auth-policies/2") is False
    assert is_config_change("DELETE", "/api/v1/api-armor/auth-policies/2") is False
    assert is_config_change("POST", "/api/v1/api-armor/api-key-lists") is False
    assert is_config_change("DELETE", "/api/v1/api-armor/api-key-lists/1") is False
    assert is_config_change("POST", "/api/v1/api-armor/profiles/4/finalize") is False
    assert is_config_change("DELETE", "/api/v1/api-armor/profiles/4") is False
    assert is_config_change("DELETE", "/api/v1/api-armor/anomalies") is False


def test_is_config_change_page_protect_observational():
    """Page protect scripts/baseline/reports are observational, not config."""
    assert is_config_change("PUT", "/api/v1/page-protect/scripts/5") is False
    assert is_config_change("DELETE", "/api/v1/page-protect/scripts/5") is False
    assert is_config_change("POST", "/api/v1/page-protect/scripts/5/check") is False
    assert is_config_change("POST", "/api/v1/page-protect/scripts/check-all") is False
    assert is_config_change("POST", "/api/v1/page-protect/sample") is False
    assert is_config_change("POST", "/api/v1/page-protect/baseline/start") is False
    assert is_config_change("POST", "/api/v1/page-protect/baseline/stop") is False
    assert is_config_change("DELETE", "/api/v1/page-protect/baseline") is False
    assert is_config_change("DELETE", "/api/v1/page-protect/reports") is False


def test_is_config_change_maxmind_license_key():
    """MaxMind license key storage doesn't affect config (files downloaded separately)."""
    assert is_config_change("PUT", "/api/v1/settings/maxmind/license-key") is False


def test_is_config_change_mcp_operational():
    """MCP operational endpoints don't affect the bundle."""
    assert is_config_change("POST", "/api/v1/mcp/marketplace/discover-env-vars") is False
    assert is_config_change("POST", "/api/v1/mcp/servers/3/oauth/discover") is False
    assert is_config_change("POST", "/api/v1/mcp/servers/3/oauth/authorize") is False
    assert is_config_change("POST", "/api/v1/mcp/skills/5/export") is False
    assert is_config_change("DELETE", "/api/v1/mcp/sessions/abc123") is False
    assert is_config_change("POST", "/api/v1/mcp/identities/2/revoke") is False
    assert is_config_change("POST", "/api/v1/mcp/config/regenerate") is False
    assert is_config_change("PUT", "/api/v1/mcp/alerts/config") is False
    assert is_config_change("POST", "/api/v1/mcp/teams/1/members") is False
    assert is_config_change("DELETE", "/api/v1/mcp/teams/1/members/5") is False
    assert is_config_change("POST", "/api/v1/mcp/skills/3/versions") is False


def test_is_config_change_config_affecting_paths():
    """Config-affecting paths return True (conservative default)."""
    assert is_config_change("POST", "/api/v1/backends") is True
    assert is_config_change("PUT", "/api/v1/backends/5") is True
    assert is_config_change("DELETE", "/api/v1/backends/5") is True
    assert is_config_change("POST", "/api/v1/listeners") is True
    assert is_config_change("PUT", "/api/v1/listeners/3") is True
    assert is_config_change("POST", "/api/v1/waf/rules") is True
    assert is_config_change("PUT", "/api/v1/waf/rules/5") is True
    assert is_config_change("DELETE", "/api/v1/waf/rules/5") is True
    assert is_config_change("POST", "/api/v1/security-lists/network") is True
    assert is_config_change("POST", "/api/v1/security-rules") is True
    assert is_config_change("POST", "/api/v1/risk-rules") is True
    assert is_config_change("POST", "/api/v1/certificates") is True
    assert is_config_change("POST", "/api/v1/mcp/servers") is True
    assert is_config_change("PUT", "/api/v1/mcp/servers/3") is True
    assert is_config_change("DELETE", "/api/v1/mcp/servers/3") is True
    assert is_config_change("POST", "/api/v1/mcp/policies") is True
    assert is_config_change("POST", "/api/v1/mcp/skills") is True
    assert is_config_change("POST", "/api/v1/mcp/skills/3/publish") is True


def test_is_config_change_ambiguous_paths_default_true():
    """Ambiguous paths (captcha/settings, settings/{key}) default to True."""
    # captcha/settings writes captcha_provider which IS read by generate_config
    assert is_config_change("PUT", "/api/v1/captcha/settings") is True
    # settings/{key} is key-dependent; conservative default is True
    assert is_config_change("PUT", "/api/v1/settings/ja4_enabled") is True
    assert is_config_change("PUT", "/api/v1/settings/some_non_config_key") is True


def test_is_config_change_unknown_path_defaults_true():
    """Unknown paths default to True (conservative — treat as config-affecting)."""
    assert is_config_change("POST", "/api/v1/some-unknown-endpoint") is True
    assert is_config_change("DELETE", "/api/v1/unknown/42") is True


def test_is_config_change_strips_api_v1_prefix():
    """The helper should work with or without the /api/v1 prefix."""
    assert is_config_change("POST", "/auth/token") is False
    assert is_config_change("POST", "/api/v1/auth/token") is False
    assert is_config_change("POST", "backends") is True
