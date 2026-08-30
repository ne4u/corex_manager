"""Tests for the /security-rules API endpoints."""
import pytest
from fastapi.testclient import TestClient

from app.models.models import SecurityRule, NetworkList, NetworkListEntry, PatternList


class TestSecurityRulesAPI:
    def test_list_empty(self, client):
        resp = client.get("/api/v1/security-rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_rule(self, client, db):
        resp = client.post("/api/v1/security-rules", json={
            "name": "Block WP logins",
            "enabled": True,
            "listener_ids": [],
            "expression": 'http.request.uri.path = "/wp-login.php"',
            "action": "block",
            "log": False,
            "status_code": 403,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Block WP logins"
        assert data["action"] == "block"
        assert data["priority"] == 0
        assert data["expression_ast"] is not None

    def test_create_invalid_expression(self, client):
        resp = client.post("/api/v1/security-rules", json={
            "name": "Bad rule",
            "expression": "http.host @",
            "action": "block",
        })
        assert resp.status_code == 400
        assert "error" in resp.json().get("detail", "").lower() or "unexpected" in resp.json().get("detail", "").lower()

    def test_list_rules(self, client, db):
        # Create two rules
        client.post("/api/v1/security-rules", json={
            "name": "Rule 1", "expression": 'http.host = "a"', "action": "block",
        })
        client.post("/api/v1/security-rules", json={
            "name": "Rule 2", "expression": 'http.host = "b"', "action": "allow",
        })
        resp = client.get("/api/v1/security-rules")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["priority"] == 0
        assert data[1]["priority"] == 1

    def test_update_rule(self, client, db):
        create = client.post("/api/v1/security-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "action": "block",
        })
        rid = create.json()["id"]
        resp = client.put(f"/api/v1/security-rules/{rid}", json={
            "name": "Updated rule",
            "action": "allow",
        })
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated rule"
        assert resp.json()["action"] == "allow"

    def test_update_invalid_expression(self, client, db):
        create = client.post("/api/v1/security-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "action": "block",
        })
        rid = create.json()["id"]
        resp = client.put(f"/api/v1/security-rules/{rid}", json={
            "expression": "http.host @",
        })
        assert resp.status_code == 400

    def test_delete_rule(self, client, db):
        create = client.post("/api/v1/security-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "action": "block",
        })
        rid = create.json()["id"]
        resp = client.delete(f"/api/v1/security-rules/{rid}")
        assert resp.status_code == 200
        # Verify deleted
        resp = client.get("/api/v1/security-rules")
        assert len(resp.json()) == 0

    def test_reorder(self, client, db):
        r1 = client.post("/api/v1/security-rules", json={"name": "R1", "expression": 'http.host = "a"', "action": "block"}).json()
        r2 = client.post("/api/v1/security-rules", json={"name": "R2", "expression": 'http.host = "b"', "action": "block"}).json()
        r3 = client.post("/api/v1/security-rules", json={"name": "R3", "expression": 'http.host = "c"', "action": "block"}).json()
        # Reorder: R3, R1, R2
        resp = client.put("/api/v1/security-rules/reorder", json={"ordered_ids": [r3["id"], r1["id"], r2["id"]]})
        assert resp.status_code == 200
        rules = client.get("/api/v1/security-rules").json()
        assert rules[0]["name"] == "R3"
        assert rules[1]["name"] == "R1"
        assert rules[2]["name"] == "R2"
        assert rules[0]["priority"] == 0
        assert rules[1]["priority"] == 1
        assert rules[2]["priority"] == 2

    def test_validate_endpoint(self, client):
        resp = client.post("/api/v1/security-rules/validate", json={"expression": 'http.host = "a"'})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["ast"] is not None

    def test_validate_invalid(self, client):
        resp = client.post("/api/v1/security-rules/validate", json={"expression": "http.host @"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is False
        assert data["error"] is not None

    def test_create_with_list_ref(self, client, db):
        # Create a network list first
        lst = NetworkList(name="badactors")
        db.add(lst)
        db.commit()
        db.refresh(lst)
        db.add(NetworkListEntry(list_id=lst.id, value="1.2.3.4"))
        db.commit()
        resp = client.post("/api/v1/security-rules", json={
            "name": "Block bad actors",
            "expression": "ip.src in $network:badactors",
            "action": "block",
        })
        assert resp.status_code == 200

    def test_create_with_missing_list_ref(self, client):
        resp = client.post("/api/v1/security-rules", json={
            "name": "Bad list ref",
            "expression": "ip.src in $network:nonexistent",
            "action": "block",
        })
        assert resp.status_code == 400

    def test_create_with_pattern_list_ref(self, client, db):
        # Create a pattern list first
        lst = PatternList(name="bad_bots")
        db.add(lst)
        db.commit()
        db.refresh(lst)
        resp = client.post("/api/v1/security-rules", json={
            "name": "Block bad bots",
            "expression": "http.request.user_agent in $pattern:bad_bots",
            "action": "block",
        })
        assert resp.status_code == 200

    def test_create_with_pattern_list_ref_non_string_field(self, client, db):
        # Pattern lists can only be used with string-typed fields
        lst = PatternList(name="bad_bots")
        db.add(lst)
        db.commit()
        db.refresh(lst)
        resp = client.post("/api/v1/security-rules", json={
            "name": "Bad pattern ref",
            "expression": "ip.src in $pattern:bad_bots",
            "action": "block",
        })
        assert resp.status_code == 400

    def test_listener_scoping(self, client, db):
        # Create a rule scoped to listener 1
        client.post("/api/v1/security-rules", json={
            "name": "Scoped rule",
            "expression": 'http.host = "a"',
            "action": "block",
            "listener_ids": [1],
        })
        rules = client.get("/api/v1/security-rules").json()
        assert rules[0]["listener_ids"] == [1]

    def test_all_actions(self, client, db):
        for action in ["block", "allow", "redirect", "custom_response", "skip_rules", "skip_rules_ratelimit", "skip_rules_waf", "skip_all"]:
            resp = client.post("/api/v1/security-rules", json={
                "name": f"Action {action}",
                "expression": 'http.host = "a"',
                "action": action,
            })
            assert resp.status_code == 200, f"Failed for action {action}: {resp.text}"

    def test_create_redirect_rule(self, client, db):
        resp = client.post("/api/v1/security-rules", json={
            "name": "Redirect rule",
            "expression": 'http.host = "bad.com"',
            "action": "redirect",
            "redirect_url": "https://example.com/blocked",
            "redirect_code": 301,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "redirect"
        assert data["redirect_url"] == "https://example.com/blocked"
        assert data["redirect_code"] == 301

    def test_create_custom_response_rule(self, client, db):
        from app.models.models import CustomErrorPage
        ep = CustomErrorPage(code=403, content_type="text/html", content="<h1>Blocked</h1>")
        db.add(ep)
        db.commit()
        db.refresh(ep)
        resp = client.post("/api/v1/security-rules", json={
            "name": "Custom response rule",
            "expression": 'http.host = "bad.com"',
            "action": "custom_response",
            "status_code": 403,
            "error_page_id": ep.id,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "custom_response"
        assert data["error_page_id"] == ep.id


class TestJa4Toggle:
    def test_toggle_off_disables_ja4_rules(self, client, db):
        """Toggling ja4_enabled=false disables security rules referencing JA4."""
        # Create a JA4 rule and a non-JA4 rule
        client.post("/api/v1/security-rules", json={
            "name": "ja4-rule", "expression": 'http.request.ja4 = "t13d1516h2_abc"',
            "action": "block",
        })
        client.post("/api/v1/security-rules", json={
            "name": "path-rule", "expression": 'http.request.uri.path = "/foo"',
            "action": "block",
        })

        resp = client.put("/api/v1/settings/ja4_enabled", json={"value": "false"})
        assert resp.status_code == 200

        rules = db.query(SecurityRule).all()
        by_name = {r.name: r for r in rules}
        assert by_name["ja4-rule"].enabled is False
        assert by_name["path-rule"].enabled is True

        # The auto-disabled IDs should be stored
        from app.services.settings import get_setting
        import json
        stored = get_setting(db, "ja4_auto_disabled_rule_ids", "[]") or "[]"
        ids = json.loads(stored)
        assert by_name["ja4-rule"].id in ids

    def test_toggle_on_reenables_ja4_rules(self, client, db):
        """Toggling ja4_enabled=true re-enables auto-disabled JA4 rules."""
        # Create a JA4 rule
        client.post("/api/v1/security-rules", json={
            "name": "ja4-rule", "expression": 'http.request.ja4 = "t13d1516h2_abc"',
            "action": "block",
        })
        # Toggle off
        client.put("/api/v1/settings/ja4_enabled", json={"value": "false"})
        # Toggle back on
        resp = client.put("/api/v1/settings/ja4_enabled", json={"value": "true"})
        assert resp.status_code == 200

        rule = db.query(SecurityRule).filter(SecurityRule.name == "ja4-rule").first()
        assert rule is not None
        assert rule.enabled is True

        # The auto-disabled IDs should be cleared
        from app.services.settings import get_setting
        import json
        stored = get_setting(db, "ja4_auto_disabled_rule_ids", "[]") or "[]"
        ids = json.loads(stored)
        assert ids == []
