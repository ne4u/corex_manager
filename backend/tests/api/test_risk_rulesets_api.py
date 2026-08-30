"""Tests for the /risk-rulesets API endpoints."""
import pytest
from fastapi.testclient import TestClient

from app.models.models import RiskRuleset, RiskRule


class TestRiskRulesetsAPI:
    def test_list_rulesets(self, client, db):
        resp = client.get("/api/v1/risk-rulesets")
        assert resp.status_code == 200
        data = resp.json()
        # At least the default ruleset (created by fixture)
        assert len(data) >= 1
        default = next(rs for rs in data if rs["slug"] == "default")
        assert default["name"] == "Default"
        assert default["rule_count"] == 0

    def test_create_ruleset(self, client, db):
        resp = client.post("/api/v1/risk-rulesets", json={
            "name": "Human Score",
            "description": "Browser traffic scoring",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Human Score"
        assert data["slug"] == "human_score"
        assert data["description"] == "Browser traffic scoring"
        assert data["enabled"] is True
        assert data["rule_count"] == 0

    def test_create_ruleset_duplicate_name(self, client, db):
        client.post("/api/v1/risk-rulesets", json={"name": "Human", "description": ""})
        resp = client.post("/api/v1/risk-rulesets", json={"name": "Human", "description": ""})
        assert resp.status_code == 200
        # Should auto-generate a unique slug
        data = resp.json()
        assert data["slug"] == "human_2"

    def test_update_ruleset(self, client, db):
        create = client.post("/api/v1/risk-rulesets", json={"name": "Test RS", "description": ""})
        rsid = create.json()["id"]
        resp = client.put(f"/api/v1/risk-rulesets/{rsid}", json={
            "name": "Renamed RS",
            "description": "Updated description",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Renamed RS"
        assert data["slug"] == "renamed_rs"
        assert data["description"] == "Updated description"

    def test_delete_ruleset(self, client, db):
        create = client.post("/api/v1/risk-rulesets", json={"name": "ToDelete", "description": ""})
        rsid = create.json()["id"]
        resp = client.delete(f"/api/v1/risk-rulesets/{rsid}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_default_ruleset_prevented(self, client, db):
        # The default ruleset (id=1) should not be deletable
        resp = client.delete("/api/v1/risk-rulesets/1")
        assert resp.status_code == 400
        assert "default" in resp.json().get("detail", "").lower()

    def test_delete_ruleset_cascades_rules(self, client, db):
        create = client.post("/api/v1/risk-rulesets", json={"name": "ToDelete", "description": ""})
        rsid = create.json()["id"]
        # Create a rule in this ruleset
        client.post("/api/v1/risk-rules", json={
            "name": "Test rule",
            "expression": 'http.host = "a"',
            "points": 5,
            "ruleset_id": rsid,
        })
        # Delete the ruleset
        resp = client.delete(f"/api/v1/risk-rulesets/{rsid}")
        assert resp.status_code == 200
        # Verify the rule is gone
        rules = client.get("/api/v1/risk-rules").json()
        assert len(rules) == 0

    def test_list_rules_by_ruleset(self, client, db):
        # Create a second ruleset
        create = client.post("/api/v1/risk-rulesets", json={"name": "Human", "description": ""})
        human_id = create.json()["id"]
        # Create rules in both rulesets
        client.post("/api/v1/risk-rules", json={
            "name": "Default rule",
            "expression": 'http.host = "a"',
            "points": 5,
            "ruleset_id": 1,
        })
        client.post("/api/v1/risk-rules", json={
            "name": "Human rule",
            "expression": 'http.host = "b"',
            "points": 5,
            "ruleset_id": human_id,
        })
        # List all
        all_rules = client.get("/api/v1/risk-rules").json()
        assert len(all_rules) == 2
        # List filtered by human ruleset
        human_rules = client.get(f"/api/v1/risk-rules?ruleset_id={human_id}").json()
        assert len(human_rules) == 1
        assert human_rules[0]["name"] == "Human rule"
        assert human_rules[0]["ruleset_id"] == human_id

    def test_create_rule_invalid_ruleset(self, client, db):
        resp = client.post("/api/v1/risk-rules", json={
            "name": "Test",
            "expression": 'http.host = "a"',
            "points": 5,
            "ruleset_id": 9999,
        })
        assert resp.status_code == 400
        assert "not found" in resp.json().get("detail", "")
