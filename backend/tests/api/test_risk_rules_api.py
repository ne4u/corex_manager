"""Tests for the /risk-rules API endpoints."""
import pytest
from fastapi.testclient import TestClient

from app.models.models import RiskRule, GeoList, AsnList, Ja4List, NetworkList


class TestRiskRulesAPI:
    def test_list_empty(self, client):
        resp = client.get("/api/v1/risk-rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_rule(self, client, db):
        resp = client.post("/api/v1/risk-rules", json={
            "name": "HTTP/1.0 protocol",
            "enabled": True,
            "listener_ids": [],
            "expression": "http.request.version_numeric < 11",
            "points": 4,
            "log": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "HTTP/1.0 protocol"
        assert data["points"] == 4
        assert data["priority"] == 0
        assert data["expression_ast"] is not None
        assert data["category"] == "protocol"  # auto-derived

    def test_create_invalid_expression(self, client):
        resp = client.post("/api/v1/risk-rules", json={
            "name": "Bad rule",
            "expression": "http.host @",
            "points": 5,
        })
        assert resp.status_code == 400

    def test_create_negative_points(self, client, db):
        # Negative points (trust signals) should be allowed
        resp = client.post("/api/v1/risk-rules", json={
            "name": "Trust rule",
            "expression": 'auth.valid',
            "points": -15,
        })
        assert resp.status_code == 200
        assert resp.json()["category"] == "trust"

    def test_create_disabled_rule(self, client, db):
        resp = client.post("/api/v1/risk-rules", json={
            "name": "Disabled rule",
            "expression": 'http.host = "b"',
            "points": 50,
            "enabled": False,
        })
        assert resp.status_code == 200

    def test_list_rules(self, client, db):
        client.post("/api/v1/risk-rules", json={
            "name": "Rule 1", "expression": 'http.host = "a"', "points": 5,
        })
        client.post("/api/v1/risk-rules", json={
            "name": "Rule 2", "expression": 'http.host = "b"', "points": 10,
        })
        resp = client.get("/api/v1/risk-rules")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["priority"] == 0
        assert data[1]["priority"] == 1

    def test_update_rule(self, client, db):
        create = client.post("/api/v1/risk-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "points": 5,
        })
        rid = create.json()["id"]
        resp = client.put(f"/api/v1/risk-rules/{rid}", json={
            "name": "Updated rule",
            "points": 10,
        })
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated rule"
        assert resp.json()["points"] == 10

    def test_update_expression_rederives_category(self, client, db):
        create = client.post("/api/v1/risk-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "points": 5,
        })
        rid = create.json()["id"]
        # Update expression to a protocol field
        resp = client.put(f"/api/v1/risk-rules/{rid}", json={
            "expression": "http.request.version_numeric < 11",
        })
        assert resp.status_code == 200
        assert resp.json()["category"] == "protocol"

    def test_update_explicit_category_preserved(self, client, db):
        create = client.post("/api/v1/risk-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "points": 5,
            "category": "custom",
        })
        rid = create.json()["id"]
        # Update expression but also provide category → should keep explicit
        resp = client.put(f"/api/v1/risk-rules/{rid}", json={
            "expression": "http.request.version_numeric < 11",
            "category": "custom",
        })
        assert resp.status_code == 200
        assert resp.json()["category"] == "custom"

    def test_delete_rule(self, client, db):
        create = client.post("/api/v1/risk-rules", json={
            "name": "Test rule", "expression": 'http.host = "a"', "points": 5,
        })
        rid = create.json()["id"]
        resp = client.delete(f"/api/v1/risk-rules/{rid}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        # Verify deleted
        resp = client.get("/api/v1/risk-rules")
        assert len(resp.json()) == 0

    def test_reorder_rules(self, client, db):
        c1 = client.post("/api/v1/risk-rules", json={
            "name": "Rule 1", "expression": 'http.host = "a"', "points": 5,
        })
        c2 = client.post("/api/v1/risk-rules", json={
            "name": "Rule 2", "expression": 'http.host = "b"', "points": 10,
        })
        id1 = c1.json()["id"]
        id2 = c2.json()["id"]
        # Reorder: swap
        resp = client.put("/api/v1/risk-rules/reorder", json={"ordered_ids": [id2, id1]})
        assert resp.status_code == 200
        rules = client.get("/api/v1/risk-rules").json()
        assert rules[0]["id"] == id2
        assert rules[1]["id"] == id1

    def test_validate_expression(self, client):
        resp = client.post("/api/v1/risk-rules/validate", json={
            "expression": "http.request.version_numeric < 11",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["suggested_category"] == "protocol"

    def test_validate_expression_geo(self, client):
        resp = client.post("/api/v1/risk-rules/validate", json={
            "expression": "http.request.geo_lang_mismatch",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["suggested_category"] == "geo"

    def test_validate_expression_list(self, client, db):
        # Create the list so the reference resolves
        from app.models.models import NetworkList
        lst = NetworkList(name="mylist")
        db.add(lst)
        db.commit()
        resp = client.post("/api/v1/risk-rules/validate", json={
            "expression": "ip.src in $network:mylist",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["suggested_category"] == "list"

    def test_validate_invalid_expression(self, client):
        resp = client.post("/api/v1/risk-rules/validate", json={
            "expression": "http.host @",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is False
        assert data["error"] is not None

    def test_seed_baseline(self, client, db):
        resp = client.post("/api/v1/risk-rules/seed-baseline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["created_rules"] > 0
        assert data["created_lists"] == 4
        assert data["created_rulesets"] == 0  # default was created by fixture
        assert data["skipped"] == 1  # default ruleset already exists

    def test_seed_baseline_idempotent(self, client, db):
        client.post("/api/v1/risk-rules/seed-baseline")
        resp = client.post("/api/v1/risk-rules/seed-baseline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["created_rules"] == 0
        assert data["created_lists"] == 0
        assert data["created_rulesets"] == 0
        assert data["skipped"] > 0

    def test_seed_baseline_with_categories(self, client, db):
        client.post("/api/v1/risk-rules/seed-baseline")
        rules = client.get("/api/v1/risk-rules").json()
        for rule in rules:
            assert rule["category"] is not None
            assert rule["category"] in ("protocol", "headers", "geo", "behavioral", "list", "trust")

    def test_category_auto_derived_on_create(self, client, db):
        resp = client.post("/api/v1/risk-rules", json={
            "name": "Geo rule",
            "expression": "http.request.geo_lang_mismatch",
            "points": 4,
        })
        assert resp.json()["category"] == "geo"

    def test_category_explicit_override(self, client, db):
        resp = client.post("/api/v1/risk-rules", json={
            "name": "Custom cat",
            "expression": "http.request.geo_lang_mismatch",
            "points": 4,
            "category": "custom",
        })
        assert resp.json()["category"] == "custom"
