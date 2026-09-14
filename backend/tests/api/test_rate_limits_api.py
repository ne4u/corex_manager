"""Tests for the /rate-limits API endpoints, including priority ordering."""


class TestRateLimitsAPI:
    def _create(self, client, name, **overrides):
        payload = {"name": name, "limit_type": "basic", "events": 100, "window_seconds": 60}
        payload.update(overrides)
        resp = client.post("/api/v1/rate-limits", json=payload)
        assert resp.status_code == 200
        return resp.json()

    def test_list_empty(self, client):
        resp = client.get("/api/v1/rate-limits")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_assigns_incrementing_priority(self, client, db):
        r1 = self._create(client, "rl1")
        r2 = self._create(client, "rl2")
        assert r1["priority"] == 0
        assert r2["priority"] == 1

    def test_list_ordered_by_priority(self, client, db):
        self._create(client, "rl1")
        self._create(client, "rl2")
        rules = client.get("/api/v1/rate-limits").json()
        assert [r["name"] for r in rules] == ["rl1", "rl2"]

    def test_reorder(self, client, db):
        r1 = self._create(client, "rl1")
        r2 = self._create(client, "rl2")
        r3 = self._create(client, "rl3")
        resp = client.put("/api/v1/rate-limits/reorder", json={"ordered_ids": [r3["id"], r1["id"], r2["id"]]})
        assert resp.status_code == 200
        rules = client.get("/api/v1/rate-limits").json()
        assert [r["name"] for r in rules] == ["rl3", "rl1", "rl2"]
        assert [r["priority"] for r in rules] == [0, 1, 2]

    def test_create_after_reorder_appends_at_end(self, client, db):
        r1 = self._create(client, "rl1")
        r2 = self._create(client, "rl2")
        client.put("/api/v1/rate-limits/reorder", json={"ordered_ids": [r2["id"], r1["id"]]})
        r3 = self._create(client, "rl3")
        rules = client.get("/api/v1/rate-limits").json()
        assert [r["name"] for r in rules] == ["rl2", "rl1", "rl3"]
        assert r3["priority"] == 2
