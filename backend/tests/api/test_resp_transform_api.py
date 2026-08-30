"""Tests for the /resp-transforms API endpoints."""
from app.services.settings import set_setting
from tests.factories import make_backend, make_response_transform


def _enable_resp_transform(db):
    """Enable the resp_transform feature for mutating API tests."""
    set_setting(db, "resp_transform_enabled", "true")


def test_list_empty(client, db):
    """GET /resp-transforms returns empty list when no transforms exist."""
    resp = client.get("/api/v1/resp-transforms")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_works_when_feature_disabled(client, db):
    """GET (list) is accessible even when the feature is not enabled."""
    # Feature is disabled by default (no setting in DB, config default is False)
    resp = client.get("/api/v1/resp-transforms")
    assert resp.status_code == 200


def test_create_replace_rule(client, db):
    """POST creates a replace-type transform."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_test",
        "transform_type": "replace",
        "find_regex": "<title>(.*?)</title>",
        "replace_string": "<title>NEW</title>",
        "content_types": "text/html",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "rt_test"
    assert data["transform_type"] == "replace"
    assert data["id"] > 0


def test_create_inject_rule(client, db):
    """POST creates an inject-type transform."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_inject",
        "transform_type": "inject",
        "find_regex": "</body>",
        "inject_string": "<script src='/beam.js'></script>",
        "inject_position": "before",
    })
    assert resp.status_code == 200
    assert resp.json()["transform_type"] == "inject"


def test_create_mask_detector_tokenize(client, db):
    """POST creates a mask rule with detector + tokenize mode."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_mask_tok",
        "transform_type": "mask",
        "mask_mode": "detector",
        "detector": "email",
        "token_mode": "tokenize",
        "token_prefix": "TOK_",
        "token_ttl": 3600,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["mask_mode"] == "detector"
    assert data["token_mode"] == "tokenize"


def test_create_mask_regex_encrypt(client, db):
    """POST creates a mask rule with regex + encrypt mode."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_mask_enc",
        "transform_type": "mask",
        "mask_mode": "regex",
        "find_regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "token_mode": "encrypt",
        "token_prefix": "ENC_",
        "encrypt_key_env": "RESP_TRANSFORM_KEY",
    })
    assert resp.status_code == 200
    assert resp.json()["token_mode"] == "encrypt"


def test_create_replace_missing_fields_rejected(client, db):
    """POST replace without find_regex is rejected."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_bad",
        "transform_type": "replace",
        "replace_string": "foo",
    })
    assert resp.status_code == 422


def test_create_inject_bad_position_rejected(client, db):
    """POST inject with invalid inject_position is rejected."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_bad_pos",
        "transform_type": "inject",
        "find_regex": "foo",
        "inject_string": "bar",
        "inject_position": "middle",
    })
    assert resp.status_code == 422


def test_create_mask_missing_token_mode_rejected(client, db):
    """POST mask without token_mode is rejected."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_bad_mask",
        "transform_type": "mask",
        "mask_mode": "detector",
        "detector": "email",
    })
    assert resp.status_code == 422


def test_create_invalid_regex_rejected(client, db):
    """POST with invalid regex is rejected at API time."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_bad_regex",
        "transform_type": "replace",
        "find_regex": "[unclosed",
        "replace_string": "foo",
    })
    assert resp.status_code == 422


def test_create_bad_detector_rejected(client, db):
    """POST mask with invalid detector is rejected."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_bad_det",
        "transform_type": "mask",
        "mask_mode": "detector",
        "detector": "passport",
        "token_mode": "tokenize",
        "token_prefix": "TOK_",
        "token_ttl": 3600,
    })
    assert resp.status_code == 422


def test_update_transform(client, db):
    """PUT updates an existing transform."""
    _enable_resp_transform(db)
    backend = make_backend(db, name="be_upd")
    rt = make_response_transform(
        db,
        name="rt_upd",
        backend_id=backend.id,
        transform_type="replace",
        find_regex="old",
        replace_string="new",
    )
    resp = client.put(f"/api/v1/resp-transforms/{rt.id}", json={
        "replace_string": "updated",
    })
    assert resp.status_code == 200
    assert resp.json()["replace_string"] == "updated"


def test_update_not_found(client, db):
    """PUT on non-existent transform returns 404."""
    _enable_resp_transform(db)
    resp = client.put("/api/v1/resp-transforms/99999", json={"enabled": False})
    assert resp.status_code == 404


def test_delete_transform(client, db):
    """DELETE removes a transform."""
    _enable_resp_transform(db)
    rt = make_response_transform(
        db,
        name="rt_del",
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    resp = client.delete(f"/api/v1/resp-transforms/{rt.id}")
    assert resp.status_code == 200
    # Verify it's gone
    resp2 = client.get("/api/v1/resp-transforms")
    assert all(r["id"] != rt.id for r in resp2.json())


def test_delete_not_found(client, db):
    """DELETE on non-existent transform returns 404."""
    _enable_resp_transform(db)
    resp = client.delete("/api/v1/resp-transforms/99999")
    assert resp.status_code == 404


def test_reorder_transforms(client, db):
    """PUT /reorder updates priorities."""
    _enable_resp_transform(db)
    rt1 = make_response_transform(db, name="rt_r1", transform_type="replace", find_regex="a", replace_string="b", priority=0)
    rt2 = make_response_transform(db, name="rt_r2", transform_type="replace", find_regex="c", replace_string="d", priority=1)
    resp = client.put("/api/v1/resp-transforms/reorder", json={
        "ordered_ids": [rt2.id, rt1.id],
    })
    assert resp.status_code == 200
    # Verify priorities were swapped
    listing = client.get("/api/v1/resp-transforms").json()
    by_id = {r["id"]: r for r in listing}
    assert by_id[rt2.id]["priority"] == 0
    assert by_id[rt1.id]["priority"] == 1


def test_validate_endpoint_valid(client, db):
    """POST /validate returns valid=True for a correct spec."""
    # Validate works even when feature is disabled (no DB write)
    resp = client.post("/api/v1/resp-transforms/validate", json={
        "transform_type": "replace",
        "find_regex": "<title>(.*?)</title>",
        "replace_string": "<title>NEW</title>",
    })
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_validate_endpoint_invalid(client, db):
    """POST /validate returns valid=False for an invalid spec."""
    resp = client.post("/api/v1/resp-transforms/validate", json={
        "transform_type": "replace",
        "find_regex": "[unclosed",
        "replace_string": "foo",
    })
    assert resp.status_code == 200
    assert resp.json()["valid"] is False
    assert resp.json()["error"] is not None


def test_list_with_existing_transforms(client, db):
    """GET returns all transforms ordered by priority."""
    _enable_resp_transform(db)
    make_response_transform(db, name="rt_l1", transform_type="replace", find_regex="a", replace_string="b", priority=1)
    make_response_transform(db, name="rt_l2", transform_type="replace", find_regex="c", replace_string="d", priority=0)
    resp = client.get("/api/v1/resp-transforms")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Ordered by priority ascending
    assert data[0]["priority"] <= data[1]["priority"]


# ---------------------------------------------------------------------------
# Feature-gating tests (mutating endpoints return 403 when feature is off)
# ---------------------------------------------------------------------------

def test_create_blocked_when_disabled(client, db):
    """POST returns 403 when the feature is not enabled."""
    # Feature is disabled by default
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_blocked",
        "transform_type": "replace",
        "find_regex": "foo",
        "replace_string": "bar",
    })
    assert resp.status_code == 403
    assert "not enabled" in resp.json()["detail"].lower()


def test_update_blocked_when_disabled(client, db):
    """PUT returns 403 when the feature is not enabled."""
    rt = make_response_transform(
        db,
        name="rt_blocked_upd",
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    resp = client.put(f"/api/v1/resp-transforms/{rt.id}", json={"enabled": False})
    assert resp.status_code == 403


def test_delete_blocked_when_disabled(client, db):
    """DELETE returns 403 when the feature is not enabled."""
    rt = make_response_transform(
        db,
        name="rt_blocked_del",
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    resp = client.delete(f"/api/v1/resp-transforms/{rt.id}")
    assert resp.status_code == 403


def test_reorder_blocked_when_disabled(client, db):
    """PUT /reorder returns 403 when the feature is not enabled."""
    resp = client.put("/api/v1/resp-transforms/reorder", json={"ordered_ids": [1, 2]})
    assert resp.status_code == 403


def test_validate_works_when_disabled(client, db):
    """POST /validate works even when the feature is not enabled."""
    resp = client.post("/api/v1/resp-transforms/validate", json={
        "transform_type": "replace",
        "find_regex": "foo",
        "replace_string": "bar",
    })
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


# ---------------------------------------------------------------------------
# detokenize_query field tests
# ---------------------------------------------------------------------------


def test_create_mask_with_detokenize_query(client, db):
    """POST creates a mask rule with detokenize_query=True."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_detok",
        "transform_type": "mask",
        "mask_mode": "detector",
        "detector": "ssn",
        "token_mode": "tokenize",
        "token_prefix": "SSN_",
        "token_ttl": 3600,
        "detokenize_query": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["detokenize_query"] is True


def test_create_mask_detokenize_query_defaults_false(client, db):
    """POST without detokenize_query defaults to False."""
    _enable_resp_transform(db)
    resp = client.post("/api/v1/resp-transforms", json={
        "name": "rt_no_detok",
        "transform_type": "mask",
        "mask_mode": "detector",
        "detector": "ssn",
        "token_mode": "tokenize",
        "token_prefix": "SSN_",
        "token_ttl": 3600,
    })
    assert resp.status_code == 200
    assert resp.json()["detokenize_query"] is False


def test_update_detokenize_query(client, db):
    """PUT updates detokenize_query on an existing transform."""
    _enable_resp_transform(db)
    rt = make_response_transform(
        db,
        name="rt_upd_detok",
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=False,
    )
    resp = client.put(f"/api/v1/resp-transforms/{rt.id}", json={
        "detokenize_query": True,
    })
    assert resp.status_code == 200
    assert resp.json()["detokenize_query"] is True
