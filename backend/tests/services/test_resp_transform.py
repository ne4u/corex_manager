"""Tests for the response transform service layer."""
import pytest
from app.services import resp_transform as rt_svc
from app.services.resp_transform import (
    create_response_transform,
    delete_response_transform,
    get_response_transform,
    list_response_transforms,
    reorder_response_transforms,
    update_response_transform,
    validate_regex,
    validate_response_transform,
)
from app.schemas.resp_transform import (
    ResponseTransformCreate,
    ResponseTransformUpdate,
    ResponseTransformValidateRequest,
)
from tests.factories import make_backend, make_response_transform, make_server


def test_validate_regex_valid():
    assert validate_regex("<title>(.*?)</title>") is True


def test_validate_regex_empty():
    assert validate_regex("") is True
    assert validate_regex(None) is True


def test_validate_regex_invalid():
    assert validate_regex("[unclosed") is False


def test_create_and_get(db):
    t_in = ResponseTransformCreate(
        name="rt_svc_create",
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    obj = create_response_transform(db, t_in)
    assert obj.id > 0
    fetched = get_response_transform(db, obj.id)
    assert fetched is not None
    assert fetched.name == "rt_svc_create"


def test_list_ordered_by_priority(db):
    make_response_transform(db, name="rt_p1", transform_type="replace", find_regex="a", replace_string="b", priority=1)
    make_response_transform(db, name="rt_p0", transform_type="replace", find_regex="c", replace_string="d", priority=0)
    items = list_response_transforms(db)
    assert items[0].priority <= items[1].priority


def test_update(db):
    rt = make_response_transform(db, name="rt_upd", transform_type="replace", find_regex="old", replace_string="old")
    t_in = ResponseTransformUpdate(replace_string="new_value")
    updated = update_response_transform(db, rt.id, t_in)
    assert updated is not None
    assert updated.replace_string == "new_value"


def test_update_not_found(db):
    t_in = ResponseTransformUpdate(replace_string="x")
    assert update_response_transform(db, 99999, t_in) is None


def test_delete(db):
    rt = make_response_transform(db, name="rt_del", transform_type="replace", find_regex="a", replace_string="b")
    assert delete_response_transform(db, rt.id) is True
    assert get_response_transform(db, rt.id) is None


def test_delete_not_found(db):
    assert delete_response_transform(db, 99999) is False


def test_reorder(db):
    rt1 = make_response_transform(db, name="rt_r1", transform_type="replace", find_regex="a", replace_string="b", priority=0)
    rt2 = make_response_transform(db, name="rt_r2", transform_type="replace", find_regex="c", replace_string="d", priority=1)
    reorder_response_transforms(db, [rt2.id, rt1.id])
    db.expire_all()
    assert get_response_transform(db, rt2.id).priority == 0
    assert get_response_transform(db, rt1.id).priority == 1


def test_validate_response_transform_valid():
    req = ResponseTransformValidateRequest(
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
    )
    valid, error = validate_response_transform(req)
    assert valid is True
    assert error is None


def test_validate_response_transform_invalid_regex():
    req = ResponseTransformValidateRequest(
        transform_type="replace",
        find_regex="[bad",
        replace_string="bar",
    )
    valid, error = validate_response_transform(req)
    assert valid is False
    assert error is not None


def test_validate_response_transform_missing_fields():
    req = ResponseTransformValidateRequest(
        transform_type="replace",
        find_regex=None,
        replace_string="bar",
    )
    valid, error = validate_response_transform(req)
    assert valid is False


def test_backends_with_transforms_scoped(db):
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_b")
    make_server(db, be_b.id)
    make_response_transform(db, name="rt_a", backend_id=be_a.id, transform_type="replace", find_regex="x", replace_string="y")
    ids = rt_svc.backends_with_transforms(db)
    assert be_a.id in ids
    assert be_b.id not in ids


def test_backends_with_transforms_via_ids(db):
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_b")
    make_server(db, be_b.id)
    make_response_transform(db, name="rt_both", backend_ids=[be_a.id, be_b.id], transform_type="replace", find_regex="x", replace_string="y")
    ids = rt_svc.backends_with_transforms(db)
    assert be_a.id in ids
    assert be_b.id in ids


def test_backends_with_transforms_disabled_excluded(db):
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    make_response_transform(db, name="rt_dis", backend_id=be_a.id, transform_type="replace", find_regex="x", replace_string="y", enabled=False)
    ids = rt_svc.backends_with_transforms(db)
    assert be_a.id not in ids


def test_matches_backend_any_with_scoped_rule(db):
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_b")
    make_server(db, be_b.id)
    make_response_transform(db, name="rt_a", backend_id=be_a.id, transform_type="replace", find_regex="x", replace_string="y")
    assert rt_svc._matches_backend_any(db, be_a) is True
    assert rt_svc._matches_backend_any(db, be_b) is False


def test_matches_backend_any_global_rule(db):
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    make_response_transform(db, name="rt_global", transform_type="replace", find_regex="x", replace_string="y")
    assert rt_svc._matches_backend_any(db, be_a) is True


def test_matches_backend_any_no_rules(db):
    be_a = make_backend(db, name="be_a")
    make_server(db, be_a.id)
    assert rt_svc._matches_backend_any(db, be_a) is False


def test_rule_to_dict_replace(db):
    rt = make_response_transform(
        db,
        name="rt_dict",
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
        content_types="text/html, application/json",
        max_body_size=2048,
    )
    d = rt_svc._rule_to_dict(rt)
    assert d["transform_type"] == "replace"
    assert d["find_regex"] == "foo"
    assert d["replace_string"] == "bar"
    assert d["content_types"] == ["text/html", "application/json"]
    assert d["max_body_size"] == 2048


def test_rule_to_dict_mask(db):
    rt = make_response_transform(
        db,
        name="rt_dict_mask",
        transform_type="mask",
        mask_mode="detector",
        detector="email",
        token_mode="tokenize",
        token_prefix="TOK_",
        token_ttl=1800,
    )
    d = rt_svc._rule_to_dict(rt)
    assert d["transform_type"] == "mask"
    assert d["mask_mode"] == "detector"
    assert d["detector"] == "email"
    assert d["token_mode"] == "tokenize"
    assert d["token_prefix"] == "TOK_"
    assert d["token_ttl"] == 1800


def _baseline_configs(db, tmp_path, monkeypatch):
    """Point config paths at tmp_path and write .applied baselines for every
    generated config so get_config_status starts False. Only resp-transform
    edits can subsequently move it."""
    from app.core.config import get_settings
    from app.services import haproxy
    from app.services.settings import set_setting
    import os

    s = get_settings()
    rt_dir = tmp_path / "resp-transform"
    rt_dir.mkdir()
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(rt_dir))
    monkeypatch.setattr(s, "SECURITY_LISTS_DIR", str(lists_dir))
    monkeypatch.setattr(s, "HAPROXY_CONFIG_PATH", str(tmp_path / "haproxy.cfg"))
    monkeypatch.setattr(s, "CORAZA_SPOA_ENABLED", False)
    # Enable the resp_transform filter so the backend filter line is stable.
    set_setting(db, "resp_transform_enabled", "true")

    cfg_path = str(tmp_path / "haproxy.cfg")
    baseline = haproxy.generate_config(db)
    with open(cfg_path, "w") as f:
        f.write(baseline)
    with open(f"{cfg_path}.applied", "w") as f:
        f.write(baseline)

    # Risk rules data file baseline (if risk scoring is importable).
    try:
        from app.services.risk_scoring import generate_risk_rules_data, _risk_rules_data_path
        rrd_path = _risk_rules_data_path()
        rrd = generate_risk_rules_data(db)
        os.makedirs(os.path.dirname(rrd_path), exist_ok=True)
        with open(rrd_path, "w") as f:
            f.write(rrd)
        with open(f"{rrd_path}.applied", "w") as f:
            f.write(rrd)
    except Exception:
        pass


def test_config_status_detects_resp_transform_edit(db, tmp_path, monkeypatch):
    """Editing a ResponseTransform should make get_config_status report unapplied
    changes (the change banner appears) even when haproxy.cfg itself is unchanged."""
    from app.services.config import get_config_status
    from app.services.resp_transform import write_resp_transform_files

    be = make_backend(db, name="be_rt")
    make_server(db, be.id)
    make_response_transform(
        db, name="rt1", backend_id=be.id, transform_type="replace",
        find_regex="foo", replace_string="bar",
    )

    _baseline_configs(db, tmp_path, monkeypatch)

    # Apply: writes the per-backend JSON → status should be False.
    write_resp_transform_files(db)
    assert get_config_status(db) is False

    # Edit the transform's replace_string. haproxy.cfg is unchanged (the filter
    # line is identical) — only the JSON config content changes. The banner
    # must still appear.
    rt = rt_svc.list_response_transforms(db)[0]
    rt_svc.update_response_transform(db, rt.id, ResponseTransformUpdate(replace_string="baz"))
    assert get_config_status(db) is True

    # Re-apply → status back to False.
    write_resp_transform_files(db)
    assert get_config_status(db) is False


def test_config_status_detects_resp_transform_add(db, tmp_path, monkeypatch):
    """Adding a ResponseTransform to a backend that already had one (so the
    filter line is already present) must trigger the banner via the JSON diff."""
    from app.services.config import get_config_status
    from app.services.resp_transform import write_resp_transform_files

    be = make_backend(db, name="be_rt2")
    make_server(db, be.id)
    make_response_transform(
        db, name="rt1", backend_id=be.id, transform_type="replace",
        find_regex="foo", replace_string="bar",
    )

    _baseline_configs(db, tmp_path, monkeypatch)
    write_resp_transform_files(db)
    assert get_config_status(db) is False

    # Add a second transform to the same backend. haproxy.cfg's filter line is
    # unchanged; only the JSON rules array grows.
    make_response_transform(
        db, name="rt2", backend_id=be.id, transform_type="replace",
        find_regex="a", replace_string="b", priority=1,
    )
    assert get_config_status(db) is True

    write_resp_transform_files(db)
    assert get_config_status(db) is False


def test_config_status_detects_resp_transform_delete(db, tmp_path, monkeypatch):
    """Deleting a ResponseTransform must trigger the banner (orphan/stale detection)."""
    from app.services.config import get_config_status
    from app.services.resp_transform import write_resp_transform_files

    be = make_backend(db, name="be_rt3")
    make_server(db, be.id)
    rt = make_response_transform(
        db, name="rt1", backend_id=be.id, transform_type="replace",
        find_regex="foo", replace_string="bar",
    )

    _baseline_configs(db, tmp_path, monkeypatch)
    write_resp_transform_files(db)
    assert get_config_status(db) is False

    rt_svc.delete_response_transform(db, rt.id)
    # The on-disk JSON still holds the old rule (stale) → generated is empty → diff.
    assert get_config_status(db) is True


def test_generate_resp_transform_file_contents_matches_write(db, tmp_path, monkeypatch):
    """generate_resp_transform_file_contents must produce identical text to what
    write_resp_transform_files writes to disk."""
    import json
    import os
    from app.core.config import get_settings
    from app.services.resp_transform import (
        generate_resp_transform_file_contents,
        write_resp_transform_files,
    )

    s = get_settings()
    rt_dir = tmp_path / "resp-transform"
    rt_dir.mkdir()
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(rt_dir))

    be = make_backend(db, name="be_match")
    make_server(db, be.id)
    make_response_transform(
        db, name="rt1", backend_id=be.id, transform_type="replace",
        find_regex="foo", replace_string="bar",
    )

    generated = generate_resp_transform_file_contents(db)
    assert "be_match.json" in generated
    # Round-trip: the generated text is valid JSON with a rules array.
    parsed = json.loads(generated["be_match.json"])
    assert parsed["rules"][0]["replace_string"] == "bar"

    write_resp_transform_files(db)
    with open(os.path.join(str(rt_dir), "be_match.json")) as f:
        on_disk = f.read()
    assert on_disk == generated["be_match.json"]


# ---------------------------------------------------------------------------
# detokenize_query — query-string detokenization config
# ---------------------------------------------------------------------------


def test_rule_to_dict_includes_detokenize_query(db):
    """_rule_to_dict includes detokenize_query when True."""
    rt = make_response_transform(
        db,
        name="rt_detok",
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    d = rt_svc._rule_to_dict(rt)
    assert d["detokenize_query"] is True


def test_rule_to_dict_omits_detokenize_query_when_false(db):
    """_rule_to_dict does not include detokenize_query when False (default)."""
    rt = make_response_transform(
        db,
        name="rt_no_detok",
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=False,
    )
    d = rt_svc._rule_to_dict(rt)
    assert "detokenize_query" not in d


def test_build_query_detok_config_includes_enabled_mask_rules(db):
    """_build_query_detok_config includes enabled mask rules with detokenize_query=True."""
    be = make_backend(db, name="be_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_detok_on",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    config = rt_svc._build_query_detok_config(db)
    assert len(config["rules"]) == 1
    assert config["rules"][0]["token_prefix"] == "SSN_"
    assert config["rules"][0]["token_mode"] == "tokenize"


def test_build_query_detok_config_excludes_detokenize_query_false(db):
    """_build_query_detok_config excludes mask rules with detokenize_query=False."""
    be = make_backend(db, name="be_no_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_detok_off",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=False,
    )
    config = rt_svc._build_query_detok_config(db)
    assert len(config["rules"]) == 0


def test_build_query_detok_config_excludes_non_mask_rules(db):
    """_build_query_detok_config excludes replace/inject rules even with detokenize_query=True."""
    be = make_backend(db, name="be_replace_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_replace_detok",
        backend_id=be.id,
        transform_type="replace",
        find_regex="foo",
        replace_string="bar",
        detokenize_query=True,
    )
    config = rt_svc._build_query_detok_config(db)
    assert len(config["rules"]) == 0


def test_build_query_detok_config_excludes_disabled(db):
    """_build_query_detok_config excludes disabled mask rules."""
    be = make_backend(db, name="be_disabled_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_disabled_detok",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
        enabled=False,
    )
    config = rt_svc._build_query_detok_config(db)
    assert len(config["rules"]) == 0


def test_build_query_detok_config_mixed_modes(db):
    """_build_query_detok_config includes both tokenize and encrypt mode rules."""
    be = make_backend(db, name="be_mixed")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_tok",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    make_response_transform(
        db,
        name="rt_enc",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="credit_card",
        token_mode="encrypt",
        token_prefix="ENC_",
        encrypt_key_env="RESP_TRANSFORM_KEY",
        detokenize_query=True,
    )
    config = rt_svc._build_query_detok_config(db)
    assert len(config["rules"]) == 2
    prefixes = {r["token_prefix"] for r in config["rules"]}
    assert prefixes == {"SSN_", "ENC_"}


def test_write_query_detokenize_config_writes_file(db, tmp_path, monkeypatch):
    """write_query_detokenize_config writes the global JSON config file."""
    import json
    import os
    from app.core.config import get_settings

    s = get_settings()
    rt_dir = tmp_path / "resp-transform"
    rt_dir.mkdir()
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(rt_dir))

    be = make_backend(db, name="be_write_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_write_detok",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    result = rt_svc.write_query_detokenize_config(db)
    assert result["rule_count"] == 1

    filepath = os.path.join(str(rt_dir), "query_detokenize.json")
    with open(filepath) as f:
        config = json.load(f)
    assert len(config["rules"]) == 1
    assert config["rules"][0]["token_prefix"] == "SSN_"


def test_mask_detokenize_prefixes_for_backend_scoped(db):
    """_mask_detokenize_prefixes_for_backend returns prefixes only for matching backends."""
    be_a = make_backend(db, name="be_detok_a")
    make_server(db, be_a.id)
    be_b = make_backend(db, name="be_detok_b")
    make_server(db, be_b.id)
    make_response_transform(
        db,
        name="rt_detok_a",
        backend_id=be_a.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    assert rt_svc._mask_detokenize_prefixes_for_backend(db, be_a) == ["SSN_"]
    assert rt_svc._mask_detokenize_prefixes_for_backend(db, be_b) == []


def test_mask_detokenize_prefixes_for_backend_multiple(db):
    """_mask_detokenize_prefixes_for_backend returns multiple prefixes when multiple rules apply."""
    be = make_backend(db, name="be_multi_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_ssn",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    make_response_transform(
        db,
        name="rt_cc",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="credit_card",
        token_mode="encrypt",
        token_prefix="ENC_",
        encrypt_key_env="RESP_TRANSFORM_KEY",
        detokenize_query=True,
    )
    prefixes = rt_svc._mask_detokenize_prefixes_for_backend(db, be)
    assert set(prefixes) == {"SSN_", "ENC_"}


def test_generate_resp_transform_file_contents_includes_query_detokenize(db, tmp_path, monkeypatch):
    """generate_resp_transform_file_contents includes query_detokenize.json."""
    import json
    from app.core.config import get_settings

    s = get_settings()
    rt_dir = tmp_path / "resp-transform"
    rt_dir.mkdir()
    monkeypatch.setattr(s, "RESP_TRANSFORM_DIR", str(rt_dir))

    be = make_backend(db, name="be_gen_detok")
    make_server(db, be.id)
    make_response_transform(
        db,
        name="rt_gen_detok",
        backend_id=be.id,
        transform_type="mask",
        mask_mode="detector",
        detector="ssn",
        token_mode="tokenize",
        token_prefix="SSN_",
        token_ttl=3600,
        detokenize_query=True,
    )
    generated = rt_svc.generate_resp_transform_file_contents(db)
    assert "query_detokenize.json" in generated
    parsed = json.loads(generated["query_detokenize.json"])
    assert len(parsed["rules"]) == 1
    assert parsed["rules"][0]["token_prefix"] == "SSN_"
