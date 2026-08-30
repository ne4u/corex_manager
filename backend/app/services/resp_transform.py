"""Response Transform service — CRUD, validation, and per-backend config file writing.

Response Transforms are per-backend rules that rewrite, inject, or mask response
body content via the haproxy-resp-transform Rust Lua filter. The filter reads
JSON config files written by ``write_resp_transform_files``; Valkey connection
params for tokenize mode are injected into the global ``modules.lua`` loader by
``haproxy.py`` (not stored in the per-backend JSON).
"""
import json
import os
import re
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.routing import ResponseTransform
from ..models.proxy import Backend
from ..schemas.resp_transform import (
    ResponseTransformCreate,
    ResponseTransformUpdate,
    ResponseTransformValidateRequest,
)

settings = get_settings()

# Built-in PII detector regex patterns (must match the Rust module's constants).
DETECTORS: Dict[str, str] = {
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "phone": r"\+?\d[\d\s().-]{7,}\d",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,19}\b",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


def validate_regex(pattern: Optional[str]) -> bool:
    """Compile-check a regex pattern. Returns True if valid (or empty)."""
    if not pattern:
        return True
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _rule_to_dict(rule: ResponseTransform) -> Dict[str, Any]:
    """Convert a ResponseTransform row to the JSON config format the Rust filter expects."""
    content_types: List[str] = []
    if rule.content_types:
        content_types = [c.strip() for c in rule.content_types.split(",") if c.strip()]
    d: Dict[str, Any] = {
        "id": rule.id,
        "enabled": bool(rule.enabled),
        "priority": rule.priority,
        "transform_type": rule.transform_type,
        "content_types": content_types,
        "max_body_size": rule.max_body_size or 1048576,
    }
    if rule.find_regex:
        d["find_regex"] = rule.find_regex
    if rule.replace_string is not None:
        d["replace_string"] = rule.replace_string
    if rule.inject_string is not None:
        d["inject_string"] = rule.inject_string
    if rule.inject_position:
        d["inject_position"] = rule.inject_position
    if rule.mask_mode:
        d["mask_mode"] = rule.mask_mode
    if rule.detector:
        d["detector"] = rule.detector
    if rule.token_mode:
        d["token_mode"] = rule.token_mode
    if rule.token_prefix:
        d["token_prefix"] = rule.token_prefix
    if rule.token_ttl is not None:
        d["token_ttl"] = rule.token_ttl
    if rule.encrypt_key_env:
        d["encrypt_key_env"] = rule.encrypt_key_env
    if rule.detokenize_query:
        d["detokenize_query"] = True
    return d


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_response_transforms(db: Session) -> List[ResponseTransform]:
    return db.query(ResponseTransform).order_by(ResponseTransform.priority).all()


def get_response_transform(db: Session, rid: int) -> Optional[ResponseTransform]:
    return db.query(ResponseTransform).filter(ResponseTransform.id == rid).first()


def create_response_transform(db: Session, t_in: ResponseTransformCreate) -> ResponseTransform:
    obj = ResponseTransform(**t_in.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def update_response_transform(db: Session, rid: int, t_in: ResponseTransformUpdate) -> Optional[ResponseTransform]:
    obj = get_response_transform(db, rid)
    if not obj:
        return None
    for k, v in t_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


def delete_response_transform(db: Session, rid: int) -> bool:
    obj = get_response_transform(db, rid)
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True


def reorder_response_transforms(db: Session, ordered_ids: List[int]) -> None:
    for i, rid in enumerate(ordered_ids):
        obj = get_response_transform(db, rid)
        if obj:
            obj.priority = i
    db.commit()


def validate_response_transform(req: ResponseTransformValidateRequest) -> tuple:
    """Validate a transform spec without saving. Returns (valid, error)."""
    from ..schemas.resp_transform import ResponseTransformBase
    try:
        ResponseTransformBase(
            name="__validation__",
            transform_type=req.transform_type,
            find_regex=req.find_regex,
            replace_string=req.replace_string,
            inject_string=req.inject_string,
            inject_position=req.inject_position,
            mask_mode=req.mask_mode,
            detector=req.detector,
            token_mode=req.token_mode,
            token_prefix=req.token_prefix,
            token_ttl=req.token_ttl,
            encrypt_key_env=req.encrypt_key_env,
            detokenize_query=req.detokenize_query or False,
        )
        return True, None
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Config file writer (consumed by HAProxy config generation)
# ---------------------------------------------------------------------------

def backends_with_transforms(db: Session) -> Set[int]:
    """Return the set of backend IDs that have at least one enabled ResponseTransform."""
    ids: Set[int] = set()
    for t in db.query(ResponseTransform).filter(ResponseTransform.enabled == True).all():  # noqa: E712
        if t.backend_id:
            ids.add(t.backend_id)
        if t.backend_ids:
            ids.update(t.backend_ids)
    return ids


def _matches_backend_any(db: Session, backend: Backend) -> bool:
    """Check if any enabled ResponseTransform applies to the given backend."""
    transforms = db.query(ResponseTransform).filter(ResponseTransform.enabled == True).all()  # noqa: E712
    return any(_matches_backend(t, backend) for t in transforms)


def _matches_backend(transform: ResponseTransform, backend: Backend) -> bool:
    """Check if a transform applies to a given backend."""
    if not transform.enabled:
        return False
    if transform.backend_id and transform.backend_id == backend.id:
        return True
    if transform.backend_ids and backend.id in transform.backend_ids:
        return True
    # No backend specified = applies to all backends
    if not transform.backend_id and not transform.backend_ids:
        return True
    return False


def _build_resp_transform_configs(db: Session) -> Dict[str, dict]:
    """Build the per-backend config dicts the Rust filter expects, without writing.

    Returns ``{filename: config_dict}`` where ``filename`` is
    ``{safe_backend_name}.json`` (relative to ``RESP_TRANSFORM_DIR``). Includes
    Page Protect beacon injection rules where applicable. Used by both
    ``write_resp_transform_files`` (disk writer) and
    ``generate_resp_transform_file_contents`` (config-status comparison) so the
    two never drift.
    """
    from .page_protect import get_beacon_settings, build_beacon_rule

    backends = db.query(Backend).all()
    transforms = db.query(ResponseTransform).order_by(ResponseTransform.priority).all()

    # Page Protect beacon injection settings
    beacon = get_beacon_settings(db)
    beacon_enabled = beacon["enabled"]
    beacon_backend_ids = beacon.get("backend_ids") or []
    beacon_rule = None
    if beacon_enabled:
        beacon_rule = build_beacon_rule(beacon, beacon["beacon_script_path"])

    configs: Dict[str, dict] = {}
    for backend in backends:
        applicable = [t for t in transforms if _matches_backend(t, backend)]
        # Check if beacon injection applies to this backend
        has_beacon = (
            beacon_enabled
            and beacon_rule is not None
            and (not beacon_backend_ids or backend.id in beacon_backend_ids)
        )
        if not applicable and not has_beacon:
            continue
        safe_name = _safe_path_name(backend.name)
        filename = f"{safe_name}.json"
        rules = [_rule_to_dict(t) for t in applicable]
        if has_beacon and beacon_rule is not None:
            rules.insert(0, beacon_rule)
        configs[filename] = {"rules": rules}
    return configs


# ---------------------------------------------------------------------------
# Query detokenize config (global file read by the Rust detokenize_query action)
# ---------------------------------------------------------------------------

QUERY_DETOKENIZE_FILENAME = "query_detokenize.json"


def _build_query_detok_config(db: Session) -> Dict[str, Any]:
    """Build the global query-detokenize config dict from enabled mask rules
    with ``detokenize_query=True``.

    Returns ``{"rules": [...]}`` where each rule has ``token_prefix``,
    ``token_mode``, and ``encrypt_key_env``. The Rust action reads this file
    with mtime-based hot-reload.
    """
    transforms = db.query(ResponseTransform).filter(
        ResponseTransform.enabled == True,  # noqa: E712
        ResponseTransform.transform_type == "mask",
        ResponseTransform.detokenize_query == True,  # noqa: E712
    ).all()
    rules: List[Dict[str, Any]] = []
    for t in transforms:
        if not t.token_prefix:
            continue
        rules.append({
            "token_prefix": t.token_prefix,
            "token_mode": t.token_mode or "tokenize",
            "encrypt_key_env": t.encrypt_key_env,
        })
    return {"rules": rules}


def write_query_detokenize_config(db: Session) -> Dict[str, Any]:
    """Write the global query-detokenize config file for the Rust action.

    Contains all enabled mask rules with ``detokenize_query=True`` across all
    backends. Written to ``{RESP_TRANSFORM_DIR}/query_detokenize.json``.
    """
    config = _build_query_detok_config(db)
    out_dir = settings.RESP_TRANSFORM_DIR
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, QUERY_DETOKENIZE_FILENAME)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    return {"written": path, "rule_count": len(config["rules"])}


def _mask_detokenize_prefixes_for_backend(db: Session, backend: Backend) -> List[str]:
    """Return ``token_prefix`` values from enabled mask rules with
    ``detokenize_query=True`` that apply to the given backend.

    Used by haproxy.py to emit the per-backend ACL guard so the Lua action
    only runs on requests whose query string contains one of these prefixes.
    """
    transforms = db.query(ResponseTransform).filter(
        ResponseTransform.enabled == True,  # noqa: E712
        ResponseTransform.transform_type == "mask",
        ResponseTransform.detokenize_query == True,  # noqa: E712
    ).all()
    prefixes: List[str] = []
    for t in transforms:
        if t.token_prefix and _matches_backend(t, backend):
            prefixes.append(t.token_prefix)
    return prefixes


def generate_resp_transform_file_contents(db: Session) -> Dict[str, str]:
    """Return ``{filename: json_text}`` for every backend resp-transform config.

    ``filename`` is relative to ``RESP_TRANSFORM_DIR`` (e.g.
    ``"my_backend.json"``). Content is the serialized JSON the Rust filter
    reads. Used by the config-status check to detect unapplied response-transform
    edits without touching disk — mirrors ``generate_security_list_file_contents``.
    """
    configs = _build_resp_transform_configs(db)
    contents = {fname: json.dumps(cfg, indent=2) for fname, cfg in configs.items()}
    # Include the global query-detokenize config so pending-changes detection
    # catches edits to detokenize_query on mask rules.
    contents[QUERY_DETOKENIZE_FILENAME] = json.dumps(_build_query_detok_config(db), indent=2)
    return contents


def write_resp_transform_files(db: Session) -> Dict[str, Any]:
    """Write per-backend JSON config files for the Rust filter.

    For each backend that has >=1 enabled ResponseTransform (or a Page Protect
    beacon injection rule), writes ``{RESP_TRANSFORM_DIR}/{backend_name}.json``
    containing the rules array. Stale files (backends with no rules) are removed.
    Returns a summary dict.
    """
    import logging
    logger = logging.getLogger(__name__)

    out_dir = settings.RESP_TRANSFORM_DIR
    os.makedirs(out_dir, exist_ok=True)

    configs = _build_resp_transform_configs(db)
    written: List[str] = []
    removed: List[str] = []

    expected_files: Set[str] = set()
    for filename, config in configs.items():
        filepath = os.path.join(out_dir, filename)
        expected_files.add(filepath)
        rules = config["rules"]
        try:
            with open(filepath, "w") as f:
                json.dump(config, f, indent=2)
            written.append(filename)
            logger.info("write_resp_transform_files: wrote %s (%d rules)",
                        filepath, len(rules))
        except OSError as e:
            logger.error("write_resp_transform_files: FAILED to write %s: %s", filepath, e)

    # Write the global query-detokenize config (read by the Rust action).
    # Add it to expected_files so the stale cleanup below doesn't remove it.
    detok_result = write_query_detokenize_config(db)
    detok_path = os.path.join(out_dir, QUERY_DETOKENIZE_FILENAME)
    expected_files.add(detok_path)
    logger.info("write_resp_transform_files: wrote %s (%d query-detok rules)",
                detok_path, detok_result["rule_count"])

    # Remove stale files
    if os.path.isdir(out_dir):
        for existing in os.listdir(out_dir):
            if existing.endswith(".json"):
                fpath = os.path.join(out_dir, existing)
                if fpath not in expected_files:
                    try:
                        os.remove(fpath)
                        removed.append(existing)
                    except OSError:
                        pass

    return {"written": written, "removed": removed}


def _safe_path_name(name: str) -> str:
    """Sanitize a value used in a filesystem path (mirrors haproxy.py helper)."""
    if not isinstance(name, str):
        name = str(name)
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("_.-").strip() or "unnamed"
