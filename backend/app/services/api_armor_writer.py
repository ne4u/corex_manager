"""API Armor data-file writer.

Writes the runtime data bundle the haproxy-api-armor Rust module reads:
  - data/api-armor/schema-index.json       (maps method+path -> schema files)
  - data/api-armor/schemas/{file}.json      (per-endpoint JSON Schemas)
  - data/api-armor/api-keys/{name}.lst      (one key per line)
  - data/api-armor/auth-policies.json       (all enabled auth policies)
  - data/api-armor/profiles.json            (learned behavioral baselines)

Called from haproxy.write_config() before config validation.
"""
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.api_armor import ApiKeyList, ApiProfile, ApiSchema, AuthPolicy, OpenApiSpec

settings = get_settings()


# Filename sanitizer. Must match the safe-name logic used for other data files.
_safe_name_re = re.compile(r"[^A-Za-z0-9._-]")


def _safe_filename(name: str) -> str:
    if not isinstance(name, str):
        name = str(name)
    cleaned = _safe_name_re.sub("_", name).strip("._-").strip() or "unnamed"
    if cleaned in (".", ".."):
        cleaned = "unnamed"
    return cleaned


def _safe_schema_filename(method: str, path: str) -> str:
    """Build a unique, filesystem-safe name for a schema file.

    The path pattern (e.g. /api/v1/users/:id) is preserved; colons from :param
    are kept because they are safe on all target filesystems and informative.
    """
    name = f"{_safe_filename(method)}_{_safe_filename(path)}"
    # Collapse repeated underscores and leading/trailing separators.
    name = re.sub(r"_+", "_", name).strip("_")
    return name or "schema"


def _schema_path_pattern_matches(pattern: str, path: str) -> bool:
    """Check if a concrete path matches a schema path pattern with :param wildcards.

    This is a mirror of the logic in api_armor_schemas.path_matches for use in
    the schema index: the index stores both the pattern and a regex the Rust
    module can use at runtime.
    """
    regex = re.sub(r":[^/]+", r"[^/]+", pattern)
    regex = f"^{regex}$"
    return bool(re.match(regex, path))


def _build_schema_index(schemas: List[ApiSchema]) -> List[Dict[str, Any]]:
    """Build the schema index used at runtime by the Rust module.

    Each entry contains the method, the pattern path, a regex, and the relative
    schema file path. The Rust module picks the first matching method+regex.
    OpenAPI-sourced schemas are preferred over learned schemas by emitting them
    first.
    """
    index: List[Dict[str, Any]] = []
    # Prefer openapi, then learned, to match get_schema_for_endpoint behavior.
    ordered = sorted(schemas, key=lambda s: 0 if s.source == "openapi" else 1)
    for schema in ordered:
        if not schema.enabled:
            continue
        filename = f"schemas/{_safe_schema_filename(schema.method, schema.path)}.json"
        regex = re.sub(r":[^/]+", r"[^/]+", schema.path)
        regex = f"^{regex}$"
        index.append({
            "id": schema.id,
            "name": schema.name,
            "method": schema.method,
            "path_pattern": schema.path,
            "path_regex": regex,
            "file": filename,
            "source": schema.source,
            "sample_count": schema.sample_count or 0,
        })
    return index


def write_api_armor_schemas(db: Session, base_dir: str) -> Dict[str, Any]:
    """Write schema index and per-endpoint schema files.

    Returns a summary with the index path and schema count.
    """
    schemas_dir = os.path.join(base_dir, "schemas")
    os.makedirs(schemas_dir, exist_ok=True)

    schemas = db.query(ApiSchema).filter(ApiSchema.enabled == True).all()  # noqa: E712
    index = _build_schema_index(schemas)

    index_path = os.path.join(base_dir, "schema-index.json")
    expected_files: Set[str] = {index_path}

    with open(index_path, "w") as f:
        json.dump({"schemas": index, "generated_at": _utc_now_iso()}, f, indent=2)

    for entry, schema in zip(index, schemas):
        # Re-derive filename to stay in sync with the index.
        filename = _safe_schema_filename(schema.method, schema.path) + ".json"
        path = os.path.join(schemas_dir, filename)
        with open(path, "w") as f:
            json.dump(schema.schema or {}, f, indent=2)
        expected_files.add(path)

    # Remove stale schema files (deleted or renamed schemas).
    _remove_stale_files(schemas_dir, expected_files)

    return {"index_path": index_path, "schema_count": len(index)}


def write_api_armor_api_keys(db: Session, base_dir: str) -> Dict[str, Any]:
    """Write API key lists as one file per list.

    Returns a summary with the list files and key counts.
    """
    keys_dir = os.path.join(base_dir, "api-keys")
    os.makedirs(keys_dir, exist_ok=True)

    key_lists = db.query(ApiKeyList).all()
    expected_files: Set[str] = set()
    summary: List[Dict[str, Any]] = []

    for key_list in key_lists:
        filename = f"{_safe_filename(key_list.name)}.lst"
        path = os.path.join(keys_dir, filename)
        entries = [e.value for e in key_list.entries]
        content = "".join(f"{v}\n" for v in entries)
        with open(path, "w") as f:
            f.write(content)
        # Keep keys files private.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        expected_files.add(path)
        summary.append({"list_id": key_list.id, "name": key_list.name, "path": path, "count": len(entries)})

    _remove_stale_files(keys_dir, expected_files, extension=".lst")

    return {"dir": keys_dir, "lists": summary}


def write_api_armor_auth_policies(db: Session, base_dir: str) -> Dict[str, Any]:
    """Write enabled auth policies to auth-policies.json.

    The Rust module reads this file and matches a request to the active policy
    based on txn variables set in the HAProxy frontend (Phase 3).
    """
    policies = (
        db.query(AuthPolicy)
        .filter(AuthPolicy.enabled == True)  # noqa: E712
        .all()
    )

    data: List[Dict[str, Any]] = []
    for policy in policies:
        api_key_list_name = None
        if policy.api_key_list_id:
            lst = db.get(ApiKeyList, policy.api_key_list_id)
            if lst:
                api_key_list_name = lst.name

        data.append({
            "id": policy.id,
            "name": policy.name,
            "listener_ids": policy.listener_ids or [],
            "backend_ids": policy.backend_ids or [],
            "auth_type": policy.auth_type,
            "jwt_algorithm": policy.jwt_algorithm,
            "jwt_secret_env": policy.jwt_secret_env,
            "jwt_jwks_url": policy.jwt_jwks_url,
            "jwt_issuer": policy.jwt_issuer,
            "jwt_audience": policy.jwt_audience,
            "jwt_claim_headers": policy.jwt_claim_headers or [],
            "api_key_header": policy.api_key_header,
            "api_key_list_id": policy.api_key_list_id,
            "api_key_list_name": api_key_list_name,
            "on_failure": policy.on_failure,
        })

    path = os.path.join(base_dir, "auth-policies.json")
    with open(path, "w") as f:
        json.dump({"policies": data, "generated_at": _utc_now_iso()}, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    return {"path": path, "count": len(data)}


def write_api_armor_profiles(db: Session, base_dir: str) -> Dict[str, Any]:
    """Write learned profiles to profiles.json.

    Only learned profiles are written; unlearned profiles are kept in the DB
    but not used for runtime anomaly checks.
    """
    profiles = (
        db.query(ApiProfile)
        .filter(ApiProfile.learned == True)  # noqa: E712
        .all()
    )

    data: List[Dict[str, Any]] = []
    for p in profiles:
        data.append({
            "id": p.id,
            "listener_id": p.listener_id,
            "method": p.method,
            "path": p.path,
            "dimensions": p.dimensions or {},
            "status_codes": p.status_codes or {},
        })

    path = os.path.join(base_dir, "profiles.json")
    with open(path, "w") as f:
        json.dump({"profiles": data, "generated_at": _utc_now_iso()}, f, indent=2)

    return {"path": path, "count": len(data)}


def write_api_armor_files(db: Session) -> Dict[str, Any]:
    """Write the complete API Armor data bundle for the Rust module.

    Returns a summary dict describing every file written.
    """
    base_dir = settings.API_ARMOR_DIR
    os.makedirs(base_dir, exist_ok=True)

    result = {
        "base_dir": base_dir,
        "schemas": write_api_armor_schemas(db, base_dir),
        "api_keys": write_api_armor_api_keys(db, base_dir),
        "auth_policies": write_api_armor_auth_policies(db, base_dir),
        "profiles": write_api_armor_profiles(db, base_dir),
    }
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _remove_stale_files(directory: str, expected: Set[str], extension: str = ".json") -> None:
    """Remove files in directory that are no longer in the expected set."""
    if not os.path.isdir(directory):
        return
    for existing in os.listdir(directory):
        if not existing.endswith(extension):
            continue
        path = os.path.join(directory, existing)
        if path not in expected and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
