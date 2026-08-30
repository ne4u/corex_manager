"""Config lifecycle and preview helpers."""
import difflib
import os
from typing import Any, Dict, List, Tuple

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.models import Setting
from ..models.tasks import ConfigSnapshot
from ..schemas.config import (
    ConfigApplyResponse,
    ConfigRevertResponse,
    ConfigSnapshotRollbackResponse,
)
from ..schemas.settings import SettingResponse
from ..services.coraza_config import generate_coraza_spoa_config
from ..services.haproxy import generate_config, generate_coraza_spoe_config
from ..services.settings import get_setting, set_setting
from ..services.tasks import get_task, queue_task


def _applied_snapshot_path(path: str) -> str:
    return f"{path}.applied"


def _ensure_applied_snapshot(path: str, generated: str) -> None:
    applied_path = _applied_snapshot_path(path)
    if os.path.exists(applied_path):
        return
    os.makedirs(os.path.dirname(applied_path), exist_ok=True)
    with open(applied_path, "w") as f:
        f.write(generated)


def _read_current_config(path: str) -> str:
    applied_path = _applied_snapshot_path(path)
    if os.path.exists(applied_path):
        with open(applied_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return ""


def _config_status_data(db: Session) -> Tuple[bool, Dict[str, str], Dict[str, str]]:
    cfg = get_settings()
    files: List[tuple[str, str, Any]] = [
        ("haproxy.cfg", cfg.HAPROXY_CONFIG_PATH, generate_config),
    ]
    if cfg.CORAZA_SPOA_ENABLED:
        files.append(("coraza.cfg", cfg.CORAZA_SPOE_CONFIG_PATH, generate_coraza_spoe_config))
        files.append(("coraza-spoa.yaml", cfg.CORAZA_SPOA_CONFIG_PATH, generate_coraza_spoa_config))

    # Risk rules data file (Lua) — compared so that risk ruleset changes
    # (e.g. density amplification) show as unapplied and trigger the banner.
    try:
        from ..services.risk_scoring import generate_risk_rules_data, _risk_rules_data_path
        files.append(("risk_rules_data.lua", _risk_rules_data_path(), generate_risk_rules_data))
    except Exception:
        pass  # risk scoring not configured — skip

    # Disk cache VCL is generated and applied alongside HAProxy config, so it
    # must also be compared for the "unapplied changes" banner and diff.
    disk_cache_on = get_setting(db, "disk_cache_enabled", str(cfg.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")
    if disk_cache_on:
        from ..models.models import CacheConfig
        any_disk = db.query(CacheConfig).filter(CacheConfig.disk_cache_enabled == True).first()  # noqa: E712
        if any_disk:
            from ..services.varnish import generate_vcl as generate_varnish_vcl
            files.append(("varnish.vcl", cfg.VARNISH_VCL_PATH, generate_varnish_vcl))

    # MCP Gateway config bundle — compared as decrypted plaintext because
    # Fernet uses a random IV (ciphertext comparison would always show a diff).
    # Wrapped in try/except so MCP failures don't break the entire config
    # status/diff system (e.g. MCP_SECRETS_KEY not set, bundle build error).
    mcp_on = get_setting(db, "mcp_gateway_enabled", str(cfg.MCP_GATEWAY_ENABLED)).lower() in ("true", "1", "yes")
    mcp_current = ""
    mcp_generated = ""
    mcp_failed = False
    if mcp_on:
        try:
            from ..services.mcp_config import generate_mcp_bundle_text, read_applied_mcp_bundle
            mcp_generated = generate_mcp_bundle_text(db)
            mcp_current = read_applied_mcp_bundle()
        except Exception:
            mcp_failed = True

    current: Dict[str, str] = {}
    generated: Dict[str, str] = {}
    unapplied = False
    for label, path, generator in files:
        gen = generator(db)
        generated[label] = gen
        cur = _read_current_config(path)
        current[label] = cur
        if cur != gen:
            unapplied = True

    # MCP bundle comparison (decrypted plaintext). If bundle generation failed,
    # treat as unapplied so the banner shows (the user needs to apply or fix
    # the MCP config), but don't include a broken diff entry.
    if mcp_on:
        if mcp_failed:
            unapplied = True
        else:
            current["mcp-bundle.json"] = mcp_current
            generated["mcp-bundle.json"] = mcp_generated
            if mcp_current != mcp_generated:
                unapplied = True

    # Security list files (.lst) — compared so that list edits and dynamic
    # feed refreshes show as unapplied and trigger the change banner. Both
    # generated content and on-disk applied snapshots are keyed by a
    # "lists/{subdir}/{name}.lst" label. Deleted lists (applied file exists
    # but no generated content) are also detected as unapplied.
    try:
        from ..services.security_lists import generate_security_list_file_contents
        sec_base = cfg.SECURITY_LISTS_DIR
        sec_gen = generate_security_list_file_contents(db)
        # Discover applied files on disk (including orphans from deleted lists).
        applied_rels: set = set()
        for sub in ("network", "asn", "geo", "ja4", "pattern"):
            sub_dir = os.path.join(sec_base, sub)
            if not os.path.isdir(sub_dir):
                continue
            for fn in os.listdir(sub_dir):
                if fn.endswith(".lst.applied"):
                    applied_rels.add(f"{sub}/{fn[:-len('.applied')]}")
        for rel in set(sec_gen) | applied_rels:
            label = f"lists/{rel}"
            gen = sec_gen.get(rel, "")
            cur = _read_current_config(os.path.join(sec_base, rel))
            generated[label] = gen
            current[label] = cur
            if cur != gen:
                unapplied = True
    except Exception:
        pass  # security lists not configured — skip

    # Response transform per-backend JSON configs — compared so that adding,
    # editing, or deleting a ResponseTransform (or Page Protect beacon settings)
    # shows as unapplied and triggers the change banner. The on-disk files are
    # only written during apply (write_resp_transform_files), so they reflect
    # the last-applied state. Deleted backends/transforms leave orphaned .json
    # files which are also detected as unapplied.
    try:
        from ..services.resp_transform import generate_resp_transform_file_contents
        rt_base = cfg.RESP_TRANSFORM_DIR
        rt_gen = generate_resp_transform_file_contents(db)
        # Discover on-disk files (including orphans from deleted backends/transforms).
        rt_applied: set = set()
        if os.path.isdir(rt_base):
            for fn in os.listdir(rt_base):
                if fn.endswith(".json"):
                    rt_applied.add(fn)
        for fn in set(rt_gen) | rt_applied:
            label = f"resp-transform/{fn}"
            gen = rt_gen.get(fn, "")
            cur = _read_current_config(os.path.join(rt_base, fn))
            generated[label] = gen
            current[label] = cur
            if cur != gen:
                unapplied = True
    except Exception:
        pass  # resp transform not configured — skip

    return unapplied, current, generated


def security_list_files_unapplied(db: Session) -> Tuple[bool, bool]:
    """Return ``(security_list_unapplied, other_unapplied)``.

    Used by the dynamic feed updater to decide whether to auto-apply after a
    feed refresh. Auto-apply only fires when the *sole* pending changes are
    security list files — unrelated pending config edits (backends, listeners,
    WAF rules, …) are never swept up by an automatic apply.
    """
    unapplied, current, generated = _config_status_data(db)
    if not unapplied:
        return (False, False)
    sec = any(current[lbl] != generated[lbl] for lbl in current if lbl.startswith("lists/"))
    other = any(current[lbl] != generated[lbl] for lbl in current if not lbl.startswith("lists/"))
    return (sec, other)


def _queue_and_wait(task_name: str, payload: dict, db: Session, error_detail: str):
    task_id = queue_task(task_name, payload=payload)
    task = get_task(db, task_id)
    if task and task.status in ("success", "failed"):
        if task.status == "failed":
            raise RuntimeError(task.result or task.error or error_detail)
        return {"status": "ok", "message": task.result.get("message", error_detail), "task_id": task_id}
    return {"status": "ok", "message": "Queued for background processing", "task_id": task_id}


def apply_config(db: Session, username: str, comment: str) -> ConfigApplyResponse:
    result = _queue_and_wait(
        "apply_config",
        {"created_by": username, "comment": comment},
        db,
        "Apply failed",
    )
    return ConfigApplyResponse(**result)


def revert_config(db: Session, username: str, confirmed: bool) -> ConfigRevertResponse:
    if not confirmed:
        raise RuntimeError("Reversion not confirmed")
    result = _queue_and_wait(
        "revert_config",
        {"created_by": username},
        db,
        "Revert failed",
    )
    return ConfigRevertResponse(**result)


def list_config_snapshots(db: Session):
    return db.query(ConfigSnapshot).order_by(ConfigSnapshot.created_at.desc()).all()


def get_max_snapshots_row(db: Session):
    value = get_setting(db, "max_snapshots", "10")
    row = db.query(Setting).filter(Setting.key == "max_snapshots").first()
    if not row:
        row = Setting(key="max_snapshots", value=value)
    return row


def set_max_snapshots(db: Session, value: str) -> Setting:
    try:
        val = max(1, int(value))
    except (TypeError, ValueError):
        raise RuntimeError("max_snapshots must be a positive integer")
    return set_setting(db, "max_snapshots", str(val))


def rollback_config_snapshot(db: Session, snapshot_id: int, username: str) -> ConfigSnapshotRollbackResponse:
    snap = db.get(ConfigSnapshot, snapshot_id)
    if not snap:
        raise RuntimeError("Snapshot not found")
    result = _queue_and_wait(
        "rollback_snapshot",
        {"snapshot_id": snapshot_id, "created_by": username},
        db,
        "Rollback failed",
    )
    return ConfigSnapshotRollbackResponse(**result)


def preview_config(db: Session) -> str:
    return generate_config(db)


def preview_all_configs(db: Session) -> Dict[str, str]:
    """Return all generated config files as {label: content}.

    Only includes configs that are actually generated (e.g. Varnish VCL
    only if disk cache is enabled, MCP bundle only if MCP gateway is enabled).
    """
    cfg = get_settings()
    configs: Dict[str, str] = {}
    configs["haproxy.cfg"] = generate_config(db)
    if cfg.CORAZA_SPOA_ENABLED:
        configs["coraza.cfg"] = generate_coraza_spoe_config(db)
        configs["coraza-spoa.yaml"] = generate_coraza_spoa_config(db)
    disk_cache_on = get_setting(db, "disk_cache_enabled", str(cfg.DISK_CACHE_ENABLED)).lower() in ("true", "1", "yes")
    if disk_cache_on:
        from ..models.models import CacheConfig
        any_disk = db.query(CacheConfig).filter(CacheConfig.disk_cache_enabled == True).first()  # noqa: E712
        if any_disk:
            from ..services.varnish import generate_vcl as generate_varnish_vcl
            configs["varnish.vcl"] = generate_varnish_vcl(db)
    mcp_on = get_setting(db, "mcp_gateway_enabled", str(cfg.MCP_GATEWAY_ENABLED)).lower() in ("true", "1", "yes")
    if mcp_on:
        try:
            from ..services.mcp_config import generate_mcp_bundle_text
            configs["mcp-bundle.json"] = generate_mcp_bundle_text(db)
        except Exception:
            pass  # MCP bundle generation failed — skip it
    return configs


def get_config_status(db: Session) -> bool:
    unapplied, _, _ = _config_status_data(db)
    return unapplied


def get_config_diff(db: Session) -> dict:
    unapplied, current, generated = _config_status_data(db)
    parts: List[str] = []
    for label in current:
        if current[label] == generated[label]:
            continue
        diff = "\n".join(
            difflib.unified_diff(
                current[label].splitlines(),
                generated[label].splitlines(),
                fromfile=f"{label}.applied",
                tofile=f"{label}",
                lineterm="",
            )
        )
        if diff:
            parts.append(f"--- {label} ---\n{diff}")
    return {
        "unapplied": unapplied,
        "diff": "\n\n".join(parts),
        "current": current.get("haproxy.cfg", ""),
        "generated": generated.get("haproxy.cfg", ""),
    }
