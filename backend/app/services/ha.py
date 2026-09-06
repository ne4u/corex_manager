"""High Availability (HA) service — instance inventory, peers section,
keepalived config generation, multi-instance config push, and health aggregation.

When HA is disabled (``HA_ENABLED=false``), every function here short-circuits
to the single-instance behavior, preserving byte-for-byte parity with the
pre-HA codebase.
"""
from __future__ import annotations

import logging
import os
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..core.config import get_settings
from . import dataplane
from .settings import get_setting, set_setting

logger = logging.getLogger(__name__)
settings = get_settings()


# ---------------------------------------------------------------------------
# Instance inventory
# ---------------------------------------------------------------------------

class HaproxyInstance:
    """A single HAProxy instance with its Data Plane API endpoint."""

    __slots__ = ("name", "url", "user", "password")

    def __init__(self, name: str, url: str, user: Optional[str] = None, password: Optional[str] = None):
        self.name = name
        self.url = url
        self.user = user
        self.password = password

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "url": self.url, "user": self.user, "password": self.password}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HaproxyInstance":
        return cls(
            name=d.get("name", ""),
            url=d.get("url", ""),
            user=d.get("user"),
            password=d.get("password"),
        )


def _parse_instances(raw: str) -> List[HaproxyInstance]:
    """Parse a semicolon-separated ``name=url[,user[,password]]`` string.

    Instances are separated by ``;``. Within each instance, the format is
    ``name=url[,user[,password]]`` — credentials are comma-separated after
    the URL. Returns an empty list if the string is empty or malformed.
    Also supports comma-separated instances without credentials (backward
    compatibility with the simpler ``name=url,name2=url2`` format) —
    detected when there are no semicolons and every comma-separated chunk
    contains ``=``.
    """
    instances: List[HaproxyInstance] = []
    if ";" in raw:
        # Semicolon-separated format (preferred — supports credentials)
        chunks = [c.strip() for c in raw.split(";") if c.strip()]
    else:
        # Comma-separated format (backward compat — no credentials)
        # Only treat as multiple instances if every chunk has "="
        comma_chunks = [c.strip() for c in raw.split(",") if c.strip()]
        if comma_chunks and all("=" in c for c in comma_chunks):
            chunks = comma_chunks
        else:
            # Single instance with credentials (url,user,password)
            chunks = [raw.strip()] if raw.strip() else []
    for chunk in chunks:
        if "=" not in chunk:
            continue
        name, rest = chunk.split("=", 1)
        name = name.strip()
        rest = rest.strip()
        if not name or not rest:
            continue
        # rest may contain "url,user,password"
        parts = rest.split(",")
        url = parts[0].strip()
        user = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
        password = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
        instances.append(HaproxyInstance(name=name, url=url, user=user, password=password))
    return instances


def _instances_to_str(instances: List[HaproxyInstance]) -> str:
    """Serialize instances back to the semicolon-separated string format."""
    parts: List[str] = []
    for inst in instances:
        s = f"{inst.name}={inst.url}"
        if inst.user:
            s += f",{inst.user}"
            if inst.password:
                s += f",{inst.password}"
        parts.append(s)
    return ";".join(parts)


def get_haproxy_instances(db: Optional[Session] = None) -> List[HaproxyInstance]:
    """Return the list of HAProxy instances.

    Priority: DB setting ``haproxy_instances`` → env ``HAPROXY_INSTANCES``.
    When HA is disabled or no instances are configured, falls back to a
    single instance derived from ``DATAPLANE_API_URL`` with name "corex".
    """
    raw: Optional[str] = None
    if db is not None:
        raw = get_setting(db, "haproxy_instances", settings.HAPROXY_INSTANCES)
    if raw is None:
        raw = settings.HAPROXY_INSTANCES

    instances = _parse_instances(raw or "")
    if not instances:
        # Fallback: single instance from the default Data Plane API URL
        instances = [HaproxyInstance(
            name="corex",
            url=settings.DATAPLANE_API_URL,
            user=settings.DATAPLANE_API_USER,
            password=settings.DATAPLANE_API_PASSWORD,
        )]
    return instances


def is_ha_enabled(db: Optional[Session] = None) -> bool:
    """Return True if HA mode is enabled (DB setting or env fallback)."""
    if db is not None:
        val = get_setting(db, "ha_enabled", str(settings.HA_ENABLED))
        return val.lower() in ("true", "1", "yes")
    return settings.HA_ENABLED


# ---------------------------------------------------------------------------
# Peers section (stick-table sync)
# ---------------------------------------------------------------------------

def _extract_host(url: str) -> str:
    """Extract the hostname from a Data Plane API URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def generate_peers_section(db: Optional[Session] = None) -> str:
    """Emit the ``peers`` section for stick-table replication.

    Returns an empty string when HA is disabled or fewer than 2 instances
    are configured (no point in a single-peer peers section).
    """
    if not is_ha_enabled(db):
        return ""

    instances = get_haproxy_instances(db)
    if len(instances) < 2:
        return ""

    peer_port = settings.HAPROXY_PEER_PORT
    lines = [f"peers corex-peers"]
    for inst in instances:
        host = _extract_host(inst.url)
        # Use the instance name as the peer name (HAProxy requires unique
        # peer names; the local peer's name must match HAPROXY_PEER_NAME).
        lines.append(f"    peer {inst.name} {host}:{peer_port}")
    return "\n".join(lines) + "\n\n"


def maybe_peers(db: Optional[Session] = None) -> str:
    """Return `` peers corex-peers`` (with leading space) or empty string.

    Appended to every ``stick-table`` directive when HA is on and the peers
    section is present. Returns empty string otherwise (zero behavior change).
    """
    if not is_ha_enabled(db):
        return ""
    instances = get_haproxy_instances(db)
    if len(instances) < 2:
        return ""
    return " peers corex-peers"


# ---------------------------------------------------------------------------
# Keepalived config generation
# ---------------------------------------------------------------------------

def _get_keepalived_setting(db: Optional[Session], key: str, default: str) -> str:
    """Read a keepalived setting from DB (with env fallback)."""
    if db is not None:
        return get_setting(db, key, default) or default
    return default


def generate_keepalived_config(db: Optional[Session] = None, instance_name: Optional[str] = None) -> str:
    """Render a keepalived.conf from DB/env settings.

    Returns an empty string when HA is disabled or Swarm mode is active
    (Swarm's ingress mesh provides VIP + failover; keepalived is not needed).
    """
    if not is_ha_enabled(db):
        return ""
    if getattr(settings, "SWARM_MODE", False):
        # In Swarm mode, the ingress routing mesh handles VIP and failover.
        # keepalived is not started (entrypoint.sh also checks SWARM_MODE).
        return ""

    vip = _get_keepalived_setting(db, "keepalived_vip", settings.KEEPALIVED_VIP)
    if not vip:
        # No VIP configured — return empty so entrypoint skips keepalived
        return ""

    vrid = int(_get_keepalived_setting(db, "keepalived_virtual_router_id", str(settings.KEEPALIVED_VIRTUAL_ROUTER_ID)))
    priority = int(_get_keepalived_setting(db, "keepalived_priority", str(settings.KEEPALIVED_PRIORITY)))
    interface = _get_keepalived_setting(db, "keepalived_interface", settings.KEEPALIVED_INTERFACE)
    auth_pass = _get_keepalived_setting(db, "keepalived_auth_password", settings.KEEPALIVED_AUTH_PASSWORD or "")
    peer_addrs_raw = _get_keepalived_setting(db, "keepalived_peer_addresses", settings.KEEPALIVED_PEER_ADDRESSES or "")
    advert_int = int(_get_keepalived_setting(db, "keepalived_advert_int", str(settings.KEEPALIVED_ADVERT_INT)))
    preempt = _get_keepalived_setting(db, "keepalived_preempt", str(settings.KEEPALIVED_PREEMPT)).lower() in ("true", "1", "yes")
    track_script = _get_keepalived_setting(db, "keepalived_track_script", settings.KEEPALIVED_TRACK_SCRIPT or "")

    if not vip:
        # No VIP configured — return empty so entrypoint skips keepalived
        return ""

    lines: List[str] = []
    lines.append("# Generated by coreX Manager — do not edit manually")
    lines.append("global_defs {")
    lines.append(f"    enable_script_security")
    lines.append("}")
    lines.append("")

    # Track script (optional HAProxy health check)
    if track_script:
        lines.append(f"vrrp_script chk_haproxy {{")
        lines.append(f'    script "{track_script}"')
        lines.append(f"    interval 2")
        lines.append(f"    weight -20")
        lines.append(f"}}")
        lines.append("")

    preempt_str = " preempt" if preempt else " nopreempt"
    lines.append(f"vrrp_instance VI_1 {{")
    lines.append(f"    state BACKUP")
    lines.append(f"    interface {interface}")
    lines.append(f"    virtual_router_id {vrid}")
    lines.append(f"    priority {priority}")
    lines.append(f"    advert_int {advert_int}")
    lines.append(f"    {preempt_str.strip()}")
    lines.append("")

    if auth_pass:
        lines.append("    authentication {")
        lines.append("        auth_type PASS")
        lines.append(f"        auth_pass {auth_pass}")
        lines.append("    }")
        lines.append("")

    lines.append("    virtual_ipaddress {")
    lines.append(f"        {vip}")
    lines.append("    }")
    lines.append("")

    # Unicast peers (for environments where multicast is not available)
    peers = [p.strip() for p in peer_addrs_raw.split(",") if p.strip()] if peer_addrs_raw else []
    if peers:
        lines.append("    unicast_peer {")
        for p in peers:
            lines.append(f"        {p}")
        lines.append("    }")
        lines.append("")

    # Notify script — writes VRRP state to /app/data/keepalived.state
    lines.append('    notify_master "/usr/local/bin/keepalived_notify.sh MASTER"')
    lines.append('    notify_backup "/usr/local/bin/keepalived_notify.sh BACKUP"')
    lines.append('    notify_fault  "/usr/local/bin/keepalived_notify.sh FAULT"')
    lines.append("")

    if track_script:
        lines.append("    track_script {")
        lines.append("        chk_haproxy")
        lines.append("    }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines) + "\n"


def write_keepalived_configs(db: Optional[Session] = None) -> None:
    """Write keepalived.conf to the shared data directory.

    In single-host mode, all HAProxy containers share the same data volume,
    so a single keepalived.conf is written. In multi-host mode, each host's
    entrypoint renders its own from env vars (this function still writes
    a reference file).
    """
    if not is_ha_enabled(db):
        return

    config = generate_keepalived_config(db)
    if not config:
        return

    path = os.path.join(os.path.dirname(settings.HAPROXY_CONFIG_PATH) or ".", "keepalived.conf")
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(config)
        logger.info("keepalived.conf written to %s", path)
    except Exception as e:
        logger.warning("Failed to write keepalived.conf: %s", e)


# ---------------------------------------------------------------------------
# Multi-instance config push
# ---------------------------------------------------------------------------

def push_config_to_all_instances(
    db: Optional[Session],
    config_text: str,
) -> Dict[str, Dict[str, Any]]:
    """Push generated HAProxy config to every instance via its Data Plane API.

    Returns a dict mapping instance name → push result dict.
    When HA is disabled, pushes to the single default instance (preserving
    the original ``dataplane.push_config(config)`` behavior).
    """
    instances = get_haproxy_instances(db)
    results: Dict[str, Dict[str, Any]] = {}

    for inst in instances:
        try:
            result = dataplane.push_config(
                config_text,
                base_url=inst.url,
                user=inst.user,
                password=inst.password,
            )
            results[inst.name] = result
        except Exception as e:
            results[inst.name] = {"status": "error", "message": str(e)}

    return results


# ---------------------------------------------------------------------------
# Health aggregation
# ---------------------------------------------------------------------------

def _read_keepalived_state() -> Optional[str]:
    """Read the keepalived VRRP state from /app/data/keepalived.state.

    Returns one of "MASTER", "BACKUP", "FAULT", or None if the file doesn't
    exist (keepalived not running or HA disabled).
    """
    state_path = os.path.join(
        os.path.dirname(settings.HAPROXY_CONFIG_PATH) or ".",
        "keepalived.state",
    )
    try:
        with open(state_path, "r") as f:
            return f.read().strip().upper() or None
    except Exception:
        return None


def get_ha_health(db: Optional[Session] = None) -> Dict[str, Any]:
    """Aggregate health across all HA instances.

    Returns a dict matching the ``HaHealthSummary`` schema.
    """
    ha_enabled = is_ha_enabled(db)
    instances = get_haproxy_instances(db)

    # HAProxy instance health
    haproxy_health: List[Dict[str, Any]] = []
    for inst in instances:
        entry: Dict[str, Any] = {
            "name": inst.name,
            "url": inst.url,
            "available": False,
            "version": None,
            "status": None,
            "current_connections": None,
            "keepalived_state": None,
            "error": None,
        }
        try:
            info = dataplane.get_info(base_url=inst.url, user=inst.user, password=inst.password)
            if info and info.get("status") != "error" and not info.get("enabled") is False:
                entry["available"] = True
                # Data Plane API info has a nested structure; extract common fields
                data = info.get("data", info)
                entry["version"] = data.get("version") or data.get("haproxy_version")
                entry["status"] = data.get("status") or data.get("run_mode")
                entry["current_connections"] = data.get("current_connections")
            elif info and info.get("status") == "error":
                entry["error"] = info.get("message", "unknown error")
        except Exception as e:
            entry["error"] = str(e)

        # Keepalived state (only for the local instance, not in Swarm mode)
        if ha_enabled and not getattr(settings, "SWARM_MODE", False):
            ks = _read_keepalived_state()
            if ks:
                entry["keepalived_state"] = ks

        haproxy_health.append(entry)

    # Valkey node health
    valkey_nodes: List[Dict[str, Any]] = []
    try:
        from . import valkey_inspect
        info = valkey_inspect.server_info()
        valkey_nodes.append({
            "role": info.get("role", ""),
            "host": settings.VALKEY_HOST,
            "available": info.get("available", False),
            "error": info.get("error"),
        })
        # In HA mode, also check the replica (best-effort)
        if ha_enabled:
            # The replica host is conventionally "valkey-replica"
            try:
                from ..core.valkey_client import _get_client as _vc_get
                from valkey import Valkey
                replica = Valkey(
                    host="valkey-replica",
                    port=settings.VALKEY_PORT,
                    password=settings.VALKEY_PASSWORD or None,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                    decode_responses=True,
                )
                r_info = replica.info()
                valkey_nodes.append({
                    "role": r_info.get("role", "slave"),
                    "host": "valkey-replica",
                    "available": True,
                    "error": None,
                })
                replica.close()
            except Exception as e:
                valkey_nodes.append({
                    "role": "slave",
                    "host": "valkey-replica",
                    "available": False,
                    "error": str(e),
                })
    except Exception as e:
        valkey_nodes.append({
            "role": "",
            "host": settings.VALKEY_HOST,
            "available": False,
            "error": str(e),
        })

    # Coraza instance health (from HAProxy stats — the coraza backend servers)
    coraza_health: List[Dict[str, Any]] = []
    try:
        stats = dataplane.get_stats()
        for row in stats:
            backend = row.get("backend_name", "") or row.get("backend", "")
            if backend == "coraza-spoa":
                coraza_health.append({
                    "name": row.get("server_name", "") or row.get("svname", ""),
                    "state": row.get("status", "") or row.get("state", ""),
                    "check_status": row.get("check_status"),
                    "error": None,
                })
    except Exception:
        pass

    return {
        "ha_enabled": ha_enabled,
        "swarm_mode": getattr(settings, "SWARM_MODE", False),
        "haproxy_instances": haproxy_health,
        "valkey_nodes": valkey_nodes,
        "coraza_instances": coraza_health,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Config response / update helpers
# ---------------------------------------------------------------------------

def get_ha_config(db: Session) -> Dict[str, Any]:
    """Return the full HA config for the ``GET /ha/config`` endpoint."""
    instances = get_haproxy_instances(db)
    ha_enabled = is_ha_enabled(db)

    # Keepalived settings
    keepalived = {
        "vip": _get_keepalived_setting(db, "keepalived_vip", settings.KEEPALIVED_VIP),
        "virtual_router_id": int(_get_keepalived_setting(db, "keepalived_virtual_router_id", str(settings.KEEPALIVED_VIRTUAL_ROUTER_ID))),
        "priority": int(_get_keepalived_setting(db, "keepalived_priority", str(settings.KEEPALIVED_PRIORITY))),
        "interface": _get_keepalived_setting(db, "keepalived_interface", settings.KEEPALIVED_INTERFACE),
        "auth_password": _get_keepalived_setting(db, "keepalived_auth_password", settings.KEEPALIVED_AUTH_PASSWORD or ""),
        "peer_addresses": [p.strip() for p in _get_keepalived_setting(db, "keepalived_peer_addresses", settings.KEEPALIVED_PEER_ADDRESSES or "").split(",") if p.strip()],
        "advert_int": int(_get_keepalived_setting(db, "keepalived_advert_int", str(settings.KEEPALIVED_ADVERT_INT))),
        "preempt": _get_keepalived_setting(db, "keepalived_preempt", str(settings.KEEPALIVED_PREEMPT)).lower() in ("true", "1", "yes"),
        "track_script": _get_keepalived_setting(db, "keepalived_track_script", settings.KEEPALIVED_TRACK_SCRIPT or "") or None,
    }

    # Valkey sentinel settings
    sentinel_enabled = _get_keepalived_setting(db, "valkey_sentinel_enabled", str(settings.VALKEY_SENTINEL_ENABLED)).lower() in ("true", "1", "yes")
    sentinel_hosts_raw = _get_keepalived_setting(db, "valkey_sentinel_hosts", settings.VALKEY_SENTINEL_HOSTS or "")
    sentinel_hosts = [h.strip() for h in sentinel_hosts_raw.split(",") if h.strip()]

    return {
        "ha_enabled": ha_enabled,
        "swarm_mode": getattr(settings, "SWARM_MODE", False),
        "ha_topology": _get_keepalived_setting(db, "ha_topology", settings.HA_TOPOLOGY),
        "haproxy_ha_replicas": int(_get_keepalived_setting(db, "haproxy_ha_replicas", str(settings.HAPROXY_HA_REPLICAS))),
        "valkey_ha_replicas": int(_get_keepalived_setting(db, "valkey_ha_replicas", str(settings.VALKEY_HA_REPLICAS))),
        "coraza_ha_replicas": int(_get_keepalived_setting(db, "coraza_ha_replicas", str(settings.CORAZA_HA_REPLICAS))),
        "haproxy_instances": [inst.to_dict() for inst in instances],
        "haproxy_peer_port": settings.HAPROXY_PEER_PORT,
        "keepalived": keepalived,
        "valkey_sentinel_enabled": sentinel_enabled,
        "valkey_sentinel_hosts": sentinel_hosts,
        "valkey_sentinel_service": _get_keepalived_setting(db, "valkey_sentinel_service", settings.VALKEY_SENTINEL_SERVICE),
    }


def update_ha_config(db: Session, update: Dict[str, Any]) -> None:
    """Apply a partial HA config update (admin only).

    Writes each provided field to the DB ``Setting`` table. Fields not in the
    update dict are left unchanged.
    """
    if "ha_enabled" in update and update["ha_enabled"] is not None:
        set_setting(db, "ha_enabled", str(update["ha_enabled"]).lower())

    if "ha_topology" in update and update["ha_topology"] is not None:
        set_setting(db, "ha_topology", str(update["ha_topology"]))

    if "haproxy_ha_replicas" in update and update["haproxy_ha_replicas"] is not None:
        set_setting(db, "haproxy_ha_replicas", str(update["haproxy_ha_replicas"]))

    if "valkey_ha_replicas" in update and update["valkey_ha_replicas"] is not None:
        set_setting(db, "valkey_ha_replicas", str(update["valkey_ha_replicas"]))

    if "coraza_ha_replicas" in update and update["coraza_ha_replicas"] is not None:
        set_setting(db, "coraza_ha_replicas", str(update["coraza_ha_replicas"]))

    if "haproxy_instances" in update and update["haproxy_instances"] is not None:
        instances = [HaproxyInstance.from_dict(d) if isinstance(d, dict) else d for d in update["haproxy_instances"]]
        set_setting(db, "haproxy_instances", _instances_to_str(instances))

    if "haproxy_peer_port" in update and update["haproxy_peer_port"] is not None:
        set_setting(db, "haproxy_peer_port", str(update["haproxy_peer_port"]))

    if "valkey_sentinel_enabled" in update and update["valkey_sentinel_enabled"] is not None:
        set_setting(db, "valkey_sentinel_enabled", str(update["valkey_sentinel_enabled"]).lower())

    if "valkey_sentinel_hosts" in update and update["valkey_sentinel_hosts"] is not None:
        set_setting(db, "valkey_sentinel_hosts", ",".join(update["valkey_sentinel_hosts"]))

    if "valkey_sentinel_service" in update and update["valkey_sentinel_service"] is not None:
        set_setting(db, "valkey_sentinel_service", str(update["valkey_sentinel_service"]))

    # Keepalived nested update
    ka = update.get("keepalived")
    if ka and isinstance(ka, dict):
        if ka.get("vip") is not None:
            set_setting(db, "keepalived_vip", str(ka["vip"]))
        if ka.get("virtual_router_id") is not None:
            set_setting(db, "keepalived_virtual_router_id", str(ka["virtual_router_id"]))
        if ka.get("priority") is not None:
            set_setting(db, "keepalived_priority", str(ka["priority"]))
        if ka.get("interface") is not None:
            set_setting(db, "keepalived_interface", str(ka["interface"]))
        if ka.get("auth_password") is not None:
            set_setting(db, "keepalived_auth_password", str(ka["auth_password"]))
        if ka.get("peer_addresses") is not None:
            set_setting(db, "keepalived_peer_addresses", ",".join(ka["peer_addresses"]))
        if ka.get("advert_int") is not None:
            set_setting(db, "keepalived_advert_int", str(ka["advert_int"]))
        if ka.get("preempt") is not None:
            set_setting(db, "keepalived_preempt", str(ka["preempt"]).lower())
        if ka.get("track_script") is not None:
            set_setting(db, "keepalived_track_script", str(ka["track_script"]))
