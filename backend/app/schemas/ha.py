"""Pydantic schemas for the High Availability (HA) feature."""

from typing import Any

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Instance inventory
# ---------------------------------------------------------------------------


class HaproxyInstance(BaseModel):
    """A single HAProxy instance with its Data Plane API endpoint."""

    name: str
    url: str
    user: str | None = None
    password: str | None = None  # not serialized in responses by default


# ---------------------------------------------------------------------------
# Keepalived configuration
# ---------------------------------------------------------------------------


class KeepalivedConfig(BaseModel):
    vip: str = ""
    virtual_router_id: int = 51
    priority: int = 100
    interface: str = "eth0"
    auth_password: str | None = None
    peer_addresses: list[str] = []
    advert_int: int = 1
    preempt: bool = True
    track_script: str | None = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class HaproxyInstanceHealth(BaseModel):
    name: str
    url: str
    available: bool = False
    version: str | None = None
    status: str | None = None
    current_connections: int | None = None
    keepalived_state: str | None = None  # MASTER / BACKUP / FAULT
    error: str | None = None


class ValkeyNodeHealth(BaseModel):
    role: str = ""  # master / slave (replica)
    host: str = ""
    available: bool = False
    error: str | None = None


class CorazaInstanceHealth(BaseModel):
    name: str
    state: str = ""  # UP / DOWN / MAINT
    check_status: str | None = None
    error: str | None = None


class HaHealthSummary(BaseModel):
    ha_enabled: bool = False
    swarm_mode: bool = False
    haproxy_instances: list[HaproxyInstanceHealth] = []
    valkey_nodes: list[ValkeyNodeHealth] = []
    coraza_instances: list[CorazaInstanceHealth] = []
    error: str | None = None


# ---------------------------------------------------------------------------
# Config response / update
# ---------------------------------------------------------------------------


class HaConfigResponse(BaseModel):
    ha_enabled: bool = False
    swarm_mode: bool = False
    ha_topology: str = "single"
    haproxy_ha_replicas: int = 1
    valkey_ha_replicas: int = 1
    coraza_ha_replicas: int = 1
    haproxy_instances: list[HaproxyInstance] = []
    haproxy_peer_port: int = 10000
    keepalived: KeepalivedConfig = KeepalivedConfig()
    valkey_sentinel_enabled: bool = False
    valkey_sentinel_hosts: list[str] = []
    valkey_sentinel_service: str = "mymaster"


class KeepalivedConfigUpdate(BaseModel):
    """Partial update for keepalived settings (admin only)."""

    vip: str | None = None
    virtual_router_id: int | None = None
    priority: int | None = None
    interface: str | None = None
    auth_password: str | None = None
    peer_addresses: list[str] | None = None
    advert_int: int | None = None
    preempt: bool | None = None
    track_script: str | None = None


class HaConfigUpdate(BaseModel):
    """Full HA config update (admin only). All fields optional."""

    ha_enabled: bool | None = None
    ha_topology: str | None = None
    haproxy_ha_replicas: int | None = None
    valkey_ha_replicas: int | None = None
    coraza_ha_replicas: int | None = None
    haproxy_instances: list[HaproxyInstance] | None = None
    haproxy_peer_port: int | None = None
    keepalived: KeepalivedConfigUpdate | None = None
    valkey_sentinel_enabled: bool | None = None
    valkey_sentinel_hosts: list[str] | None = None
    valkey_sentinel_service: str | None = None


class HaApplyResponse(BaseModel):
    status: str = "ok"
    results: dict[str, Any] = {}
    error: str | None = None


__all__ = [
    "HaproxyInstance",
    "KeepalivedConfig",
    "HaproxyInstanceHealth",
    "ValkeyNodeHealth",
    "CorazaInstanceHealth",
    "HaHealthSummary",
    "HaConfigResponse",
    "KeepalivedConfigUpdate",
    "HaConfigUpdate",
    "HaApplyResponse",
]
