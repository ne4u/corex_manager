"""Pydantic schemas for the High Availability (HA) feature."""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Instance inventory
# ---------------------------------------------------------------------------

class HaproxyInstance(BaseModel):
    """A single HAProxy instance with its Data Plane API endpoint."""
    name: str
    url: str
    user: Optional[str] = None
    password: Optional[str] = None  # not serialized in responses by default


# ---------------------------------------------------------------------------
# Keepalived configuration
# ---------------------------------------------------------------------------

class KeepalivedConfig(BaseModel):
    vip: str = ""
    virtual_router_id: int = 51
    priority: int = 100
    interface: str = "eth0"
    auth_password: Optional[str] = None
    peer_addresses: List[str] = []
    advert_int: int = 1
    preempt: bool = True
    track_script: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HaproxyInstanceHealth(BaseModel):
    name: str
    url: str
    available: bool = False
    version: Optional[str] = None
    status: Optional[str] = None
    current_connections: Optional[int] = None
    keepalived_state: Optional[str] = None  # MASTER / BACKUP / FAULT
    error: Optional[str] = None


class ValkeyNodeHealth(BaseModel):
    role: str = ""  # master / slave (replica)
    host: str = ""
    available: bool = False
    error: Optional[str] = None


class CorazaInstanceHealth(BaseModel):
    name: str
    state: str = ""  # UP / DOWN / MAINT
    check_status: Optional[str] = None
    error: Optional[str] = None


class HaHealthSummary(BaseModel):
    ha_enabled: bool = False
    swarm_mode: bool = False
    haproxy_instances: List[HaproxyInstanceHealth] = []
    valkey_nodes: List[ValkeyNodeHealth] = []
    coraza_instances: List[CorazaInstanceHealth] = []
    error: Optional[str] = None


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
    haproxy_instances: List[HaproxyInstance] = []
    haproxy_peer_port: int = 10000
    keepalived: KeepalivedConfig = KeepalivedConfig()
    valkey_sentinel_enabled: bool = False
    valkey_sentinel_hosts: List[str] = []
    valkey_sentinel_service: str = "mymaster"


class KeepalivedConfigUpdate(BaseModel):
    """Partial update for keepalived settings (admin only)."""
    vip: Optional[str] = None
    virtual_router_id: Optional[int] = None
    priority: Optional[int] = None
    interface: Optional[str] = None
    auth_password: Optional[str] = None
    peer_addresses: Optional[List[str]] = None
    advert_int: Optional[int] = None
    preempt: Optional[bool] = None
    track_script: Optional[str] = None


class HaConfigUpdate(BaseModel):
    """Full HA config update (admin only). All fields optional."""
    ha_enabled: Optional[bool] = None
    ha_topology: Optional[str] = None
    haproxy_ha_replicas: Optional[int] = None
    valkey_ha_replicas: Optional[int] = None
    coraza_ha_replicas: Optional[int] = None
    haproxy_instances: Optional[List[HaproxyInstance]] = None
    haproxy_peer_port: Optional[int] = None
    keepalived: Optional[KeepalivedConfigUpdate] = None
    valkey_sentinel_enabled: Optional[bool] = None
    valkey_sentinel_hosts: Optional[List[str]] = None
    valkey_sentinel_service: Optional[str] = None


class HaApplyResponse(BaseModel):
    status: str = "ok"
    results: Dict[str, Any] = {}
    error: Optional[str] = None


__all__ = [
    'HaproxyInstance',
    'KeepalivedConfig',
    'HaproxyInstanceHealth',
    'ValkeyNodeHealth',
    'CorazaInstanceHealth',
    'HaHealthSummary',
    'HaConfigResponse',
    'KeepalivedConfigUpdate',
    'HaConfigUpdate',
    'HaApplyResponse',
]
