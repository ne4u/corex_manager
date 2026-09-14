from typing import Any

from pydantic import BaseModel


class StatsResponse(BaseModel):
    process_id: int
    cpu_load: float
    memory_usage: float
    current_connections: int
    max_connections: int
    total_requests: int
    bytes_in: int
    bytes_out: int
    listeners: list[dict[str, Any]] = []
    backends: list[dict[str, Any]] = []


class MetricsResponse(BaseModel):
    data: list[dict[str, Any]]


class WafMetricsResponse(BaseModel):
    time: list[str]
    series: list[dict[str, Any]]
    breakdown: str
    totals: dict[str, int]


# ---------------------------------------------------------------------------
# HAProxy stick-table viewer (System → Tables tab)
# ---------------------------------------------------------------------------


class StickTableSummary(BaseModel):
    name: str
    type: str
    size: int
    used: int


class StickTableEntry(BaseModel):
    key: str = ""
    use: Any = 0
    exp: Any = 0
    stores: dict[str, str] = {}


class StickTableDetail(BaseModel):
    name: str
    type: str = ""
    size: int = 0
    used: int = 0
    total: int = 0
    offset: int = 0
    limit: int = 100
    entries: list[StickTableEntry] = []


class StickTableClearResponse(BaseModel):
    ok: bool
    cleared: int


# ---------------------------------------------------------------------------
# Valkey inspector (System → Valkey tab)
# ---------------------------------------------------------------------------


class ValkeyServerInfo(BaseModel):
    available: bool
    version: str | None = None
    uptime_seconds: int = 0
    connected_clients: int = 0
    used_memory_human: str = ""
    used_memory_peak_human: str = ""
    total_keys: int = 0
    db_count: int = 0
    role: str = ""
    error: str | None = None


class ValkeyNamespaceSummary(BaseModel):
    prefix: str
    count: int
    sample_keys: list[str] = []


class ValkeyKeyEntry(BaseModel):
    key: str
    type: str
    ttl: int  # -1 = no expiry, -2 = missing
    size: int | None = None  # bytes from MEMORY USAGE
    preview: str = ""


class ValkeyNamespaceDetail(BaseModel):
    prefix: str
    total: int = 0
    offset: int = 0
    limit: int = 100
    keys: list[ValkeyKeyEntry] = []


class ValkeyDeleteResponse(BaseModel):
    ok: bool
    deleted: int


__all__ = [
    "MetricsResponse",
    "StatsResponse",
    "WafMetricsResponse",
    "StickTableSummary",
    "StickTableEntry",
    "StickTableDetail",
    "StickTableClearResponse",
    "ValkeyServerInfo",
    "ValkeyNamespaceSummary",
    "ValkeyKeyEntry",
    "ValkeyNamespaceDetail",
    "ValkeyDeleteResponse",
]
