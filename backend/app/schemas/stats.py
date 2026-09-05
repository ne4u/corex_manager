from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

class StatsResponse(BaseModel):
    process_id: int
    cpu_load: float
    memory_usage: float
    current_connections: int
    max_connections: int
    total_requests: int
    bytes_in: int
    bytes_out: int
    listeners: List[Dict[str, Any]] = []
    backends: List[Dict[str, Any]] = []


class MetricsResponse(BaseModel):
    data: List[Dict[str, Any]]


class WafMetricsResponse(BaseModel):
    time: List[str]
    series: List[Dict[str, Any]]
    breakdown: str
    totals: Dict[str, int]


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
    stores: Dict[str, str] = {}


class StickTableDetail(BaseModel):
    name: str
    type: str = ""
    size: int = 0
    used: int = 0
    total: int = 0
    offset: int = 0
    limit: int = 100
    entries: List[StickTableEntry] = []


class StickTableClearResponse(BaseModel):
    ok: bool
    cleared: int


__all__ = [
    'MetricsResponse',
    'StatsResponse',
    'WafMetricsResponse',
    'StickTableSummary',
    'StickTableEntry',
    'StickTableDetail',
    'StickTableClearResponse',
]
