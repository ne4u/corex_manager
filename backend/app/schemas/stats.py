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


__all__ = ['MetricsResponse', 'StatsResponse', 'WafMetricsResponse']
