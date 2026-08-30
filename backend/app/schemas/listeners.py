from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from ._base import _optional_update

from .haproxy_options import HaproxyOption

class ListenerBase(BaseModel):
    name: str
    bind_address: str = "0.0.0.0"
    bind_port: int = Field(..., ge=1, le=65535)
    mode: str = "http"
    protocol: str = Field(default="http", pattern="^(http|tcp|grpc|jsonrpc|fastcgi|mcp)$")
    enabled: bool = True
    ssl_enabled: bool = False
    certificate_id: Optional[int] = None
    certificate_ids: Optional[List[int]] = []
    http2: bool = False
    quic: bool = False
    alpn: Optional[str] = None
    proxy_protocol: bool = False
    force_https: bool = False
    default_backend_id: Optional[int] = None
    options: Optional[Dict[str, Any]] = {}
    haproxy_options: Optional[List[HaproxyOption]] = []


class ListenerCreate(ListenerBase):
    pass


class ListenerUpdate(BaseModel):
    name: Optional[str] = None
    bind_address: Optional[str] = None
    bind_port: Optional[int] = None
    mode: Optional[str] = None
    protocol: Optional[str] = Field(default=None, pattern="^(http|tcp|grpc|jsonrpc|fastcgi|mcp)$")
    enabled: Optional[bool] = None
    ssl_enabled: Optional[bool] = None
    certificate_id: Optional[int] = None
    certificate_ids: Optional[List[int]] = None
    http2: Optional[bool] = None
    quic: Optional[bool] = None
    alpn: Optional[str] = None
    proxy_protocol: Optional[bool] = None
    force_https: Optional[bool] = None
    default_backend_id: Optional[int] = None
    options: Optional[Dict[str, Any]] = None
    haproxy_options: Optional[List[HaproxyOption]] = None


class ListenerResponse(ListenerBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = ['ListenerBase', 'ListenerCreate', 'ListenerResponse', 'ListenerUpdate']
