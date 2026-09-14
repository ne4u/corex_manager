from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .haproxy_options import HaproxyOption


class ListenerBase(BaseModel):
    name: str
    bind_address: str = "0.0.0.0"
    bind_port: int = Field(..., ge=1, le=65535)
    mode: str = "http"
    protocol: str = Field(default="http", pattern="^(http|tcp|grpc|jsonrpc|fastcgi|mcp)$")
    enabled: bool = True
    ssl_enabled: bool = False
    certificate_id: int | None = None
    certificate_ids: list[int] | None = []
    http2: bool = False
    quic: bool = False
    alpn: str | None = None
    proxy_protocol: bool = False
    force_https: bool = False
    default_backend_id: int | None = None
    options: dict[str, Any] | None = {}
    haproxy_options: list[HaproxyOption] | None = []


class ListenerCreate(ListenerBase):
    pass


class ListenerUpdate(BaseModel):
    name: str | None = None
    bind_address: str | None = None
    bind_port: int | None = None
    mode: str | None = None
    protocol: str | None = Field(default=None, pattern="^(http|tcp|grpc|jsonrpc|fastcgi|mcp)$")
    enabled: bool | None = None
    ssl_enabled: bool | None = None
    certificate_id: int | None = None
    certificate_ids: list[int] | None = None
    http2: bool | None = None
    quic: bool | None = None
    alpn: str | None = None
    proxy_protocol: bool | None = None
    force_https: bool | None = None
    default_backend_id: int | None = None
    options: dict[str, Any] | None = None
    haproxy_options: list[HaproxyOption] | None = None


class ListenerResponse(ListenerBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


__all__ = ["ListenerBase", "ListenerCreate", "ListenerResponse", "ListenerUpdate"]
