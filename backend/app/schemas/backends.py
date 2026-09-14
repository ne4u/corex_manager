from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ._base import _optional_update
from .haproxy_options import HaproxyOption


class ServerBase(BaseModel):
    name: str
    address: str
    port: int = Field(..., ge=1, le=65535)
    weight: int = 100
    maxconn: int = 10000
    check: bool = True
    backup: bool = False
    inter: int | None = None
    rise: int | None = None
    fall: int | None = None
    slowstart: int | None = None
    maxqueue: int | None = None
    ssl: bool = False
    verify: str | None = "none"
    verifyhost: str | None = None
    ciphers: str | None = None
    alpn: str | None = None
    sni: str | None = None
    check_ssl: bool = False
    check_sni: str | None = None
    check_port: int | None = Field(default=None, ge=1, le=65535)
    send_proxy: bool = False
    send_proxy_v2: bool = False
    resolve: bool = False
    init_addr: str | None = None
    agent_check: bool = False
    agent_port: int | None = Field(default=None, ge=1, le=65535)
    track: str | None = None
    protocol: str = Field(default="http", pattern="^(http|tcp|grpc|jsonrpc|fastcgi)$")
    options: dict[str, Any] | None = {}
    ca_certificate_id: int | None = None
    client_certificate_id: int | None = None


class ServerCreate(ServerBase):
    pass


class ServerResponse(ServerBase):
    id: int
    backend_id: int

    model_config = ConfigDict(from_attributes=True)


class ServerUpdate(BaseModel):
    name: str | None = None
    address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    weight: int | None = None
    maxconn: int | None = None
    check: bool | None = None
    backup: bool | None = None
    inter: int | None = None
    rise: int | None = None
    fall: int | None = None
    slowstart: int | None = None
    maxqueue: int | None = None
    ssl: bool | None = None
    verify: str | None = None
    verifyhost: str | None = None
    ciphers: str | None = None
    alpn: str | None = None
    sni: str | None = None
    check_ssl: bool | None = None
    check_sni: str | None = None
    check_port: int | None = Field(default=None, ge=1, le=65535)
    send_proxy: bool | None = None
    send_proxy_v2: bool | None = None
    resolve: bool | None = None
    init_addr: str | None = None
    agent_check: bool | None = None
    agent_port: int | None = Field(default=None, ge=1, le=65535)
    track: str | None = None
    protocol: str | None = Field(default=None, pattern="^(http|tcp|grpc|jsonrpc|fastcgi)$")
    options: dict[str, Any] | None = None
    ca_certificate_id: int | None = None
    client_certificate_id: int | None = None


class BackendBase(BaseModel):
    name: str
    mode: str = "http"
    protocol: str = Field(default="http", pattern="^(http|tcp|grpc|jsonrpc|fastcgi)$")
    algorithm: str = Field(
        default="roundrobin",
        pattern="^(roundrobin|leastconn|source|uri|static-rr|random|first|hdr|url_param|rdp-cookie)$",
    )
    sticky_sessions: bool = False
    cookie_name: str | None = None
    balance_args: str | None = None
    health_check_enabled: bool = True
    health_check_interval: int = 2000
    health_check_uri: str = "/"
    health_check_method: str = "GET"
    health_check_expect_status: str | None = None
    health_check_expect_body: str | None = None
    retries: int = 3
    redispatch: bool = False
    timeout_queue: int | None = None
    timeout_check: int | None = None
    timeout_tunnel: int | None = None
    http_reuse: str | None = Field(default=None, pattern="^(aggressive|safe|never)$")
    fullconn: int | None = None
    stick_table: bool = False
    stick_table_size: str = "1m"
    stick_table_expire: str = "30m"
    stick_table_type: str = Field(default="ip", pattern="^(ip|cookie|binary|integer|string)$")
    resolvers: str | None = None
    host_header: str | None = None
    restore_client_ip: bool = False
    client_ip_header: str = "X-Forwarded-For"
    fcgi_app_id: int | None = None
    options: dict[str, Any] | None = {}
    haproxy_options: list[HaproxyOption] | None = []

    @field_validator("algorithm")
    @classmethod
    def _validate_algorithm(cls, v: str | None) -> str | None:
        if v is None:
            return v
        allowed = {
            "roundrobin",
            "leastconn",
            "source",
            "uri",
            "static-rr",
            "random",
            "first",
            "hdr",
            "url_param",
            "rdp-cookie",
        }
        if v not in allowed:
            raise ValueError(f"algorithm must be one of: {', '.join(sorted(allowed))}")
        return v

    @field_validator("stick_table_type")
    @classmethod
    def _validate_stick_table_type(cls, v: str | None) -> str | None:
        if v is None:
            return v
        allowed = {"ip", "cookie", "binary", "integer", "string"}
        if v not in allowed:
            raise ValueError(f"stick_table_type must be one of: {', '.join(sorted(allowed))}")
        return v

    @field_validator("client_ip_header")
    @classmethod
    def _validate_client_ip_header(cls, v: str | None) -> str | None:
        # Header names only: letters, digits, hyphen. Reject anything that
        # could break the HAProxy req.fhdr(<header>) directive.
        import re

        if v is None or v == "":
            return "X-Forwarded-For"
        if not re.fullmatch(r"[A-Za-z0-9-]+", v):
            raise ValueError("client_ip_header must contain only letters, digits, and hyphens")
        return v


class BackendCreate(BackendBase):
    servers: list[ServerCreate] | None = []


BackendUpdate = _optional_update(BackendBase)


class BackendResponse(BackendBase):
    id: int
    servers: list[ServerResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BackendRuleCondition(BaseModel):
    condition_type: str = Field(pattern="^(path|host|hdr|cookie|url_param|src)$")
    condition_name: str | None = None
    operator: str = Field(pattern="^(beg|end|sub|dir|eq|found|len|reg)$")
    value: str | None = None
    join: str = Field(default="and", pattern="^(and|or)$")


class BackendRuleBase(BaseModel):
    listener_id: int
    backend_id: int
    name: str | None = None
    priority: int = 100
    condition_type: str = Field(default="path", pattern="^(path|host|hdr|cookie|url_param|src)$")
    condition_name: str | None = None
    operator: str = Field(default="beg", pattern="^(beg|end|sub|dir|eq|found|len|reg)$")
    value: str | None = None
    enabled: bool = True
    conditions: list[BackendRuleCondition] | None = Field(default=None, max_length=4)

    @field_validator("conditions", mode="before")
    @classmethod
    def _normalize_conditions(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            return []
        return v


class BackendRuleCreate(BackendRuleBase):
    pass


BackendRuleUpdate = _optional_update(BackendRuleBase)


class BackendRuleResponse(BackendRuleBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    "BackendBase",
    "BackendCreate",
    "BackendResponse",
    "BackendRuleBase",
    "BackendRuleCondition",
    "BackendRuleCreate",
    "BackendRuleResponse",
    "BackendRuleUpdate",
    "BackendUpdate",
    "ServerBase",
    "ServerCreate",
    "ServerResponse",
    "ServerUpdate",
]
