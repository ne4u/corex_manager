from datetime import datetime
from typing import Optional, List, Dict, Any, Type, TypeVar
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
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
    inter: Optional[int] = None
    rise: Optional[int] = None
    fall: Optional[int] = None
    slowstart: Optional[int] = None
    maxqueue: Optional[int] = None
    ssl: bool = False
    verify: Optional[str] = "none"
    verifyhost: Optional[str] = None
    ciphers: Optional[str] = None
    alpn: Optional[str] = None
    sni: Optional[str] = None
    check_ssl: bool = False
    check_sni: Optional[str] = None
    check_port: Optional[int] = Field(default=None, ge=1, le=65535)
    send_proxy: bool = False
    send_proxy_v2: bool = False
    resolve: bool = False
    init_addr: Optional[str] = None
    agent_check: bool = False
    agent_port: Optional[int] = Field(default=None, ge=1, le=65535)
    track: Optional[str] = None
    protocol: str = Field(default="http", pattern="^(http|tcp|grpc|jsonrpc|fastcgi)$")
    options: Optional[Dict[str, Any]] = {}
    ca_certificate_id: Optional[int] = None
    client_certificate_id: Optional[int] = None


class ServerCreate(ServerBase):
    pass


class ServerResponse(ServerBase):
    id: int
    backend_id: int

    model_config = ConfigDict(from_attributes=True)


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    weight: Optional[int] = None
    maxconn: Optional[int] = None
    check: Optional[bool] = None
    backup: Optional[bool] = None
    inter: Optional[int] = None
    rise: Optional[int] = None
    fall: Optional[int] = None
    slowstart: Optional[int] = None
    maxqueue: Optional[int] = None
    ssl: Optional[bool] = None
    verify: Optional[str] = None
    verifyhost: Optional[str] = None
    ciphers: Optional[str] = None
    alpn: Optional[str] = None
    sni: Optional[str] = None
    check_ssl: Optional[bool] = None
    check_sni: Optional[str] = None
    check_port: Optional[int] = Field(default=None, ge=1, le=65535)
    send_proxy: Optional[bool] = None
    send_proxy_v2: Optional[bool] = None
    resolve: Optional[bool] = None
    init_addr: Optional[str] = None
    agent_check: Optional[bool] = None
    agent_port: Optional[int] = Field(default=None, ge=1, le=65535)
    track: Optional[str] = None
    protocol: Optional[str] = Field(default=None, pattern="^(http|tcp|grpc|jsonrpc|fastcgi)$")
    options: Optional[Dict[str, Any]] = None
    ca_certificate_id: Optional[int] = None
    client_certificate_id: Optional[int] = None


class BackendBase(BaseModel):
    name: str
    mode: str = "http"
    protocol: str = Field(default="http", pattern="^(http|tcp|grpc|jsonrpc|fastcgi)$")
    algorithm: str = Field(default="roundrobin", pattern="^(roundrobin|leastconn|source|uri|static-rr|random|first|hdr|url_param|rdp-cookie)$")
    sticky_sessions: bool = False
    cookie_name: Optional[str] = None
    balance_args: Optional[str] = None
    health_check_enabled: bool = True
    health_check_interval: int = 2000
    health_check_uri: str = "/"
    health_check_method: str = "GET"
    health_check_expect_status: Optional[str] = None
    health_check_expect_body: Optional[str] = None
    retries: int = 3
    redispatch: bool = False
    timeout_queue: Optional[int] = None
    timeout_check: Optional[int] = None
    timeout_tunnel: Optional[int] = None
    http_reuse: Optional[str] = Field(default=None, pattern="^(aggressive|safe|never)$")
    fullconn: Optional[int] = None
    stick_table: bool = False
    stick_table_size: str = "1m"
    stick_table_expire: str = "30m"
    stick_table_type: str = Field(default="ip", pattern="^(ip|cookie|binary|integer|string)$")
    resolvers: Optional[str] = None
    host_header: Optional[str] = None
    restore_client_ip: bool = False
    client_ip_header: str = "X-Forwarded-For"
    fcgi_app_id: Optional[int] = None
    options: Optional[Dict[str, Any]] = {}
    haproxy_options: Optional[List[HaproxyOption]] = []

    @field_validator("algorithm")
    @classmethod
    def _validate_algorithm(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"roundrobin", "leastconn", "source", "uri", "static-rr", "random", "first", "hdr", "url_param", "rdp-cookie"}
        if v not in allowed:
            raise ValueError(f"algorithm must be one of: {', '.join(sorted(allowed))}")
        return v

    @field_validator("stick_table_type")
    @classmethod
    def _validate_stick_table_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"ip", "cookie", "binary", "integer", "string"}
        if v not in allowed:
            raise ValueError(f"stick_table_type must be one of: {', '.join(sorted(allowed))}")
        return v

    @field_validator("client_ip_header")
    @classmethod
    def _validate_client_ip_header(cls, v: Optional[str]) -> Optional[str]:
        # Header names only: letters, digits, hyphen. Reject anything that
        # could break the HAProxy req.fhdr(<header>) directive.
        import re
        if v is None or v == "":
            return "X-Forwarded-For"
        if not re.fullmatch(r"[A-Za-z0-9-]+", v):
            raise ValueError(
                "client_ip_header must contain only letters, digits, and hyphens"
            )
        return v


class BackendCreate(BackendBase):
    servers: Optional[List[ServerCreate]] = []


BackendUpdate = _optional_update(BackendBase)


class BackendResponse(BackendBase):
    id: int
    servers: List[ServerResponse] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BackendRuleCondition(BaseModel):
    condition_type: str = Field(pattern="^(path|host|hdr|cookie|url_param|src)$")
    condition_name: Optional[str] = None
    operator: str = Field(pattern="^(beg|end|sub|dir|eq|found|len|reg)$")
    value: Optional[str] = None
    join: str = Field(default="and", pattern="^(and|or)$")


class BackendRuleBase(BaseModel):
    listener_id: int
    backend_id: int
    name: Optional[str] = None
    priority: int = 100
    condition_type: str = Field(default="path", pattern="^(path|host|hdr|cookie|url_param|src)$")
    condition_name: Optional[str] = None
    operator: str = Field(default="beg", pattern="^(beg|end|sub|dir|eq|found|len|reg)$")
    value: Optional[str] = None
    enabled: bool = True
    conditions: Optional[List[BackendRuleCondition]] = Field(default=None, max_length=4)

    @field_validator('conditions', mode='before')
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


__all__ = ['BackendBase', 'BackendCreate', 'BackendResponse', 'BackendRuleBase', 'BackendRuleCondition', 'BackendRuleCreate', 'BackendRuleResponse', 'BackendRuleUpdate', 'BackendUpdate', 'ServerBase', 'ServerCreate', 'ServerResponse', 'ServerUpdate']
