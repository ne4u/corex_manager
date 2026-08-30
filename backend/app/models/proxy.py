from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    domain = Column(String, default="", nullable=False)
    provider = Column(String, default="letsencrypt")  # letsencrypt, custom
    email = Column(String, nullable=True)
    is_wildcard = Column(Boolean, default=False)
    auto_renew = Column(Boolean, default=True)
    cert_path = Column(String, nullable=True)
    key_path = Column(String, nullable=True)
    chain_path = Column(String, nullable=True)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    subject_cn = Column(String, nullable=True)
    sans = Column(String, nullable=True)
    key_type = Column(String, default="ecdsa-p384")
    acme_challenge = Column(String, default="dns")  # http, dns
    acme_ca = Column(String, nullable=True)  # letsencrypt, zerossl, buypass, etc.
    dns_provider = Column(String, nullable=True)
    dns_credentials = Column(JSON, nullable=True)
    kind = Column(String, default="server")  # server, client, ca
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class CipherSuite(Base):
    __tablename__ = "cipher_suites"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    baseline = Column(String, nullable=False)  # fips, fedramp, pci, modern, custom
    ciphers = Column(Text, nullable=False)
    tls_options = Column(String, default="no-sslv3 no-tlsv10 no-tlsv11")
    min_tls_version = Column(String, default="TLSv1.2")
    quantum_safe = Column(Boolean, default=False)
    hsts_enabled = Column(Boolean, default=True)
    hsts_max_age = Column(Integer, default=31536000)
    hsts_include_subdomains = Column(Boolean, default=True)
    hsts_preload = Column(Boolean, default=False)


class FcgiApp(Base):
    __tablename__ = "fcgi_apps"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    docroot = Column(String, nullable=True)
    index = Column("index_file", String, nullable=True)
    path_info = Column(String, nullable=True)
    log_stderr_enabled = Column(Boolean, default=False)
    log_stderr_target = Column(String, nullable=True)
    keep_conn = Column(Boolean, default=True)
    mpxs_conns = Column(Boolean, default=False)
    max_reqs = Column(Integer, default=1)
    params = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class Listener(Base):
    __tablename__ = "listeners"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    bind_address = Column(String, default="0.0.0.0")
    bind_port = Column(Integer, nullable=False)
    mode = Column(String, default="http")  # http, tcp
    protocol = Column(String, default="http")  # http, tcp, grpc, jsonrpc, mcp
    enabled = Column(Boolean, default=True)
    ssl_enabled = Column(Boolean, default=False)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    certificate_ids = Column(JSON, default=list, nullable=True)
    http2 = Column(Boolean, default=False)
    quic = Column(Boolean, default=False)
    alpn = Column(String, nullable=True)  # h2,http/1.1 or h3
    proxy_protocol = Column(Boolean, default=False)
    force_https = Column(Boolean, default=False)
    default_backend_id = Column(Integer, ForeignKey("backends.id"), nullable=True)
    options = Column(JSON, default=dict)
    haproxy_options = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    certificate = relationship("Certificate")


class Backend(Base):
    __tablename__ = "backends"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    mode = Column(String, default="http")  # http, tcp
    protocol = Column(String, default="http")  # http, tcp, grpc, jsonrpc
    algorithm = Column(String, default="roundrobin")  # roundrobin, leastconn, source, uri, static-rr
    sticky_sessions = Column(Boolean, default=False)
    cookie_name = Column(String, nullable=True)
    balance_args = Column(String, nullable=True)
    health_check_enabled = Column(Boolean, default=True)
    health_check_interval = Column(Integer, default=2000)
    health_check_uri = Column(String, default="/")
    health_check_method = Column(String, default="GET")
    health_check_expect_status = Column(String, nullable=True)
    health_check_expect_body = Column(String, nullable=True)
    retries = Column(Integer, default=3)
    redispatch = Column(Boolean, default=False)
    timeout_queue = Column(Integer, nullable=True)
    timeout_check = Column(Integer, nullable=True)
    timeout_tunnel = Column(Integer, nullable=True)
    http_reuse = Column(String, nullable=True)  # aggressive, safe, never
    fullconn = Column(Integer, nullable=True)
    stick_table = Column(Boolean, default=False)
    stick_table_size = Column(String, default="1m")
    stick_table_expire = Column(String, default="30m")
    stick_table_type = Column(String, default="ip")  # ip, cookie, etc
    resolvers = Column(String, nullable=True)
    host_header = Column(String, nullable=True)
    # Restore the real client IP from a header (e.g. X-Forwarded-For) for pools
    # whose traffic arrives via a CDN/proxy. Emits http-request set-src in the
    # frontend so logging %ci and all src-based rules see the real client IP.
    restore_client_ip = Column(Boolean, default=False)
    client_ip_header = Column(String, default="X-Forwarded-For")
    fcgi_app_id = Column(Integer, ForeignKey("fcgi_apps.id", ondelete="SET NULL"), nullable=True)
    options = Column(JSON, default=dict)
    haproxy_options = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    fcgi_app = relationship("FcgiApp")
    servers = relationship("Server", back_populates="backend", cascade="all, delete-orphan")
    cache_config = relationship("CacheConfig", uselist=False, back_populates="backend", cascade="all, delete-orphan")


class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)
    backend_id = Column(Integer, ForeignKey("backends.id"), nullable=False)
    name = Column(String, nullable=False)
    address = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    weight = Column(Integer, default=100)
    maxconn = Column(Integer, default=10000)
    check = Column(Boolean, default=True)
    backup = Column(Boolean, default=False)
    inter = Column(Integer, nullable=True)
    rise = Column(Integer, nullable=True)
    fall = Column(Integer, nullable=True)
    slowstart = Column(Integer, nullable=True)
    maxqueue = Column(Integer, nullable=True)
    ssl = Column(Boolean, default=False)
    verify = Column(String, default="none")  # none, required
    verifyhost = Column(String, nullable=True)
    ciphers = Column(String, nullable=True)
    alpn = Column(String, nullable=True)
    sni = Column(String, nullable=True)
    check_ssl = Column(Boolean, default=False)
    check_sni = Column(String, nullable=True)
    check_port = Column(Integer, nullable=True)
    send_proxy = Column(Boolean, default=False)
    send_proxy_v2 = Column(Boolean, default=False)
    resolve = Column(Boolean, default=False)
    init_addr = Column(String, nullable=True)
    agent_check = Column(Boolean, default=False)
    agent_port = Column(Integer, nullable=True)
    track = Column(String, nullable=True)
    protocol = Column(String, default="http")  # http, tcp, grpc, jsonrpc, fastcgi
    options = Column(JSON, default=dict)
    ca_certificate_id = Column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True)
    client_certificate_id = Column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True)

    backend = relationship("Backend", back_populates="servers")
    ca_certificate = relationship("Certificate", foreign_keys=[ca_certificate_id])
    client_certificate = relationship("Certificate", foreign_keys=[client_certificate_id])


class BackendRule(Base):
    __tablename__ = "backend_rules"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=False)
    backend_id = Column(Integer, ForeignKey("backends.id"), nullable=False)
    name = Column(String, nullable=False)
    priority = Column(Integer, default=100)
    condition_type = Column(String, default="path")  # path, host, hdr, cookie, url_param, src
    condition_name = Column(String, nullable=True)  # header name, cookie name, url param name
    operator = Column(String, default="beg")  # beg, end, sub, dir, eq, found
    value = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    conditions = Column(JSON, default=list, nullable=True)  # chained conditions (2nd-5th)

    listener = relationship("Listener")
    backend = relationship("Backend")


__all__ = ['Backend', 'BackendRule', 'Certificate', 'CipherSuite', 'FcgiApp', 'Listener', 'Server']
