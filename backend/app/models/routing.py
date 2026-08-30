from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class RateLimit(Base):
    __tablename__ = "rate_limits"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    name = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True)
    limit_type = Column(String, default="basic")  # basic, advanced, waf, response_code
    events = Column(Integer, default=100)
    window_seconds = Column(Integer, default=60)
    burst = Column(Integer, default=20)
    action = Column(String, default="block")  # allow, block, log, tarpit, challenge
    duration_seconds = Column(Integer, default=300)
    expression = Column(Text, nullable=True)  # For advanced/waf conditions
    response_code = Column(Integer, nullable=True)
    match_status_code = Column(Integer, nullable=True)  # For response_code type: backend status to count (e.g. 404)
    url_path = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    waf_event_threshold = Column(Integer, nullable=True)
    waf_window_seconds = Column(Integer, nullable=True)
    waf_block_duration = Column(Integer, nullable=True)
    rate_key = Column(String, default="src")  # src, user_id, header, path, asn, graphql_operation, api_key
    rate_header = Column(String, nullable=True)
    log = Column(Boolean, default=True)  # record action in request log line
    no_log = Column(Boolean, default=False)  # suppress entire request log line
    # API Armor per-endpoint scoping
    path_pattern = Column(String, nullable=True)  # regex or prefix for endpoint scoping
    method = Column(String, nullable=True)  # GET, POST, etc. (None = all methods)
    api_armor_scoped = Column(Boolean, default=False)  # true when using graphql_operation/api_key rate key
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    listener = relationship("Listener")


class Redirect(Base):
    __tablename__ = "redirects"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    listener_ids = Column(JSON, default=list, nullable=True)
    priority = Column(Integer, default=0, index=True, nullable=False)
    name = Column(String, unique=True, index=True, nullable=False)
    source = Column(String, nullable=False)
    target = Column(String, nullable=False)
    type = Column(String, default="permanent")  # permanent, temporary, regex
    code = Column(Integer, default=301)
    preserve_query = Column(Boolean, default=True)
    error_page_id = Column(Integer, ForeignKey("custom_error_pages.id"), nullable=True)
    error_page_query = Column(String, nullable=True)
    listener = relationship("Listener")
    error_page = relationship("CustomErrorPage")


class Rewrite(Base):
    __tablename__ = "rewrites"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    listener_ids = Column(JSON, default=list, nullable=True)
    priority = Column(Integer, default=0, index=True, nullable=False)
    name = Column(String, unique=True, index=True, nullable=False)
    host_match = Column(String, nullable=True)  # host header value; None = any host
    source_regex = Column(String, nullable=False)
    target = Column(String, nullable=False)
    type = Column(String, default="path")  # path, query, both
    listener = relationship("Listener")


class ResponseHeader(Base):
    __tablename__ = "response_headers"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    listener_ids = Column(JSON, default=list, nullable=True)
    name = Column(String, nullable=False)
    header = Column(String, nullable=False)
    value = Column(String, nullable=False)
    action = Column(String, default="override")  # add, del, override
    condition = Column(String, nullable=True)
    listener = relationship("Listener")


class RequestHeader(Base):
    __tablename__ = "request_headers"

    id = Column(Integer, primary_key=True, index=True)
    backend_id = Column(Integer, ForeignKey("backends.id"), nullable=True)
    backend_ids = Column(JSON, default=list, nullable=True)
    name = Column(String, nullable=False)
    header = Column(String, nullable=False)
    value = Column(String, nullable=False)
    action = Column(String, default="override")  # add, del, override
    condition = Column(String, nullable=True)
    backend = relationship("Backend")


class ResponseTransform(Base):
    __tablename__ = "response_transforms"

    id = Column(Integer, primary_key=True, index=True)
    backend_id = Column(Integer, ForeignKey("backends.id"), nullable=True)
    backend_ids = Column(JSON, default=list, nullable=True)  # per-backend scoping
    priority = Column(Integer, default=0, index=True, nullable=False)
    name = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True)
    transform_type = Column(String, nullable=False)  # replace | inject | mask
    content_types = Column(String, nullable=True)  # comma-sep MIME prefixes; empty = all
    max_body_size = Column(Integer, default=1048576)  # skip if body larger
    # replace / inject
    find_regex = Column(Text, nullable=True)
    replace_string = Column(Text, nullable=True)  # replace mode (supports $1 backrefs)
    # inject mode
    inject_string = Column(Text, nullable=True)
    inject_position = Column(String, nullable=True)  # before | after | replace
    # mask mode
    mask_mode = Column(String, nullable=True)  # regex | detector
    detector = Column(String, nullable=True)  # email | phone | ssn | credit_card | ip
    token_mode = Column(String, nullable=True)  # tokenize | encrypt
    token_prefix = Column(String, nullable=True)  # e.g. TOK_ / ENC_
    token_ttl = Column(Integer, nullable=True)  # seconds; tokenize mode
    encrypt_key_env = Column(String, nullable=True)  # env var name holding AES key; encrypt mode
    detokenize_query = Column(Boolean, default=False, nullable=False)  # mask: also detokenize query string on request
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    backend = relationship("Backend")


__all__ = ['RateLimit', 'Redirect', 'RequestHeader', 'ResponseHeader', 'ResponseTransform', 'Rewrite']
