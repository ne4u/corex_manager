from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class CacheConfig(Base):
    """Per-backend cache configuration for memory cache (HAProxy native) and disk cache."""
    __tablename__ = "cache_configs"

    id = Column(Integer, primary_key=True, index=True)
    backend_id = Column(Integer, ForeignKey("backends.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)

    # Memory cache (HAProxy native in-memory cache)
    haproxy_enabled = Column(Boolean, default=False)
    haproxy_total_max_size = Column(Integer, default=100)  # MB (1-4095)
    haproxy_max_object_size = Column(Integer, default=1000000)  # bytes (~1MB)
    haproxy_max_age = Column(Integer, default=300)  # seconds
    haproxy_process_vary = Column(Boolean, default=True)
    haproxy_max_secondary_entries = Column(Integer, default=10)
    haproxy_cache_condition = Column(String, nullable=True)  # optional HAProxy ACL condition
    # RFC 7234 compliance for the memory cache. When False (default, CDN-style
    # behavior), request-side Cache-Control/Pragma headers are stripped before
    # the cache lookup so a single client's "no-cache" reload does not bypass
    # the shared cache for everyone. When True, the headers are honored per RFC
    # 7234 and a request with Cache-Control: no-cache bypasses the cache.
    haproxy_rfc7234_compliance = Column(Boolean, default=False)

    # Disk cache (file-backed, gated by global disk_cache_enabled setting)
    disk_cache_enabled = Column(Boolean, default=False)
    disk_cache_ttl = Column(Integer, default=120)  # seconds
    disk_cache_grace = Column(Integer, default=600)  # seconds
    disk_cache_purge_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    backend = relationship("Backend", back_populates="cache_config")
    rules = relationship(
        "CacheRule",
        back_populates="cache_config",
        cascade="all, delete-orphan",
        order_by="CacheRule.priority",
    )


class CacheRule(Base):
    """Ordered, first-match-wins cacheability rule for a backend's cache config.

    Rules decide whether a request is cacheable. They are evaluated in `priority`
    order and the first match wins: `action="cache"` allows caching, `action="bypass"`
    proxies to the origin without storing. When a tier is enabled but no rule
    matches, nothing is cached.

    Each rule targets a specific cache tier via the `tier` field (required):
    - "memory": applies only to memory cache (HAProxy ACLs on `http-request cache-use`)
    - "disk": applies only to disk cache (HAProxy use-server directives)
    
    To cache the same pattern in both tiers, create two separate rules.
    """
    __tablename__ = "cache_rules"

    id = Column(Integer, primary_key=True, index=True)
    cache_config_id = Column(Integer, ForeignKey("cache_configs.id", ondelete="CASCADE"), nullable=False, index=True)
    priority = Column(Integer, default=0, nullable=False)
    enabled = Column(Boolean, default=True)
    match_type = Column(String, nullable=False)  # "path" | "filename" | "extension"
    pattern = Column(String, nullable=False)     # normalized on save
    action = Column(String, default="cache", nullable=False)  # "cache" | "bypass"
    tier = Column(String, nullable=False)  # "memory" | "disk" (required)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    cache_config = relationship("CacheConfig", back_populates="rules")


__all__ = ['CacheConfig', 'CacheRule']
