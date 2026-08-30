from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    captured_at = Column(DateTime, default=utcnow, index=True)
    process_info = Column(JSON, nullable=True)
    stats = Column(JSON, nullable=True)  # list of HAProxy CSV stat rows


class CacheMetricSnapshot(Base):
    """Periodic snapshot of cache metrics for time-series charts."""
    __tablename__ = "cache_metric_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    backend_id = Column(Integer, ForeignKey("backends.id", ondelete="CASCADE"), nullable=True, index=True)  # null = global aggregate
    haproxy_stats = Column(JSON, default=dict)  # memory cache hit/miss/bytes from show stat
    disk_cache_stats = Column(JSON, default=dict)  # disk cache hit/miss/objects from varnishstat
    lua_module_stats = Column(JSON, default=dict)  # brotli/zstd + WebP bytes-saved from Rust module CLI
__all__ = ['CacheMetricSnapshot', 'MetricSnapshot']
