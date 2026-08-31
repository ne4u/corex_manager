from sqlalchemy import Column, Integer, BigInteger, String, Boolean, Text, DateTime, ForeignKey, JSON, Index
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


class SslLabsScan(Base):
    """SSL Labs assessment result for a certificate's host.

    Multiple historical scans per (certificate_id, host) are kept. The
    ``ssllabs_max_scans_per_host`` setting controls how many completed
    scans are retained; older completed scans are pruned on each new
    completion.
    """
    __tablename__ = "ssllabs_scans"

    id = Column(Integer, primary_key=True, index=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False, index=True)
    host = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)  # DNS, IN_PROGRESS, READY, ERROR
    status_message = Column(String, nullable=True)
    grade = Column(String, nullable=True)  # best endpoint grade (e.g. A+, A, B)
    report = Column(JSON, nullable=True)  # full SSL Labs Host object
    start_time = Column(BigInteger, nullable=True)  # SSL Labs ms epoch
    test_time = Column(BigInteger, nullable=True)  # SSL Labs ms epoch (completion)
    engine_version = Column(String, nullable=True)
    criteria_version = Column(String, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_ssllabs_scans_cert_host_created", "certificate_id", "host", "created_at"),
    )


__all__ = ['CacheMetricSnapshot', 'MetricSnapshot', 'SslLabsScan']
