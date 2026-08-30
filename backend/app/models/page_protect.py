from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class PageProtectPolicy(Base):
    """CSP policy scoped to backends. Generates Content-Security-Policy headers."""
    __tablename__ = "page_protect_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True)
    backend_ids = Column(JSON, default=list, nullable=True)  # [] = all backends
    mode = Column(String, default="monitor")  # "monitor" | "enforce"
    sample_rate_percent = Column(Integer, default=100)  # 1-100, user-selectable
    report_path = Column(String, default="/_csp-report")  # CSP report-uri path
    directives = Column(JSON, default=dict, nullable=True)  # {"script-src": ["'self'", "https://..."], ...}
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class CspReport(Base):
    """Individual CSP violation report collected from HAProxy logs."""
    __tablename__ = "csp_reports"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("page_protect_policies.id"), nullable=True)
    captured_at = Column(DateTime, default=utcnow, index=True)
    client_ip = Column(String, nullable=True)
    document_uri = Column(String, nullable=True)
    referrer = Column(String, nullable=True)
    violated_directive = Column(String, nullable=True, index=True)
    effective_directive = Column(String, nullable=True)
    original_policy = Column(Text, nullable=True)
    blocked_uri = Column(String, nullable=True, index=True)
    source_file = Column(String, nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    status_code = Column(Integer, nullable=True)
    script_sample = Column(Text, nullable=True)
    backend_name = Column(String, nullable=True)
    listener_name = Column(String, nullable=True)
    report_type = Column(String, default="csp")  # "csp" (report-uri) | "reporting-api" (report-to)

    policy = relationship("PageProtectPolicy")


class PageProtectScript(Base):
    """Detected script/connection/resource inventory with code-change tracking."""
    __tablename__ = "page_protect_scripts"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True, nullable=False)
    resource_type = Column(String, default="script")  # script|connect|img|style|font|frame|object|other
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    occurrence_count = Column(Integer, default=1)
    domain = Column(String, nullable=True, index=True)
    first_hash = Column(String, nullable=True)  # SHA-256 of first-seen content
    first_hash_at = Column(DateTime, nullable=True)
    last_hash = Column(String, nullable=True)  # SHA-256 of last-checked content
    last_hash_at = Column(DateTime, nullable=True)  # When last_hash was set (last successful check)
    hash_checked_at = Column(DateTime, nullable=True)
    hash_changed = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    source = Column(String, default="csp")  # csp | manual | beacon


__all__ = ['CspReport', 'PageProtectPolicy', 'PageProtectScript']
