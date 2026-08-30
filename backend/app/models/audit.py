from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON, text
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String, nullable=True)
    action = Column(String, nullable=False)  # semantic: create_backend, apply_config, login
    method = Column(String, nullable=False)  # POST/PUT/DELETE/PATCH
    path = Column(String, nullable=False)
    resource_type = Column(String, nullable=True)  # backend, server, listener, etc.
    resource_id = Column(String, nullable=True)  # affected entity id
    status_code = Column(Integer, nullable=True)
    ip_address = Column(String, nullable=True)
    payload = Column(JSON, nullable=True)  # request body (truncated, JSON only)
    snapshot_id = Column(Integer, ForeignKey("config_snapshots.id"), nullable=True, index=True)
    # True when the action affects generated config (HAProxy/Coraza/Varnish/MCP/
    # security-list/risk-rules). False for non-config actions (theme, user CRUD,
    # captcha key management, logins, cache flush, validation-only, etc.) so the
    # audit log "Pending Changes" section doesn't show them as needing an apply.
    config_change = Column(Boolean, default=True, nullable=False, server_default=text("true"))

    user = relationship("User")


__all__ = ['AuditEvent']
