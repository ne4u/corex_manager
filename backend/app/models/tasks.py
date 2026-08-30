from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_type = Column(String, nullable=False)  # apply_config, issue_certificate, renew_certificates
    status = Column(String, default="pending")  # pending, running, success, failed
    payload = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class ConfigSnapshot(Base):
    __tablename__ = "config_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=utcnow)
    created_by = Column(String, nullable=True)
    comment = Column(String, nullable=True)
    diff = Column(Text, nullable=True)
    snapshot_path = Column(String, nullable=False)


__all__ = ['ConfigSnapshot', 'Task']
