from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class LogDestination(Base):
    __tablename__ = "log_destinations"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    name = Column(String, unique=True, index=True, nullable=False)
    target = Column(String, nullable=False)
    facility = Column(String, default="local0")
    level = Column(String, default="info")
    format = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    listener = relationship("Listener")


class LoggedField(Base):
    __tablename__ = "logged_fields"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    name = Column(String, nullable=False)
    field = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    listener = relationship("Listener")


class CustomErrorPage(Base):
    __tablename__ = "custom_error_pages"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    listener_ids = Column(JSON, default=list, nullable=True)
    code = Column(Integer, nullable=False)
    content_type = Column(String, default="text/html")
    content = Column(Text, nullable=False)
    listener = relationship("Listener")


__all__ = ['CustomErrorPage', 'LogDestination', 'LoggedField']
