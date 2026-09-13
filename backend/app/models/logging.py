from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class VectorSink(Base):
    __tablename__ = "vector_sinks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    type = Column(String, nullable=False)
    source = Column(String, nullable=False, default="corex")
    options = Column(JSON, default=dict, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class CustomErrorPage(Base):
    __tablename__ = "custom_error_pages"

    id = Column(Integer, primary_key=True, index=True)
    listener_id = Column(Integer, ForeignKey("listeners.id"), nullable=True)
    listener_ids = Column(JSON, default=list, nullable=True)
    code = Column(Integer, nullable=False)
    content_type = Column(String, default="text/html")
    content = Column(Text, nullable=False)
    listener = relationship("Listener")


__all__ = ['CustomErrorPage', 'VectorSink']
