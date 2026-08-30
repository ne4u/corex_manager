from sqlalchemy import Column, DateTime, func
from sqlalchemy.orm import declarative_base

from ..core.database import Base as _Base

Base = _Base


def utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
