from sqlalchemy import Column, DateTime, func
from sqlalchemy.orm import declarative_base

from ..core.database import Base as _Base

Base = _Base


def utcnow():
    from datetime import datetime, timezone
    # Return naive UTC — the column type is TIMESTAMP WITHOUT TIME ZONE.
    # Passing a tz-aware datetime to PostgreSQL for a non-tz column causes
    # the server to convert it to the session timezone before stripping the
    # offset, which can shift stored values away from UTC if the session TZ
    # is not UTC. Returning naive UTC avoids this conversion entirely.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TimestampMixin:
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
