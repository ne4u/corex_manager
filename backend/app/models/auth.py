from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, utcnow


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="operator")  # admin, operator, viewer
    is_admin = Column(Boolean, default=False)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    # SSL Labs API registration contact fields
    email = Column(String, nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    # Password rotation + last-login tracking. password_changed_at is set on
    # account creation and every successful password change; last_login_at is
    # updated on each successful login.
    last_login_at = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=utcnow)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class UserPreference(Base):
    __tablename__ = "user_preferences"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    theme = Column(String, nullable=True)  # active theme name
    custom_themes = Column(JSON, nullable=True)  # user-created themes as JSON
    language = Column(String, nullable=True)  # UI language code (e.g. 'en', 'es'); null = default
    datetime_format = Column(String, nullable=True)  # date-fns format string (e.g. 'yyyy-MM-dd HH:mm:ss'); null = default
    timezone = Column(String, nullable=True)  # 'local', 'utc', or IANA tz (e.g. 'America/New_York'); null = default
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    user = relationship("User", backref="preferences")


__all__ = ['Setting', 'User', 'UserPreference']
