"""Dynamic settings stored in the database, with env fallback."""
from typing import Optional
from sqlalchemy.orm import Session
from ..core.config import get_settings
from ..models.models import Setting

settings = get_settings()


def get_setting(db: Session, key: str, default: Optional[str] = None) -> Optional[str]:
    """Return a setting value from the database or fall back to env/config.

    Values are always returned as strings so they serialize cleanly as SettingResponse.
    """
    row = db.query(Setting).filter(Setting.key == key).first()
    if row and row.value is not None:
        return row.value
    value = getattr(settings, key.upper(), default)
    if value is None:
        return None
    return str(value)


def set_setting(db: Session, key: str, value: Optional[str]) -> Setting:
    """Create or update a setting value."""
    row = db.query(Setting).filter(Setting.key == key).first()
    if not row:
        row = Setting(key=key, value=value)
        db.add(row)
    else:
        row.value = value
    db.commit()
    db.refresh(row)
    return row


def list_settings(db: Session) -> list[Setting]:
    return db.query(Setting).all()


def get_maxmind_license_key(db: Session) -> Optional[str]:
    """Return the MaxMind license key, preferring DB over env."""
    return get_setting(db, "maxmind_license_key", settings.MAXMIND_LICENSE_KEY)
