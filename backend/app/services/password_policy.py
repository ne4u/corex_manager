"""Password complexity and rotation policy.

Settings are stored in the ``settings`` table (overridable at runtime by an
admin) with env/config fallback defaults from :class:`Settings`. All values
are read as strings from the settings table and normalized here.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..models.auth import User
from .settings import get_setting

settings = get_settings()


# Setting keys (lowercase, as stored in the settings table).
KEY_MIN_LENGTH = "password_min_length"
KEY_REQUIRE_UPPERCASE = "password_require_uppercase"
KEY_REQUIRE_LOWERCASE = "password_require_lowercase"
KEY_REQUIRE_DIGIT = "password_require_digit"
KEY_REQUIRE_SYMBOL = "password_require_symbol"
KEY_ROTATION_MONTHS = "password_rotation_months"


def _to_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return (str(value).strip().lower() in ("true", "1", "yes", "on"))


def _to_int(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def get_password_policy(db: Session) -> dict:
    """Return the active password policy as a typed dict."""
    return {
        "min_length": max(1, _to_int(get_setting(db, KEY_MIN_LENGTH), settings.PASSWORD_MIN_LENGTH)),
        "require_uppercase": _to_bool(get_setting(db, KEY_REQUIRE_UPPERCASE), settings.PASSWORD_REQUIRE_UPPERCASE),
        "require_lowercase": _to_bool(get_setting(db, KEY_REQUIRE_LOWERCASE), settings.PASSWORD_REQUIRE_LOWERCASE),
        "require_digit": _to_bool(get_setting(db, KEY_REQUIRE_DIGIT), settings.PASSWORD_REQUIRE_DIGIT),
        "require_symbol": _to_bool(get_setting(db, KEY_REQUIRE_SYMBOL), settings.PASSWORD_REQUIRE_SYMBOL),
        "rotation_months": max(0, _to_int(get_setting(db, KEY_ROTATION_MONTHS), settings.PASSWORD_ROTATION_MONTHS)),
    }


def validate_password_complexity(db: Session, password: str) -> None:
    """Raise ``ValueError`` with a descriptive message if ``password`` fails
    the configured complexity rules. Returns silently on success.
    """
    policy = get_password_policy(db)
    errors: list[str] = []

    if len(password) < policy["min_length"]:
        errors.append(f"at least {policy['min_length']} characters")
    if policy["require_uppercase"] and not any(c.isupper() for c in password):
        errors.append("an uppercase letter")
    if policy["require_lowercase"] and not any(c.islower() for c in password):
        errors.append("a lowercase letter")
    if policy["require_digit"] and not any(c.isdigit() for c in password):
        errors.append("a digit")
    if policy["require_symbol"] and not any(not c.isalnum() for c in password):
        errors.append("a symbol")

    if errors:
        raise ValueError("Password must contain " + ", ".join(errors))


def is_password_expired(user: User, db: Session) -> bool:
    """Return ``True`` if the user's password is past the rotation period.

    Rotation is disabled (returns ``False``) when ``rotation_months`` is 0.
    A user with no ``password_changed_at`` falls back to ``created_at``; if
    neither is set the password is treated as not expired (defensive).
    """
    policy = get_password_policy(db)
    months = policy["rotation_months"]
    if months <= 0:
        return False

    anchor = user.password_changed_at or user.created_at
    if anchor is None:
        return False

    # Normalize naive datetimes (SQLite stores tz-naive) to UTC for comparison.
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)

    expiry = anchor.replace(tzinfo=timezone.utc) + _months_to_timedelta(months)
    return datetime.now(timezone.utc) >= expiry


def _months_to_timedelta(months: int):
    """Approximate a month as 30 days for expiry comparison."""
    from datetime import timedelta
    return timedelta(days=30 * months)
