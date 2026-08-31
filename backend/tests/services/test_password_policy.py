"""Unit tests for the password policy service."""
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import get_password_hash
from app.models.models import Setting, User
from app.services.password_policy import (
    get_password_policy,
    is_password_expired,
    validate_password_complexity,
)


def test_default_policy_lenient(db):
    policy = get_password_policy(db)
    assert policy["min_length"] == 8
    assert policy["require_uppercase"] is False
    assert policy["require_lowercase"] is False
    assert policy["require_digit"] is False
    assert policy["require_symbol"] is False
    assert policy["rotation_months"] == 0


def test_policy_reads_settings(db):
    for key, val in [
        ("password_min_length", "12"),
        ("password_require_uppercase", "true"),
        ("password_require_lowercase", "1"),
        ("password_require_digit", "yes"),
        ("password_require_symbol", "false"),
        ("password_rotation_months", "3"),
    ]:
        db.add(Setting(key=key, value=val))
    db.commit()
    policy = get_password_policy(db)
    assert policy["min_length"] == 12
    assert policy["require_uppercase"] is True
    assert policy["require_lowercase"] is True
    assert policy["require_digit"] is True
    assert policy["require_symbol"] is False
    assert policy["rotation_months"] == 3


def test_validate_too_short(db):
    db.add(Setting(key="password_min_length", value="10"))
    db.commit()
    with pytest.raises(ValueError, match="at least 10 characters"):
        validate_password_complexity(db, "short")


def test_validate_requires_uppercase(db):
    db.add(Setting(key="password_require_uppercase", value="true"))
    db.commit()
    with pytest.raises(ValueError, match="uppercase"):
        validate_password_complexity(db, "alllowercase1!")


def test_validate_requires_lowercase(db):
    db.add(Setting(key="password_require_lowercase", value="true"))
    db.commit()
    with pytest.raises(ValueError, match="lowercase"):
        validate_password_complexity(db, "ALLUPPERCASE1!")


def test_validate_requires_digit(db):
    db.add(Setting(key="password_require_digit", value="true"))
    db.commit()
    with pytest.raises(ValueError, match="digit"):
        validate_password_complexity(db, "NoDigitsHere!")


def test_validate_requires_symbol(db):
    db.add(Setting(key="password_require_symbol", value="true"))
    db.commit()
    with pytest.raises(ValueError, match="symbol"):
        validate_password_complexity(db, "NoSymbol123")


def test_validate_all_rules_pass(db):
    for key, val in [
        ("password_min_length", "8"),
        ("password_require_uppercase", "true"),
        ("password_require_lowercase", "true"),
        ("password_require_digit", "true"),
        ("password_require_symbol", "true"),
    ]:
        db.add(Setting(key=key, value=val))
    db.commit()
    # Should not raise.
    validate_password_complexity(db, "Abcdef1!")


def test_is_password_expired_disabled(db):
    user = User(username="u1", hashed_password="x")
    db.add(user)
    db.commit()
    db.refresh(user)
    assert is_password_expired(user, db) is False


def test_is_password_expired_not_yet(db):
    db.add(Setting(key="password_rotation_months", value="3"))
    db.commit()
    user = User(
        username="u2",
        hashed_password="x",
        password_changed_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    assert is_password_expired(user, db) is False


def test_is_password_expired_past(db):
    db.add(Setting(key="password_rotation_months", value="1"))
    db.commit()
    # 2 months ago > 1 month rotation
    user = User(
        username="u3",
        hashed_password="x",
        password_changed_at=datetime.now(timezone.utc) - timedelta(days=60),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    assert is_password_expired(user, db) is True


def test_is_password_expired_falls_back_to_created_at(db):
    db.add(Setting(key="password_rotation_months", value="1"))
    db.commit()
    user = User(
        username="u4",
        hashed_password="x",
        created_at=datetime.now(timezone.utc) - timedelta(days=60),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    # Force password_changed_at to NULL (the column default=utcnow would
    # otherwise set it on insert). This simulates a row where the backfill
    # didn't run or the column was manually cleared.
    from sqlalchemy import text
    db.execute(text("UPDATE users SET password_changed_at = NULL WHERE id = :id"), {"id": user.id})
    db.commit()
    db.refresh(user)
    assert user.password_changed_at is None
    assert is_password_expired(user, db) is True


def test_is_password_expired_no_timestamps(db):
    db.add(Setting(key="password_rotation_months", value="1"))
    db.commit()
    user = User(username="u5", hashed_password="x")
    db.add(user)
    db.commit()
    db.refresh(user)
    # Force both timestamps to NULL to simulate a completely bare row.
    from sqlalchemy import text
    db.execute(
        text("UPDATE users SET password_changed_at = NULL, created_at = NULL WHERE id = :id"),
        {"id": user.id},
    )
    db.commit()
    db.refresh(user)
    assert user.password_changed_at is None
    assert user.created_at is None
    # No timestamps at all -> not expired (defensive)
    assert is_password_expired(user, db) is False
